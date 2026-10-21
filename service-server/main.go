// arauth 依赖方（主站）后端转发参考实现（docs/DESIGN.md 第 9 节）。
//
// 这是"模式示范"，不是生产模板：会话与代持票据全部放进程内存 map、无持久化、
// 无前端页面、无优雅退出。生产依赖方应把 map 换成自己的会话存储（Redis/DB），
// 但转发与换发的模式照抄本文件即可。
//
// 集成红线（冻结决定 8，DESIGN.md 第 7 节）：浏览器永不直连 arauth。
// 链路永远是 浏览器 → 本服务（第一方）→ arauth（服务器到服务器）。
//
// 为什么这里完全没有 CORS：CORS 是浏览器对跨源脚本请求的放行机制。浏览器只
// 与本服务通信（同源，第一方），本服务到 arauth 是服务器到服务器调用，不经
// 浏览器、没有 Origin 概念。因此本文件不出现任何 Access-Control-* 头；生产
// 形态下 arauth 侧也不提供 CORS。
//
// 头/字段重写清单（相对"原样转发"的全部例外，逐条理由见各 handler 注释）：
//  1. arauth 响应的 Set-Cookie（arauth_session）一律不透传给浏览器：
//     register/verify 时代持进服务端 jar（register/confirm 与 TOTP enroll 用它
//     鉴权），login/verify 时代持进 rp_session 对应条目，仅保留 15 分钟 fresh
//     窗口供 TOTP enroll 使用；登录态本身仍由本服务的 rp_session 表达。
//  2. arauth /login/verify 响应体里的 exchange_code 不转发给浏览器：
//     它是"必须配合共享 API key 才能用"的服务端票据，本服务收到后立即
//     调 /exchange 核销，给浏览器的响应只留最小字段。
//  3. /exchange 请求注入 X-Arauth-Exchange-Key：共享密钥只存在于服务器到
//     服务器通道，绝不出现在任何响应、日志或浏览器可见的位置。
//  4. register/confirm 与 recovery/totp/enroll/* 转发时注入代持的
//     Cookie: arauth_session=...。浏览器侧的 rp_pending / rp_session cookie
//     只是服务端条目的钥匙（opaque 随机串），本身不是 arauth 会话凭证；
//     enroll 的 flow=register/login 仅显式选择对应钥匙，防止身份歧义。
//  5. 所有上行请求只带本服务生成的单值 X-Forwarded-For；除恢复 token
//     白名单与上述服务端注入头外，不复制任何浏览器请求头。
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// 依赖方自身会话与 pending 代持的存活时长。参考实现取定值即可（与 arauth
// 默认对齐），生产依赖方按自己的产品需要定。
const (
	sessionTTL = 14 * 24 * time.Hour // rp_session 存活时长
	pendingTTL = 24 * time.Hour      // rp_pending（注册确认代持）存活时长
	freshTTL   = 15 * time.Minute    // 登录后允许 TOTP enroll 的 fresh 窗口

	// maxBodySize 是转发请求体的上限（WebAuthn attestation/assertion JSON
	// 不过数 KB，1 MiB 已极宽裕）。
	maxBodySize = 1 << 20

	// rp_session / rp_pending 是本服务种给浏览器的两个第一方 cookie。
	// 名字固定即可，不是可调数值。
	sessionCookieName = "rp_session"
	pendingCookieName = "rp_pending"
)

// config 是参考服务的全部配置（RP_ 前缀环境变量）。
type config struct {
	addr              string
	arauthURL         string // arauth 服务端 URL（内网 HTTP 或外部 HTTPS）
	exchangeAPIKey    string // 与 arauth 的 ARAUTH_EXCHANGE_API_KEY 共享（服务器机密）
	rpID              string // WebAuthn rp.id，必须与 arauth 的 ARAUTH_RPID 一致
	origins           []string
	cookieSecure      bool
	trustProxyHeaders bool
	httpClient        *http.Client
}

// loadConfig 读环境变量并做启动期校验。缺必填项或 RP ID 纪律违例直接报错
// 退出——宁可起不来，不带病运行。
func loadConfig() (*config, error) {
	c := &config{
		addr:           envOr("RP_ADDR", ":8081"),
		arauthURL:      strings.TrimRight(os.Getenv("RP_ARAUTH_URL"), "/"),
		exchangeAPIKey: os.Getenv("RP_EXCHANGE_API_KEY"),
		rpID:           os.Getenv("RP_ID"),
		cookieSecure:   true,
	}

	if raw := os.Getenv("RP_COOKIE_SECURE"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("config: RP_COOKIE_SECURE 只接受 true/false，得到 %q", raw)
		}
		c.cookieSecure = b
	}
	if raw := os.Getenv("RP_TRUST_PROXY_HEADERS"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("config: RP_TRUST_PROXY_HEADERS 只接受 true/false，得到 %q", raw)
		}
		c.trustProxyHeaders = b
	}

	// 仅在可信单跳代理后开启 RP_TRUST_PROXY_HEADERS：此时边缘 nginx 写入的
	// XFF 末项才是客户端地址；直连形态必须保持默认 false，忽略伪造 XFF。

	// RP ID 纪律示范（docs/DESIGN.md 第 8 节，与 arauth 侧配置一一对应）：
	// 1. rp.id 显式配置，必填，禁止依赖任何默认值；
	// 2. rp.id = 父域，绝不设成 arauth. 服务子域——凭据注册时把 rp.id 哈希
	//    定型、终身不可改，设错 = 全员重注册且无迁移路径；
	// 3. origins 显式白名单，禁止通配；每个 origin 的 host 必须就是 rp.id
	//    或其子域（WebAuthn 规则：origin 必须是 rp.id 的后缀匹配），且必须
	//    HTTPS（生产硬前提）。
	if c.rpID == "" {
		return nil, fmt.Errorf("config: 缺少必填环境变量 RP_ID（必须是父域，与 arauth 的 ARAUTH_RPID 一致）")
	}
	if strings.HasPrefix(c.rpID, "arauth.") {
		return nil, fmt.Errorf("config: RP_ID %q 不合法：rp.id 必须是父域，不得使用 arauth. 子域（凭据终身绑定 rp.id，设错无法迁移）", c.rpID)
	}
	rawOrigins := os.Getenv("RP_ORIGINS")
	if rawOrigins == "" {
		return nil, fmt.Errorf("config: 缺少必填环境变量 RP_ORIGINS（逗号分隔白名单，与 arauth 的 ARAUTH_RP_ORIGINS 一致）")
	}
	for _, o := range strings.Split(rawOrigins, ",") {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		u, err := url.Parse(o)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
			return nil, fmt.Errorf("config: RP_ORIGINS 条目 %q 不合法：必须是 https://host 形态（显式 origin，禁通配、禁路径）", o)
		}
		host := u.Hostname()
		if host != c.rpID && !strings.HasSuffix(host, "."+c.rpID) {
			return nil, fmt.Errorf("config: RP_ORIGINS 条目 %q 不合法：origin 的 host 必须是 rp.id(%q) 或其子域", o, c.rpID)
		}
		c.origins = append(c.origins, o)
	}
	if len(c.origins) == 0 {
		return nil, fmt.Errorf("config: RP_ORIGINS 至少需要一个有效 origin")
	}

	if c.arauthURL == "" {
		return nil, fmt.Errorf("config: 缺少必填环境变量 RP_ARAUTH_URL（如内网 http://arauth:8080 或外部 https://arauth.example.com）")
	}
	if c.exchangeAPIKey == "" {
		return nil, fmt.Errorf("config: 缺少必填环境变量 RP_EXCHANGE_API_KEY（与 arauth 的 ARAUTH_EXCHANGE_API_KEY 共享）")
	}

	// 调 arauth 的 HTTP 客户端：公网 HTTPS 上游用系统根证书；
	// RP_ARAUTH_CA_FILE 仅供自签/内网 CA 上游追加信任，绝不是跳过证书校验。
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if caFile := os.Getenv("RP_ARAUTH_CA_FILE"); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("config: 读 RP_ARAUTH_CA_FILE 失败: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("config: RP_ARAUTH_CA_FILE %q 不含有效 PEM 证书", caFile)
		}
	}
	c.httpClient = &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
	}
	return c, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// jarEntry 是服务端代持的 arauth pending 会话（注册确认用）。
type jarEntry struct {
	arauthToken string // arauth_session 的值（cookie 原文），浏览器永远见不到
	expires     time.Time
}

// sessionEntry 是依赖方自己的第一方会话。
type sessionEntry struct {
	userHandle  string // base64url
	backedUp    bool
	expires     time.Time
	arauthToken string    // 登录时 arauth_session，仅供 fresh TOTP enroll
	freshUntil  time.Time // 此后删除代持 token；rp_session 本身仍有效
}

// server 持有配置与进程内存态。map + 惰性过期是"最薄示范"的取舍，
// 生产依赖方换成自己的会话存储即可。
type server struct {
	cfg *config

	mu       sync.Mutex
	jar      map[string]jarEntry     // rp_pending cookie 值 → 代持的 arauth 会话
	sessions map[string]sessionEntry // rp_session cookie 值 → 依赖方会话
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("启动失败: %v", err)
	}
	s := &server{
		cfg:      cfg,
		jar:      make(map[string]jarEntry),
		sessions: make(map[string]sessionEntry),
	}

	r := s.routes()

	log.Printf("依赖方参考服务监听 %s（rp.id=%s，arauth=%s）", cfg.addr, cfg.rpID, cfg.arauthURL)
	log.Fatal(http.ListenAndServe(cfg.addr, r))
}

// routes 集中装配同名 API；独立成函数让测试无需启动监听端口。
func (s *server) routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/health", s.health)
	// 浏览器只能经本服务访问 arauth。普通端点原样转发 body；register/confirm
	// 与 TOTP enroll 额外注入服务端代持会话，login/verify 额外完成 exchange。
	r.Get("/pow/challenge", s.forwardPlain(http.MethodGet, "/pow/challenge"))
	r.Post("/register/options", s.forwardPlain(http.MethodPost, "/register/options"))
	r.Post("/register/verify", s.registerVerify)
	r.Post("/register/confirm", s.registerConfirm)
	r.Post("/login/options", s.forwardPlain(http.MethodPost, "/login/options"))
	r.Post("/login/verify", s.loginVerify)
	r.Post("/recovery/redeem", s.forwardPlain(http.MethodPost, "/recovery/redeem"))
	r.Post("/recovery/totp/redeem", s.forwardPlain(http.MethodPost, "/recovery/totp/redeem"))
	r.Post("/recovery/options", s.forwardRecovery("/recovery/options"))
	r.Post("/recovery/verify", s.forwardRecovery("/recovery/verify"))
	r.Post("/recovery/totp/enroll/begin", s.forwardEnroll("/recovery/totp/enroll/begin", false))
	r.Post("/recovery/totp/enroll/confirm", s.forwardEnroll("/recovery/totp/enroll/confirm", true))
	// 演示"依赖方 cookie 生效"的最小受保护端点。
	r.Get("/whoami", s.whoami)
	return r
}

// callArauth 以服务器到服务器方式调 arauth，返回状态码、响应体与响应头。
// 请求总是新建，不复制入站 Header/Cookie；唯一自动加入的客户端头是由本服务
// 重新计算的单值 X-Forwarded-For。调用方绝不可透传返回头里的 Set-Cookie。
func (s *server) callArauth(inbound *http.Request, method, path string, body []byte, headers map[string]string) (int, []byte, http.Header, error) {
	req, err := http.NewRequest(method, s.cfg.arauthURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-Forwarded-For", clientIP(inbound, s.cfg.trustProxyHeaders))
	resp, err := s.cfg.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, respBody, resp.Header, nil
}

// relay 把 arauth 的状态码与响应体回给浏览器。响应头只白名单 Retry-After，
// 让调用方自行退避；Content-Type 固定 JSON，Set-Cookie 与其余头绝不下行。
func relay(w http.ResponseWriter, status int, body []byte, upstreamHeader http.Header) {
	w.Header().Set("Content-Type", "application/json")
	if retryAfter := upstreamHeader.Get("Retry-After"); retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// forwardPlain 是最纯粹的转发：请求体原样上行，响应原样下行。
// 适用于无 cookie/票据参与的端点（pow/challenge、register/options、
// login/options、recovery/redeem、recovery/totp/redeem）。
func (s *server) forwardPlain(method, upstreamPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		status, respBody, respHeader, err := s.callArauth(r, method, upstreamPath, body, nil)
		if err != nil {
			log.Printf("转发 %s 失败: %v", upstreamPath, err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		relay(w, status, respBody, respHeader)
	}
}

// forwardRecovery 除 body 外只白名单转发 recovery token。浏览器的 Cookie、
// exchange key、Authorization 等头不会搭便车进入服务器到服务器通道。
func (s *server) forwardRecovery(upstreamPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		var headers map[string]string
		if token := r.Header.Get("X-Arauth-Recovery-Token"); token != "" {
			headers = map[string]string{"X-Arauth-Recovery-Token": token}
		}
		status, respBody, respHeader, err := s.callArauth(r, http.MethodPost, upstreamPath, body, headers)
		if err != nil {
			log.Printf("转发 %s 失败: %v", upstreamPath, err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		relay(w, status, respBody, respHeader)
	}
}

// forwardEnroll 转发 TOTP enroll。begin 的上行请求固定为空，confirm 只转发
// 自己的 JSON body；flow=register/login 显式选择 rp_pending/rp_session 对应的
// 服务端代持会话，避免两种 Cookie 并存时绑到错误身份。
func (s *server) forwardEnroll(upstreamPath string, forwardBody bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		arauthToken, ok := s.enrollToken(r, r.URL.Query().Get("flow"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid")
			return
		}
		var body []byte
		if forwardBody {
			var err error
			body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid")
				return
			}
		}
		status, respBody, respHeader, err := s.callArauth(r, http.MethodPost, upstreamPath, body,
			map[string]string{"Cookie": "arauth_session=" + arauthToken})
		if err != nil {
			log.Printf("转发 %s 失败: %v", upstreamPath, err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		relay(w, status, respBody, respHeader)
	}
}

// enrollToken 按调用方显式声明的流程选择服务端代持会话。flow 不是鉴权
// 凭证，只是消除两种第一方 Cookie 并存时的身份歧义；真正授权仍由对应的
// arauth_session 与 arauth 的 fresh 校验完成。
func (s *server) enrollToken(r *http.Request, flow string) (string, bool) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if flow == "login" {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			return "", false
		}
		sess, ok := s.sessions[cookie.Value]
		if !ok {
			return "", false
		}
		if !now.Before(sess.expires) {
			delete(s.sessions, cookie.Value)
			return "", false
		}
		if sess.arauthToken == "" {
			return "", false
		}
		if !now.Before(sess.freshUntil) {
			// fresh 过期只清除代持票据，不延长也不破坏 RP 自己的登录会话。
			sess.arauthToken = ""
			sess.freshUntil = time.Time{}
			s.sessions[cookie.Value] = sess
			return "", false
		}
		return sess.arauthToken, true
	}

	if flow != "register" {
		return "", false
	}
	cookie, err := r.Cookie(pendingCookieName)
	if err != nil {
		return "", false
	}
	entry, ok := s.jar[cookie.Value]
	if ok && !now.Before(entry.expires) {
		delete(s.jar, cookie.Value)
		ok = false
	}
	if !ok || entry.arauthToken == "" {
		return "", false
	}
	return entry.arauthToken, true
}

// health 只在 arauth 上游健康时报告 ok，供 compose/e2e 探活等待真实依赖就绪。
func (s *server) health(w http.ResponseWriter, r *http.Request) {
	status, _, _, err := s.callArauth(r, http.MethodGet, "/health", nil, nil)
	if err != nil {
		log.Printf("检查 arauth /health 失败: %v", err)
		writeError(w, http.StatusServiceUnavailable, "unhealthy")
		return
	}
	if status != http.StatusOK {
		writeError(w, http.StatusServiceUnavailable, "unhealthy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// clientIP 计算上行 XFF 的唯一值。信任代理时取入站 XFF 全链末项（nginx
// 写入的真实对端），否则取 RemoteAddr host；缺头或无法拆端口时回退原值。
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := strings.Join(r.Header.Values("X-Forwarded-For"), ","); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// registerVerify 转发注册 verify。arauth 成功响应带两件对浏览器不可见的
// 东西：Set-Cookie（pending 会话，confirm 要凭它鉴权）——按重写清单第 1 条
// 代持进服务端 jar，浏览器只拿到一把 opaque 钥匙（rp_pending cookie）；
// 响应体（含恢复码原文）原样下行——恢复码本就属于用户本人，仅此一次展示。
func (s *server) registerVerify(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	status, respBody, respHeader, err := s.callArauth(r, http.MethodPost, "/register/verify", body, nil)
	if err != nil {
		log.Printf("转发 /register/verify 失败: %v", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if status != http.StatusOK {
		relay(w, status, respBody, respHeader)
		return
	}

	arauthToken := cookieValue(respHeader, "arauth_session")
	if arauthToken == "" {
		log.Printf("arauth /register/verify 成功但未发 pending 会话 cookie")
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	pendingID, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.mu.Lock()
	s.jar[pendingID] = jarEntry{arauthToken: arauthToken, expires: time.Now().Add(pendingTTL)}
	s.mu.Unlock()

	s.setCookie(w, pendingCookieName, pendingID, pendingTTL)
	relay(w, status, respBody, respHeader)
}

// registerConfirm 转发注册确认：按重写清单第 4 条，用 rp_pending 钥匙从
// jar 取出代持的 arauth 会话，以 Cookie 头注入上行请求。浏览器自始至终
// 接触不到 arauth_session 的值。确认成功后钥匙作废（jar 条目删除、
// rp_pending cookie 清除）。
func (s *server) registerConfirm(w http.ResponseWriter, r *http.Request) {
	pendingID, err := r.Cookie(pendingCookieName)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid")
		return
	}
	s.mu.Lock()
	entry, ok := s.jar[pendingID.Value]
	if ok && time.Now().After(entry.expires) {
		delete(s.jar, pendingID.Value)
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid")
		return
	}

	status, respBody, respHeader, err := s.callArauth(r, http.MethodPost, "/register/confirm", nil,
		map[string]string{"Cookie": "arauth_session=" + entry.arauthToken})
	if err != nil {
		log.Printf("转发 /register/confirm 失败: %v", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if status == http.StatusOK {
		s.mu.Lock()
		delete(s.jar, pendingID.Value)
		s.mu.Unlock()
		s.setCookie(w, pendingCookieName, "", -1) // 清除钥匙
	}
	relay(w, status, respBody, respHeader)
}

// loginVerify 转发登录 verify，成功后完成换发（DESIGN.md 第 7 节）：
//  1. arauth 的 Set-Cookie 只代持进服务端 sessionEntry，fresh 窗口 15 分钟；
//     浏览器始终只得到 rp_session，whoami 也不暴露该 token；
//  2. 响应体里的 exchange_code 不转发给浏览器（重写清单第 2 条），本服务
//     立即持共享 API key 调 /exchange 核销（重写清单第 3 条）；
//  3. 换到 {user_handle, backed_up} 后种依赖方自己的第一方 rp_session，
//     给浏览器的响应只留最小字段。
func (s *server) loginVerify(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodySize))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	status, respBody, respHeader, err := s.callArauth(r, http.MethodPost, "/login/verify", body, nil)
	if err != nil {
		log.Printf("转发 /login/verify 失败: %v", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if status != http.StatusOK {
		relay(w, status, respBody, respHeader)
		return
	}

	var loginResp struct {
		ExchangeCode string `json:"exchange_code"`
		BackedUp     bool   `json:"backed_up"`
	}
	if err := json.Unmarshal(respBody, &loginResp); err != nil || loginResp.ExchangeCode == "" {
		log.Printf("arauth /login/verify 响应缺少 exchange_code")
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	exchangeReq, _ := json.Marshal(map[string]string{"code": loginResp.ExchangeCode})
	exStatus, exBody, exHeader, err := s.callArauth(r, http.MethodPost, "/exchange", exchangeReq,
		map[string]string{"X-Arauth-Exchange-Key": s.cfg.exchangeAPIKey})
	if err != nil {
		log.Printf("调 /exchange 失败: %v", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if exStatus != http.StatusOK {
		// exchange 失败（code 过期等）对浏览器等同登录失败，原样回状态与词表。
		relay(w, exStatus, exBody, exHeader)
		return
	}
	var exResp struct {
		UserHandle string `json:"user_handle"`
		BackedUp   bool   `json:"backed_up"`
	}
	if err := json.Unmarshal(exBody, &exResp); err != nil || exResp.UserHandle == "" {
		log.Printf("arauth /exchange 响应畸形")
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	token, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	now := time.Now()
	sess := sessionEntry{
		userHandle: exResp.UserHandle,
		backedUp:   exResp.BackedUp,
		expires:    now.Add(sessionTTL),
	}
	// 缺少 arauth_session 不妨碍 RP 自己的登录会话生效，但后续 enroll 会
	// 因缺 fresh token 返回 401；有 token 时也只代持到 fresh 窗口结束。
	if arauthToken := cookieValue(respHeader, "arauth_session"); arauthToken != "" {
		sess.arauthToken = arauthToken
		sess.freshUntil = now.Add(freshTTL)
	}
	s.mu.Lock()
	s.sessions[token] = sess
	s.mu.Unlock()

	s.setCookie(w, sessionCookieName, token, sessionTTL)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "backed_up": exResp.BackedUp})
}

// whoami 是最小受保护端点：凭 rp_session 返回当前身份。演示依赖方第一方
// cookie 独立生效（arauth 的 cookie 从未到过浏览器）。
func (s *server) whoami(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid")
		return
	}
	s.mu.Lock()
	sess, ok := s.sessions[cookie.Value]
	if ok && time.Now().After(sess.expires) {
		delete(s.sessions, cookie.Value)
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_handle": sess.userHandle,
		"backed_up":   sess.backedUp,
	})
}

// setCookie 种依赖方自己的第一方 cookie：httpOnly（脚本不可读）、
// SameSite=Strict、不设 Domain（不向父域/子域放大——共享父域 Cookie 已被
// 冻结决定 8 排除）、Secure 按配置（生产 HTTPS 必须 true）。
// maxAge < 0 表示立即清除。
func (s *server) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

// cookieValue 从 arauth 响应头里取指定 cookie 的值（只用于服务端代持，
// 绝不透传给浏览器）。
func cookieValue(header http.Header, name string) string {
	for _, line := range header.Values("Set-Cookie") {
		parts := strings.SplitN(line, ";", 2)
		kv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
		if len(kv) == 2 && kv[0] == name {
			return kv[1]
		}
	}
	return ""
}

// randomToken 生成 256 位 opaque 随机串（base64url），用作 rp_session /
// rp_pending 的 cookie 值。
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
