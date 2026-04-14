package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/store"
)

// tokenLen 是 opaque token 与 exchange code 的字节数：256 位 crypto/rand
// （DESIGN.md 第 7 节）。
const tokenLen = 32

// cookieName 是会话 cookie 名。固定值即可，不是可调数值。
const cookieName = "arauth_session"

// ErrInvalidExchange 表示 exchange code 无效（不存在/已使用/已过期）。
// 对外与 API key 错误不可区分，由 server 统一映射为 401（保密红线第 6 条）。
var ErrInvalidExchange = errors.New("session: exchange code 无效")

// ErrInvalidSession 表示会话凭证无效（cookie 缺失/畸形/不存在/已过期）。
// 对外不区分原因，由 server 统一映射为 401（保密红线第 6 条）。
var ErrInvalidSession = errors.New("session: 会话凭证无效")

// Store 是 session 对数据层的最小依赖。
type Store interface {
	InsertSession(ctx context.Context, sess *store.Session) error
	GetSession(ctx context.Context, tokenHash []byte) (*store.Session, error)
	InsertExchangeCode(ctx context.Context, ec *store.ExchangeCode) error
	ConsumeExchangeCode(ctx context.Context, codeHash []byte) (*store.ExchangeCode, error)
}

// Service 签发与管理 opaque token 会话及一次性 exchange code。
// 两者原文只经客户端与 cookie/响应体传递，服务器自始至终只存 SHA-256
// （数据分级第 3 条）——任何"需要原文"的设计都直接拒绝。
type Service struct {
	st  Store
	cfg *config.Config
	now func() time.Time // 可注入时钟，测试用
}

// New 构建会话服务。
func New(cfg *config.Config, st Store) *Service {
	return &Service{st: st, cfg: cfg, now: time.Now}
}

// Issue 在登录验证通过后同时签发会话 token 与一次性 exchange code，
// 返回两者原文。原文只出现于返回值与 cookie/响应体，库中只落哈希。
func (s *Service) Issue(ctx context.Context, userHandle []byte, backedUp bool) (token, exchangeCode []byte, err error) {
	token, err = randomToken()
	if err != nil {
		return nil, nil, fmt.Errorf("session: 生成 token 失败: %w", err)
	}
	if err := s.st.InsertSession(ctx, &store.Session{
		TokenHash:  hash(token),
		UserHandle: userHandle,
		ExpiresAt:  s.now().Add(s.cfg.SessionTTL),
	}); err != nil {
		return nil, nil, fmt.Errorf("session: 会话落库失败: %w", err)
	}

	exchangeCode, err = randomToken()
	if err != nil {
		return nil, nil, fmt.Errorf("session: 生成 exchange code 失败: %w", err)
	}
	if err := s.st.InsertExchangeCode(ctx, &store.ExchangeCode{
		CodeHash:   hash(exchangeCode),
		UserHandle: userHandle,
		BackedUp:   backedUp,
		ExpiresAt:  s.now().Add(s.cfg.ExchangeCodeTTL),
	}); err != nil {
		return nil, nil, fmt.Errorf("session: exchange code 落库失败: %w", err)
	}

	return token, exchangeCode, nil
}

// Exchange 原子核销一次性 exchange code，返回白名单信息。code 无效
// （不存在/已使用/已过期）一律 ErrInvalidExchange，不区分原因。
func (s *Service) Exchange(ctx context.Context, code []byte) (*store.ExchangeCode, error) {
	if len(code) != tokenLen {
		return nil, ErrInvalidExchange
	}
	ec, err := s.st.ConsumeExchangeCode(ctx, hash(code))
	if err != nil {
		// 不存在/已使用/已过期在 store 层统一为 ErrNotFound；其他
		// 错误（如连接失败）也归一为无效——对外只给 401，细节进日志
		// 由调用方按 errors.Is 区分内部记录。
		return nil, fmt.Errorf("%w: %v", ErrInvalidExchange, err)
	}
	return ec, nil
}

// IssuePendingSession 为刚注册成功的 pending identity 签发会话 token，
// 供 /register/confirm 确认"已保存恢复码"时鉴权（DESIGN.md 第 4 节：
// 客户端确认已保存 → 激活 identity）。不发 exchange code——注册不是登录。
func (s *Service) IssuePendingSession(ctx context.Context, userHandle []byte) (token []byte, err error) {
	token, err = randomToken()
	if err != nil {
		return nil, fmt.Errorf("session: 生成 token 失败: %w", err)
	}
	if err := s.st.InsertSession(ctx, &store.Session{
		TokenHash:  hash(token),
		UserHandle: userHandle,
		ExpiresAt:  s.now().Add(s.cfg.SessionTTL),
	}); err != nil {
		return nil, fmt.Errorf("session: 会话落库失败: %w", err)
	}
	return token, nil
}

// Authenticate 从请求的会话 cookie 定位身份：读 cookie → base64url 解码
// → SHA-256 查库（含过期校验）→ 返回 user_handle。任何失败统一
// ErrInvalidSession，不区分"没 cookie"与"会话不存在"。
func (s *Service) Authenticate(r *http.Request) ([]byte, error) {
	sess, err := s.authenticate(r)
	if err != nil {
		return nil, err
	}
	return sess.UserHandle, nil
}

// AuthenticateFresh 只接受签发时间不超过 maxAge 的会话。恢复因素管理
// 需要刚完成的 WebAuthn 授权，不能拿 14 天旧会话单独添加 TOTP。
func (s *Service) AuthenticateFresh(r *http.Request, maxAge time.Duration) ([]byte, error) {
	sess, err := s.authenticate(r)
	if err != nil {
		return nil, err
	}
	age := s.now().Sub(sess.CreatedAt)
	if maxAge <= 0 || age < 0 || age > maxAge {
		return nil, fmt.Errorf("%w: 会话不在新鲜窗口", ErrInvalidSession)
	}
	return sess.UserHandle, nil
}

func (s *Service) authenticate(r *http.Request) (*store.Session, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSession, err)
	}
	token, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(token) != tokenLen {
		return nil, fmt.Errorf("%w: cookie 畸形", ErrInvalidSession)
	}
	sess, err := s.st.GetSession(r.Context(), hash(token))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSession, err)
	}
	return sess, nil
}

// WriteCookie 把会话 token 原文写进 httpOnly cookie。Secure 属性按
// config 环境切（生产 HTTPS 必须为 true，本地开发可关）；SameSite=Strict；
// 不设 Domain 属性（禁止向依赖方域名放大，DESIGN.md 第 7 节）。
func (s *Service) WriteCookie(w http.ResponseWriter, token []byte) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    base64url(token),
		Path:     "/",
		Expires:  s.now().Add(s.cfg.SessionTTL),
		HttpOnly: true,
		Secure:   s.cfg.SessionCookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func randomToken() ([]byte, error) {
	b := make([]byte, tokenLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func hash(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// base64url 编码为无填充 base64url（token 的 cookie/响应体编码形态）。
func base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
