// Package server 负责 chi 路由与 HTTP handler，只做协议适配，不含业务裁决。
package server

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/arithmaton/arauth/internal/authn"
	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/ratelimit"
	"github.com/arithmaton/arauth/internal/recovery"
	"github.com/arithmaton/arauth/internal/session"
	"github.com/arithmaton/arauth/internal/store"
)

// Registrar 是注册 ceremony 的最小接口（由 authn.Service 实现），
// server 只依赖接口，便于用 stub 做 handler 测试。含注册尾部的确认激活
// 与找回挂新密钥两条子流程（DESIGN.md 第 4 节）。
type Registrar interface {
	BeginRegistration() (*protocol.CredentialCreation, error)
	FinishRegistration(ctx context.Context, r *http.Request) (*authn.Registration, error)
	ConfirmRegistration(ctx context.Context, userHandle []byte) error
	BeginRecoveryRegistration(token []byte) (*protocol.CredentialCreation, error)
	FinishRecoveryRegistration(ctx context.Context, r *http.Request, token []byte) (*authn.RecoveryRegistration, error)
}

// LoginCeremony 是登录 ceremony 的最小接口（由 authn.Service 实现）。
type LoginCeremony interface {
	BeginLogin() (*protocol.CredentialAssertion, error)
	FinishLogin(ctx context.Context, r *http.Request) (*authn.Login, error)
}

// SessionService 是会话与 exchange code 的最小接口（由 session.Service
// 实现）。token 与 code 原文只经返回值传递，服务器只存哈希。
type SessionService interface {
	Issue(ctx context.Context, userHandle []byte, backedUp bool) (token, exchangeCode []byte, err error)
	IssuePendingSession(ctx context.Context, userHandle []byte) (token []byte, err error)
	Authenticate(r *http.Request) (userHandle []byte, err error)
	Exchange(ctx context.Context, code []byte) (*store.ExchangeCode, error)
	WriteCookie(w http.ResponseWriter, token []byte)
}

// RecoveryRedeemer 是恢复码兑换的最小接口（由 recovery.Service 实现）。
// 兑换成功签发一次性恢复凭证，唯一权限是找回挂新密钥。
type RecoveryRedeemer interface {
	Redeem(ctx context.Context, code string) (token []byte, err error)
}

// totpRecoveryService 由 recovery.Service 实现。独立接口断言让既有恢复码
// handler 测试桩不必实现与自身无关的 TOTP 方法。
type totpRecoveryService interface {
	BeginTOTPEnrollment(userHandle []byte) (*recovery.TOTPSetup, error)
	ConfirmTOTPEnrollment(ctx context.Context, userHandle, setupToken []byte, code string) error
	RedeemTOTP(ctx context.Context, recoveryID, code string) (token []byte, err error)
}

type freshSessionService interface {
	AuthenticateFresh(r *http.Request, maxAge time.Duration) (userHandle []byte, err error)
}

// PoWGate 是 PoW 门的最小接口（由 pow.Service 实现）。挂点只有注册与
// 恢复兑换（一次性恢复码或 TOTP），登录端点不得挂。
type PoWGate interface {
	Issue() (challenge []byte, difficulty int)
	Verify(challenge, nonce []byte) bool
}

// RateLimiter 是 per-IP 限流的最小接口（由 ratelimit.Limiter 实现）。
// 拒绝时返回建议的重试等待时长（写 Retry-After 响应头）。
type RateLimiter interface {
	Allow(ip string, tier ratelimit.Tier) (ok bool, retryAfter time.Duration)
}

// OutcomeRecorder 是 PoW 自适应难度信号的最小接口（由 ratelimit.Adaptive
// 实现）：server 在注册与两种恢复兑换的 PoW 门验证后记录成败。
type OutcomeRecorder interface {
	Record(ok bool)
}

// maxPoWBodySize 是带 PoW 字段请求体的上限（PoW 字段仅两个 base64url
// 短串，超此上限即视为畸形）。
const maxPoWBodySize = 4096

// maxExchangeBodySize 是 /exchange 请求体的上限（仅一个 base64url 短串）。
const maxExchangeBodySize = 4096

// maxRedeemBodySize 是恢复兑换与 TOTP setup 请求体的上限（短字段 +
// 两个 PoW base64url 短串）。
const maxRedeemBodySize = 4096

// exchangeAPIKeyHeader 是依赖方后端调 /exchange 时携带共享 API key 的
// header 名。key 是服务器机密，只在服务端到服务端通道出现。
const exchangeAPIKeyHeader = "X-Arauth-Exchange-Key"

// recoveryTokenHeader 是找回流程携带一次性恢复凭证的 header 名。
// WebAuthn verify 的请求体被 attestation JSON 占满，凭证只能走 header。
const recoveryTokenHeader = "X-Arauth-Recovery-Token"

// New 装配路由并返回 HTTP handler。
func New(cfg *config.Config, reg Registrar, gate PoWGate, login LoginCeremony, sess SessionService, rec RecoveryRedeemer, rl RateLimiter, adaptive OutcomeRecorder) http.Handler {
	r := chi.NewRouter()
	r.Get("/health", health)
	// per-IP 限流：凭空造身份与票据兑换类走严格档，登录走宽松档
	// （登录禁止挂 PoW，限流是唯一防线，DESIGN.md 第 6 节）。
	r.Get("/pow/challenge", rateLimit(rl, ratelimit.TierStrict, cfg.TrustProxyHeaders, powChallenge(gate)))
	r.Post("/register/options", rateLimit(rl, ratelimit.TierStrict, cfg.TrustProxyHeaders, registerOptions(reg, gate, adaptive)))
	r.Post("/register/verify", rateLimit(rl, ratelimit.TierStrict, cfg.TrustProxyHeaders, registerVerify(reg, sess)))
	r.Post("/register/confirm", rateLimit(rl, ratelimit.TierStrict, cfg.TrustProxyHeaders, registerConfirm(reg, sess)))
	r.Post("/login/options", rateLimit(rl, ratelimit.TierLenient, cfg.TrustProxyHeaders, loginOptions(login)))
	r.Post("/login/verify", rateLimit(rl, ratelimit.TierLenient, cfg.TrustProxyHeaders, loginVerify(login, sess)))
	r.Post("/recovery/redeem", rateLimit(rl, ratelimit.TierStrict, cfg.TrustProxyHeaders, recoveryRedeem(rec, gate, adaptive)))
	r.Post("/recovery/totp/enroll/begin", rateLimit(rl, ratelimit.TierStrict, cfg.TrustProxyHeaders, totpEnrollBegin(rec, sess, cfg.TOTPFreshSessionTTL)))
	r.Post("/recovery/totp/enroll/confirm", rateLimit(rl, ratelimit.TierStrict, cfg.TrustProxyHeaders, totpEnrollConfirm(rec, sess, cfg.TOTPFreshSessionTTL)))
	r.Post("/recovery/totp/redeem", rateLimit(rl, ratelimit.TierStrict, cfg.TrustProxyHeaders, totpRedeem(rec, gate, adaptive)))
	r.Post("/recovery/options", recoveryOptions(reg))
	r.Post("/recovery/verify", recoveryVerify(reg))
	r.Post("/exchange", rateLimit(rl, ratelimit.TierStrict, cfg.TrustProxyHeaders, exchange(cfg, sess)))
	return r
}

// rateLimit 是 per-IP 限流中间件：超限时 429 + Retry-After（秒，上取整，
// 至少 1）+ {"error":"rate limited"}，与 PoW 失败同语（保密红线第 6 条
// 错误词表）。客户端 IP 由 clientIP 提取，trustProxy 语义见 config。
func rateLimit(rl RateLimiter, tier ratelimit.Tier, trustProxy bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ok, retryAfter := rl.Allow(clientIP(r, trustProxy), tier)
		if !ok {
			secs := int(math.Ceil(retryAfter.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		next(w, r)
	}
}

// clientIP 提取 per-IP 限流的客户端 IP。trustProxy 为 true 时取
// X-Forwarded-For 最后一个条目；可信 service-server 会把浏览器伪造的
// 链改写成单一有效客户端 IP。header 缺失、末项为空或开关关闭时回退
// RemoteAddr 主机部分。为 true 时 arauth 不得被非可信调用方直连。
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
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

// health 是存活探针，无鉴权，无敏感信息。
func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// powChallenge 签发一次性 PoW challenge（32 字节随机数，base64url 下发）。
func powChallenge(gate PoWGate) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		challenge, difficulty := gate.Issue()
		writeJSON(w, http.StatusOK, map[string]any{
			"challenge":  base64.RawURLEncoding.EncodeToString(challenge),
			"difficulty": difficulty,
		})
	}
}

// registerOptions 先验 PoW 解再下发 creation options（JSON 形状即
// PublicKeyCredential.parseCreationOptionsFromJSON 可直接消费的结构）。
// PoW 失败一律 429，不暴露细节（challenge 不存在/已过期/前缀不对对外
// 不可区分，保密红线第 6 条）。
func registerOptions(reg Registrar, gate PoWGate, adaptive OutcomeRecorder) http.HandlerFunc {
	type request struct {
		Challenge string `json:"pow_challenge"`
		Nonce     string `json:"pow_nonce"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPoWBodySize)).Decode(&req); err != nil ||
			req.Challenge == "" || req.Nonce == "" {
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		challenge, err1 := base64.RawURLEncoding.DecodeString(req.Challenge)
		nonce, err2 := base64.RawURLEncoding.DecodeString(req.Nonce)
		if err1 != nil || err2 != nil {
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		ok := gate.Verify(challenge, nonce)
		adaptive.Record(ok) // 失败率信号喂给自适应难度
		if !ok {
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		creation, err := reg.BeginRegistration()
		if err != nil {
			log.Printf("server: 生成注册 options 失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeJSON(w, http.StatusOK, creation)
	}
}

// registerVerify 验证 attestation 并落库，随后签发 pending 会话
// （Set-Cookie，供 /register/confirm 鉴权），成功只返回白名单字段——
// recovery_code 是恢复码原文，仅在本响应里出现一次（DESIGN.md 第 4 节
// 注册流程；数据分级第 3 条）。一切 ceremony 失败统一 400
// {"error":"invalid"}，不泄露失败步骤（保密红线第 6 条）。
func registerVerify(reg Registrar, sess SessionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		regn, err := reg.FinishRegistration(r.Context(), r)
		if errors.Is(err, authn.ErrInvalidCeremony) {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		if err != nil {
			log.Printf("server: 注册 verify 失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		// 签发 pending 会话 cookie：/register/confirm 凭它鉴权（user
		// handle 只在服务端内部使用，不下发——confirm 从 cookie 定位身份）。
		token, err := sess.IssuePendingSession(r.Context(), regn.UserHandle)
		if err != nil {
			log.Printf("server: pending 会话签发失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		sess.WriteCookie(w, token)
		writeJSON(w, http.StatusOK, map[string]any{
			"credential_id": base64.RawURLEncoding.EncodeToString(regn.CredentialID),
			"backed_up":     regn.BackedUp,
			"recovery_code": regn.RecoveryCode,
		})
	}
}

// registerConfirm 确认"已保存恢复码"→ 激活 identity。鉴权只认注册时
// 下发的 pending 会话 cookie。一切失败（无 cookie/会话无效/identity
// 状态不允许）统一 401 {"error":"invalid"}，不泄露原因；已激活时幂等
// 返回 200。
func registerConfirm(reg Registrar, sess SessionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handle, err := sess.Authenticate(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid")
			return
		}
		if err := reg.ConfirmRegistration(r.Context(), handle); err != nil {
			if !errors.Is(err, authn.ErrInvalidCeremony) {
				log.Printf("server: 确认激活失败: %v", err)
			}
			writeError(w, http.StatusUnauthorized, "invalid")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// loginOptions 下发 discoverable assertion options（allowCredentials 为空，
// 靠 user_handle 定位身份）。登录不挂 PoW（DESIGN.md 第 6 节：没有密钥的
// 人发起不了有效断言，限流就够）。
func loginOptions(login LoginCeremony) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		assertion, err := login.BeginLogin()
		if err != nil {
			log.Printf("server: 生成登录 options 失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeJSON(w, http.StatusOK, assertion)
	}
}

// loginVerify 验证 assertion，通过后签发会话（Set-Cookie）与一次性
// exchange code，响应只含白名单字段 {exchange_code, backed_up}。
// ceremony 失败统一 400 {"error":"invalid"}；pending identity（恢复码
// 未确认）单独映射 403——响应体同样是不可区分的 invalid，只有持真
// 私钥通过验签的合法主人才能看到这一区别。
func loginVerify(login LoginCeremony, sess SessionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lg, err := login.FinishLogin(r.Context(), r)
		if errors.Is(err, authn.ErrIdentityPending) {
			writeError(w, http.StatusForbidden, "invalid")
			return
		}
		if errors.Is(err, authn.ErrInvalidCeremony) {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		if err != nil {
			log.Printf("server: 登录 verify 失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		token, code, err := sess.Issue(r.Context(), lg.UserHandle, lg.BackedUp)
		if err != nil {
			log.Printf("server: 会话签发失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		sess.WriteCookie(w, token)
		writeJSON(w, http.StatusOK, map[string]any{
			"exchange_code": base64.RawURLEncoding.EncodeToString(code),
			"backed_up":     lg.BackedUp,
		})
	}
}

// recoveryRedeem 一次性恢复码兑换：先验 PoW 解（恢复兑换挂点之一），
// 失败一律 429 与限流同语。码错误（不存在/已轮换/畸形）统一 401 {"error":"invalid"}，不区分原因。成功签发一次性恢复凭证
// （响应体下发一次，后续经 X-Arauth-Recovery-Token header 携带）。
func recoveryRedeem(rec RecoveryRedeemer, gate PoWGate, adaptive OutcomeRecorder) http.HandlerFunc {
	type request struct {
		Code      string `json:"recovery_code"`
		Challenge string `json:"pow_challenge"`
		Nonce     string `json:"pow_nonce"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRedeemBodySize)).Decode(&req); err != nil ||
			req.Code == "" || req.Challenge == "" || req.Nonce == "" {
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		challenge, err1 := base64.RawURLEncoding.DecodeString(req.Challenge)
		nonce, err2 := base64.RawURLEncoding.DecodeString(req.Nonce)
		if err1 != nil || err2 != nil {
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		ok := gate.Verify(challenge, nonce)
		adaptive.Record(ok) // 失败率信号喂给自适应难度
		if !ok {
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		token, err := rec.Redeem(r.Context(), req.Code)
		if errors.Is(err, recovery.ErrInvalidRedeem) {
			writeError(w, http.StatusUnauthorized, "invalid")
			return
		}
		if err != nil {
			log.Printf("server: 恢复码兑换失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"recovery_token": base64.RawURLEncoding.EncodeToString(token),
		})
	}
}

// totpEnrollBegin 只凭新鲜 WebAuthn 会话创建 pending 绑定。种子、URI
// 与 recovery_id 只在成功响应出现一次；setup token 采用 base64url。
func totpEnrollBegin(rec RecoveryRedeemer, sess SessionService, freshTTL time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		totp, totpOK := rec.(totpRecoveryService)
		fresh, freshOK := sess.(freshSessionService)
		if !totpOK || !freshOK {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		handle, err := fresh.AuthenticateFresh(r, freshTTL)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid")
			return
		}
		setup, err := totp.BeginTOTPEnrollment(handle)
		if err != nil {
			log.Printf("server: 开始 TOTP 绑定失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"setup_token": base64.RawURLEncoding.EncodeToString(setup.SetupToken),
			"secret":      setup.Secret,
			"otpauth_uri": setup.URI,
			"recovery_id": setup.RecoveryID,
		})
	}
}

// totpEnrollConfirm 消费 setup token 并确认动态码。会话鉴权先于 token
// 消费；失败不会覆盖已有活跃种子。
func totpEnrollConfirm(rec RecoveryRedeemer, sess SessionService, freshTTL time.Duration) http.HandlerFunc {
	type request struct {
		SetupToken string `json:"setup_token"`
		Code       string `json:"code"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		totp, totpOK := rec.(totpRecoveryService)
		fresh, freshOK := sess.(freshSessionService)
		if !totpOK || !freshOK {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		handle, err := fresh.AuthenticateFresh(r, freshTTL)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid")
			return
		}
		var req request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRedeemBodySize)).Decode(&req); err != nil ||
			req.SetupToken == "" || req.Code == "" {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		setupToken, err := base64.RawURLEncoding.DecodeString(req.SetupToken)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		if err := totp.ConfirmTOTPEnrollment(r.Context(), handle, setupToken, req.Code); errors.Is(err, recovery.ErrInvalidTOTPSetup) {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		} else if err != nil {
			log.Printf("server: 确认 TOTP 绑定失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// totpRedeem 与恢复码兑换共享 PoW、自适应信号和恢复票据响应形状。
// PoW 必须先于 recovery_id 查询和种子解密。
func totpRedeem(rec RecoveryRedeemer, gate PoWGate, adaptive OutcomeRecorder) http.HandlerFunc {
	type request struct {
		RecoveryID string `json:"recovery_id"`
		Code       string `json:"code"`
		Challenge  string `json:"pow_challenge"`
		Nonce      string `json:"pow_nonce"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRedeemBodySize)).Decode(&req); err != nil ||
			req.RecoveryID == "" || req.Code == "" || req.Challenge == "" || req.Nonce == "" {
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		challenge, err1 := base64.RawURLEncoding.DecodeString(req.Challenge)
		nonce, err2 := base64.RawURLEncoding.DecodeString(req.Nonce)
		if err1 != nil || err2 != nil {
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		ok := gate.Verify(challenge, nonce)
		adaptive.Record(ok)
		if !ok {
			writeError(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		totp, ok := rec.(totpRecoveryService)
		if !ok {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		token, err := totp.RedeemTOTP(r.Context(), req.RecoveryID, req.Code)
		if errors.Is(err, recovery.ErrInvalidRedeem) {
			writeError(w, http.StatusUnauthorized, "invalid")
			return
		}
		if err != nil {
			log.Printf("server: TOTP 恢复兑换失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"recovery_token": base64.RawURLEncoding.EncodeToString(token),
		})
	}
}

// recoveryToken 从 header 取出恢复凭证（base64url 解码），畸形即失败。
func recoveryToken(r *http.Request) ([]byte, bool) {
	raw := r.Header.Get(recoveryTokenHeader)
	if raw == "" {
		return nil, false
	}
	token, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, false
	}
	return token, true
}

// recoveryOptions 为找回流程下发 creation options（绑定原 user handle）。
// 恢复凭证无效统一 400 invalid（与 ceremony 失败同语，不区分原因）。
func recoveryOptions(reg Registrar) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := recoveryToken(r)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		creation, err := reg.BeginRecoveryRegistration(token)
		if errors.Is(err, authn.ErrInvalidCeremony) {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		if err != nil {
			log.Printf("server: 生成找回 options 失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeJSON(w, http.StatusOK, creation)
	}
}

// recoveryVerify 验证 attestation 并把新凭据挂到原 user_handle，同事务
// 轮换恢复码。成功只返回白名单 {credential_id, backed_up, recovery_code}
// ——recovery_code 是轮换后的新码原文，仅在本响应里出现一次（用后即焚）。
func recoveryVerify(reg Registrar) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := recoveryToken(r)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		regn, err := reg.FinishRecoveryRegistration(r.Context(), r, token)
		if errors.Is(err, authn.ErrInvalidCeremony) {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		if err != nil {
			log.Printf("server: 找回 verify 失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"credential_id": base64.RawURLEncoding.EncodeToString(regn.CredentialID),
			"backed_up":     regn.BackedUp,
			"recovery_code": regn.RecoveryCode,
		})
	}
}

// exchange 是依赖方后端的兑换端点（服务器到服务器）：先常量时间比对
// 共享 API key，再原子核销一次性 code。key 错误、code 无效（不存在/
// 已使用/已过期）一律 401 {"error":"invalid"}，对外不区分原因
// （保密红线第 6 条）。成功只返回白名单 {user_handle, backed_up}。
func exchange(cfg *config.Config, sess SessionService) http.HandlerFunc {
	type request struct {
		Code string `json:"code"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get(exchangeAPIKeyHeader)
		if subtle.ConstantTimeCompare([]byte(key), []byte(cfg.ExchangeAPIKey)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid")
			return
		}
		var req request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxExchangeBodySize)).Decode(&req); err != nil ||
			req.Code == "" {
			writeError(w, http.StatusUnauthorized, "invalid")
			return
		}
		code, err := base64.RawURLEncoding.DecodeString(req.Code)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid")
			return
		}
		ec, err := sess.Exchange(r.Context(), code)
		if errors.Is(err, session.ErrInvalidExchange) {
			writeError(w, http.StatusUnauthorized, "invalid")
			return
		}
		if err != nil {
			log.Printf("server: exchange 兑换失败: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user_handle": base64.RawURLEncoding.EncodeToString(ec.UserHandle),
			"backed_up":   ec.BackedUp,
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
