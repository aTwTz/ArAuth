package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/arithmaton/arauth/internal/authn"
	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/pow"
	"github.com/arithmaton/arauth/internal/ratelimit"
	"github.com/arithmaton/arauth/internal/recovery"
	"github.com/arithmaton/arauth/internal/session"
	"github.com/arithmaton/arauth/internal/store"
)

// stubRegistrar 是 Registrar 的测试桩，方法行为由字段控制。
type stubRegistrar struct {
	creation   *protocol.CredentialCreation
	beginErr   error
	regn       *authn.Registration
	finErr     error
	beginCalls int

	confirmErr   error
	confirmCalls int
	confirmGot   []byte // ConfirmRegistration 收到的 user handle

	recCreation *protocol.CredentialCreation
	recBeginErr error
	recRegn     *authn.RecoveryRegistration
	recFinErr   error
	recBeginGot []byte // BeginRecoveryRegistration 收到的 token
	recFinGot   []byte // FinishRecoveryRegistration 收到的 token
}

func (s *stubRegistrar) BeginRegistration() (*protocol.CredentialCreation, error) {
	s.beginCalls++
	return s.creation, s.beginErr
}

func (s *stubRegistrar) FinishRegistration(_ context.Context, _ *http.Request) (*authn.Registration, error) {
	return s.regn, s.finErr
}

func (s *stubRegistrar) ConfirmRegistration(_ context.Context, userHandle []byte) error {
	s.confirmCalls++
	s.confirmGot = userHandle
	return s.confirmErr
}

func (s *stubRegistrar) BeginRecoveryRegistration(token []byte) (*protocol.CredentialCreation, error) {
	s.recBeginGot = token
	return s.recCreation, s.recBeginErr
}

func (s *stubRegistrar) FinishRecoveryRegistration(_ context.Context, _ *http.Request, token []byte) (*authn.RecoveryRegistration, error) {
	s.recFinGot = token
	return s.recRegn, s.recFinErr
}

// stubRedeemer 是恢复码与 TOTP 恢复服务的测试桩。
type stubRedeemer struct {
	token      []byte
	redeemErr  error
	redeemCode string // Redeem 收到的恢复码原文（断言"只经兑换一次"用）

	totpSetup         *recovery.TOTPSetup
	totpBeginErr      error
	totpBeginGot      []byte
	totpConfirmErr    error
	totpConfirmHandle []byte
	totpConfirmGot    []byte
	totpConfirmCode   string
	totpRedeemErr     error
	totpRedeemCalls   int
	totpGotID         string
	totpGotCode       string
}

func (s *stubRedeemer) Redeem(_ context.Context, code string) ([]byte, error) {
	s.redeemCode = code
	return s.token, s.redeemErr
}

func (s *stubRedeemer) BeginTOTPEnrollment(userHandle []byte) (*recovery.TOTPSetup, error) {
	s.totpBeginGot = userHandle
	return s.totpSetup, s.totpBeginErr
}

func (s *stubRedeemer) ConfirmTOTPEnrollment(_ context.Context, userHandle, setupToken []byte, code string) error {
	s.totpConfirmHandle = userHandle
	s.totpConfirmGot = setupToken
	s.totpConfirmCode = code
	return s.totpConfirmErr
}

func (s *stubRedeemer) RedeemTOTP(_ context.Context, recoveryID, code string) ([]byte, error) {
	s.totpRedeemCalls++
	s.totpGotID, s.totpGotCode = recoveryID, code
	return s.token, s.totpRedeemErr
}

// stubGate 是 PoWGate 的测试桩，verify 结果由 ok 字段控制。
type stubGate struct {
	ok         bool
	challenge  []byte
	difficulty int
}

func (g *stubGate) Issue() ([]byte, int) {
	if g.challenge == nil {
		return []byte("stub-challenge"), g.difficulty
	}
	return g.challenge, g.difficulty
}

func (g *stubGate) Verify(_, _ []byte) bool { return g.ok }

// stubLimiter 是 RateLimiter 的测试桩：默认全部放行，block 时按
// retryAfter 拒绝。记录末次调用的 IP 与档位供断言。
type stubLimiter struct {
	block      bool
	retryAfter time.Duration
	calls      int
	lastTier   ratelimit.Tier
	lastIP     string
}

func (s *stubLimiter) Allow(ip string, tier ratelimit.Tier) (bool, time.Duration) {
	s.calls++
	s.lastTier, s.lastIP = tier, ip
	if s.block {
		return false, s.retryAfter
	}
	return true, 0
}

// stubRecorder 是 OutcomeRecorder 的测试桩，顺次记录成败。
type stubRecorder struct{ oks []bool }

func (s *stubRecorder) Record(ok bool) { s.oks = append(s.oks, ok) }

func newStubServer(reg Registrar, gate PoWGate) *httptest.Server {
	return httptest.NewServer(New(&config.Config{}, reg, gate, &stubLogin{}, &stubSession{}, &stubRedeemer{}, &stubLimiter{}, &stubRecorder{}))
}

// newFullStubServer 带全部依赖桩与显式 cfg 的服务器（登录/exchange 测试用）。
func newFullStubServer(cfg *config.Config, reg Registrar, gate PoWGate, login LoginCeremony, sess SessionService) *httptest.Server {
	return httptest.NewServer(New(cfg, reg, gate, login, sess, &stubRedeemer{}, &stubLimiter{}, &stubRecorder{}))
}

// stubLogin 是 LoginCeremony 的测试桩。
type stubLogin struct {
	assertion *protocol.CredentialAssertion
	beginErr  error
	login     *authn.Login
	finErr    error
}

func (s *stubLogin) BeginLogin() (*protocol.CredentialAssertion, error) {
	return s.assertion, s.beginErr
}

func (s *stubLogin) FinishLogin(_ context.Context, _ *http.Request) (*authn.Login, error) {
	return s.login, s.finErr
}

// stubSession 是 SessionService 的测试桩。
type stubSession struct {
	token       []byte
	code        []byte
	issueErr    error
	issueCalls  int
	pendCalls   int
	pendErr     error
	authHandle  []byte
	authErr     error
	ec          *store.ExchangeCode
	exchErr     error
	cookieCalls int
	freshCalls  int
	freshMaxAge time.Duration
}

func (s *stubSession) Issue(_ context.Context, _ []byte, _ bool) ([]byte, []byte, error) {
	s.issueCalls++
	return s.token, s.code, s.issueErr
}

func (s *stubSession) IssuePendingSession(_ context.Context, _ []byte) ([]byte, error) {
	s.pendCalls++
	return s.token, s.pendErr
}

func (s *stubSession) Authenticate(_ *http.Request) ([]byte, error) {
	return s.authHandle, s.authErr
}

func (s *stubSession) AuthenticateFresh(_ *http.Request, maxAge time.Duration) ([]byte, error) {
	s.freshCalls++
	s.freshMaxAge = maxAge
	return s.authHandle, s.authErr
}

func (s *stubSession) Exchange(_ context.Context, _ []byte) (*store.ExchangeCode, error) {
	return s.ec, s.exchErr
}

func (s *stubSession) WriteCookie(w http.ResponseWriter, token []byte) {
	s.cookieCalls++
	http.SetCookie(w, &http.Cookie{
		Name:     "arauth_session",
		Value:    base64.RawURLEncoding.EncodeToString(token),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func TestHealth(t *testing.T) {
	srv := newStubServer(&stubRegistrar{}, &stubGate{ok: true})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("请求 /health 失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", resp.StatusCode)
	}

	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	if got := string(buf[:n]); got != `{"status":"ok"}`+"\n" {
		t.Errorf("响应体 = %q，期望 {\"status\":\"ok\"}", got)
	}
}

func TestUnknownRoute(t *testing.T) {
	srv := newStubServer(&stubRegistrar{}, &stubGate{ok: true})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/nope")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("状态码 = %d，期望 404", resp.StatusCode)
	}
}

// TestPoWChallenge 验证 challenge 端点下发形状：32 字节 challenge +
// 难度字段。
func TestPoWChallenge(t *testing.T) {
	srv := newStubServer(&stubRegistrar{}, pow.New(8, time.Minute))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/pow/challenge")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", resp.StatusCode)
	}

	var body struct {
		Challenge  string `json:"challenge"`
		Difficulty int    `json:"difficulty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body.Challenge)
	if err != nil {
		t.Fatalf("challenge 不是合法 base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("challenge 长度 = %d，期望 32", len(raw))
	}
	if body.Difficulty != 8 {
		t.Errorf("difficulty = %d，期望 8", body.Difficulty)
	}
}

// postOptions 带 PoW 字段请求 /register/options。
func postOptions(t *testing.T, url string, challenge, nonce []byte) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"pow_challenge":%q,"pow_nonce":%q}`,
		base64.RawURLEncoding.EncodeToString(challenge),
		base64.RawURLEncoding.EncodeToString(nonce))
	resp, err := http.Post(url+"/register/options", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	return resp
}

func TestRegisterOptions(t *testing.T) {
	stub := &stubRegistrar{creation: &protocol.CredentialCreation{
		Response: protocol.PublicKeyCredentialCreationOptions{
			Challenge: protocol.URLEncodedBase64("fake-challenge"),
		},
	}}
	srv := newStubServer(stub, &stubGate{ok: true})
	defer srv.Close()

	resp := postOptions(t, srv.URL, []byte("c"), []byte("n"))
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q，期望 application/json", ct)
	}
}

// TestRegisterOptionsWithoutPoW 无请求体 / 缺字段 / 坏 base64 一律 429，
// 且不得触及 Registrar。
func TestRegisterOptionsWithoutPoW(t *testing.T) {
	bodies := map[string]string{
		"空体":       "",
		"空 JSON":   "{}",
		"畸形 JSON":  "{",
		"坏 base64": `{"pow_challenge":"%%%","pow_nonce":"%%%"}`,
	}
	for name, body := range bodies {
		stub := &stubRegistrar{}
		srv := newStubServer(stub, &stubGate{ok: true})
		resp, err := http.Post(srv.URL+"/register/options", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("%s: 请求失败: %v", name, err)
		}
		_ = resp.Body.Close()
		srv.Close()

		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("%s: 状态码 = %d，期望 429", name, resp.StatusCode)
		}
		if stub.beginCalls != 0 {
			t.Errorf("%s: PoW 未过不得调用 BeginRegistration", name)
		}
	}
}

// TestRegisterOptionsBadPoW 校验失败 → 429，且不得触及 Registrar。
func TestRegisterOptionsBadPoW(t *testing.T) {
	stub := &stubRegistrar{}
	srv := newStubServer(stub, &stubGate{ok: false})
	defer srv.Close()

	resp := postOptions(t, srv.URL, []byte("c"), []byte("n"))
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("状态码 = %d，期望 429", resp.StatusCode)
	}
	if stub.beginCalls != 0 {
		t.Error("PoW 未过不得调用 BeginRegistration")
	}
}

// TestRegisterOptionsRealPoW 端到端：真实 pow.Service 低难度实例——
// 领 challenge、求解、通过；同一 challenge 复用第二次 429。
func TestRegisterOptionsRealPoW(t *testing.T) {
	stub := &stubRegistrar{creation: &protocol.CredentialCreation{}}
	srv := newStubServer(stub, pow.New(8, time.Minute))
	defer srv.Close()

	// 领 challenge。
	resp, err := http.Get(srv.URL + "/pow/challenge")
	if err != nil {
		t.Fatalf("领 challenge 失败: %v", err)
	}
	var issued struct {
		Challenge  string `json:"challenge"`
		Difficulty int    `json:"difficulty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		t.Fatalf("解析 challenge 响应失败: %v", err)
	}
	_ = resp.Body.Close()
	challenge, err := base64.RawURLEncoding.DecodeString(issued.Challenge)
	if err != nil {
		t.Fatalf("challenge base64 解码失败: %v", err)
	}

	// 暴搜求解。
	nonce := make([]byte, 8)
	for i := uint64(0); ; i++ {
		binary.BigEndian.PutUint64(nonce, i)
		sum := sha256.Sum256(append(append([]byte{}, challenge...), nonce...))
		ok := true
		for b := 0; b < issued.Difficulty; b++ {
			if sum[b/8]&(0x80>>(b%8)) != 0 {
				ok = false
				break
			}
		}
		if ok {
			break
		}
		if i > 1<<24 {
			t.Fatal("低难度下未搜到解")
		}
	}

	// 有效解 → 200。
	resp = postOptions(t, srv.URL, challenge, nonce)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("有效解状态码 = %d，期望 200", resp.StatusCode)
	}

	// 同一 challenge 复用 → 429（一次性）。
	resp = postOptions(t, srv.URL, challenge, nonce)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("重放状态码 = %d，期望 429", resp.StatusCode)
	}
}

func TestRegisterOptionsInternalError(t *testing.T) {
	srv := newStubServer(&stubRegistrar{beginErr: errors.New("boom")}, &stubGate{ok: true})
	defer srv.Close()

	resp := postOptions(t, srv.URL, []byte("c"), []byte("n"))
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("状态码 = %d，期望 500", resp.StatusCode)
	}
}

// TestRegisterVerifyWhitelist：注册 verify 成功 → 白名单恰为
// {credential_id, backed_up, recovery_code} + pending 会话 Set-Cookie。
// recovery_code 是恢复码原文唯一一次出现。
func TestRegisterVerifyWhitelist(t *testing.T) {
	stub := &stubRegistrar{regn: &authn.Registration{
		CredentialID: []byte{0x01, 0x02, 0x03},
		BackedUp:     true,
		RecoveryCode: "test-code-0001",
		UserHandle:   bytes.Repeat([]byte{0x42}, 64),
	}}
	sess := &stubSession{token: bytes.Repeat([]byte{0x7}, 32)}
	srv := httptest.NewServer(New(&config.Config{}, stub, &stubGate{ok: true}, &stubLogin{}, sess, &stubRedeemer{}, &stubLimiter{}, &stubRecorder{}))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/register/verify", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(body) != 3 {
		t.Errorf("响应只能含白名单字段，得到 %v", body)
	}
	if body["credential_id"] != "AQID" {
		t.Errorf("credential_id = %v，期望 base64url(AQID)", body["credential_id"])
	}
	if body["backed_up"] != true {
		t.Errorf("backed_up = %v，期望 true", body["backed_up"])
	}
	if body["recovery_code"] != "test-code-0001" {
		t.Errorf("recovery_code = %v，期望展示串", body["recovery_code"])
	}

	// pending 会话 cookie 必须随 verify 下发（confirm 的鉴权凭据）。
	if sess.pendCalls != 1 || sess.cookieCalls != 1 {
		t.Errorf("应签发 1 次 pending 会话并写 1 次 cookie，得到 %d/%d", sess.pendCalls, sess.cookieCalls)
	}
	if len(resp.Cookies()) != 1 || resp.Cookies()[0].Name != "arauth_session" {
		t.Errorf("Set-Cookie 应为 arauth_session，得到 %v", resp.Cookies())
	}
}

// TestRegisterVerifyErrorsIndistinguishable 验证 ceremony 失败对外
// 完全一致：同状态码、同响应体，不泄露失败步骤（保密红线第 6 条）。
// authn 把所有客户端侧失败归一为 ErrInvalidCeremony（可能包装），
// 这里验证两种形态映射相同。
func TestRegisterVerifyErrorsIndistinguishable(t *testing.T) {
	cases := map[string]error{
		"裸 sentinel":  authn.ErrInvalidCeremony,
		"包装 sentinel": fmt.Errorf("authn: 细节不对外: %w", authn.ErrInvalidCeremony),
	}

	var wantStatus int
	var wantBody string
	for name, err := range cases {
		srv := newStubServer(&stubRegistrar{finErr: err}, &stubGate{ok: true})
		resp, reqErr := http.Post(srv.URL+"/register/verify", "application/json", strings.NewReader("{}"))
		if reqErr != nil {
			t.Fatalf("%s: 请求失败: %v", name, reqErr)
		}
		buf := make([]byte, 256)
		n, _ := resp.Body.Read(buf)
		_ = resp.Body.Close()
		srv.Close()

		if wantStatus == 0 {
			wantStatus = resp.StatusCode
			wantBody = string(buf[:n])
			continue
		}
		if resp.StatusCode != wantStatus || string(buf[:n]) != wantBody {
			t.Errorf("%s: 响应与其他失败不一致: %d %q vs %d %q",
				name, resp.StatusCode, string(buf[:n]), wantStatus, wantBody)
		}
	}
	if wantStatus != http.StatusBadRequest {
		t.Errorf("ceremony 失败状态码 = %d，期望 400", wantStatus)
	}
}

// memSessionStore 是 session.Store 的内存实现（server 端到端测试用，
// 逻辑正确性由 internal/session 自己的测试覆盖）。
type memSessionStore struct {
	sessions []*store.Session
	codes    map[string]*store.ExchangeCode
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{codes: map[string]*store.ExchangeCode{}}
}

func (m *memSessionStore) InsertSession(_ context.Context, sess *store.Session) error {
	m.sessions = append(m.sessions, sess)
	return nil
}

func (m *memSessionStore) GetSession(_ context.Context, tokenHash []byte) (*store.Session, error) {
	for _, sess := range m.sessions {
		if bytes.Equal(sess.TokenHash, tokenHash) && time.Now().Before(sess.ExpiresAt) {
			return sess, nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *memSessionStore) InsertExchangeCode(_ context.Context, ec *store.ExchangeCode) error {
	m.codes[string(ec.CodeHash)] = ec
	return nil
}

func (m *memSessionStore) ConsumeExchangeCode(_ context.Context, codeHash []byte) (*store.ExchangeCode, error) {
	ec, ok := m.codes[string(codeHash)]
	if !ok || ec.UsedAt != nil || time.Now().After(ec.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	now := time.Now()
	ec.UsedAt = &now
	return ec, nil
}

const testExchangeKey = "server-to-server-secret"

// loginServer 装配登录测试服务器：真实 session.Service（内存 store）+
// stub 登录 ceremony，cfg 带 exchange API key。
func loginServer(t *testing.T, login LoginCeremony) (*httptest.Server, *memSessionStore) {
	t.Helper()
	mst := newMemSessionStore()
	cfg := &config.Config{
		SessionTTL:          time.Hour,
		ExchangeCodeTTL:     5 * time.Minute,
		SessionCookieSecure: true,
		ExchangeAPIKey:      testExchangeKey,
	}
	srv := newFullStubServer(cfg, &stubRegistrar{}, &stubGate{ok: true}, login, session.New(cfg, mst))
	t.Cleanup(srv.Close)
	return srv, mst
}

func TestLoginOptions(t *testing.T) {
	login := &stubLogin{assertion: &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: protocol.URLEncodedBase64("fake-login-challenge"),
		},
	}}
	srv, _ := loginServer(t, login)

	resp, err := http.Post(srv.URL+"/login/options", "application/json", nil)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", resp.StatusCode)
	}
	var body struct {
		PublicKey struct {
			Challenge          string `json:"challenge"`
			AllowedCredentials []any  `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(body.PublicKey.AllowedCredentials) != 0 {
		t.Error("discoverable 登录不得下发 allowCredentials")
	}
}

// TestLoginVerifyHappyPath：登录成功 → Set-Cookie 三属性齐全且不设
// Domain → 响应白名单恰为 {exchange_code, backed_up} → code 兑换一次
// 成功、二次 401。
func TestLoginVerifyHappyPath(t *testing.T) {
	handle := bytes.Repeat([]byte{0x42}, 64)
	login := &stubLogin{login: &authn.Login{UserHandle: handle, BackedUp: true}}
	srv, mst := loginServer(t, login)

	resp, err := http.Post(srv.URL+"/login/verify", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", resp.StatusCode)
	}

	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "arauth_session" {
		t.Fatalf("Set-Cookie 应为 arauth_session，得到 %v", cookies)
	}
	c := cookies[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie 属性: HttpOnly=%v Secure=%v SameSite=%v，期望 true/true/Strict",
			c.HttpOnly, c.Secure, c.SameSite)
	}
	if c.Domain != "" {
		t.Errorf("不得设 Domain 属性，得到 %q", c.Domain)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(body) != 2 {
		t.Errorf("响应只能含白名单字段 {exchange_code, backed_up}，得到 %v", body)
	}
	if body["backed_up"] != true {
		t.Errorf("backed_up = %v，期望 true", body["backed_up"])
	}
	code, ok := body["exchange_code"].(string)
	if !ok || code == "" {
		t.Fatalf("exchange_code 缺失或非字符串: %v", body["exchange_code"])
	}
	if len(mst.sessions) != 1 || len(mst.codes) != 1 {
		t.Fatalf("应落库 1 条 session + 1 条 exchange code，得到 %d/%d",
			len(mst.sessions), len(mst.codes))
	}

	// 兑换成功一次。
	exResp := postExchange(t, srv.URL, testExchangeKey, code)
	if exResp.StatusCode != http.StatusOK {
		t.Fatalf("exchange 状态码 = %d，期望 200", exResp.StatusCode)
	}
	var exBody map[string]any
	if err := json.NewDecoder(exResp.Body).Decode(&exBody); err != nil {
		t.Fatalf("解析 exchange 响应失败: %v", err)
	}
	_ = exResp.Body.Close()
	if len(exBody) != 2 {
		t.Errorf("exchange 响应只能含白名单字段 {user_handle, backed_up}，得到 %v", exBody)
	}
	if exBody["user_handle"] != base64.RawURLEncoding.EncodeToString(handle) {
		t.Errorf("user_handle = %v，与登录身份不符", exBody["user_handle"])
	}
	if exBody["backed_up"] != true {
		t.Errorf("backed_up = %v，期望 true", exBody["backed_up"])
	}

	// 同一 code 二次兑换 → 401。
	exResp = postExchange(t, srv.URL, testExchangeKey, code)
	_ = exResp.Body.Close()
	if exResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("重放兑换状态码 = %d，期望 401", exResp.StatusCode)
	}
}

func postExchange(t *testing.T, url, key, code string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", url+"/exchange",
		strings.NewReader(fmt.Sprintf(`{"code":%q}`, code)))
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Arauth-Exchange-Key", key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	return resp
}

// TestLoginVerifyInvalid：ceremony 失败 → 400 invalid，不发 cookie、
// 不签发会话。
func TestLoginVerifyInvalid(t *testing.T) {
	login := &stubLogin{finErr: fmt.Errorf("authn: 细节不对外: %w", authn.ErrInvalidCeremony)}
	srv, mst := loginServer(t, login)

	resp, err := http.Post(srv.URL+"/login/verify", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("状态码 = %d，期望 400", resp.StatusCode)
	}
	if len(resp.Cookies()) != 0 {
		t.Error("ceremony 失败不得发 cookie")
	}
	if len(mst.sessions) != 0 {
		t.Error("ceremony 失败不得签发会话")
	}
}

// TestExchangeAuth：api key 缺失/错误、code 无效一律 401，且响应体一致
// （对外不区分原因，保密红线第 6 条）。
func TestExchangeAuth(t *testing.T) {
	login := &stubLogin{login: &authn.Login{UserHandle: bytes.Repeat([]byte{0x42}, 64)}}
	srv, _ := loginServer(t, login)

	// 先登录拿一个有效 code，但不兑换。
	resp, err := http.Post(srv.URL+"/login/verify", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	var body struct {
		Code string `json:"exchange_code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析登录响应失败: %v", err)
	}
	_ = resp.Body.Close()

	bodies := map[string]*http.Response{}

	req, _ := http.NewRequest("POST", srv.URL+"/exchange", strings.NewReader(`{"code":"`+body.Code+`"}`))
	// 缺 key（不放 header）
	r1, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	bodies["缺 key"] = r1

	bodies["错 key"] = postExchange(t, srv.URL, "wrong-key", body.Code)
	bodies["未知 code"] = postExchange(t, srv.URL, testExchangeKey,
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x99}, 32)))

	var wantBody string
	for name, r := range bodies {
		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		_ = r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: 状态码 = %d，期望 401", name, r.StatusCode)
		}
		if wantBody == "" {
			wantBody = string(buf[:n])
			continue
		}
		if string(buf[:n]) != wantBody {
			t.Errorf("%s: 响应体 %q 与其他失败 %q 不一致", name, string(buf[:n]), wantBody)
		}
	}
	if wantBody != `{"error":"invalid"}`+"\n" {
		t.Errorf("失败响应体 = %q，期望 {\"error\":\"invalid\"}", wantBody)
	}
}

// TestLoginIssueError：会话签发失败 → 500，不发 cookie。
func TestLoginIssueError(t *testing.T) {
	login := &stubLogin{login: &authn.Login{UserHandle: bytes.Repeat([]byte{0x42}, 64)}}
	sess := &stubSession{issueErr: errors.New("db down")}
	srv := newFullStubServer(&config.Config{ExchangeAPIKey: testExchangeKey},
		&stubRegistrar{}, &stubGate{ok: true}, login, sess)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/login/verify", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("状态码 = %d，期望 500", resp.StatusCode)
	}
	if sess.cookieCalls != 0 {
		t.Error("签发失败不得写 cookie")
	}
}

// TestLoginVerifyPending403：pending identity（恢复码未确认）登录 →
// 403，响应体仍是不可区分的 invalid。
func TestLoginVerifyPending403(t *testing.T) {
	login := &stubLogin{finErr: authn.ErrIdentityPending}
	srv, mst := loginServer(t, login)

	resp, err := http.Post(srv.URL+"/login/verify", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("状态码 = %d，期望 403", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if body["error"] != "invalid" || len(body) != 1 {
		t.Errorf("响应体应为不可区分的 invalid，得到 %v", body)
	}
	if len(resp.Cookies()) != 0 {
		t.Error("pending 拒绝不得发 cookie")
	}
	if len(mst.sessions) != 0 {
		t.Error("pending 拒绝不得签发会话")
	}
}

// confirmServer 装配 confirm 测试服务器：真实 session.Service（内存
// store）+ stub registrar，可先把 pending 会话发出来再走 confirm。
func confirmServer(t *testing.T, reg Registrar) (*httptest.Server, *session.Service) {
	t.Helper()
	mst := newMemSessionStore()
	cfg := &config.Config{
		SessionTTL:          time.Hour,
		SessionCookieSecure: true,
		ExchangeAPIKey:      testExchangeKey,
	}
	sess := session.New(cfg, mst)
	srv := httptest.NewServer(New(cfg, reg, &stubGate{ok: true}, &stubLogin{}, sess, &stubRedeemer{}, &stubLimiter{}, &stubRecorder{}))
	t.Cleanup(srv.Close)
	return srv, sess
}

// TestRegisterConfirmHappyPath：注册 verify 拿到 cookie → confirm 激活
// （ConfirmRegistration 收到 cookie 对应的 user handle）→ 200。
func TestRegisterConfirmHappyPath(t *testing.T) {
	handle := bytes.Repeat([]byte{0x42}, 64)
	reg := &stubRegistrar{regn: &authn.Registration{
		CredentialID: []byte{0x01},
		RecoveryCode: "test-code-0001",
		UserHandle:   handle,
	}}
	srv, _ := confirmServer(t, reg)

	// verify 拿到 pending 会话 cookie。
	resp, err := http.Post(srv.URL+"/register/verify", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("verify 请求失败: %v", err)
	}
	_ = resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("verify 应下发 1 个会话 cookie，得到 %d", len(cookies))
	}

	// confirm。
	req, _ := http.NewRequest("POST", srv.URL+"/register/confirm", nil)
	req.AddCookie(cookies[0])
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("confirm 请求失败: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("confirm 状态码 = %d，期望 200", resp2.StatusCode)
	}
	if reg.confirmCalls != 1 || !bytes.Equal(reg.confirmGot, handle) {
		t.Errorf("ConfirmRegistration 调用 %d 次、handle=%x，期望 1 次且为会话身份",
			reg.confirmCalls, reg.confirmGot)
	}
}

// TestRegisterConfirmRejections：无 cookie / 未知会话 / 激活失败（超
// 宽限）一律 401 invalid，响应体一致。
func TestRegisterConfirmRejections(t *testing.T) {
	reg := &stubRegistrar{}
	srv, _ := confirmServer(t, reg)

	readBody := func(r *http.Response) string {
		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		_ = r.Body.Close()
		return string(buf[:n])
	}

	// 无 cookie。
	resp, err := http.Post(srv.URL+"/register/confirm", "application/json", nil)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("无 cookie 状态码 = %d，期望 401", resp.StatusCode)
	}
	wantBody := readBody(resp)

	// 未知会话 cookie。
	req, _ := http.NewRequest("POST", srv.URL+"/register/confirm", nil)
	req.AddCookie(&http.Cookie{Name: "arauth_session", Value: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x99}, 32))})
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized || readBody(resp) != wantBody {
		t.Errorf("未知会话应 401 且响应体一致")
	}

	if reg.confirmCalls != 0 {
		t.Error("鉴权失败不得触及 Registrar")
	}

	// 激活被拒（如超 PendingTTL，authn 归一 ErrInvalidCeremony）。
	reg2 := &stubRegistrar{confirmErr: fmt.Errorf("authn: pending 超宽限: %w", authn.ErrInvalidCeremony)}
	mst := newMemSessionStore()
	cfg := &config.Config{SessionTTL: time.Hour, SessionCookieSecure: true, ExchangeAPIKey: testExchangeKey}
	sess := session.New(cfg, mst)
	srv2 := httptest.NewServer(New(cfg, reg2, &stubGate{ok: true}, &stubLogin{}, sess, &stubRedeemer{}, &stubLimiter{}, &stubRecorder{}))
	defer srv2.Close()

	token, err := sess.IssuePendingSession(context.Background(), bytes.Repeat([]byte{0x42}, 64))
	if err != nil {
		t.Fatalf("签发 pending 会话失败: %v", err)
	}
	req, _ = http.NewRequest("POST", srv2.URL+"/register/confirm", nil)
	req.AddCookie(&http.Cookie{Name: "arauth_session", Value: base64.RawURLEncoding.EncodeToString(token)})
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized || readBody(resp) != wantBody {
		t.Errorf("激活被拒应 401 且响应体一致，得到 %d", resp.StatusCode)
	}
}

// postRedeem 带恢复码与 PoW 字段请求 /recovery/redeem。
func postRedeem(t *testing.T, url, code string, challenge, nonce []byte) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"recovery_code":%q,"pow_challenge":%q,"pow_nonce":%q}`,
		code,
		base64.RawURLEncoding.EncodeToString(challenge),
		base64.RawURLEncoding.EncodeToString(nonce))
	resp, err := http.Post(url+"/recovery/redeem", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	return resp
}

// TestRecoveryRedeemHappyPath：PoW 通过 + 码正确 → 200 下发一次性
// 恢复凭证；Redeem 只被调用一次（码原文只经兑换入口）。
func TestRecoveryRedeemHappyPath(t *testing.T) {
	rec := &stubRedeemer{token: bytes.Repeat([]byte{0x55}, 32)}
	srv := httptest.NewServer(New(&config.Config{}, &stubRegistrar{}, &stubGate{ok: true}, &stubLogin{}, &stubSession{}, rec, &stubLimiter{}, &stubRecorder{}))
	defer srv.Close()

	resp := postRedeem(t, srv.URL, "test-code-0001", []byte("c"), []byte("n"))
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(body) != 1 {
		t.Errorf("响应只能含白名单字段 {recovery_token}，得到 %v", body)
	}
	token, ok := body["recovery_token"].(string)
	if !ok || token == "" {
		t.Fatalf("recovery_token 缺失: %v", body)
	}
	if _, err := base64.RawURLEncoding.DecodeString(token); err != nil {
		t.Errorf("recovery_token 不是合法 base64url: %v", err)
	}
	if rec.redeemCode != "test-code-0001" {
		t.Errorf("Redeem 收到的码 = %q，期望请求原样传递", rec.redeemCode)
	}
}

// TestRecoveryRedeemPoWGate：无体/缺字段/坏 base64/坏解一律 429，
// 且不得触及 Redeem（码原文不得越过 PoW 门）。
func TestRecoveryRedeemPoWGate(t *testing.T) {
	bodies := map[string]string{
		"空体":       "",
		"空 JSON":   "{}",
		"缺 PoW":    `{"recovery_code":"aaaa-bbbb"}`,
		"坏 base64": `{"recovery_code":"aaaa-bbbb","pow_challenge":"%%%","pow_nonce":"%%%"}`,
	}
	for name, body := range bodies {
		rec := &stubRedeemer{}
		srv := httptest.NewServer(New(&config.Config{}, &stubRegistrar{}, &stubGate{ok: true}, &stubLogin{}, &stubSession{}, rec, &stubLimiter{}, &stubRecorder{}))
		resp, err := http.Post(srv.URL+"/recovery/redeem", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("%s: 请求失败: %v", name, err)
		}
		_ = resp.Body.Close()
		srv.Close()
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("%s: 状态码 = %d，期望 429", name, resp.StatusCode)
		}
		if rec.redeemCode != "" {
			t.Errorf("%s: PoW 未过不得触及 Redeem", name)
		}
	}

	rec := &stubRedeemer{}
	srv := httptest.NewServer(New(&config.Config{}, &stubRegistrar{}, &stubGate{ok: false}, &stubLogin{}, &stubSession{}, rec, &stubLimiter{}, &stubRecorder{}))
	defer srv.Close()
	resp := postRedeem(t, srv.URL, "aaaa-bbbb", []byte("c"), []byte("n"))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("坏解状态码 = %d，期望 429", resp.StatusCode)
	}
	if rec.redeemCode != "" {
		t.Error("坏解不得触及 Redeem")
	}
}

// TestRecoveryRedeemInvalidCode：码错误统一 401 invalid（不区分
// 不存在/已轮换），响应体与 confirm 失败一致。
func TestRecoveryRedeemInvalidCode(t *testing.T) {
	rec := &stubRedeemer{redeemErr: fmt.Errorf("recovery: 细节不对外: %w", recovery.ErrInvalidRedeem)}
	srv := httptest.NewServer(New(&config.Config{}, &stubRegistrar{}, &stubGate{ok: true}, &stubLogin{}, &stubSession{}, rec, &stubLimiter{}, &stubRecorder{}))
	defer srv.Close()

	resp := postRedeem(t, srv.URL, "wrong-code", []byte("c"), []byte("n"))
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("状态码 = %d，期望 401", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if body["error"] != "invalid" || len(body) != 1 {
		t.Errorf("响应体应为不可区分的 invalid，得到 %v", body)
	}
}

// recoveryTokenHeaderValue 构造合法 header 值。
func recoveryTokenHeaderValue(token []byte) string {
	return base64.RawURLEncoding.EncodeToString(token)
}

// TestRecoveryOptionsAndVerify：凭证走 header；options 透传 creation
// options；verify 成功白名单恰为 {credential_id, backed_up, recovery_code}
// （新码原文唯一一次出现）；缺/坏凭证一律 400 invalid。
func TestRecoveryOptionsAndVerify(t *testing.T) {
	token := bytes.Repeat([]byte{0x55}, 32)
	reg := &stubRegistrar{
		recCreation: &protocol.CredentialCreation{
			Response: protocol.PublicKeyCredentialCreationOptions{
				Challenge: protocol.URLEncodedBase64("fake-recovery-challenge"),
			},
		},
		recRegn: &authn.RecoveryRegistration{
			CredentialID: []byte{0x09},
			BackedUp:     true,
			RecoveryCode: "test-code-0002",
		},
	}
	srv := newStubServer(reg, &stubGate{ok: true})
	defer srv.Close()

	// options：带凭证 → 200，token 原样传给 Registrar。
	req, _ := http.NewRequest("POST", srv.URL+"/recovery/options", nil)
	req.Header.Set(recoveryTokenHeader, recoveryTokenHeaderValue(token))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("options 请求失败: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("options 状态码 = %d，期望 200", resp.StatusCode)
	}
	if !bytes.Equal(reg.recBeginGot, token) {
		t.Error("BeginRecoveryRegistration 未收到 header 里的凭证")
	}

	// verify：带凭证 → 200 + 白名单三字段。
	req, _ = http.NewRequest("POST", srv.URL+"/recovery/verify", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(recoveryTokenHeader, recoveryTokenHeaderValue(token))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("verify 请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify 状态码 = %d，期望 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(body) != 3 || body["recovery_code"] != "test-code-0002" || body["backed_up"] != true || body["credential_id"] != "CQ" {
		t.Errorf("verify 响应白名单不符: %v", body)
	}
	if !bytes.Equal(reg.recFinGot, token) {
		t.Error("FinishRecoveryRegistration 未收到 header 里的凭证")
	}
}

// TestRecoveryEndpointsBadToken：缺 header / 坏 base64 / authn 拒绝
// 一律 400 invalid，响应体一致。
func TestRecoveryEndpointsBadToken(t *testing.T) {
	reg := &stubRegistrar{
		recBeginErr: fmt.Errorf("authn: 细节不对外: %w", authn.ErrInvalidCeremony),
		recFinErr:   fmt.Errorf("authn: 细节不对外: %w", authn.ErrInvalidCeremony),
	}
	srv := newStubServer(reg, &stubGate{ok: true})
	defer srv.Close()

	readBody := func(r *http.Response) string {
		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		_ = r.Body.Close()
		return string(buf[:n])
	}

	var want string
	for _, endpoint := range []string{"/recovery/options", "/recovery/verify"} {
		// 缺 header。
		resp, err := http.Post(srv.URL+endpoint, "application/json", nil)
		if err != nil {
			t.Fatalf("%s: 请求失败: %v", endpoint, err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s 缺凭证状态码 = %d，期望 400", endpoint, resp.StatusCode)
		}
		if want == "" {
			want = readBody(resp)
		} else if got := readBody(resp); got != want {
			t.Errorf("%s 缺凭证响应体 %q 与预期 %q 不一致", endpoint, got, want)
		}

		// 坏 base64 header。
		req, _ := http.NewRequest("POST", srv.URL+endpoint, nil)
		req.Header.Set(recoveryTokenHeader, "%%%")
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: 请求失败: %v", endpoint, err)
		}
		if resp.StatusCode != http.StatusBadRequest || readBody(resp) != want {
			t.Errorf("%s 坏凭证应 400 且响应体一致", endpoint)
		}

		// authn 拒绝（凭证无效）。
		req, _ = http.NewRequest("POST", srv.URL+endpoint, nil)
		req.Header.Set(recoveryTokenHeader, recoveryTokenHeaderValue([]byte("无效")))
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: 请求失败: %v", endpoint, err)
		}
		if resp.StatusCode != http.StatusBadRequest || readBody(resp) != want {
			t.Errorf("%s 无效凭证应 400 且响应体一致", endpoint)
		}
	}
}

// TestDevCORSOffByDefault：未配置 CORS 白名单时，带 Origin 的请求不得
// 收到任何 Access-Control-* 头（默认即同源形态）。
func TestDevCORSOffByDefault(t *testing.T) {
	srv := newStubServer(&stubRegistrar{}, &stubGate{ok: true})
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	_ = resp.Body.Close()
	for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
		if got := resp.Header.Get(h); got != "" {
			t.Errorf("未配置 CORS 时不得下发 %s，得到 %q", h, got)
		}
	}
}
