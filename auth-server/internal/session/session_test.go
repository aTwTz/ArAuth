package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/store"
)

// fakeSessionStore 记录写入内容，ConsumeExchangeCode 模拟原子核销语义。
type fakeSessionStore struct {
	sessions   []*store.Session
	codes      map[string]*store.ExchangeCode
	consumeErr error
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{codes: map[string]*store.ExchangeCode{}}
}

func (f *fakeSessionStore) InsertSession(_ context.Context, sess *store.Session) error {
	f.sessions = append(f.sessions, sess)
	return nil
}

// GetSession 模拟"按哈希取未过期会话"：不存在或过期一律 ErrNotFound。
func (f *fakeSessionStore) GetSession(_ context.Context, tokenHash []byte) (*store.Session, error) {
	for _, sess := range f.sessions {
		if bytes.Equal(sess.TokenHash, tokenHash) && time.Now().Before(sess.ExpiresAt) {
			return sess, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeSessionStore) InsertExchangeCode(_ context.Context, ec *store.ExchangeCode) error {
	f.codes[string(ec.CodeHash)] = ec
	return nil
}

func (f *fakeSessionStore) ConsumeExchangeCode(_ context.Context, codeHash []byte) (*store.ExchangeCode, error) {
	if f.consumeErr != nil {
		return nil, f.consumeErr
	}
	ec, ok := f.codes[string(codeHash)]
	if !ok || ec.UsedAt != nil || time.Now().After(ec.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	now := time.Now()
	ec.UsedAt = &now
	return ec, nil
}

func testConfig() *config.Config {
	return &config.Config{
		SessionTTL:          time.Hour,
		ExchangeCodeTTL:     5 * time.Minute,
		SessionCookieSecure: true,
	}
}

// TestIssueStoresHashesOnly：签发的 token/code 原文不落库，库中只有
// SHA-256 哈希（数据分级第 3 条）。
func TestIssueStoresHashesOnly(t *testing.T) {
	fst := newFakeSessionStore()
	svc := New(testConfig(), fst)
	handle := bytes.Repeat([]byte{0x42}, 64)

	token, code, err := svc.Issue(context.Background(), handle, true)
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	if len(token) != tokenLen || len(code) != tokenLen {
		t.Fatalf("token/code 应为 %d 字节，得到 %d/%d", tokenLen, len(token), len(code))
	}
	if len(fst.sessions) != 1 {
		t.Fatalf("sessions 落库 %d 条，期望 1", len(fst.sessions))
	}
	sess := fst.sessions[0]
	sum := sha256.Sum256(token)
	if !bytes.Equal(sess.TokenHash, sum[:]) {
		t.Error("库中 token_hash 不是 token 的 SHA-256")
	}
	if bytes.Contains(sess.TokenHash, token) {
		t.Error("token 原文泄露进库存储")
	}
	if !bytes.Equal(sess.UserHandle, handle) {
		t.Error("session 未挂到正确 user_handle")
	}
	codeSum := sha256.Sum256(code)
	stored, ok := fst.codes[string(codeSum[:])]
	if !ok {
		t.Fatal("exchange code 哈希未落库")
	}
	if !stored.BackedUp {
		t.Error("exchange code 应记录签发时的 backed_up=true")
	}
	if got := time.Until(stored.ExpiresAt); got <= 0 || got > 5*time.Minute {
		t.Errorf("exchange code TTL = %v，期望 (0, 5m]", got)
	}
	if got := time.Until(sess.ExpiresAt); got <= 0 || got > time.Hour {
		t.Errorf("session TTL = %v，期望 (0, 1h]", got)
	}
}

// TestExchangeOnce：兑换成功返回白名单信息；同一 code 二次兑换失败；
// 未知 code 失败——三者中只有成功那次返回值。
func TestExchangeOnce(t *testing.T) {
	fst := newFakeSessionStore()
	svc := New(testConfig(), fst)
	handle := bytes.Repeat([]byte{0x42}, 64)

	_, code, err := svc.Issue(context.Background(), handle, true)
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}

	ec, err := svc.Exchange(context.Background(), code)
	if err != nil {
		t.Fatalf("首次兑换应成功: %v", err)
	}
	if !bytes.Equal(ec.UserHandle, handle) || !ec.BackedUp {
		t.Error("兑换结果白名单字段不符")
	}

	if _, err := svc.Exchange(context.Background(), code); !errors.Is(err, ErrInvalidExchange) {
		t.Fatalf("重放兑换应失败，得到: %v", err)
	}
	if _, err := svc.Exchange(context.Background(), bytes.Repeat([]byte{0x99}, tokenLen)); !errors.Is(err, ErrInvalidExchange) {
		t.Fatalf("未知 code 应失败，得到: %v", err)
	}
	if _, err := svc.Exchange(context.Background(), []byte("short")); !errors.Is(err, ErrInvalidExchange) {
		t.Fatalf("长度不符的 code 应失败，得到: %v", err)
	}
}

// TestExchangeExpired：过期 code 拒绝兑换（与不存在不可区分）。
func TestExchangeExpired(t *testing.T) {
	fst := newFakeSessionStore()
	svc := New(testConfig(), fst)
	svc.now = func() time.Time { return time.Now().Add(-10 * time.Minute) } // 签发时刻在过去

	_, code, err := svc.Issue(context.Background(), bytes.Repeat([]byte{0x42}, 64), false)
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	if _, err := svc.Exchange(context.Background(), code); !errors.Is(err, ErrInvalidExchange) {
		t.Fatalf("过期 code 应拒绝，得到: %v", err)
	}
}

// TestWriteCookieAttributes：cookie 带 httpOnly + Secure + SameSite=Strict +
// Path=/，不设 Domain（禁止向依赖方域名放大）；Secure 按 config 切换。
func TestWriteCookieAttributes(t *testing.T) {
	for _, secure := range []bool{true, false} {
		cfg := testConfig()
		cfg.SessionCookieSecure = secure
		svc := New(cfg, newFakeSessionStore())

		rec := httptest.NewRecorder()
		token := bytes.Repeat([]byte{0x7}, tokenLen)
		svc.WriteCookie(rec, token)

		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("Set-Cookie 数 = %d，期望 1", len(cookies))
		}
		c := cookies[0]
		if c.Name != cookieName {
			t.Errorf("cookie 名 = %q，期望 %q", c.Name, cookieName)
		}
		if !c.HttpOnly {
			t.Error("缺 HttpOnly")
		}
		if c.Secure != secure {
			t.Errorf("Secure = %v，期望 %v", c.Secure, secure)
		}
		if c.SameSite != http.SameSiteStrictMode {
			t.Errorf("SameSite = %v，期望 Strict", c.SameSite)
		}
		if c.Path != "/" {
			t.Errorf("Path = %q，期望 /", c.Path)
		}
		if c.Domain != "" {
			t.Errorf("不得设 Domain 属性，得到 %q", c.Domain)
		}
		if strings.Contains(c.Value, "+") || strings.Contains(c.Value, "/") || strings.Contains(c.Value, "=") {
			t.Errorf("cookie 值应为 base64url 无填充编码: %q", c.Value)
		}
	}
}

// TestIssuePendingSession：pending 会话只发 token、不发 exchange code，
// 库中仍只存 SHA-256 哈希。
func TestIssuePendingSession(t *testing.T) {
	fst := newFakeSessionStore()
	svc := New(testConfig(), fst)
	handle := bytes.Repeat([]byte{0x42}, 64)

	token, err := svc.IssuePendingSession(context.Background(), handle)
	if err != nil {
		t.Fatalf("IssuePendingSession 失败: %v", err)
	}
	if len(token) != tokenLen {
		t.Errorf("token 应为 %d 字节，得到 %d", tokenLen, len(token))
	}
	if len(fst.sessions) != 1 {
		t.Fatalf("sessions 落库 %d 条，期望 1", len(fst.sessions))
	}
	if len(fst.codes) != 0 {
		t.Errorf("pending 会话不得发 exchange code，落库 %d 条", len(fst.codes))
	}
	sum := sha256.Sum256(token)
	if !bytes.Equal(fst.sessions[0].TokenHash, sum[:]) {
		t.Error("库中 token_hash 不是 token 的 SHA-256")
	}
}

// TestAuthenticate：cookie 定位身份；无 cookie、畸形值、未知会话、
// 过期会话统一 ErrInvalidSession，不区分原因。
func TestAuthenticate(t *testing.T) {
	fst := newFakeSessionStore()
	svc := New(testConfig(), fst)
	handle := bytes.Repeat([]byte{0x42}, 64)

	token, err := svc.IssuePendingSession(context.Background(), handle)
	if err != nil {
		t.Fatalf("IssuePendingSession 失败: %v", err)
	}

	withCookie := func(value string) *http.Request {
		r := httptest.NewRequest("POST", "/register/confirm", nil)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: value})
		return r
	}

	got, err := svc.Authenticate(withCookie(base64url(token)))
	if err != nil {
		t.Fatalf("合法会话应鉴权成功: %v", err)
	}
	if !bytes.Equal(got, handle) {
		t.Error("鉴权结果的 user_handle 不符")
	}

	if _, err := svc.Authenticate(httptest.NewRequest("POST", "/register/confirm", nil)); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("无 cookie 应 ErrInvalidSession，得到: %v", err)
	}
	if _, err := svc.Authenticate(withCookie("!!! 不是 base64url !!!")); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("畸形 cookie 应 ErrInvalidSession，得到: %v", err)
	}
	if _, err := svc.Authenticate(withCookie(base64url(bytes.Repeat([]byte{0x99}, tokenLen)))); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("未知会话应 ErrInvalidSession，得到: %v", err)
	}

	// 过期会话：签发于 2 小时前（TTL 1 小时）
	svc.now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	stale, err := svc.IssuePendingSession(context.Background(), handle)
	if err != nil {
		t.Fatalf("IssuePendingSession 失败: %v", err)
	}
	if _, err := svc.Authenticate(withCookie(base64url(stale))); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("过期会话应 ErrInvalidSession，得到: %v", err)
	}
}

// TestAuthenticateFresh：恢复因素管理只接受新鲜会话；过期 fresh 窗口
// 不影响普通会话鉴权，但不得用于 TOTP 绑定。
func TestAuthenticateFresh(t *testing.T) {
	fst := newFakeSessionStore()
	svc := New(testConfig(), fst)
	handle := bytes.Repeat([]byte{0x42}, 64)
	token, err := svc.IssuePendingSession(context.Background(), handle)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	fst.sessions[0].CreatedAt = now
	svc.now = func() time.Time { return now }
	r := httptest.NewRequest("POST", "/recovery/totp/enroll/begin", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: base64url(token)})

	if got, err := svc.AuthenticateFresh(r, 15*time.Minute); err != nil || !bytes.Equal(got, handle) {
		t.Fatalf("新鲜会话应通过: %q, %v", got, err)
	}
	fst.sessions[0].CreatedAt = now.Add(-16 * time.Minute)
	if _, err := svc.AuthenticateFresh(r, 15*time.Minute); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("超过 fresh 窗口应拒绝，得到 %v", err)
	}
	if _, err := svc.Authenticate(r); err != nil {
		t.Fatalf("普通会话不应受 fresh 窗口影响: %v", err)
	}
	fst.sessions[0].CreatedAt = now.Add(time.Minute)
	if _, err := svc.AuthenticateFresh(r, 15*time.Minute); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("未来签发时间应拒绝，得到 %v", err)
	}
}
