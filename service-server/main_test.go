package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T, upstream http.HandlerFunc) *server {
	t.Helper()
	arauth := httptest.NewServer(upstream)
	t.Cleanup(arauth.Close)
	return &server{
		cfg: &config{
			arauthURL:      arauth.URL,
			exchangeAPIKey: "server-exchange-key",
			httpClient:     arauth.Client(),
		},
		jar:      make(map[string]jarEntry),
		sessions: make(map[string]sessionEntry),
	}
}

func serve(s *server, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, r)
	return rec
}

func responseCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("响应缺少 cookie %q；Set-Cookie=%v", name, rec.Header().Values("Set-Cookie"))
	return nil
}

func assertNoArauthCookie(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, line := range rec.Header().Values("Set-Cookie") {
		if strings.Contains(line, "arauth_session=") {
			t.Errorf("arauth_session 不得下行：%q", line)
		}
	}
}

func TestEnrollAuth(t *testing.T) {
	const confirmBody = `{"setup_token":"setup","code":"123456"}`
	tests := []struct {
		name         string
		path         string
		flow         string
		cookieName   string
		cookieValue  string
		wantCookie   string
		wantBody     string
		upstreamBody string
	}{
		{
			name:         "pending begin",
			path:         "/recovery/totp/enroll/begin",
			flow:         "register",
			cookieName:   pendingCookieName,
			cookieValue:  "pending-id",
			wantCookie:   "arauth_session=pending-token",
			wantBody:     `{"setup_token":"setup","secret":"secret","otpauth_uri":"otpauth://totp/example","recovery_id":"recovery-id"}`,
			upstreamBody: "",
		},
		{
			name:         "pending confirm",
			path:         "/recovery/totp/enroll/confirm",
			flow:         "register",
			cookieName:   pendingCookieName,
			cookieValue:  "pending-id",
			wantCookie:   "arauth_session=pending-token",
			wantBody:     `{"status":"ok"}`,
			upstreamBody: confirmBody,
		},
		{
			name:         "rp session begin",
			path:         "/recovery/totp/enroll/begin",
			flow:         "login",
			cookieName:   sessionCookieName,
			cookieValue:  "session-id",
			wantCookie:   "arauth_session=session-token",
			wantBody:     `{"setup_token":"setup","secret":"secret","otpauth_uri":"otpauth://totp/example","recovery_id":"recovery-id"}`,
			upstreamBody: "",
		},
		{
			name:         "rp session confirm",
			path:         "/recovery/totp/enroll/confirm",
			flow:         "login",
			cookieName:   sessionCookieName,
			cookieValue:  "session-id",
			wantCookie:   "arauth_session=session-token",
			wantBody:     `{"status":"ok"}`,
			upstreamBody: confirmBody,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != tc.path {
					t.Errorf("上行请求 = %s %s，want POST %s", r.Method, r.URL.Path, tc.path)
				}
				if got := r.Header.Get("Cookie"); got != tc.wantCookie {
					t.Errorf("上行 Cookie = %q，want %q", got, tc.wantCookie)
				}
				if got := r.Header.Get("X-Arauth-Exchange-Key"); got != "" {
					t.Errorf("浏览器 exchange key 被转发：%q", got)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("读上行 body: %v", err)
				}
				if string(body) != tc.upstreamBody {
					t.Errorf("上行 body = %q，want %q", body, tc.upstreamBody)
				}
				w.Header().Set("Set-Cookie", "arauth_session=upstream-secret; Path=/")
				w.Header().Set("X-Upstream-Secret", "do-not-forward")
				_, _ = w.Write([]byte(tc.wantBody))
			})
			now := time.Now()
			s.jar["pending-id"] = jarEntry{arauthToken: "pending-token", expires: now.Add(time.Hour)}
			s.sessions["session-id"] = sessionEntry{
				userHandle:  "dXNlcg",
				expires:     now.Add(time.Hour),
				arauthToken: "session-token",
				freshUntil:  now.Add(freshTTL),
			}

			// begin 即使收到浏览器 body 也固定向上游发空请求；伪造的浏览器
			// arauth cookie/user_handle 均不参与鉴权。
			req := httptest.NewRequest(http.MethodPost, tc.path+"?flow="+tc.flow, strings.NewReader(confirmBody))
			req.AddCookie(&http.Cookie{Name: tc.cookieName, Value: tc.cookieValue})
			req.AddCookie(&http.Cookie{Name: "arauth_session", Value: "browser-forged"})
			req.Header.Set("X-Arauth-Exchange-Key", "browser-key")
			rec := serve(s, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("状态码 = %d，body=%s", rec.Code, rec.Body.String())
			}
			if rec.Body.String() != tc.wantBody {
				t.Errorf("下行 body = %q，want %q", rec.Body.String(), tc.wantBody)
			}
			if got := rec.Header().Get("Set-Cookie"); got != "" {
				t.Errorf("enroll 不应种 cookie：%q", got)
			}
			if got := rec.Header().Get("X-Upstream-Secret"); got != "" {
				t.Errorf("非白名单响应头被透传：%q", got)
			}
			if calls != 1 {
				t.Errorf("上游调用次数 = %d，want 1", calls)
			}
		})
	}
}

func TestEnrollExplicitFlow(t *testing.T) {
	for _, tc := range []struct {
		flow       string
		wantCookie string
	}{
		{flow: "register", wantCookie: "arauth_session=pending-token"},
		{flow: "login", wantCookie: "arauth_session=session-token"},
	} {
		t.Run("两种 cookie 并存时选择 "+tc.flow, func(t *testing.T) {
			s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Cookie"); got != tc.wantCookie {
					t.Errorf("上行 Cookie = %q，want %q", got, tc.wantCookie)
				}
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})
			now := time.Now()
			s.jar["pending-id"] = jarEntry{arauthToken: "pending-token", expires: now.Add(time.Hour)}
			s.sessions["session-id"] = sessionEntry{
				expires: now.Add(time.Hour), arauthToken: "session-token", freshUntil: now.Add(freshTTL),
			}
			req := httptest.NewRequest(http.MethodPost, "/recovery/totp/enroll/begin?flow="+tc.flow, nil)
			req.AddCookie(&http.Cookie{Name: pendingCookieName, Value: "pending-id"})
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-id"})
			if rec := serve(s, req); rec.Code != http.StatusOK {
				t.Fatalf("状态码 = %d，body=%s", rec.Code, rec.Body.String())
			}
		})
	}

	for _, flow := range []string{"register", "login"} {
		t.Run(flow+" 不回退另一种会话", func(t *testing.T) {
			calls := 0
			s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})
			now := time.Now()
			s.jar["pending-id"] = jarEntry{arauthToken: "pending-token", expires: now.Add(time.Hour)}
			s.sessions["session-id"] = sessionEntry{
				expires: now.Add(time.Hour), arauthToken: "session-token", freshUntil: now.Add(freshTTL),
			}
			req := httptest.NewRequest(http.MethodPost, "/recovery/totp/enroll/begin?flow="+flow, nil)
			if flow == "register" {
				req.AddCookie(&http.Cookie{Name: pendingCookieName, Value: "unknown-pending"})
				req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-id"})
			} else {
				req.AddCookie(&http.Cookie{Name: pendingCookieName, Value: "pending-id"})
				req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "unknown-session"})
			}
			rec := serve(s, req)
			if rec.Code != http.StatusUnauthorized || calls != 0 {
				t.Fatalf("无效所选会话应 401 且不上行: status=%d calls=%d", rec.Code, calls)
			}
		})
	}

	t.Run("缺失或未知 flow", func(t *testing.T) {
		calls := 0
		s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) { calls++ })
		for _, suffix := range []string{"", "?flow=other"} {
			req := httptest.NewRequest(http.MethodPost, "/recovery/totp/enroll/begin"+suffix, nil)
			if rec := serve(s, req); rec.Code != http.StatusUnauthorized {
				t.Errorf("%q 状态码 = %d，期望 401", suffix, rec.Code)
			}
		}
		if calls != 0 {
			t.Errorf("无效 flow 不得调用上游，calls=%d", calls)
		}
	})
}

func TestEnrollRequiresFreshSession(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		arauthToken string
		freshUntil  time.Time
	}{
		{name: "fresh 过期", path: "/recovery/totp/enroll/begin", arauthToken: "expired-token", freshUntil: time.Now().Add(-time.Second)},
		{name: "缺 fresh token", path: "/recovery/totp/enroll/confirm", freshUntil: time.Now().Add(freshTTL)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})
			s.sessions["session-id"] = sessionEntry{
				userHandle: "dXNlcg", expires: time.Now().Add(time.Hour),
				arauthToken: tc.arauthToken, freshUntil: tc.freshUntil,
			}
			req := httptest.NewRequest(http.MethodPost, tc.path+"?flow=login", strings.NewReader(`{"user_handle":"forged"}`))
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-id"})
			rec := serve(s, req)
			if rec.Code != http.StatusUnauthorized || rec.Body.String() != "{\"error\":\"invalid\"}\n" {
				t.Fatalf("响应 = %d %q，want 401 invalid", rec.Code, rec.Body.String())
			}
			if calls != 0 {
				t.Errorf("无效 fresh 会话不得调用上游，calls=%d", calls)
			}
			if tc.arauthToken != "" && s.sessions["session-id"].arauthToken != "" {
				t.Error("fresh 过期后应清除服务端代持 token")
			}
		})
	}
}

func TestRegisterConfirmKeepsPendingLifecycle(t *testing.T) {
	s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register/verify":
			if got := r.Header.Get("Cookie"); got != "" {
				t.Errorf("register/verify 转发了浏览器 Cookie：%q", got)
			}
			if got := r.Header.Get("X-Arauth-Exchange-Key"); got != "" {
				t.Errorf("register/verify 转发了浏览器 exchange key：%q", got)
			}
			w.Header().Set("Set-Cookie", "arauth_session=pending-token; Path=/; HttpOnly")
			_, _ = w.Write([]byte(`{"status":"ok","recovery_codes":["plain-code"]}`))
		case "/register/confirm":
			if got := r.Header.Get("Cookie"); got != "arauth_session=pending-token" {
				t.Errorf("register/confirm Cookie = %q", got)
			}
			body, _ := io.ReadAll(r.Body)
			if len(body) != 0 {
				t.Errorf("register/confirm 上行 body = %q，want empty", body)
			}
			w.Header().Set("Set-Cookie", "arauth_session=rotated-secret; Path=/")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			t.Errorf("意外上游路径 %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	req := httptest.NewRequest(http.MethodPost, "/register/verify", strings.NewReader(`{"credential":"new"}`))
	req.AddCookie(&http.Cookie{Name: "arauth_session", Value: "browser-forged"})
	req.Header.Set("X-Arauth-Exchange-Key", "browser-key")
	rec := serve(s, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register/verify 状态码 = %d，body=%s", rec.Code, rec.Body.String())
	}
	assertNoArauthCookie(t, rec)
	pending := responseCookie(t, rec, pendingCookieName)
	if pending.Value == "" {
		t.Fatal("rp_pending 不应为空")
	}
	s.mu.Lock()
	entry, ok := s.jar[pending.Value]
	s.mu.Unlock()
	if !ok || entry.arauthToken != "pending-token" {
		t.Fatalf("服务端 pending jar = %+v, %v", entry, ok)
	}

	confirm := httptest.NewRequest(http.MethodPost, "/register/confirm", nil)
	confirm.AddCookie(&http.Cookie{Name: pendingCookieName, Value: pending.Value})
	confirm.AddCookie(&http.Cookie{Name: "arauth_session", Value: "browser-forged"})
	confirmRec := serve(s, confirm)
	if confirmRec.Code != http.StatusOK || confirmRec.Body.String() != `{"status":"ok"}` {
		t.Fatalf("register/confirm 响应 = %d %q", confirmRec.Code, confirmRec.Body.String())
	}
	assertNoArauthCookie(t, confirmRec)
	if cookie := responseCookie(t, confirmRec, pendingCookieName); cookie.Value != "" {
		t.Errorf("确认后 rp_pending 应清空，得到 %q", cookie.Value)
	}
	s.mu.Lock()
	_, ok = s.jar[pending.Value]
	s.mu.Unlock()
	if ok {
		t.Error("register/confirm 成功后必须删除 pending jar")
	}
}

func TestLoginVerifyStoresFreshTokenWithoutLeakingTickets(t *testing.T) {
	s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/verify":
			if got := r.Header.Get("Cookie"); got != "" {
				t.Errorf("login/verify 转发了浏览器 Cookie：%q", got)
			}
			if got := r.Header.Get("X-Arauth-Exchange-Key"); got != "" {
				t.Errorf("login/verify 转发了浏览器 exchange key：%q", got)
			}
			w.Header().Set("Set-Cookie", "arauth_session=login-fresh-token; Path=/; HttpOnly")
			_, _ = w.Write([]byte(`{"exchange_code":"one-time-code","backed_up":false,"extra":"do-not-forward"}`))
		case "/exchange":
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"code":"one-time-code"}` {
				t.Errorf("exchange body = %q", body)
			}
			if got := r.Header.Get("X-Arauth-Exchange-Key"); got != "server-exchange-key" {
				t.Errorf("exchange key = %q，want 服务端共享密钥", got)
			}
			if got := r.Header.Get("Cookie"); got != "" {
				t.Errorf("exchange 不应带 Cookie：%q", got)
			}
			_, _ = w.Write([]byte(`{"user_handle":"dXNlcg","backed_up":true}`))
		default:
			t.Errorf("意外上游路径 %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	before := time.Now()
	req := httptest.NewRequest(http.MethodPost, "/login/verify", strings.NewReader(`{"assertion":"ok"}`))
	req.AddCookie(&http.Cookie{Name: "arauth_session", Value: "browser-forged"})
	req.Header.Set("X-Arauth-Exchange-Key", "browser-key")
	rec := serve(s, req)
	after := time.Now()
	if rec.Code != http.StatusOK {
		t.Fatalf("login/verify 状态码 = %d，body=%s", rec.Code, rec.Body.String())
	}
	var loginBody map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &loginBody); err != nil {
		t.Fatalf("登录响应 JSON: %v", err)
	}
	if len(loginBody) != 2 || loginBody["status"] != "ok" || loginBody["backed_up"] != true {
		t.Errorf("登录下行 body = %v，want 仅 status/backed_up", loginBody)
	}
	if strings.Contains(rec.Body.String(), "exchange_code") || strings.Contains(rec.Body.String(), "one-time-code") {
		t.Error("exchange_code 或其值不得下行")
	}
	assertNoArauthCookie(t, rec)
	rpSession := responseCookie(t, rec, sessionCookieName)

	s.mu.Lock()
	entry, ok := s.sessions[rpSession.Value]
	s.mu.Unlock()
	if !ok {
		t.Fatal("登录后缺少服务端 rp_session 条目")
	}
	if entry.arauthToken != "login-fresh-token" {
		t.Errorf("服务端 fresh token = %q", entry.arauthToken)
	}
	if entry.freshUntil.Before(before.Add(freshTTL)) || entry.freshUntil.After(after.Add(freshTTL)) {
		t.Errorf("freshUntil = %s，want 登录后 15 分钟", entry.freshUntil)
	}

	whoami := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	whoami.AddCookie(&http.Cookie{Name: sessionCookieName, Value: rpSession.Value})
	whoRec := serve(s, whoami)
	if whoRec.Code != http.StatusOK {
		t.Fatalf("whoami 状态码 = %d", whoRec.Code)
	}
	var identity map[string]any
	if err := json.Unmarshal(whoRec.Body.Bytes(), &identity); err != nil {
		t.Fatalf("whoami JSON: %v", err)
	}
	if len(identity) != 2 || identity["user_handle"] != "dXNlcg" || identity["backed_up"] != true {
		t.Errorf("whoami 返回了额外字段或错误身份：%v", identity)
	}
	if strings.Contains(whoRec.Body.String(), "login-fresh-token") {
		t.Error("whoami 不得返回 arauth token")
	}
}

func TestRecoveryForwarding(t *testing.T) {
	for _, path := range []string{"/recovery/redeem", "/recovery/totp/redeem"} {
		t.Run(path, func(t *testing.T) {
			const body = `{"recovery_id":"rid","code":"123456","pow_challenge":"challenge","pow_nonce":"nonce"}`
			s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != path {
					t.Errorf("上游路径 = %q，want %q", r.URL.Path, path)
				}
				upstreamBody, _ := io.ReadAll(r.Body)
				if string(upstreamBody) != body {
					t.Errorf("上行 body = %q", upstreamBody)
				}
				if got := r.Header.Get("Cookie"); got != "" {
					t.Errorf("redeem 转发了 Cookie：%q", got)
				}
				if got := r.Header.Get("X-Arauth-Exchange-Key"); got != "" {
					t.Errorf("redeem 转发了 exchange key：%q", got)
				}
				if got := r.Header.Get("X-Arauth-Recovery-Token"); got != "" {
					t.Errorf("redeem 不应带 recovery token：%q", got)
				}
				_, _ = w.Write([]byte(`{"recovery_token":"server-token"}`))
			})
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.AddCookie(&http.Cookie{Name: "arauth_session", Value: "browser-forged"})
			req.Header.Set("X-Arauth-Exchange-Key", "browser-key")
			req.Header.Set("X-Arauth-Recovery-Token", "not-for-this-endpoint")
			rec := serve(s, req)
			if rec.Code != http.StatusOK || rec.Body.String() != `{"recovery_token":"server-token"}` {
				t.Fatalf("响应 = %d %q", rec.Code, rec.Body.String())
			}
		})
	}

	for _, path := range []string{"/recovery/options", "/recovery/verify"} {
		t.Run(path, func(t *testing.T) {
			const body = `{"recovery":"body"}`
			s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				upstreamBody, _ := io.ReadAll(r.Body)
				if string(upstreamBody) != body {
					t.Errorf("上行 body = %q", upstreamBody)
				}
				if got := r.Header.Get("X-Arauth-Recovery-Token"); got != "browser-recovery-token" {
					t.Errorf("recovery token = %q", got)
				}
				for _, header := range []string{"Cookie", "X-Arauth-Exchange-Key", "Authorization", "X-Custom"} {
					if got := r.Header.Get(header); got != "" {
						t.Errorf("非白名单头 %s 被转发：%q", header, got)
					}
				}
				w.Header().Set("Set-Cookie", "arauth_session=secret; Path=/")
				w.Header().Set("X-Upstream-Secret", "secret")
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("X-Arauth-Recovery-Token", "browser-recovery-token")
			req.Header.Set("X-Arauth-Exchange-Key", "browser-key")
			req.Header.Set("Authorization", "Bearer browser-token")
			req.Header.Set("X-Custom", "do-not-forward")
			req.AddCookie(&http.Cookie{Name: "arauth_session", Value: "browser-forged"})
			rec := serve(s, req)
			if rec.Code != http.StatusOK || rec.Body.String() != `{"status":"ok"}` {
				t.Fatalf("响应 = %d %q", rec.Code, rec.Body.String())
			}
			assertNoArauthCookie(t, rec)
			if got := rec.Header().Get("X-Upstream-Secret"); got != "" {
				t.Errorf("非白名单响应头被透传：%q", got)
			}
		})
	}
}

func TestRelayPreservesOnlyRetryAfter(t *testing.T) {
	s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "23")
		w.Header().Set("Set-Cookie", "arauth_session=secret; Path=/")
		w.Header().Set("X-Upstream-Secret", "secret")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limited"}`))
	})
	req := httptest.NewRequest(http.MethodPost, "/recovery/totp/redeem", strings.NewReader(`{}`))
	rec := serve(s, req)
	if rec.Code != http.StatusTooManyRequests || rec.Body.String() != `{"error":"rate limited"}` {
		t.Fatalf("响应 = %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "23" {
		t.Errorf("Retry-After = %q，want 23", got)
	}
	assertNoArauthCookie(t, rec)
	if got := rec.Header().Get("X-Upstream-Secret"); got != "" {
		t.Errorf("非白名单响应头被透传：%q", got)
	}
}

func TestClientIPForwarded(t *testing.T) {
	tests := []struct {
		name       string
		trustProxy bool
		remoteAddr string
		xff        []string
		want       string
	}{
		{name: "默认忽略入站 XFF", remoteAddr: "192.0.2.10:1234", xff: []string{"198.51.100.1, 203.0.113.1"}, want: "192.0.2.10"},
		{name: "信任代理取所有头末项", trustProxy: true, remoteAddr: "192.0.2.10:1234", xff: []string{"198.51.100.1, 198.51.100.2", "203.0.113.8"}, want: "203.0.113.8"},
		{name: "信任代理缺头回退 RemoteAddr", trustProxy: true, remoteAddr: "192.0.2.20:1234", want: "192.0.2.20"},
		{name: "末项为空回退 RemoteAddr", trustProxy: true, remoteAddr: "192.0.2.30:1234", xff: []string{"203.0.113.8, "}, want: "192.0.2.30"},
		{name: "RemoteAddr 无端口保留原值", remoteAddr: "192.0.2.40", want: "192.0.2.40"},
		{name: "RemoteAddr IPv6 取 host", remoteAddr: "[2001:db8::1]:1234", want: "2001:db8::1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				values := r.Header.Values("X-Forwarded-For")
				if len(values) != 1 || values[0] != tc.want {
					t.Errorf("上行 XFF = %v，want 单值 %q", values, tc.want)
				}
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})
			s.cfg.trustProxyHeaders = tc.trustProxy
			req := httptest.NewRequest(http.MethodGet, "/pow/challenge", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != nil {
				req.Header["X-Forwarded-For"] = tc.xff
			}
			if rec := serve(s, req); rec.Code != http.StatusOK {
				t.Fatalf("状态码 = %d，body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHealthChecksArauth(t *testing.T) {
	t.Run("上游 200", func(t *testing.T) {
		s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/health" {
				t.Errorf("上游请求 = %s %s", r.Method, r.URL.Path)
			}
			if got := r.Header.Get("Cookie"); got != "" {
				t.Errorf("health 转发了 Cookie：%q", got)
			}
			w.Header().Set("Set-Cookie", "arauth_session=secret; Path=/")
			_, _ = w.Write([]byte(`{"status":"upstream"}`))
		})
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.AddCookie(&http.Cookie{Name: "arauth_session", Value: "browser-forged"})
		rec := serve(s, req)
		if rec.Code != http.StatusOK || rec.Body.String() != "{\"status\":\"ok\"}\n" {
			t.Fatalf("health 响应 = %d %q", rec.Code, rec.Body.String())
		}
		assertNoArauthCookie(t, rec)
	})

	t.Run("上游非 200", func(t *testing.T) {
		s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		})
		rec := serve(s, httptest.NewRequest(http.MethodGet, "/health", nil))
		if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "{\"error\":\"unhealthy\"}\n" {
			t.Fatalf("health 响应 = %d %q，want 503", rec.Code, rec.Body.String())
		}
	})

	t.Run("上游网络失败", func(t *testing.T) {
		s := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {})
		s.cfg.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("upstream down")
		})}
		rec := serve(s, httptest.NewRequest(http.MethodGet, "/health", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("health 状态码 = %d，want 503", rec.Code)
		}
	})
}

func TestLoadConfigTrustProxyHeaders(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    bool
		wantErr bool
	}{
		{name: "默认关闭"},
		{name: "显式开启", raw: "true", want: true},
		{name: "显式关闭", raw: "false", want: false},
		{name: "非法值", raw: "maybe", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RP_ARAUTH_URL", "https://arauth.example.com")
			t.Setenv("RP_EXCHANGE_API_KEY", "server-secret")
			t.Setenv("RP_ID", "example.com")
			t.Setenv("RP_ORIGINS", "https://example.com")
			t.Setenv("RP_COOKIE_SECURE", "false")
			t.Setenv("RP_ARAUTH_CA_FILE", "")
			t.Setenv("RP_TRUST_PROXY_HEADERS", tc.raw)
			cfg, err := loadConfig()
			if tc.wantErr {
				if err == nil {
					t.Fatal("非法 RP_TRUST_PROXY_HEADERS 应报错")
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if cfg.trustProxyHeaders != tc.want {
				t.Errorf("trustProxyHeaders = %v，want %v", cfg.trustProxyHeaders, tc.want)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
