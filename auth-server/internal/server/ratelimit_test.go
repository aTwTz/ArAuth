package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/ratelimit"
)

// TestRateLimitStrictTierTriggers 严格档突发耗尽后 429 + Retry-After，
// 同压测下宽松档登录端点不受影响（验收标准第 1 条）。
func TestRateLimitStrictTierTriggers(t *testing.T) {
	cfg := &config.Config{
		RateStrictRPS:     0.001, // 几乎不回填：耗尽即长期拒绝
		RateStrictBurst:   2,
		RateLenientRPS:    100,
		RateLenientBurst:  100,
		PoWDifficulty:     21,
		PoWMinDifficulty:  18,
		PoWMaxDifficulty:  24,
		PoWAdaptiveWindow: 50,
		PoWAdaptiveUp:     0.5,
		PoWAdaptiveDown:   0.1,
	}
	srv := httptest.NewServer(New(cfg, &stubRegistrar{}, &stubGate{ok: true}, &stubLogin{assertion: &protocol.CredentialAssertion{}}, &stubSession{}, &stubRedeemer{},
		ratelimit.NewLimiter(cfg), ratelimit.NewAdaptive(cfg)))
	defer srv.Close()

	body := bytes.NewReader
	post := func(path string) *http.Response {
		resp, err := http.Post(srv.URL+path, "application/json", body([]byte(`{}`)))
		if err != nil {
			t.Fatalf("POST %s 失败: %v", path, err)
		}
		return resp
	}

	// 严格档突发 2：/register/options 第 3 次起 429 且带 Retry-After。
	var last *http.Response
	for i := 0; i < 3; i++ {
		last = post("/register/options")
		_ = last.Body.Close()
	}
	if last.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("突发耗尽后状态码 = %d，期望 429", last.StatusCode)
	}
	if last.Header.Get("Retry-After") == "" {
		t.Fatal("429 响应缺少 Retry-After 头")
	}

	// 登录端点（宽松档）在同源 IP 同压测下照常服务。
	resp := post("/login/options")
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Fatal("登录端点不应被严格档压力误伤")
	}
}

// TestRateLimitBlocksBeforeHandler 限流拒绝时不触达下游 handler。
func TestRateLimitBlocksBeforeHandler(t *testing.T) {
	reg := &stubRegistrar{}
	rl := &stubLimiter{block: true, retryAfter: 2 * time.Second}
	srv := httptest.NewServer(New(&config.Config{}, reg, &stubGate{ok: true}, &stubLogin{}, &stubSession{}, &stubRedeemer{},
		rl, &stubRecorder{}))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/register/options", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("POST 失败: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("状态码 = %d，期望 429", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After = %q，期望 2", got)
	}
	if reg.beginCalls != 0 {
		t.Error("限流拒绝不应触达 Registrar")
	}
	if rl.lastTier != ratelimit.TierStrict {
		t.Errorf("/register/options 命中档位 = %v，期望严格档", rl.lastTier)
	}
}

// TestAdaptiveRecordsPoWOutcome 各 PoW 门的验证成败如实喂给自适应
// 控制器（验收标准第 2 条的信号通路）。
func TestAdaptiveRecordsPoWOutcome(t *testing.T) {
	rec := &stubRecorder{}
	srv := httptest.NewServer(New(&config.Config{}, &stubRegistrar{creation: &protocol.CredentialCreation{}}, &stubGate{ok: true}, &stubLogin{}, &stubSession{}, &stubRedeemer{},
		&stubLimiter{}, rec))
	defer srv.Close()

	body := []byte(`{"pow_challenge":"YQ","pow_nonce":"Yg"}`)
	resp, err := http.Post(srv.URL+"/register/options", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST 失败: %v", err)
	}
	_ = resp.Body.Close()
	if len(rec.oks) != 1 || !rec.oks[0] {
		t.Fatalf("验过的 PoW 应记录成功，得到 %v", rec.oks)
	}

	// gate 拒绝时记录失败。
	rec2 := &stubRecorder{}
	srv2 := httptest.NewServer(New(&config.Config{}, &stubRegistrar{}, &stubGate{ok: false}, &stubLogin{}, &stubSession{}, &stubRedeemer{},
		&stubLimiter{}, rec2))
	defer srv2.Close()
	resp, err = http.Post(srv2.URL+"/register/options", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST 失败: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("坏解状态码 = %d，期望 429", resp.StatusCode)
	}
	if len(rec2.oks) != 1 || rec2.oks[0] {
		t.Fatalf("坏解应记录失败，得到 %v", rec2.oks)
	}
}

// TestClientIP 可信代理头开关下的客户端 IP 提取：开关关闭一律
// RemoteAddr；开启时取 X-Forwarded-For 末项（可信 service-server 已把
// 有效客户端地址重写为单值），header 缺失/末项为空回退 RemoteAddr。
func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		trustProxy bool
		remoteAddr string
		xff        string // 空 = 不设置 header
		want       string
	}{
		{"开关关闭忽略 XFF", false, "10.0.0.1:1234", "1.2.3.4", "10.0.0.1"},
		{"开启但 header 缺失回退 RemoteAddr", true, "10.0.0.1:1234", "", "10.0.0.1"},
		{"多跳取末项", true, "10.0.0.1:1234", "1.1.1.1, 2.2.2.2, 3.3.3.3", "3.3.3.3"},
		{"伪造前缀取末项真实值", true, "10.0.0.1:1234", "6.6.6.6, 5.6.7.8", "5.6.7.8"},
		{"单值", true, "10.0.0.1:1234", "5.6.7.8", "5.6.7.8"},
		{"带空格", true, "10.0.0.1:1234", "  1.1.1.1 ,  2.2.2.2 ", "2.2.2.2"},
		{"末项为空回退 RemoteAddr", true, "10.0.0.1:1234", "1.1.1.1, ", "10.0.0.1"},
		{"RemoteAddr 无端口原样返回", false, "10.0.0.1", "", "10.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				// 小写 header 名验证 canonical 化（大小写变体）。
				r.Header["X-Forwarded-For"] = []string{tc.xff}
			}
			if got := clientIP(r, tc.trustProxy); got != tc.want {
				t.Errorf("clientIP() = %q，期望 %q", got, tc.want)
			}
		})
	}
}
