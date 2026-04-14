package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "example.com")
	t.Setenv("ARAUTH_RP_ORIGINS", "https://a.example.com, https://b.example.com")
	t.Setenv("ARAUTH_EXCHANGE_API_KEY", "test-key")
	t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.Addr != ":8080" {
		t.Errorf("Addr = %q，期望 :8080", c.Addr)
	}
	if c.PoWDifficulty != 21 {
		t.Errorf("PoWDifficulty = %d，期望 21", c.PoWDifficulty)
	}
	if len(c.RPOrigins) != 2 || c.RPOrigins[0] != "https://a.example.com" || c.RPOrigins[1] != "https://b.example.com" {
		t.Errorf("RPOrigins = %v，解析不符预期", c.RPOrigins)
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "example.com")
	t.Setenv("ARAUTH_RP_ORIGINS", "https://a.example.com")
	t.Setenv("ARAUTH_EXCHANGE_API_KEY", "test-key")
	t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	t.Setenv("ARAUTH_ADDR", ":9090")
	t.Setenv("ARAUTH_POW_DIFFICULTY", "22") // 须落在自适应区间 [18,24] 内

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.Addr != ":9090" {
		t.Errorf("Addr = %q，期望 :9090", c.Addr)
	}
	if c.PoWDifficulty != 22 {
		t.Errorf("PoWDifficulty = %d，期望 22", c.PoWDifficulty)
	}
}

func TestLoadRateLimitDefaults(t *testing.T) {
	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "example.com")
	t.Setenv("ARAUTH_RP_ORIGINS", "https://a.example.com")
	t.Setenv("ARAUTH_EXCHANGE_API_KEY", "test-key")
	t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.RateStrictRPS != 1.0 || c.RateStrictBurst != 8 {
		t.Errorf("严格档默认 = %v/%d，期望 1.0/8", c.RateStrictRPS, c.RateStrictBurst)
	}
	if c.RateLenientRPS != 4.0 || c.RateLenientBurst != 16 {
		t.Errorf("宽松档默认 = %v/%d，期望 4.0/16", c.RateLenientRPS, c.RateLenientBurst)
	}
	if c.PoWMinDifficulty != 18 || c.PoWMaxDifficulty != 24 {
		t.Errorf("难度区间默认 = %d–%d，期望 18–24", c.PoWMinDifficulty, c.PoWMaxDifficulty)
	}
	if c.PoWAdaptiveWindow != 50 || c.PoWAdaptiveUp != 0.5 || c.PoWAdaptiveDown != 0.1 {
		t.Errorf("自适应默认 = 窗口%d/升%v/降%v，期望 50/0.5/0.1",
			c.PoWAdaptiveWindow, c.PoWAdaptiveUp, c.PoWAdaptiveDown)
	}
	if c.AttestationStrict {
		t.Error("AttestationStrict 默认应为 false")
	}

	t.Setenv("ARAUTH_RATE_STRICT_RPS", "0.2")
	t.Setenv("ARAUTH_RATE_STRICT_BURST", "3")
	t.Setenv("ARAUTH_POW_MIN_DIFFICULTY", "16")
	t.Setenv("ARAUTH_POW_MAX_DIFFICULTY", "28")
	t.Setenv("ARAUTH_POW_ADAPTIVE_WINDOW", "10")
	t.Setenv("ARAUTH_POW_ADAPTIVE_UP", "0.6")
	t.Setenv("ARAUTH_POW_ADAPTIVE_DOWN", "0.05")
	t.Setenv("ARAUTH_ATTESTATION_STRICT", "true")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.RateStrictRPS != 0.2 || c.RateStrictBurst != 3 {
		t.Errorf("严格档 = %v/%d，期望 0.2/3", c.RateStrictRPS, c.RateStrictBurst)
	}
	if c.PoWMinDifficulty != 16 || c.PoWMaxDifficulty != 28 {
		t.Errorf("难度区间 = %d–%d，期望 16–28", c.PoWMinDifficulty, c.PoWMaxDifficulty)
	}
	if c.PoWAdaptiveWindow != 10 || c.PoWAdaptiveUp != 0.6 || c.PoWAdaptiveDown != 0.05 {
		t.Errorf("自适应 = 窗口%d/升%v/降%v，期望 10/0.6/0.05",
			c.PoWAdaptiveWindow, c.PoWAdaptiveUp, c.PoWAdaptiveDown)
	}
	if !c.AttestationStrict {
		t.Error("AttestationStrict = false，期望 true")
	}
}

func TestLoadAdaptiveValidation(t *testing.T) {
	base := func() {
		t.Setenv("ARAUTH_DSN", "postgres://example")
		t.Setenv("ARAUTH_RPID", "example.com")
		t.Setenv("ARAUTH_RP_ORIGINS", "https://a.example.com")
		t.Setenv("ARAUTH_EXCHANGE_API_KEY", "test-key")
		t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	}

	// 初始难度落在区间之外（高于上限）。
	base()
	t.Setenv("ARAUTH_POW_DIFFICULTY", "25")
	if _, err := Load(); err == nil {
		t.Fatal("初始难度高于上限应报错")
	}

	// 降挡阈值不低于升挡阈值（无迟滞）。
	base()
	t.Setenv("ARAUTH_POW_ADAPTIVE_UP", "0.3")
	t.Setenv("ARAUTH_POW_ADAPTIVE_DOWN", "0.5")
	if _, err := Load(); err == nil {
		t.Fatal("down ≥ up 应报错")
	}

	// 阈值越界（≥1）。
	base()
	t.Setenv("ARAUTH_POW_ADAPTIVE_UP", "1.5")
	if _, err := Load(); err == nil {
		t.Fatal("up ≥ 1 应报错")
	}

	// 非正窗口。
	base()
	t.Setenv("ARAUTH_POW_ADAPTIVE_WINDOW", "0")
	if _, err := Load(); err == nil {
		t.Fatal("非正窗口应报错")
	}

	// 非正限流参数。
	base()
	t.Setenv("ARAUTH_RATE_STRICT_RPS", "0")
	if _, err := Load(); err == nil {
		t.Fatal("非正限流速率应报错")
	}

	// 非法布尔。
	base()
	t.Setenv("ARAUTH_ATTESTATION_STRICT", "maybe")
	if _, err := Load(); err == nil {
		t.Fatal("非法 AttestationStrict 应报错")
	}
}

func TestLoadMissingRequired(t *testing.T) {
	if _, err := Load(); err == nil {
		t.Fatal("必填项全缺时 Load() 应报错")
	}

	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "example.com")
	if _, err := Load(); err == nil {
		t.Fatal("缺 ARAUTH_RP_ORIGINS 时 Load() 应报错")
	}
}

func TestLoadBadDifficulty(t *testing.T) {
	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "example.com")
	t.Setenv("ARAUTH_RP_ORIGINS", "https://a.example.com")
	t.Setenv("ARAUTH_EXCHANGE_API_KEY", "test-key")
	t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	t.Setenv("ARAUTH_POW_DIFFICULTY", "-3")

	if _, err := Load(); err == nil {
		t.Fatal("非法 PoW 难度应报错")
	}
}

func TestLoadChallengeTTL(t *testing.T) {
	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "example.com")
	t.Setenv("ARAUTH_RP_ORIGINS", "https://a.example.com")
	t.Setenv("ARAUTH_EXCHANGE_API_KEY", "test-key")
	t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.ChallengeTTL != 300*time.Second {
		t.Errorf("ChallengeTTL 默认 = %v，期望 5m", c.ChallengeTTL)
	}

	t.Setenv("ARAUTH_CHALLENGE_TTL", "60")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.ChallengeTTL != time.Minute {
		t.Errorf("ChallengeTTL = %v，期望 1m", c.ChallengeTTL)
	}

	t.Setenv("ARAUTH_CHALLENGE_TTL", "0")
	if _, err := Load(); err == nil {
		t.Fatal("非正数 TTL 应报错")
	}
}

func TestLoadPoWChallengeTTL(t *testing.T) {
	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "example.com")
	t.Setenv("ARAUTH_RP_ORIGINS", "https://a.example.com")
	t.Setenv("ARAUTH_EXCHANGE_API_KEY", "test-key")
	t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.PoWChallengeTTL != 300*time.Second {
		t.Errorf("PoWChallengeTTL 默认 = %v，期望 5m", c.PoWChallengeTTL)
	}

	t.Setenv("ARAUTH_POW_CHALLENGE_TTL", "120")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.PoWChallengeTTL != 2*time.Minute {
		t.Errorf("PoWChallengeTTL = %v，期望 2m", c.PoWChallengeTTL)
	}

	t.Setenv("ARAUTH_POW_CHALLENGE_TTL", "abc")
	if _, err := Load(); err == nil {
		t.Fatal("非整数 TTL 应报错")
	}
}

func TestLoadRejectsServiceSubdomainRPID(t *testing.T) {
	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "arauth.example.com")
	t.Setenv("ARAUTH_RP_ORIGINS", "https://arauth.example.com")
	t.Setenv("ARAUTH_EXCHANGE_API_KEY", "test-key")
	t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	if _, err := Load(); err == nil {
		t.Fatal("arauth. 子域 rp.id 应被拒绝")
	}
}

func TestLoadSessionAndExchange(t *testing.T) {
	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "example.com")
	t.Setenv("ARAUTH_RP_ORIGINS", "https://a.example.com")
	t.Setenv("ARAUTH_EXCHANGE_API_KEY", "test-key")
	t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.SessionTTL != 14*24*time.Hour {
		t.Errorf("SessionTTL 默认 = %v，期望 14 天", c.SessionTTL)
	}
	if c.ExchangeCodeTTL != 300*time.Second {
		t.Errorf("ExchangeCodeTTL 默认 = %v，期望 5m", c.ExchangeCodeTTL)
	}
	if !c.SessionCookieSecure {
		t.Error("SessionCookieSecure 默认应为 true")
	}

	t.Setenv("ARAUTH_SESSION_TTL", "3600")
	t.Setenv("ARAUTH_EXCHANGE_CODE_TTL", "60")
	t.Setenv("ARAUTH_SESSION_COOKIE_SECURE", "false")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.SessionTTL != time.Hour {
		t.Errorf("SessionTTL = %v，期望 1h", c.SessionTTL)
	}
	if c.ExchangeCodeTTL != time.Minute {
		t.Errorf("ExchangeCodeTTL = %v，期望 1m", c.ExchangeCodeTTL)
	}
	if c.SessionCookieSecure {
		t.Error("SessionCookieSecure = true，期望 false（开发豁免）")
	}

	t.Setenv("ARAUTH_SESSION_COOKIE_SECURE", "maybe")
	if _, err := Load(); err == nil {
		t.Fatal("非法布尔值应报错")
	}
	t.Setenv("ARAUTH_SESSION_TTL", "0")
	if _, err := Load(); err == nil {
		t.Fatal("非正数 SessionTTL 应报错")
	}
}

func TestLoadMissingExchangeAPIKey(t *testing.T) {
	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "example.com")
	t.Setenv("ARAUTH_RP_ORIGINS", "https://a.example.com")

	if _, err := Load(); err == nil {
		t.Fatal("缺 ARAUTH_EXCHANGE_API_KEY 时 Load() 应报错")
	}
}

func TestLoadTOTP(t *testing.T) {
	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "example.com")
	t.Setenv("ARAUTH_RP_ORIGINS", "https://a.example.com")
	t.Setenv("ARAUTH_EXCHANGE_API_KEY", "test-key")
	t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if len(c.TOTPEncryptionKey) != 32 || c.TOTPKeyVersion != 1 || c.TOTPIssuer != "arauth" {
		t.Errorf("TOTP 密钥默认值异常: key=%d bytes, version=%d, issuer=%q", len(c.TOTPEncryptionKey), c.TOTPKeyVersion, c.TOTPIssuer)
	}
	if c.TOTPSetupTTL != 5*time.Minute || c.TOTPFreshSessionTTL != 15*time.Minute ||
		c.TOTPFailureWindow != 5*time.Minute || c.TOTPMaxFailures != 5 {
		t.Errorf("TOTP 默认窗口异常: setup=%v fresh=%v failure=%v max=%d",
			c.TOTPSetupTTL, c.TOTPFreshSessionTTL, c.TOTPFailureWindow, c.TOTPMaxFailures)
	}

	t.Setenv("ARAUTH_TOTP_KEY_VERSION", "2")
	t.Setenv("ARAUTH_TOTP_ISSUER", "example")
	t.Setenv("ARAUTH_TOTP_SETUP_TTL", "60")
	t.Setenv("ARAUTH_TOTP_FRESH_SESSION_TTL", "120")
	t.Setenv("ARAUTH_TOTP_FAILURE_WINDOW", "180")
	t.Setenv("ARAUTH_TOTP_MAX_FAILURES", "7")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load() 覆盖 TOTP 配置失败: %v", err)
	}
	if c.TOTPKeyVersion != 2 || c.TOTPIssuer != "example" || c.TOTPSetupTTL != time.Minute ||
		c.TOTPFreshSessionTTL != 2*time.Minute || c.TOTPFailureWindow != 3*time.Minute || c.TOTPMaxFailures != 7 {
		t.Error("TOTP 环境变量覆盖未生效")
	}

	for name, key := range map[string]string{
		"缺失":       "",
		"非 base64": "%%%",
		"长度不足":     "MDEyMzQ1Njc4OWFiY2RlZg==",
		"全零":       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", key)
			if _, err := Load(); err == nil {
				t.Fatal("非法 TOTP 主密钥应报错")
			}
		})
	}
}

func TestLoadRecoveryAndPendingTTL(t *testing.T) {
	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "example.com")
	t.Setenv("ARAUTH_RP_ORIGINS", "https://a.example.com")
	t.Setenv("ARAUTH_EXCHANGE_API_KEY", "test-key")
	t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.RecoveryTokenTTL != 300*time.Second {
		t.Errorf("RecoveryTokenTTL 默认 = %v，期望 5m", c.RecoveryTokenTTL)
	}
	if c.PendingTTL != 24*time.Hour {
		t.Errorf("PendingTTL 默认 = %v，期望 24h", c.PendingTTL)
	}

	t.Setenv("ARAUTH_RECOVERY_TOKEN_TTL", "120")
	t.Setenv("ARAUTH_PENDING_TTL", "3600")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.RecoveryTokenTTL != 2*time.Minute {
		t.Errorf("RecoveryTokenTTL = %v，期望 2m", c.RecoveryTokenTTL)
	}
	if c.PendingTTL != time.Hour {
		t.Errorf("PendingTTL = %v，期望 1h", c.PendingTTL)
	}

	t.Setenv("ARAUTH_RECOVERY_TOKEN_TTL", "-1")
	if _, err := Load(); err == nil {
		t.Fatal("非正数 RecoveryTokenTTL 应报错")
	}
	t.Setenv("ARAUTH_RECOVERY_TOKEN_TTL", "120")
	t.Setenv("ARAUTH_PENDING_TTL", "abc")
	if _, err := Load(); err == nil {
		t.Fatal("非整数 PendingTTL 应报错")
	}
}

func TestLoadTrustProxyHeaders(t *testing.T) {
	t.Setenv("ARAUTH_DSN", "postgres://example")
	t.Setenv("ARAUTH_RPID", "example.com")
	t.Setenv("ARAUTH_RP_ORIGINS", "https://a.example.com")
	t.Setenv("ARAUTH_EXCHANGE_API_KEY", "test-key")
	t.Setenv("ARAUTH_TOTP_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.TrustProxyHeaders {
		t.Error("TrustProxyHeaders 默认应为 false（直连形态，不信任何代理头）")
	}

	t.Setenv("ARAUTH_TRUST_PROXY_HEADERS", "true")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if !c.TrustProxyHeaders {
		t.Error("ARAUTH_TRUST_PROXY_HEADERS=true 应打开开关")
	}

	t.Setenv("ARAUTH_TRUST_PROXY_HEADERS", "0")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load() 意外报错: %v", err)
	}
	if c.TrustProxyHeaders {
		t.Error("ARAUTH_TRUST_PROXY_HEADERS=0 应关闭开关")
	}

	t.Setenv("ARAUTH_TRUST_PROXY_HEADERS", "maybe")
	if _, err := Load(); err == nil {
		t.Fatal("非法布尔值应报错")
	}
}
