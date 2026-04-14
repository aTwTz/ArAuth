// Package config 集中全部可调数值，从 ARAUTH_ 前缀环境变量加载。
// 业务代码与 handler 中禁止出现字面量，一律经本包下发。
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// 默认值。仅"有安全默认值"的字段允许省略；身份类字段（DSN/RPID/RPOrigins）
// 为必填，缺失即报错，绝不静默顶替（RP ID 纪律见 docs/DESIGN.md 第 8 节）。
const (
	defaultAddr          = ":8080"
	defaultPoWDifficulty = 21
	// defaultChallengeTTLSeconds 是 WebAuthn ceremony challenge 的内存暂存
	// 时长（一次性，过期即失效），见 docs/DESIGN.md 第 4 节注册流程。
	defaultChallengeTTLSeconds = 300
	// defaultPoWChallengeTTLSeconds 是 PoW challenge 的内存存活时长
	// （一次性，验一次即作废），见 docs/DESIGN.md 第 6 节。
	defaultPoWChallengeTTLSeconds = 300
	// defaultSessionTTLSeconds 是 opaque token 会话的存活时长（14 天），
	// 服务器只存 SHA-256，可吊销，见 docs/DESIGN.md 第 7 节。
	defaultSessionTTLSeconds = 14 * 24 * 3600
	// defaultExchangeCodeTTLSeconds 是一次性 exchange code 的存活时长
	// （5 分钟），见 docs/DESIGN.md 第 7 节。
	defaultExchangeCodeTTLSeconds = 300
	// defaultRecoveryTokenTTLSeconds 是恢复凭证（一次性 token）的存活
	// 时长（5 分钟），唯一权限是把新凭据挂到原 user_handle，
	// 见 docs/DESIGN.md 第 4 节找回流程。
	defaultRecoveryTokenTTLSeconds = 300
	// defaultPendingTTLSeconds 是 pending identity 等待恢复码确认的
	// 宽限（24 小时），超时不得再确认激活，见 docs/DESIGN.md 第 4 节。
	defaultPendingTTLSeconds = 24 * 3600
	// TOTP setup 是短期一次性流程；绑定管理只接受刚通过 WebAuthn 的会话。
	defaultTOTPSetupTTLSeconds        = 300
	defaultTOTPFreshSessionTTLSeconds = 900
	// 按 recovery_id 的失败窗口，和 per-IP 限流/PoW 共同限制在线猜测。
	defaultTOTPFailureWindowSeconds = 300
	defaultTOTPMaxFailures          = 5
	defaultTOTPIssuer               = "arauth"
	defaultTOTPKeyVersion           = 1
	// 严格档限流默认值：注册系、恢复兑换、exchange、PoW challenge 领取。
	defaultRateStrictRPS   = 1.0
	defaultRateStrictBurst = 8
	// 宽松档限流默认值：登录端点（正常用户也频繁触发，且登录禁止挂 PoW，
	// 限流是唯一防线，DESIGN.md 第 6 节）。
	defaultRateLenientRPS   = 4.0
	defaultRateLenientBurst = 16
	// PoW 自适应难度上下限（默认 18–24，初始值仍取
	// ARAUTH_POW_DIFFICULTY）。
	defaultPoWMinDifficulty = 18
	defaultPoWMaxDifficulty = 24
	// 自适应评估窗口：每集满 50 个 PoW 验证结果评估一次升/降挡。
	defaultPoWAdaptiveWindow = 50
	// 升/降挡失败率阈值（升挡阈值必须高于降挡阈值，形成迟滞）。
	defaultPoWAdaptiveUp   = 0.5
	defaultPoWAdaptiveDown = 0.1
)

// Config 是进程全部可调配置的载体。
type Config struct {
	// Addr 是 HTTP 监听地址，默认 ":8080"。
	Addr string
	// DSN 是 Postgres 连接串（必填，服务器机密）。
	DSN string
	// RPID 是 WebAuthn rp.id，必须为父域，显式配置，必填。
	RPID string
	// RPOrigins 是允许的 origin 白名单（必填，逗号分隔，禁止通配）。
	RPOrigins []string
	// PoWDifficulty 是 PoW 前缀零位数，默认 21。
	PoWDifficulty int
	// ChallengeTTL 是 WebAuthn ceremony challenge 的内存暂存时长，
	// 默认 300 秒（5 分钟），一次性消费。
	ChallengeTTL time.Duration
	// PoWChallengeTTL 是 PoW challenge 的内存存活时长，默认 300 秒
	// （5 分钟），一次性（验一次即作废，不论对错）。
	PoWChallengeTTL time.Duration
	// SessionTTL 是 opaque token 会话的存活时长，默认 14 天。
	SessionTTL time.Duration
	// ExchangeCodeTTL 是一次性 exchange code 的存活时长，默认 300 秒。
	ExchangeCodeTTL time.Duration
	// RecoveryTokenTTL 是恢复凭证（一次性 token）的存活时长，
	// 默认 300 秒，一次性消费。
	RecoveryTokenTTL time.Duration
	// PendingTTL 是 pending identity 等待恢复码确认的宽限，
	// 默认 24 小时，超时不得再确认激活。
	PendingTTL time.Duration
	// ExchangeAPIKey 是依赖方后端调 POST /exchange 的共享密钥
	// （必填，服务器机密，只与 header 做常量时间比对，绝不外发）。
	ExchangeAPIKey string
	// SessionCookieSecure 控制会话 cookie 的 Secure 属性，默认 true；
	// 仅本地开发（HTTP）允许关闭，生产必须为 true（DESIGN.md 第 8 节
	// 硬前提：HTTPS）。
	SessionCookieSecure bool
	// TOTPEncryptionKey 是 32 字节 AES-GCM 主密钥（必填，库外注入）。
	TOTPEncryptionKey []byte
	// TOTPKeyVersion 随密文落库，用于识别密钥版本；当前只配置一个活跃版本。
	TOTPKeyVersion int
	// TOTPIssuer 是 otpauth URI 中的发行方显示名。
	TOTPIssuer string
	// TOTPSetupTTL 是绑定 setup token 的内存存活时长，默认 5 分钟。
	TOTPSetupTTL time.Duration
	// TOTPFreshSessionTTL 限定 WebAuthn 会话可用于绑定管理的新鲜窗口。
	TOTPFreshSessionTTL time.Duration
	// TOTPFailureWindow / TOTPMaxFailures 是按 recovery_id 的失败节流。
	TOTPFailureWindow time.Duration
	TOTPMaxFailures   int
	// RateStrictRPS / RateStrictBurst 是严格档 per-IP 限流（注册系、
	// 恢复兑换、exchange、PoW challenge 领取），默认每秒 1 个、突发 8 个。
	RateStrictRPS   float64
	RateStrictBurst int
	// RateLenientRPS / RateLenientBurst 是宽松档 per-IP 限流（登录端点），
	// 默认每秒 4 个、突发 16 个。
	RateLenientRPS   float64
	RateLenientBurst int
	// PoWMinDifficulty / PoWMaxDifficulty 是 PoW 自适应难度的下/上限，
	// 默认 18–24；初始难度 PoWDifficulty 必须落在区间内。
	PoWMinDifficulty int
	PoWMaxDifficulty int
	// PoWAdaptiveWindow 是自适应评估窗口大小（每集满这么多个 PoW 验证
	// 结果评估一次升/降挡），默认 50。
	PoWAdaptiveWindow int
	// PoWAdaptiveUp / PoWAdaptiveDown 是升/降挡失败率阈值，默认 0.5/0.1，
	// 必须满足 0 < down < up < 1（迟滞，避免边界抖动）。
	PoWAdaptiveUp   float64
	PoWAdaptiveDown float64
	// AttestationStrict 是可选加固开关（默认关）：打开时注册只接受
	// attestation statement format 为 apple / android-key / packed
	// （带证书链），none 直接拒绝（BE=1 平台现实下默认不
	// 牺牲可用性，DESIGN.md 第 5 节）。
	AttestationStrict bool
	// TrustProxyHeaders 控制客户端 IP 的取法（per-IP 限流的唯一输入）：
	// 为 true 时取 X-Forwarded-For 最后一个条目；默认 false，取 RemoteAddr。
	// 安全不变量：此开关为 true 时，arauth 只能被会重写该头的可信
	// service-server 到达（生产 compose 中不发布端口）；一旦可被直连，
	// 攻击者即可伪造 XFF 任意换 IP 绕过限流。
	TrustProxyHeaders bool
}

// Load 从环境变量读取配置并校验必填项，缺失或不合法时返回错误。
func Load() (*Config, error) {
	c := &Config{
		Addr:                envOr("ARAUTH_ADDR", defaultAddr),
		DSN:                 os.Getenv("ARAUTH_DSN"),
		RPID:                os.Getenv("ARAUTH_RPID"),
		PoWDifficulty:       defaultPoWDifficulty,
		ChallengeTTL:        defaultChallengeTTLSeconds * time.Second,
		PoWChallengeTTL:     defaultPoWChallengeTTLSeconds * time.Second,
		SessionTTL:          defaultSessionTTLSeconds * time.Second,
		ExchangeCodeTTL:     defaultExchangeCodeTTLSeconds * time.Second,
		RecoveryTokenTTL:    defaultRecoveryTokenTTLSeconds * time.Second,
		PendingTTL:          defaultPendingTTLSeconds * time.Second,
		ExchangeAPIKey:      os.Getenv("ARAUTH_EXCHANGE_API_KEY"),
		SessionCookieSecure: true,
		TOTPKeyVersion:      defaultTOTPKeyVersion,
		TOTPIssuer:          envOr("ARAUTH_TOTP_ISSUER", defaultTOTPIssuer),
		TOTPSetupTTL:        defaultTOTPSetupTTLSeconds * time.Second,
		TOTPFreshSessionTTL: defaultTOTPFreshSessionTTLSeconds * time.Second,
		TOTPFailureWindow:   defaultTOTPFailureWindowSeconds * time.Second,
		TOTPMaxFailures:     defaultTOTPMaxFailures,
		RateStrictRPS:       defaultRateStrictRPS,
		RateStrictBurst:     defaultRateStrictBurst,
		RateLenientRPS:      defaultRateLenientRPS,
		RateLenientBurst:    defaultRateLenientBurst,
		PoWMinDifficulty:    defaultPoWMinDifficulty,
		PoWMaxDifficulty:    defaultPoWMaxDifficulty,
		PoWAdaptiveWindow:   defaultPoWAdaptiveWindow,
		PoWAdaptiveUp:       defaultPoWAdaptiveUp,
		PoWAdaptiveDown:     defaultPoWAdaptiveDown,
	}

	if raw := os.Getenv("ARAUTH_TOTP_ENCRYPTION_KEY"); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("config: ARAUTH_TOTP_ENCRYPTION_KEY 必须是 base64 编码的 32 字节密钥")
		}
		zero := true
		for _, b := range key {
			if b != 0 {
				zero = false
				break
			}
		}
		if zero {
			return nil, fmt.Errorf("config: ARAUTH_TOTP_ENCRYPTION_KEY 不得为全零密钥")
		}
		c.TOTPEncryptionKey = key
	}

	if raw := os.Getenv("ARAUTH_RP_ORIGINS"); raw != "" {
		for _, o := range strings.Split(raw, ",") {
			if o = strings.TrimSpace(o); o != "" {
				c.RPOrigins = append(c.RPOrigins, o)
			}
		}
	}

	if raw := os.Getenv("ARAUTH_POW_DIFFICULTY"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("config: ARAUTH_POW_DIFFICULTY 必须为正整数，得到 %q", raw)
		}
		c.PoWDifficulty = n
	}

	if raw := os.Getenv("ARAUTH_CHALLENGE_TTL"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("config: ARAUTH_CHALLENGE_TTL 必须为正整数秒，得到 %q", raw)
		}
		c.ChallengeTTL = time.Duration(n) * time.Second
	}

	if raw := os.Getenv("ARAUTH_POW_CHALLENGE_TTL"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("config: ARAUTH_POW_CHALLENGE_TTL 必须为正整数秒，得到 %q", raw)
		}
		c.PoWChallengeTTL = time.Duration(n) * time.Second
	}

	if raw := os.Getenv("ARAUTH_SESSION_TTL"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("config: ARAUTH_SESSION_TTL 必须为正整数秒，得到 %q", raw)
		}
		c.SessionTTL = time.Duration(n) * time.Second
	}

	if raw := os.Getenv("ARAUTH_EXCHANGE_CODE_TTL"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("config: ARAUTH_EXCHANGE_CODE_TTL 必须为正整数秒，得到 %q", raw)
		}
		c.ExchangeCodeTTL = time.Duration(n) * time.Second
	}

	if raw := os.Getenv("ARAUTH_RECOVERY_TOKEN_TTL"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("config: ARAUTH_RECOVERY_TOKEN_TTL 必须为正整数秒，得到 %q", raw)
		}
		c.RecoveryTokenTTL = time.Duration(n) * time.Second
	}

	if raw := os.Getenv("ARAUTH_PENDING_TTL"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("config: ARAUTH_PENDING_TTL 必须为正整数秒，得到 %q", raw)
		}
		c.PendingTTL = time.Duration(n) * time.Second
	}

	for _, item := range []struct {
		key string
		dst *time.Duration
	}{
		{"ARAUTH_TOTP_SETUP_TTL", &c.TOTPSetupTTL},
		{"ARAUTH_TOTP_FRESH_SESSION_TTL", &c.TOTPFreshSessionTTL},
		{"ARAUTH_TOTP_FAILURE_WINDOW", &c.TOTPFailureWindow},
	} {
		if raw := os.Getenv(item.key); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("config: %s 必须为正整数秒，得到 %q", item.key, raw)
			}
			*item.dst = time.Duration(n) * time.Second
		}
	}
	if err := envInt("ARAUTH_TOTP_KEY_VERSION", &c.TOTPKeyVersion); err != nil {
		return nil, err
	}
	if err := envInt("ARAUTH_TOTP_MAX_FAILURES", &c.TOTPMaxFailures); err != nil {
		return nil, err
	}

	if err := envBool("ARAUTH_SESSION_COOKIE_SECURE", &c.SessionCookieSecure); err != nil {
		return nil, err
	}

	if err := envBool("ARAUTH_ATTESTATION_STRICT", &c.AttestationStrict); err != nil {
		return nil, err
	}

	if err := envBool("ARAUTH_TRUST_PROXY_HEADERS", &c.TrustProxyHeaders); err != nil {
		return nil, err
	}

	if err := envFloat("ARAUTH_RATE_STRICT_RPS", &c.RateStrictRPS); err != nil {
		return nil, err
	}
	if err := envInt("ARAUTH_RATE_STRICT_BURST", &c.RateStrictBurst); err != nil {
		return nil, err
	}
	if err := envFloat("ARAUTH_RATE_LENIENT_RPS", &c.RateLenientRPS); err != nil {
		return nil, err
	}
	if err := envInt("ARAUTH_RATE_LENIENT_BURST", &c.RateLenientBurst); err != nil {
		return nil, err
	}
	if err := envInt("ARAUTH_POW_MIN_DIFFICULTY", &c.PoWMinDifficulty); err != nil {
		return nil, err
	}
	if err := envInt("ARAUTH_POW_MAX_DIFFICULTY", &c.PoWMaxDifficulty); err != nil {
		return nil, err
	}
	if err := envInt("ARAUTH_POW_ADAPTIVE_WINDOW", &c.PoWAdaptiveWindow); err != nil {
		return nil, err
	}
	if err := envFloat("ARAUTH_POW_ADAPTIVE_UP", &c.PoWAdaptiveUp); err != nil {
		return nil, err
	}
	if err := envFloat("ARAUTH_POW_ADAPTIVE_DOWN", &c.PoWAdaptiveDown); err != nil {
		return nil, err
	}
	if c.RateStrictRPS <= 0 || c.RateStrictBurst <= 0 ||
		c.RateLenientRPS <= 0 || c.RateLenientBurst <= 0 {
		return nil, fmt.Errorf("config: 限流速率与突发必须为正数（得到 strict %v/%d, lenient %v/%d）",
			c.RateStrictRPS, c.RateStrictBurst, c.RateLenientRPS, c.RateLenientBurst)
	}
	// 初始难度必须落在自适应区间内，否则升/降挡钳制会在首窗就把难度
	// 拽离显式配置值，违背"初始值仍 21"的约定。
	if c.PoWMinDifficulty > c.PoWDifficulty || c.PoWDifficulty > c.PoWMaxDifficulty {
		return nil, fmt.Errorf("config: PoW 难度区间非法：要求 min(%d) ≤ 初始(%d) ≤ max(%d)",
			c.PoWMinDifficulty, c.PoWDifficulty, c.PoWMaxDifficulty)
	}
	if c.PoWAdaptiveWindow <= 0 {
		return nil, fmt.Errorf("config: ARAUTH_POW_ADAPTIVE_WINDOW 必须为正整数，得到 %d", c.PoWAdaptiveWindow)
	}
	if !(0 < c.PoWAdaptiveDown && c.PoWAdaptiveDown < c.PoWAdaptiveUp && c.PoWAdaptiveUp < 1) {
		return nil, fmt.Errorf("config: 自适应阈值必须满足 0 < down(%v) < up(%v) < 1", c.PoWAdaptiveDown, c.PoWAdaptiveUp)
	}

	var missing []string
	if c.DSN == "" {
		missing = append(missing, "ARAUTH_DSN")
	}
	if c.RPID == "" {
		missing = append(missing, "ARAUTH_RPID")
	}
	if len(c.RPOrigins) == 0 {
		missing = append(missing, "ARAUTH_RP_ORIGINS")
	}
	if c.ExchangeAPIKey == "" {
		missing = append(missing, "ARAUTH_EXCHANGE_API_KEY")
	}
	if len(c.TOTPEncryptionKey) == 0 {
		missing = append(missing, "ARAUTH_TOTP_ENCRYPTION_KEY")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("config: 缺少必填环境变量: %s", strings.Join(missing, ", "))
	}

	// rp.id 注册时定型、哈希进凭据、终身不可改。绑到 arauth. 服务子域上
	// 等于全员重注册且无迁移路径，启动期直接拒绝（DESIGN.md 第 8 节）。
	if strings.HasPrefix(c.RPID, "arauth.") {
		return nil, fmt.Errorf("config: ARAUTH_RPID %q 不合法：rp.id 必须是父域，不得使用 arauth. 子域（凭据终身绑定 rp.id，设错无法迁移）", c.RPID)
	}

	return c, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envInt 在环境变量存在时解析为正整数并写入 *dst；不存在保持默认，
// 非正整数即报错（可调数值集中在启动期校验，拒绝带病运行）。
func envInt(key string, dst *int) error {
	raw := os.Getenv(key)
	if raw == "" {
		return nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fmt.Errorf("config: %s 必须为正整数，得到 %q", key, raw)
	}
	*dst = n
	return nil
}

// envFloat 同 envInt，解析正浮点（限流速率、失败率阈值）。
func envFloat(key string, dst *float64) error {
	raw := os.Getenv(key)
	if raw == "" {
		return nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || f <= 0 {
		return fmt.Errorf("config: %s 必须为正浮点数，得到 %q", key, raw)
	}
	*dst = f
	return nil
}

// envBool 同 envInt，解析 true/false（1/0 亦可），其余值即报错。
func envBool(key string, dst *bool) error {
	raw := os.Getenv(key)
	if raw == "" {
		return nil
	}
	switch strings.ToLower(raw) {
	case "true", "1":
		*dst = true
	case "false", "0":
		*dst = false
	default:
		return fmt.Errorf("config: %s 只接受 true/false，得到 %q", key, raw)
	}
	return nil
}
