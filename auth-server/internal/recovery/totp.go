package recovery

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // RFC 6238 的 SHA-1 是认证器互操作要求，不用于签名。
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/arithmaton/arauth/internal/store"
)

const (
	totpSecretLen     = 20 // RFC 4226/6238 常见互操作种子长度：160 位。
	totpRecoveryIDLen = 16 // 非秘密定位符仍取 128 位，避免可枚举。
	totpPeriodSeconds = 30
	totpDigits        = 6
	totpWindow        = 1
)

// ErrInvalidTOTPSetup 统一表示 setup token 失效、身份不符或确认码错误。
var ErrInvalidTOTPSetup = errors.New("recovery: TOTP 绑定无效")

// TOTPStore 是 TOTP 流程需要的最小数据能力。recovery.Service 同时支持
// 纯恢复码 fake store，因此该能力在 New 中以接口断言装配。
type TOTPStore interface {
	UpsertRecoveryTOTP(ctx context.Context, rec *store.RecoveryTOTP) error
	GetRecoveryTOTP(ctx context.Context, recoveryID string) (*store.RecoveryTOTP, error)
	ConsumeRecoveryTOTPStep(ctx context.Context, userHandle []byte, step int64) error
	RecordRecoveryTOTPFailure(ctx context.Context, userHandle []byte, now time.Time, window time.Duration) error
}

// TOTPSetup 是 begin 一次性返回的绑定材料。所有字段都会经服务后端交给
// 当前用户浏览器，但绝不写日志或 localStorage。
type TOTPSetup struct {
	SetupToken []byte
	Secret     string
	URI        string
	RecoveryID string
}

type totpSetupEntry struct {
	userHandle []byte
	recoveryID string
	ciphertext []byte
	expires    time.Time
}

// BeginTOTPEnrollment 生成 pending 种子。活跃记录直到 confirm 成功才替换，
// 所以用户放弃或输错动态码不会破坏仍可用的旧 TOTP。
func (s *Service) BeginTOTPEnrollment(userHandle []byte) (*TOTPSetup, error) {
	if s.totpStore == nil || len(userHandle) == 0 || len(s.cfg.TOTPEncryptionKey) != 32 {
		return nil, fmt.Errorf("recovery: TOTP 未正确配置")
	}
	secret := make([]byte, totpSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("recovery: 生成 TOTP 种子失败: %w", err)
	}
	defer clear(secret)

	recoveryRaw := make([]byte, totpRecoveryIDLen)
	if _, err := rand.Read(recoveryRaw); err != nil {
		return nil, fmt.Errorf("recovery: 生成 TOTP 定位符失败: %w", err)
	}
	base32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding)
	recoveryID := base32NoPad.EncodeToString(recoveryRaw)
	recoveryDisplay := group4(strings.ToLower(recoveryID))

	ciphertext, err := sealTOTPSecret(s.cfg.TOTPEncryptionKey, userHandle, secret)
	if err != nil {
		return nil, err
	}
	setupToken := make([]byte, tokenLen)
	if _, err := rand.Read(setupToken); err != nil {
		return nil, fmt.Errorf("recovery: 生成 TOTP setup token 失败: %w", err)
	}
	s.putTOTPSetup(setupToken, totpSetupEntry{
		userHandle: append([]byte(nil), userHandle...),
		recoveryID: recoveryID,
		ciphertext: ciphertext,
		expires:    s.now().Add(s.cfg.TOTPSetupTTL),
	})

	secretText := base32NoPad.EncodeToString(secret)
	query := url.Values{
		"secret":    {secretText},
		"issuer":    {s.cfg.TOTPIssuer},
		"algorithm": {"SHA1"},
		"digits":    {fmt.Sprintf("%d", totpDigits)},
		"period":    {fmt.Sprintf("%d", totpPeriodSeconds)},
	}
	label := url.PathEscape(s.cfg.TOTPIssuer + ":" + recoveryDisplay)
	return &TOTPSetup{
		SetupToken: setupToken,
		Secret:     secretText,
		URI:        "otpauth://totp/" + label + "?" + query.Encode(),
		RecoveryID: recoveryDisplay,
	}, nil
}

// ConfirmTOTPEnrollment 消费一次性 setup token 并验证动态码，成功后才
// 原子替换活跃记录。确认用时间步立即记为已消费，不能直接再用于找回。
func (s *Service) ConfirmTOTPEnrollment(ctx context.Context, userHandle, setupToken []byte, code string) error {
	entry, ok := s.consumeTOTPSetup(setupToken)
	if !ok || !bytes.Equal(entry.userHandle, userHandle) {
		return ErrInvalidTOTPSetup
	}
	secret, err := openTOTPSecret(s.cfg.TOTPEncryptionKey, entry.userHandle, entry.ciphertext)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTOTPSetup, err)
	}
	defer clear(secret)
	step, ok := matchTOTP(secret, code, s.now())
	if !ok {
		return ErrInvalidTOTPSetup
	}
	if err := s.totpStore.UpsertRecoveryTOTP(ctx, &store.RecoveryTOTP{
		UserHandle:       entry.userHandle,
		RecoveryID:       entry.recoveryID,
		SecretCiphertext: entry.ciphertext,
		KeyVersion:       s.cfg.TOTPKeyVersion,
		LastUsedStep:     step,
	}); err != nil {
		return fmt.Errorf("recovery: 确认 TOTP 绑定失败: %w", err)
	}
	return nil
}

// RedeemTOTP 验证 recovery_id + 动态码，成功时签发与一次性恢复码完全
// 相同的 recovery token；它不会直接发登录会话或 exchange code。
func (s *Service) RedeemTOTP(ctx context.Context, recoveryIDInput, code string) ([]byte, error) {
	recoveryID, err := normalizeTOTPRecoveryID(recoveryIDInput)
	if err != nil || s.totpStore == nil {
		return nil, ErrInvalidRedeem
	}
	rec, err := s.totpStore.GetRecoveryTOTP(ctx, recoveryID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRedeem, err)
	}
	now := s.now()
	if totpThrottled(rec, now, s.cfg.TOTPFailureWindow, s.cfg.TOTPMaxFailures) ||
		rec.KeyVersion != s.cfg.TOTPKeyVersion {
		return nil, ErrInvalidRedeem
	}
	secret, err := openTOTPSecret(s.cfg.TOTPEncryptionKey, rec.UserHandle, rec.SecretCiphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRedeem, err)
	}
	defer clear(secret)
	step, ok := matchTOTP(secret, code, now)
	if !ok {
		if err := s.totpStore.RecordRecoveryTOTPFailure(ctx, rec.UserHandle, now, s.cfg.TOTPFailureWindow); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidRedeem, err)
		}
		return nil, ErrInvalidRedeem
	}
	// 已消费时间步是重放，不再累计失败，避免旧动态码被用于触发节流。
	if step <= rec.LastUsedStep {
		return nil, ErrInvalidRedeem
	}
	if err := s.totpStore.ConsumeRecoveryTOTPStep(ctx, rec.UserHandle, step); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRedeem, err)
	}
	return s.issueToken(rec.UserHandle)
}

func totpThrottled(rec *store.RecoveryTOTP, now time.Time, window time.Duration, maxFailures int) bool {
	return rec.FailureWindowStartedAt != nil && rec.FailedAttempts >= maxFailures &&
		now.Before(rec.FailureWindowStartedAt.Add(window))
}

// matchTOTP 在当前及相邻一个时间步内找匹配，返回实际匹配步供防重放。
func matchTOTP(secret []byte, code string, now time.Time) (int64, bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	counter := now.Unix() / totpPeriodSeconds
	for _, offset := range []int64{0, -totpWindow, totpWindow} {
		candidate := counter + offset
		if candidate < 0 {
			continue
		}
		expected := hotp(secret, uint64(candidate), totpDigits)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return candidate, true
		}
	}
	return 0, false
}

// hotp 实现 RFC 4226 动态截断。digits 独立成参数是为了直接复用 RFC
// 6238 的 8 位测试向量；在线协议固定调用 6 位。
func hotp(secret []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(buf[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for i := 0; i < digits; i++ {
		modulus *= 10
	}
	text := fmt.Sprintf("%0*d", digits, value%modulus)
	return text
}

func sealTOTPSecret(key, userHandle, secret []byte) ([]byte, error) {
	gcm, err := newTOTPGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("recovery: 生成 TOTP nonce 失败: %w", err)
	}
	return gcm.Seal(nonce, nonce, secret, totpAAD(userHandle)), nil
}

func openTOTPSecret(key, userHandle, ciphertext []byte) ([]byte, error) {
	gcm, err := newTOTPGCM(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize()+gcm.Overhead() {
		return nil, fmt.Errorf("recovery: TOTP 密文畸形")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	plain, err := gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], totpAAD(userHandle))
	if err != nil {
		return nil, fmt.Errorf("recovery: 解开 TOTP 种子失败: %w", err)
	}
	if len(plain) != totpSecretLen {
		clear(plain)
		return nil, fmt.Errorf("recovery: TOTP 种子长度异常")
	}
	return plain, nil
}

func newTOTPGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("recovery: 初始化 TOTP 加密失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("recovery: 初始化 TOTP GCM 失败: %w", err)
	}
	return gcm, nil
}

func totpAAD(userHandle []byte) []byte {
	aad := make([]byte, 0, len(userHandle)+24)
	aad = append(aad, "arauth/recovery-totp/v1\x00"...)
	return append(aad, userHandle...)
}

func normalizeTOTPRecoveryID(input string) (string, error) {
	compact := strings.NewReplacer("-", "", " ", "").Replace(input)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(compact))
	if err != nil || len(raw) != totpRecoveryIDLen {
		return "", ErrInvalidRedeem
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

func (s *Service) putTOTPSetup(token []byte, entry totpSetupEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, existing := range s.setups {
		if now.After(existing.expires) {
			delete(s.setups, k)
		}
	}
	s.setups[tokenKey(token)] = entry
}

func (s *Service) consumeTOTPSetup(token []byte) (totpSetupEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tokenKey(token)
	entry, ok := s.setups[key]
	if !ok {
		return totpSetupEntry{}, false
	}
	delete(s.setups, key)
	if s.now().After(entry.expires) {
		return totpSetupEntry{}, false
	}
	return entry, true
}
