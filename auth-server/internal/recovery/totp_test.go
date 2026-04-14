package recovery

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/store"
)

type fakeTOTPStore struct {
	fakeStore
	mu  sync.Mutex
	rec *store.RecoveryTOTP
}

func copyTOTP(rec *store.RecoveryTOTP) *store.RecoveryTOTP {
	if rec == nil {
		return nil
	}
	clone := *rec
	clone.UserHandle = append([]byte(nil), rec.UserHandle...)
	clone.SecretCiphertext = append([]byte(nil), rec.SecretCiphertext...)
	return &clone
}

func (f *fakeTOTPStore) UpsertRecoveryTOTP(_ context.Context, rec *store.RecoveryTOTP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rec = copyTOTP(rec)
	return nil
}

func (f *fakeTOTPStore) GetRecoveryTOTP(_ context.Context, recoveryID string) (*store.RecoveryTOTP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rec == nil || f.rec.RecoveryID != recoveryID {
		return nil, store.ErrNotFound
	}
	return copyTOTP(f.rec), nil
}

func (f *fakeTOTPStore) ConsumeRecoveryTOTPStep(_ context.Context, userHandle []byte, step int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rec == nil || !bytes.Equal(f.rec.UserHandle, userHandle) || step <= f.rec.LastUsedStep {
		return store.ErrNotFound
	}
	f.rec.LastUsedStep = step
	f.rec.FailedAttempts = 0
	f.rec.FailureWindowStartedAt = nil
	return nil
}

func (f *fakeTOTPStore) RecordRecoveryTOTPFailure(_ context.Context, userHandle []byte, now time.Time, window time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rec == nil || !bytes.Equal(f.rec.UserHandle, userHandle) {
		return store.ErrNotFound
	}
	if f.rec.FailureWindowStartedAt == nil || !now.Before(f.rec.FailureWindowStartedAt.Add(window)) {
		f.rec.FailureWindowStartedAt = &now
		f.rec.FailedAttempts = 0
	}
	f.rec.FailedAttempts++
	return nil
}

func newTOTPTestService(fst *fakeTOTPStore) (*Service, *time.Time) {
	now := time.Unix(1700000007, 0)
	svc := New(&config.Config{
		RecoveryTokenTTL:  5 * time.Minute,
		TOTPEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		TOTPKeyVersion:    1,
		TOTPIssuer:        "arauth-test",
		TOTPSetupTTL:      5 * time.Minute,
		TOTPFailureWindow: 5 * time.Minute,
		TOTPMaxFailures:   5,
	}, fst)
	svc.now = func() time.Time { return now }
	return svc, &now
}

func totpSecretBytes(t *testing.T, text string) []byte {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(text)
	if err != nil {
		t.Fatalf("种子 Base32 解码失败: %v", err)
	}
	return secret
}

func codeForTime(secret []byte, at time.Time) string {
	return hotp(secret, uint64(at.Unix()/totpPeriodSeconds), totpDigits)
}

func invalidCodeForTOTP(t *testing.T, secret []byte, now time.Time) string {
	t.Helper()
	for i := 0; i < 100; i++ {
		candidate := fmt.Sprintf("%06d", i)
		if _, ok := matchTOTP(secret, candidate, now); !ok {
			return candidate
		}
	}
	t.Fatal("无法构造无效动态码")
	return ""
}

func enrollTOTP(t *testing.T, svc *Service, handle []byte, at time.Time) *TOTPSetup {
	t.Helper()
	setup, err := svc.BeginTOTPEnrollment(handle)
	if err != nil {
		t.Fatalf("BeginTOTPEnrollment 失败: %v", err)
	}
	secret := totpSecretBytes(t, setup.Secret)
	if err := svc.ConfirmTOTPEnrollment(context.Background(), handle, setup.SetupToken, codeForTime(secret, at)); err != nil {
		t.Fatalf("ConfirmTOTPEnrollment 失败: %v", err)
	}
	return setup
}

func TestTOTPEnrollAndRedeemLifecycle(t *testing.T) {
	fst := &fakeTOTPStore{}
	svc, now := newTOTPTestService(fst)
	handle := []byte("handle-totp")
	setup, err := svc.BeginTOTPEnrollment(handle)
	if err != nil {
		t.Fatalf("begin 失败: %v", err)
	}
	if fst.rec != nil {
		t.Fatal("begin 不得提前写活跃记录")
	}
	if len(setup.SetupToken) != tokenLen || !strings.Contains(setup.URI, setup.Secret) ||
		!strings.Contains(setup.URI, "otpauth://totp/") {
		t.Fatal("setup 响应形态异常")
	}
	secret := totpSecretBytes(t, setup.Secret)
	if err := svc.ConfirmTOTPEnrollment(context.Background(), handle, setup.SetupToken, invalidCodeForTOTP(t, secret, *now)); err == nil {
		t.Fatal("错误确认码不得绑定")
	}
	if fst.rec != nil {
		t.Fatal("确认失败后不得写活跃记录")
	}
	// setup token 无论成败都一次性消费。
	if err := svc.ConfirmTOTPEnrollment(context.Background(), handle, setup.SetupToken, codeForTime(secret, *now)); !errors.Is(err, ErrInvalidTOTPSetup) {
		t.Fatalf("重放 setup token 应失败，得到 %v", err)
	}

	setup = enrollTOTP(t, svc, handle, *now)
	secret = totpSecretBytes(t, setup.Secret)
	if fst.rec == nil || bytes.Contains(fst.rec.SecretCiphertext, secret) {
		t.Fatal("活跃记录不存在或密文包含明文种子")
	}
	if _, err := svc.RedeemTOTP(context.Background(), setup.RecoveryID, codeForTime(secret, *now)); !errors.Is(err, ErrInvalidRedeem) {
		t.Fatalf("绑定确认时间步不得直接重放，得到 %v", err)
	}

	next := now.Add(totpPeriodSeconds * time.Second)
	token, err := svc.RedeemTOTP(context.Background(), setup.RecoveryID, codeForTime(secret, next))
	if err != nil {
		t.Fatalf("下一时间步找回失败: %v", err)
	}
	if got, ok := svc.LookupToken(token); !ok || !bytes.Equal(got, handle) {
		t.Fatalf("恢复票据身份不符: %q, %v", got, ok)
	}
	if _, err := svc.RedeemTOTP(context.Background(), setup.RecoveryID, codeForTime(secret, next)); !errors.Is(err, ErrInvalidRedeem) {
		t.Fatalf("同一时间步重放应失败，得到 %v", err)
	}
}

func TestTOTPRotationKeepsOldUntilConfirm(t *testing.T) {
	fst := &fakeTOTPStore{}
	svc, now := newTOTPTestService(fst)
	handle := []byte("handle-rotate")
	oldSetup := enrollTOTP(t, svc, handle, *now)
	oldSecret := totpSecretBytes(t, oldSetup.Secret)
	oldRecoveryID := fst.rec.RecoveryID

	newSetup, err := svc.BeginTOTPEnrollment(handle)
	if err != nil {
		t.Fatal(err)
	}
	if fst.rec.RecoveryID != oldRecoveryID {
		t.Fatal("begin 提前轮换了活跃记录")
	}
	newSecret := totpSecretBytes(t, newSetup.Secret)
	if err := svc.ConfirmTOTPEnrollment(context.Background(), handle, newSetup.SetupToken, codeForTime(newSecret, *now)); err != nil {
		t.Fatal(err)
	}
	if fst.rec.RecoveryID == oldRecoveryID {
		t.Fatal("confirm 后活跃定位符未轮换")
	}
	next := now.Add(totpPeriodSeconds * time.Second)
	if _, err := svc.RedeemTOTP(context.Background(), oldSetup.RecoveryID, codeForTime(oldSecret, next)); !errors.Is(err, ErrInvalidRedeem) {
		t.Fatalf("旧种子/定位符轮换后应失效，得到 %v", err)
	}
	if _, err := svc.RedeemTOTP(context.Background(), newSetup.RecoveryID, codeForTime(newSecret, next)); err != nil {
		t.Fatalf("新种子应可找回: %v", err)
	}
}

func TestTOTPFailureThrottle(t *testing.T) {
	fst := &fakeTOTPStore{}
	svc, now := newTOTPTestService(fst)
	handle := []byte("handle-throttle")
	setup := enrollTOTP(t, svc, handle, *now)
	secret := totpSecretBytes(t, setup.Secret)
	wrong := invalidCodeForTOTP(t, secret, *now)
	for i := 0; i < 5; i++ {
		if _, err := svc.RedeemTOTP(context.Background(), setup.RecoveryID, wrong); !errors.Is(err, ErrInvalidRedeem) {
			t.Fatalf("第 %d 次错码响应异常: %v", i+1, err)
		}
	}
	valid := codeForTime(secret, now.Add(totpPeriodSeconds*time.Second))
	if _, err := svc.RedeemTOTP(context.Background(), setup.RecoveryID, valid); !errors.Is(err, ErrInvalidRedeem) {
		t.Fatalf("失败窗口内正确码也应暂时拒绝，得到 %v", err)
	}
	*now = now.Add(6 * time.Minute)
	valid = codeForTime(secret, *now)
	if _, err := svc.RedeemTOTP(context.Background(), setup.RecoveryID, valid); err != nil {
		t.Fatalf("失败窗口过后应恢复: %v", err)
	}
}

func TestTOTPConcurrentConsumeOnlyOnce(t *testing.T) {
	fst := &fakeTOTPStore{}
	svc, now := newTOTPTestService(fst)
	handle := []byte("handle-concurrent")
	setup := enrollTOTP(t, svc, handle, *now)
	secret := totpSecretBytes(t, setup.Secret)
	code := codeForTime(secret, now.Add(totpPeriodSeconds*time.Second))

	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.RedeemTOTP(context.Background(), setup.RecoveryID, code); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("并发同码成功数 = %d，期望 1", got)
	}
}

func TestTOTPAEADRoundTripAndTamper(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	handle := []byte("handle-aead")
	secret := make([]byte, totpSecretLen)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sealTOTPSecret(key, handle, secret)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := openTOTPSecret(key, handle, ciphertext)
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatalf("AEAD 往返失败: %v", err)
	}
	if _, err := openTOTPSecret(key, []byte("other"), ciphertext); err == nil {
		t.Fatal("AAD 身份不符必须失败")
	}
	ciphertext[len(ciphertext)-1] ^= 1
	if _, err := openTOTPSecret(key, handle, ciphertext); err == nil {
		t.Fatal("密文篡改必须失败")
	}
}

func TestHotpRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := []struct {
		seconds int64
		code    string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, vector := range vectors {
		counter := uint64(vector.seconds / totpPeriodSeconds)
		if got := hotp(secret, counter, 8); got != vector.code {
			t.Errorf("T=%d: HOTP=%s，期望 %s", vector.seconds, got, vector.code)
		}
	}
	if got := codeForTime(secret, time.Unix(59, 0)); got != "287082" {
		t.Errorf("6 位动态码 = %s，期望 287082", got)
	}
}
