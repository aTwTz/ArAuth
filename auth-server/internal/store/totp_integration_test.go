//go:build integration

package store_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arithmaton/arauth/internal/store"
)

func TestRecoveryTOTPStore(t *testing.T) {
	ctx, s, _ := setup(t)
	handle, err := randBytes(64)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertIdentity(ctx, handle); err != nil {
		t.Fatal(err)
	}
	rec := &store.RecoveryTOTP{
		UserHandle:       handle,
		RecoveryID:       "RECOVERY-ID-ONE",
		SecretCiphertext: []byte("nonce-and-aead-ciphertext"),
		KeyVersion:       1,
		LastUsedStep:     3,
	}
	if err := s.UpsertRecoveryTOTP(ctx, rec); err != nil {
		t.Fatalf("UpsertRecoveryTOTP 失败: %v", err)
	}
	got, err := s.GetRecoveryTOTP(ctx, rec.RecoveryID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.UserHandle, handle) || !bytes.Equal(got.SecretCiphertext, rec.SecretCiphertext) ||
		got.KeyVersion != 1 || got.LastUsedStep != 3 {
		t.Fatalf("TOTP 记录回读不符: %+v", got)
	}

	// 同一时间步并发消费只能有一个数据库条件更新成功。
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.ConsumeRecoveryTOTPStep(context.Background(), handle, 4); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("并发消费成功数 = %d，期望 1", successes.Load())
	}
	if err := s.ConsumeRecoveryTOTPStep(ctx, handle, 4); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("同一步重放应 ErrNotFound，得到 %v", err)
	}

	now := time.Now()
	for i := 0; i < 5; i++ {
		if err := s.RecordRecoveryTOTPFailure(ctx, handle, now, 5*time.Minute); err != nil {
			t.Fatalf("记录第 %d 次失败: %v", i+1, err)
		}
	}
	got, err = s.GetRecoveryTOTP(ctx, rec.RecoveryID)
	if err != nil || got.FailedAttempts != 5 || got.FailureWindowStartedAt == nil {
		t.Fatalf("失败窗口状态异常: %+v, %v", got, err)
	}
	if err := s.ConsumeRecoveryTOTPStep(ctx, handle, 5); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRecoveryTOTP(ctx, rec.RecoveryID)
	if got.FailedAttempts != 0 || got.FailureWindowStartedAt != nil {
		t.Fatal("成功消费后未清空失败窗口")
	}

	// confirm 轮换时替换定位符和密文，并清空旧防重放状态。
	rec.RecoveryID = "RECOVERY-ID-TWO"
	rec.SecretCiphertext = []byte("new-ciphertext")
	rec.LastUsedStep = 10
	if err := s.UpsertRecoveryTOTP(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRecoveryTOTP(ctx, "RECOVERY-ID-ONE"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("旧 recovery_id 应失效，得到 %v", err)
	}
	got, err = s.GetRecoveryTOTP(ctx, rec.RecoveryID)
	if err != nil || got.LastUsedStep != 10 || !bytes.Equal(got.SecretCiphertext, rec.SecretCiphertext) {
		t.Fatalf("轮换后记录异常: %+v, %v", got, err)
	}
}
