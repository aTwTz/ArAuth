//go:build integration

// 集成测试：sessions / exchange_codes / 登录信号更新的真实库行为。

package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/arithmaton/arauth/internal/store"
)

// TestSessionCRUD 验证会话哈希写入。
func TestSessionCRUD(t *testing.T) {
	ctx, s, _ := setup(t)

	handle, err := randBytes(64)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertIdentity(ctx, handle); err != nil {
		t.Fatalf("InsertIdentity 失败: %v", err)
	}

	tokenHash, err := randBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	sess := &store.Session{
		TokenHash:  tokenHash,
		UserHandle: handle,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	if err := s.InsertSession(ctx, sess); err != nil {
		t.Fatalf("InsertSession 失败: %v", err)
	}
}

// TestExchangeCodeConsumeOnce 验证原子核销：首次成功返回 user_handle 与
// backed_up；重放、未知哈希、过期 code 全部 ErrNotFound（对外不区分）。
func TestExchangeCodeConsumeOnce(t *testing.T) {
	ctx, s, _ := setup(t)

	handle, err := randBytes(64)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertIdentity(ctx, handle); err != nil {
		t.Fatalf("InsertIdentity 失败: %v", err)
	}

	insert := func(t *testing.T, backedUp bool, expiresAt time.Time) []byte {
		t.Helper()
		hash, err := randBytes(32)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.InsertExchangeCode(ctx, &store.ExchangeCode{
			CodeHash:   hash,
			UserHandle: handle,
			BackedUp:   backedUp,
			ExpiresAt:  expiresAt,
		}); err != nil {
			t.Fatalf("InsertExchangeCode 失败: %v", err)
		}
		return hash
	}

	// 正常核销 + 重放拒绝。
	hash := insert(t, true, time.Now().Add(5*time.Minute))
	ec, err := s.ConsumeExchangeCode(ctx, hash)
	if err != nil {
		t.Fatalf("首次核销应成功: %v", err)
	}
	if len(ec.UserHandle) != 64 || !ec.BackedUp {
		t.Errorf("核销返回 = handle %d 字节 / backed_up %v，期望 64/true",
			len(ec.UserHandle), ec.BackedUp)
	}
	if _, err := s.ConsumeExchangeCode(ctx, hash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("重放核销应返回 ErrNotFound，得到: %v", err)
	}

	// 未知哈希。
	unknown, err := randBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeExchangeCode(ctx, unknown); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("未知哈希应返回 ErrNotFound，得到: %v", err)
	}

	// 过期 code。
	expired := insert(t, false, time.Now().Add(-time.Minute))
	if _, err := s.ConsumeExchangeCode(ctx, expired); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("过期 code 应返回 ErrNotFound，得到: %v", err)
	}
}

// TestUpdateLoginSignals 验证登录信号落库：BE/BS 翻转容忍更新、
// last_used_at 置位、sign_count 按 nil 语义（nil 不回写，非 nil 回写）。
func TestUpdateLoginSignals(t *testing.T) {
	ctx, s, _ := setup(t)

	handle, err := randBytes(64)
	if err != nil {
		t.Fatal(err)
	}
	credID, err := randBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	aaguid, err := randBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{
		CredentialID: credID,
		UserHandle:   handle,
		PublicKey:    []byte{0xa5, 0x01, 0x02},
		BackedUp:     true,
		BackupState:  true,
		AAGUID:       aaguid,
		Attachment:   "platform",
		Transports:   []string{"internal"},
		SignCount:    7,
	}
	codeHash, err := randBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertRegistration(ctx, handle, cred, codeHash); err != nil {
		t.Fatalf("InsertRegistration 失败: %v", err)
	}

	// BE/BS 翻转 + sign_count 递增回写。
	nine := int64(9)
	if err := s.UpdateLoginSignals(ctx, credID, false, false, &nine); err != nil {
		t.Fatalf("UpdateLoginSignals 失败: %v", err)
	}
	got, err := s.GetCredential(ctx, credID)
	if err != nil {
		t.Fatalf("GetCredential 失败: %v", err)
	}
	if got.BackedUp || got.BackupState {
		t.Error("BE/BS 翻转后应更新为断言值 false/false")
	}
	if got.SignCount != 9 {
		t.Errorf("sign_count = %d，期望回写 9", got.SignCount)
	}
	if got.LastUsedAt == nil {
		t.Error("last_used_at 应置位")
	}

	// signCount=nil 时不动 sign_count（同步 passkey 分治）。
	if err := s.UpdateLoginSignals(ctx, credID, true, true, nil); err != nil {
		t.Fatalf("UpdateLoginSignals(nil) 失败: %v", err)
	}
	got, err = s.GetCredential(ctx, credID)
	if err != nil {
		t.Fatalf("GetCredential 失败: %v", err)
	}
	if got.SignCount != 9 {
		t.Errorf("signCount=nil 不得回写，sign_count = %d，期望 9", got.SignCount)
	}
	if !got.BackedUp || !got.BackupState {
		t.Error("BE/BS 应再次更新为断言值 true/true")
	}

	// 不存在的凭据 → ErrNotFound。
	if err := s.UpdateLoginSignals(ctx, []byte("不存在的凭据"), false, false, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("不存在时应返回 ErrNotFound，得到: %v", err)
	}
}
