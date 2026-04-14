//go:build integration

// 集成测试：恢复码哈希查询、激活、会话查询、找回事务（挂新凭据 +
// 轮换恢复码原子性）的真实库行为。

package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arithmaton/arauth/internal/store"
)

// registerForTest 用真实 store 落一份注册（identity + credential + 恢复码）。
func registerForTest(t *testing.T, ctx context.Context, s *store.Store) (handle, credID, codeHash []byte) {
	t.Helper()
	handle, err := randBytes(64)
	if err != nil {
		t.Fatal(err)
	}
	credID, err = randBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	aaguid, err := randBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	codeHash, err = randBytes(32)
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
	}
	if err := s.InsertRegistration(ctx, handle, cred, codeHash); err != nil {
		t.Fatalf("InsertRegistration 失败: %v", err)
	}
	return handle, credID, codeHash
}

// TestRecoveryCodeLookup：注册事务落恢复码哈希；按哈希可查到记录；
// 未知哈希 ErrNotFound。
func TestRecoveryCodeLookup(t *testing.T) {
	ctx, s, _ := setup(t)
	handle, _, codeHash := registerForTest(t, ctx, s)

	rc, err := s.GetRecoveryCodeByHash(ctx, codeHash)
	if err != nil {
		t.Fatalf("GetRecoveryCodeByHash 失败: %v", err)
	}
	if !bytes.Equal(rc.UserHandle, handle) {
		t.Error("恢复码未挂到正确 identity")
	}
	if rc.RotatedAt != nil {
		t.Error("新码 rotated_at 应为 NULL")
	}

	unknown, err := randBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRecoveryCodeByHash(ctx, unknown); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("未知哈希应 ErrNotFound，得到: %v", err)
	}
}

// TestActivateIdentity：注册后 pending → 激活置位；重复激活幂等不报错。
func TestActivateIdentity(t *testing.T) {
	ctx, s, _ := setup(t)
	handle, _, _ := registerForTest(t, ctx, s)

	id, err := s.GetIdentity(ctx, handle)
	if err != nil {
		t.Fatalf("GetIdentity 失败: %v", err)
	}
	if id.ActivatedAt != nil {
		t.Fatal("注册后应为 pending")
	}

	if err := s.ActivateIdentity(ctx, handle); err != nil {
		t.Fatalf("ActivateIdentity 失败: %v", err)
	}
	id, err = s.GetIdentity(ctx, handle)
	if err != nil {
		t.Fatalf("GetIdentity 失败: %v", err)
	}
	if id.ActivatedAt == nil {
		t.Error("激活后 activated_at 应置位")
	}

	// 幂等：重复激活不报错、不改动语义。
	if err := s.ActivateIdentity(ctx, handle); err != nil {
		t.Fatalf("重复激活应幂等: %v", err)
	}
}

// TestGetSession：未过期会话可查回；过期会话 ErrNotFound（与不存在不可
// 区分）。
func TestGetSession(t *testing.T) {
	ctx, s, _ := setup(t)
	handle, _, _ := registerForTest(t, ctx, s)

	insert := func(t *testing.T, expiresAt time.Time) []byte {
		t.Helper()
		tokenHash, err := randBytes(32)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.InsertSession(ctx, &store.Session{
			TokenHash:  tokenHash,
			UserHandle: handle,
			ExpiresAt:  expiresAt,
		}); err != nil {
			t.Fatalf("InsertSession 失败: %v", err)
		}
		return tokenHash
	}

	fresh := insert(t, time.Now().Add(time.Hour))
	sess, err := s.GetSession(ctx, fresh)
	if err != nil {
		t.Fatalf("GetSession 失败: %v", err)
	}
	if !bytes.Equal(sess.UserHandle, handle) {
		t.Error("会话未挂到正确 identity")
	}

	expired := insert(t, time.Now().Add(-time.Minute))
	if _, err := s.GetSession(ctx, expired); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("过期会话应 ErrNotFound，得到: %v", err)
	}

	unknown, err := randBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, unknown); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("未知会话应 ErrNotFound，得到: %v", err)
	}
}

// TestAttachCredentialAndRotate 验证找回事务：新凭据挂上原 identity、
// 恢复码哈希轮换（旧哈希即刻查不到 = 用后即焚）、rotated_at 置位，
// 两者原子可见。
func TestAttachCredentialAndRotate(t *testing.T) {
	ctx, s, _ := setup(t)
	handle, _, oldHash := registerForTest(t, ctx, s)

	newCredID, err := randBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	aaguid, err := randBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	newHash, err := randBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	newCred := &store.Credential{
		CredentialID: newCredID,
		UserHandle:   handle,
		PublicKey:    []byte{0xa5, 0x01, 0x03},
		BackedUp:     false,
		BackupState:  false,
		AAGUID:       aaguid,
		Attachment:   "cross-platform",
		Transports:   []string{"usb"},
		SignCount:    1,
	}
	if err := s.AttachCredentialAndRotate(ctx, newCred, newHash); err != nil {
		t.Fatalf("AttachCredentialAndRotate 失败: %v", err)
	}

	// 新凭据可查，挂在原 identity 上。
	cred, err := s.GetCredential(ctx, newCredID)
	if err != nil {
		t.Fatalf("GetCredential 失败: %v", err)
	}
	if !bytes.Equal(cred.UserHandle, handle) {
		t.Error("新凭据未挂到原 identity")
	}
	list, err := s.ListCredentialsByIdentity(ctx, handle)
	if err != nil {
		t.Fatalf("ListCredentialsByIdentity 失败: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("找回后凭据数 = %d，期望 2", len(list))
	}

	// 旧哈希作废（用后即焚），新哈希可查且 rotated_at 置位。
	if _, err := s.GetRecoveryCodeByHash(ctx, oldHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("旧恢复码哈希应立即作废，得到: %v", err)
	}
	rc, err := s.GetRecoveryCodeByHash(ctx, newHash)
	if err != nil {
		t.Fatalf("新恢复码哈希应可查: %v", err)
	}
	if rc.RotatedAt == nil {
		t.Error("轮换后 rotated_at 应置位")
	}
	if !bytes.Equal(rc.UserHandle, handle) {
		t.Error("新码未挂到原 identity")
	}
}
