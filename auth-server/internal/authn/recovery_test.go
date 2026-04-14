package authn

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/arithmaton/arauth/internal/store"
)

// testIdentity 构造一条 identity 记录（找回/确认测试脚手架用）。
func testIdentity(handle []byte, createdAt time.Time, activatedAt *time.Time) *store.Identity {
	return &store.Identity{UserHandle: handle, CreatedAt: createdAt, ActivatedAt: activatedAt}
}

// recoveryFixture 是找回测试脚手架：一个已注册的 identity（fakeStore
// 记录）加一枚直接签发的恢复凭证。
type recoveryFixture struct {
	svc        *Service
	fst        *fakeStore
	rec        *fakeRecovery
	token      []byte
	userHandle []byte
}

func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	fst := &fakeStore{}
	rec := newFakeRecovery()
	svc := newTestServiceWith(t, fst, rec)

	// 模拟"已有一个激活身份"（找回前提）
	handle := bytes.Repeat([]byte{0x11}, userHandleLen)
	now := time.Now()
	fst.identity = testIdentity(handle, now, &now)

	token := bytes.Repeat([]byte{0x22}, 32)
	rec.issueToken(token, handle)
	return &recoveryFixture{svc: svc, fst: fst, rec: rec, token: token, userHandle: handle}
}

// TestBeginRecoveryRegistrationShape：options 绑定原 user handle，
// 与注册 options 同形态（residentKey/UV required）。
func TestBeginRecoveryRegistrationShape(t *testing.T) {
	fx := newRecoveryFixture(t)

	creation, err := fx.svc.BeginRecoveryRegistration(fx.token)
	if err != nil {
		t.Fatalf("BeginRecoveryRegistration 失败: %v", err)
	}
	userID, ok := creation.Response.User.ID.(protocol.URLEncodedBase64)
	if !ok || !bytes.Equal([]byte(userID), fx.userHandle) {
		t.Error("找回 options 必须绑定原 user handle（不得新生成）")
	}
	if creation.Response.AuthenticatorSelection.ResidentKey != protocol.ResidentKeyRequirementRequired {
		t.Error("residentKey 应为 required")
	}
	// token 在 options 阶段不得被消费（verify 才是一次性消费点）
	if _, ok := fx.rec.LookupToken(fx.token); !ok {
		t.Error("options 阶段不得消费恢复凭证")
	}
}

// TestBeginRecoveryRegistrationBadToken：无效恢复凭证拒绝发 options。
func TestBeginRecoveryRegistrationBadToken(t *testing.T) {
	fx := newRecoveryFixture(t)
	if _, err := fx.svc.BeginRecoveryRegistration([]byte("偷来的")); !errors.Is(err, ErrInvalidCeremony) {
		t.Fatalf("无效凭证应拒绝，得到: %v", err)
	}
}

// finishRecovery 走通 options → attestation → FinishRecoveryRegistration。
func (fx *recoveryFixture) finishRecovery(t *testing.T, token []byte) (*RecoveryRegistration, error) {
	t.Helper()
	creation, err := fx.svc.BeginRecoveryRegistration(fx.token)
	if err != nil {
		t.Fatalf("BeginRecoveryRegistration 失败: %v", err)
	}
	body, _, _ := buildAttestationResponse(t, fixtureSpec{
		rpID:      testRPID,
		origin:    testOrigin,
		challenge: b64url(creation.Response.Challenge),
		flags: protocol.FlagUserPresent | protocol.FlagUserVerified |
			protocol.FlagAttestedCredentialData | protocol.FlagBackupEligible | protocol.FlagBackupState,
	})
	req := httptest.NewRequest("POST", "/recovery/verify", bytes.NewReader(body))
	return fx.svc.FinishRecoveryRegistration(context.Background(), req, token)
}

// TestFinishRecoveryRegistrationHappyPath：挂新凭据 + 轮换恢复码原子
// 完成；返回新码原文一次；token 已消费不可重放。
func TestFinishRecoveryRegistrationHappyPath(t *testing.T) {
	fx := newRecoveryFixture(t)

	regn, err := fx.finishRecovery(t, fx.token)
	if err != nil {
		t.Fatalf("FinishRecoveryRegistration 失败: %v", err)
	}
	if regn.RecoveryCode == "" {
		t.Error("找回 verify 应返回轮换后的新码原文")
	}
	if len(fx.fst.attached) != 1 {
		t.Fatalf("AttachCredentialAndRotate 落库 %d 条，期望 1", len(fx.fst.attached))
	}
	c := fx.fst.attached[0]
	if !bytes.Equal(c.UserHandle, fx.userHandle) {
		t.Error("新凭据必须挂到原 user handle")
	}
	if !c.BackedUp || !c.BackupState {
		t.Error("BE/BS 应与 attestation flags 一致（BE=1/BS=1）")
	}
	if len(fx.fst.rotatedHash) == 0 {
		t.Error("恢复码哈希未轮换")
	}
	if _, ok := fx.rec.LookupToken(fx.token); ok {
		t.Error("恢复凭证用后必须作废（一次性）")
	}
}

// TestFinishRecoveryRegistrationBadToken：无效/已消费 token 一律拒绝。
func TestFinishRecoveryRegistrationBadToken(t *testing.T) {
	fx := newRecoveryFixture(t)
	if _, err := fx.finishRecovery(t, []byte("无效凭证")); !errors.Is(err, ErrInvalidCeremony) {
		t.Fatalf("无效凭证应拒绝，得到: %v", err)
	}
	if len(fx.fst.attached) != 0 {
		t.Error("无效凭证不得落库")
	}
}

// TestFinishRecoveryRegistrationBadAttestation：attestation 伪造时拒绝，
// 且 token 已被消费（验一次即作废，失败需重新 redeem）。
func TestFinishRecoveryRegistrationBadAttestation(t *testing.T) {
	fx := newRecoveryFixture(t)
	creation, err := fx.svc.BeginRecoveryRegistration(fx.token)
	if err != nil {
		t.Fatalf("BeginRecoveryRegistration 失败: %v", err)
	}
	body, _, _ := buildAttestationResponse(t, fixtureSpec{
		rpID:      testRPID,
		origin:    "https://evil.example.net", // 白名单外 origin
		challenge: b64url(creation.Response.Challenge),
		flags:     protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagAttestedCredentialData,
	})
	req := httptest.NewRequest("POST", "/recovery/verify", bytes.NewReader(body))
	if _, err := fx.svc.FinishRecoveryRegistration(context.Background(), req, fx.token); !errors.Is(err, ErrInvalidCeremony) {
		t.Fatalf("伪造 attestation 应拒绝，得到: %v", err)
	}
	if len(fx.fst.attached) != 0 {
		t.Error("伪造 attestation 不得落库")
	}
	if _, ok := fx.rec.LookupToken(fx.token); ok {
		t.Error("失败后 token 也必须作废（验一次即作废）")
	}
}

// TestFinishRecoveryRegistrationStoreError：落库（同事务轮换）失败不算
// ceremony 失败——不得归一 ErrInvalidCeremony（server 应回 500）。
func TestFinishRecoveryRegistrationStoreError(t *testing.T) {
	fx := newRecoveryFixture(t)
	fx.fst.attachErr = errors.New("db down")

	if _, err := fx.finishRecovery(t, fx.token); err == nil {
		t.Fatal("落库失败应返回错误")
	} else if errors.Is(err, ErrInvalidCeremony) {
		t.Error("落库失败不得归一为 ErrInvalidCeremony")
	}
}

// TestConfirmRegistration：pending → 激活；重复确认幂等；超 PendingTTL
// 拒绝；未知 identity 拒绝——后两者归一 ErrInvalidCeremony。
func TestConfirmRegistration(t *testing.T) {
	t.Run("激活成功且幂等", func(t *testing.T) {
		fst := &fakeStore{}
		svc := newTestService(t, fst)
		handle := bytes.Repeat([]byte{0x33}, userHandleLen)
		fst.identity = testIdentity(handle, time.Now(), nil)

		if err := svc.ConfirmRegistration(context.Background(), handle); err != nil {
			t.Fatalf("首次确认应成功: %v", err)
		}
		if fst.identity.ActivatedAt == nil {
			t.Fatal("identity 应已激活")
		}
		if err := svc.ConfirmRegistration(context.Background(), handle); err != nil {
			t.Fatalf("重复确认应幂等成功: %v", err)
		}
	})

	t.Run("超宽限拒绝", func(t *testing.T) {
		fst := &fakeStore{}
		svc := newTestService(t, fst)
		handle := bytes.Repeat([]byte{0x44}, userHandleLen)
		fst.identity = testIdentity(handle, time.Now().Add(-25*time.Hour), nil)

		if err := svc.ConfirmRegistration(context.Background(), handle); !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("超 PendingTTL 应拒绝，得到: %v", err)
		}
		if fst.identity.ActivatedAt != nil {
			t.Error("超宽限不得激活")
		}
	})

	t.Run("未知 identity 拒绝", func(t *testing.T) {
		svc := newTestService(t, &fakeStore{})
		if err := svc.ConfirmRegistration(context.Background(), []byte("不存在")); !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("未知 identity 应拒绝，得到: %v", err)
		}
	})
}
