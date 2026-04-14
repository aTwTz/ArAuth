//go:build integration

// 集成测试：找回闭环全通——注册（发码）→ confirm 激活 → redeem →
// 挂新密钥（同事务轮换）→ 旧码失效、新码可再赎回 → 新凭据可登录。
// 运行：go test -tags integration ./internal/authn/（需先 docker compose up -d postgres）

package authn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/recovery"
)

const attestFlags = protocol.FlagUserPresent | protocol.FlagUserVerified |
	protocol.FlagAttestedCredentialData | protocol.FlagBackupEligible | protocol.FlagBackupState

const loginFlags = protocol.FlagUserPresent | protocol.FlagUserVerified |
	protocol.FlagBackupEligible | protocol.FlagBackupState

// loginOnce 走通一次 discoverable 登录：BeginLogin 取 challenge，用
// fixture 私钥签断言后 FinishLogin。
func loginOnce(t *testing.T, svc *Service, key *ecdsa.PrivateKey, credID, handle []byte) (*Login, error) {
	t.Helper()
	assertion, err := svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin 失败: %v", err)
	}
	body := buildAssertionResponse(t, key, credID, assertionSpec{
		rpID: testRPID, origin: testOrigin,
		challenge:  b64url(assertion.Response.Challenge),
		flags:      loginFlags,
		userHandle: handle,
	})
	req := httptest.NewRequest("POST", "/login/verify", bytes.NewReader(body))
	return svc.FinishLogin(context.Background(), req)
}

func TestRecoveryFullCycle(t *testing.T) {
	ctx, st := setupIntegration(t)

	cfg := &config.Config{
		RPID:             testRPID,
		RPOrigins:        []string{testOrigin},
		ChallengeTTL:     5 * time.Minute,
		PendingTTL:       24 * time.Hour,
		RecoveryTokenTTL: 5 * time.Minute,
	}
	recSvc := recovery.New(cfg, st)
	svc, err := New(cfg, st, recSvc)
	if err != nil {
		t.Fatalf("authn.New 失败: %v", err)
	}

	// 1. 注册闭环：verify 发放恢复码原文，落库 pending + 首条凭据 + 码哈希。
	creation, err := svc.BeginRegistration()
	if err != nil {
		t.Fatalf("BeginRegistration 失败: %v", err)
	}
	body, credID1, key1 := buildAttestationResponse(t, fixtureSpec{
		rpID: testRPID, origin: testOrigin,
		challenge: b64url(creation.Response.Challenge),
		flags:     attestFlags,
	})
	req := httptest.NewRequest("POST", "/register/verify", bytes.NewReader(body))
	regn, err := svc.FinishRegistration(ctx, req)
	if err != nil {
		t.Fatalf("FinishRegistration 失败: %v", err)
	}
	if regn.RecoveryCode == "" {
		t.Fatal("注册 verify 未发放恢复码")
	}

	// 2. confirm 前登录拒绝（pending，403 语义），confirm 后登录即通。
	if _, err := loginOnce(t, svc, key1, credID1, regn.UserHandle); !errors.Is(err, ErrIdentityPending) {
		t.Fatalf("confirm 前登录应 ErrIdentityPending，得到: %v", err)
	}
	if err := svc.ConfirmRegistration(ctx, regn.UserHandle); err != nil {
		t.Fatalf("ConfirmRegistration 失败: %v", err)
	}
	if _, err := loginOnce(t, svc, key1, credID1, regn.UserHandle); err != nil {
		t.Fatalf("confirm 后登录应通过: %v", err)
	}

	// 3. redeem 正确码 → 恢复凭证。
	token, err := recSvc.Redeem(ctx, regn.RecoveryCode)
	if err != nil {
		t.Fatalf("Redeem 失败: %v", err)
	}

	// 4. 找回挂新密钥：options 绑定原 handle → verify 落库 + 轮换。
	creation2, err := svc.BeginRecoveryRegistration(token)
	if err != nil {
		t.Fatalf("BeginRecoveryRegistration 失败: %v", err)
	}
	body2, credID2, key2 := buildAttestationResponse(t, fixtureSpec{
		rpID: testRPID, origin: testOrigin,
		challenge: b64url(creation2.Response.Challenge),
		flags:     attestFlags,
	})
	req2 := httptest.NewRequest("POST", "/recovery/verify", bytes.NewReader(body2))
	rr, err := svc.FinishRecoveryRegistration(ctx, req2, token)
	if err != nil {
		t.Fatalf("FinishRecoveryRegistration 失败: %v", err)
	}
	if rr.RecoveryCode == "" || rr.RecoveryCode == regn.RecoveryCode {
		t.Fatal("轮换后应下发新码原文，且与旧码不同")
	}

	// 5. 旧码即刻失效（用后即焚），新码可再赎回。
	if _, err := recSvc.Redeem(ctx, regn.RecoveryCode); !errors.Is(err, recovery.ErrInvalidRedeem) {
		t.Fatalf("旧码应失效（401 语义），得到: %v", err)
	}
	if _, err := recSvc.Redeem(ctx, rr.RecoveryCode); err != nil {
		t.Fatalf("新码应可再赎回: %v", err)
	}

	// 6. 新凭据可登录（身份已是激活态）。
	if _, err := loginOnce(t, svc, key2, credID2, regn.UserHandle); err != nil {
		t.Fatalf("新凭据登录失败: %v", err)
	}
}
