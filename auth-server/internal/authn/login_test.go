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
)

const loginFlagsBase = protocol.FlagUserPresent | protocol.FlagUserVerified

// loginFixture 是"已注册身份 + 一把钥匙"的登录测试脚手架：
// 先走通注册闭环（fakeStore 记下 credential 与 pending identity），
// 再按用例决定是否激活，然后发登录断言。
type loginFixture struct {
	svc        *Service
	fst        *fakeStore
	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
}

// register 走通注册闭环：attestation flags 固定 BE=1/BS=1（同步 passkey，
// 2026 年平台现实），signCount 由调用方指定。
func register(t *testing.T, signCount uint32) *loginFixture {
	t.Helper()
	fst := &fakeStore{}
	svc := newTestService(t, fst)

	creation, err := svc.BeginRegistration()
	if err != nil {
		t.Fatalf("BeginRegistration 失败: %v", err)
	}
	body, credID, key := buildAttestationResponse(t, fixtureSpec{
		rpID:      testRPID,
		origin:    testOrigin,
		challenge: b64url(creation.Response.Challenge),
		flags: loginFlagsBase | protocol.FlagAttestedCredentialData |
			protocol.FlagBackupEligible | protocol.FlagBackupState,
		signCount: signCount,
	})
	req := httptest.NewRequest("POST", "/register/verify", bytes.NewReader(body))
	if _, err := svc.FinishRegistration(context.Background(), req); err != nil {
		t.Fatalf("注册闭环失败: %v", err)
	}
	return &loginFixture{
		svc:        svc,
		fst:        fst,
		key:        key,
		credID:     credID,
		userHandle: fst.userHandle,
	}
}

// activate 把身份置为已激活（等效于 confirm 落地后的状态）。
func (f *loginFixture) activate() {
	now := time.Now()
	f.fst.identity.ActivatedAt = &now
}

// login 走通 options → assertion → FinishLogin，返回结果与错误。
func (f *loginFixture) login(t *testing.T, flags protocol.AuthenticatorFlags, signCount uint32) (*Login, error) {
	t.Helper()
	assertion, err := f.svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin 失败: %v", err)
	}
	body := buildAssertionResponse(t, f.key, f.credID, assertionSpec{
		rpID:       testRPID,
		origin:     testOrigin,
		challenge:  b64url(assertion.Response.Challenge),
		flags:      flags,
		signCount:  signCount,
		userHandle: f.userHandle,
	})
	req := httptest.NewRequest("POST", "/login/verify", bytes.NewReader(body))
	return f.svc.FinishLogin(context.Background(), req)
}

// TestFinishLoginHappyPath：合法断言 → 返回 user handle 与 backed_up，
// 落库一次信号更新（BE/BS 原样，sign_count 按分治规则）。
func TestFinishLoginHappyPath(t *testing.T) {
	t.Run("同步 passkey（存储 sign_count=0，不校验不回写）", func(t *testing.T) {
		fx := register(t, 0)
		fx.activate()

		lg, err := fx.login(t, loginFlagsBase|protocol.FlagBackupEligible|protocol.FlagBackupState, 0)
		if err != nil {
			t.Fatalf("FinishLogin 失败: %v", err)
		}
		if !bytes.Equal(lg.UserHandle, fx.userHandle) {
			t.Error("返回的 user handle 与注册不一致")
		}
		if !lg.BackedUp {
			t.Error("backed_up 应为 true（BE=1）")
		}
		if fx.fst.signalCalls != 1 {
			t.Fatalf("UpdateLoginSignals 调用 %d 次，期望 1", fx.fst.signalCalls)
		}
		if fx.fst.signalSC != nil {
			t.Errorf("存储 sign_count=0 时不得回写，得到 %v", *fx.fst.signalSC)
		}
	})

	t.Run("计数器凭据（存储 sign_count>0，单调递增回写）", func(t *testing.T) {
		fx := register(t, 7)
		fx.activate()

		_, err := fx.login(t, loginFlagsBase|protocol.FlagBackupEligible|protocol.FlagBackupState, 8)
		if err != nil {
			t.Fatalf("FinishLogin 失败: %v", err)
		}
		if fx.fst.signalSC == nil || *fx.fst.signalSC != 8 {
			t.Errorf("sign_count 应回写为 8，得到 %v", fx.fst.signalSC)
		}
	})
}

// TestFinishLoginPendingRejected：pending identity（activated_at 为 NULL）
// 的合法断言也必须拒绝，且单独归一为 ErrIdentityPending（server 映射
// 403，响应体仍是不可区分的 invalid）。
func TestFinishLoginPendingRejected(t *testing.T) {
	fx := register(t, 0) // 不调用 activate

	_, err := fx.login(t, loginFlagsBase|protocol.FlagBackupEligible|protocol.FlagBackupState, 0)
	if !errors.Is(err, ErrIdentityPending) {
		t.Fatalf("pending identity 应归一 ErrIdentityPending，得到: %v", err)
	}
	if fx.fst.signalCalls != 0 {
		t.Error("pending 拒绝前不得落库")
	}
}

// TestFinishLoginSignCountRegression：存储值 > 0 时断言计数不严格更大
// 即克隆信号，拒绝且不落库（DESIGN.md 第 5 节）。
func TestFinishLoginSignCountRegression(t *testing.T) {
	for _, counter := range []uint32{7, 3} { // 相等也算回退（库语义：<= 即克隆信号）
		fx := register(t, 7)
		fx.activate()

		_, err := fx.login(t, loginFlagsBase|protocol.FlagBackupEligible|protocol.FlagBackupState, counter)
		if !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("sign_count 回退（7 → %d）应拒绝，得到: %v", counter, err)
		}
		if fx.fst.signalCalls != 0 {
			t.Errorf("克隆信号场景不得落库（counter=%d）", counter)
		}
	}
}

// TestFinishLoginBEBSFlipTolerated：BE/BS 翻转是正常事件（iCloud 同步），
// 不得拒绝，且存储 flag 更新为断言值（DESIGN.md 第 5 节；go-webauthn
// 内置的 BE 一致性拒绝已被 authn 绕行）。
func TestFinishLoginBEBSFlipTolerated(t *testing.T) {
	fx := register(t, 0) // 存储 BE=1/BS=1
	fx.activate()

	// 断言翻转为 BE=0/BS=0（例如同步被用户关闭）
	lg, err := fx.login(t, loginFlagsBase, 0)
	if err != nil {
		t.Fatalf("BE/BS 翻转不得拒绝，得到: %v", err)
	}
	if lg.BackedUp {
		t.Error("backed_up 应为断言值 false")
	}
	if fx.fst.signalCalls != 1 || fx.fst.signalBE || fx.fst.signalBS {
		t.Errorf("落库 flags 应为断言值 false/false，得到 BE=%v BS=%v calls=%d",
			fx.fst.signalBE, fx.fst.signalBS, fx.fst.signalCalls)
	}
}

// TestFinishLoginRejections：伪造签名、未知/重放 challenge、畸形体
// 全部归一为 ErrInvalidCeremony。
func TestFinishLoginRejections(t *testing.T) {
	t.Run("伪造签名", func(t *testing.T) {
		fx := register(t, 0)
		fx.activate()
		assertion, err := fx.svc.BeginLogin()
		if err != nil {
			t.Fatalf("BeginLogin 失败: %v", err)
		}
		body := buildAssertionResponse(t, fx.key, fx.credID, assertionSpec{
			rpID: testRPID, origin: testOrigin,
			challenge:  b64url(assertion.Response.Challenge),
			flags:      loginFlagsBase | protocol.FlagBackupEligible | protocol.FlagBackupState,
			userHandle: fx.userHandle,
			badSig:     true,
		})
		req := httptest.NewRequest("POST", "/login/verify", bytes.NewReader(body))
		if _, err := fx.svc.FinishLogin(context.Background(), req); !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("应拒绝伪造签名，得到: %v", err)
		}
		if fx.fst.signalCalls != 0 {
			t.Error("伪造签名不得落库")
		}
	})

	t.Run("未知 challenge", func(t *testing.T) {
		fx := register(t, 0)
		fx.activate()
		body := buildAssertionResponse(t, fx.key, fx.credID, assertionSpec{
			rpID: testRPID, origin: testOrigin,
			challenge:  b64url([]byte("从未下发的 challenge")),
			flags:      loginFlagsBase | protocol.FlagBackupEligible | protocol.FlagBackupState,
			userHandle: fx.userHandle,
		})
		req := httptest.NewRequest("POST", "/login/verify", bytes.NewReader(body))
		if _, err := fx.svc.FinishLogin(context.Background(), req); !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("应拒绝未知 challenge，得到: %v", err)
		}
	})

	t.Run("重放同一断言", func(t *testing.T) {
		fx := register(t, 0)
		fx.activate()
		assertion, err := fx.svc.BeginLogin()
		if err != nil {
			t.Fatalf("BeginLogin 失败: %v", err)
		}
		body := buildAssertionResponse(t, fx.key, fx.credID, assertionSpec{
			rpID: testRPID, origin: testOrigin,
			challenge:  b64url(assertion.Response.Challenge),
			flags:      loginFlagsBase | protocol.FlagBackupEligible | protocol.FlagBackupState,
			userHandle: fx.userHandle,
		})
		finish := func() error {
			req := httptest.NewRequest("POST", "/login/verify", bytes.NewReader(body))
			_, err := fx.svc.FinishLogin(context.Background(), req)
			return err
		}
		if err := finish(); err != nil {
			t.Fatalf("首次登录应成功: %v", err)
		}
		if err := finish(); !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("重放应被拒绝，得到: %v", err)
		}
		if fx.fst.signalCalls != 1 {
			t.Errorf("重放后信号落库 = %d 次，期望仍为首秀的 1 次", fx.fst.signalCalls)
		}
	})

	t.Run("畸形请求体", func(t *testing.T) {
		fx := register(t, 0)
		fx.activate()
		req := httptest.NewRequest("POST", "/login/verify", bytes.NewReader([]byte("{不是 JSON")))
		if _, err := fx.svc.FinishLogin(context.Background(), req); !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("应拒绝畸形请求，得到: %v", err)
		}
	})
}

// TestBeginLoginShape：discoverable 断言不得下发 allowCredentials，
// userVerification 必须为 required。
func TestBeginLoginShape(t *testing.T) {
	svc := newTestService(t, &fakeStore{})

	assertion, err := svc.BeginLogin()
	if err != nil {
		t.Fatalf("BeginLogin 失败: %v", err)
	}
	if len(assertion.Response.AllowedCredentials) != 0 {
		t.Error("discoverable 登录不得下发 allowCredentials")
	}
	if assertion.Response.UserVerification != protocol.VerificationRequired {
		t.Errorf("userVerification = %q，期望 required", assertion.Response.UserVerification)
	}
	if len(assertion.Response.Challenge) == 0 {
		t.Error("challenge 不得为空")
	}
}
