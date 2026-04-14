package authn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/arithmaton/arauth/internal/store"
)

// Login 是登录 verify 成功后交给会话层的白名单信息（保密红线第 7 条）。
type Login struct {
	UserHandle []byte
	BackedUp   bool // 本次断言观察到的 BE flag（提示元数据，非安全裁决）
}

// BeginLogin 为 discoverable 登录生成 assertion options：不带
// allowCredentials（靠 user_handle 定位身份，DESIGN.md 第 3/4 节），
// 强制用户验证，challenge 暂存进内存（TTL 一次性）。
func (s *Service) BeginLogin() (*protocol.CredentialAssertion, error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("authn: 生成 assertion options 失败: %w", err)
	}

	s.challenges.put(*session)
	return assertion, nil
}

// FinishLogin 验证 discoverable 断言并按平台信号策略落库（DESIGN.md 第 5 节）。
// 解析响应 → 按 challenge 一次性消费会话 → user_handle 定位 identity
// （pending 单独归一为 ErrIdentityPending，由 server 映射 403）→
// ValidatePasskeyLogin 完成全部验证（challenge、origin、RP ID hash、签名
// 均由 go-webauthn 裁决）→ sign_count 分治与 BE/BS 翻转容忍 →
// 更新 last_used_at 与 flag。
func (s *Service) FinishLogin(ctx context.Context, r *http.Request) (*Login, error) {
	parsed, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		return nil, fmt.Errorf("%w: 解析 assertion 响应: %v", ErrInvalidCeremony, err)
	}

	session, ok := s.challenges.consume(parsed.Response.CollectedClientData.Challenge)
	if !ok {
		return nil, fmt.Errorf("%w: challenge 无效", ErrInvalidCeremony)
	}

	// BE/BS 翻转容忍绕行：go-webauthn v0.18.2 的 validateLogin 内置
	// "BE flag 与注册时不一致即拒绝"（Supabase 式事故行为），与 DESIGN.md
	// 第 5 节"翻转容忍、不拒绝"直接冲突。此处把喂给库的 credential flags
	// 用断言中的 flags 预置，使库的一致性检查恒通过；与存储值的比对和
	// 落库更新由下方自行裁决。验签等全部密码学验证仍在库内。
	assertionFlags := parsed.Response.AuthenticatorData.Flags
	assertionBE := assertionFlags.HasBackupEligible()
	assertionBS := assertionFlags.HasBackupState()

	var stored *storedCredential
	handler := func(rawID, _ []byte) (webauthn.User, error) {
		cred, err := s.st.GetCredential(ctx, rawID)
		if err != nil {
			return nil, fmt.Errorf("credential 查询失败: %v", err)
		}
		id, err := s.st.GetIdentity(ctx, cred.UserHandle)
		if err != nil {
			return nil, fmt.Errorf("identity 查询失败: %v", err)
		}
		if id.ActivatedAt == nil {
			// 恢复码未确认（pending）。此处仅标记原因，server 对外只给
			// 不可区分的 invalid（403 状态码 + 不泄露原因）。
			return nil, ErrIdentityPending
		}
		stored = &storedCredential{
			record: cred,
			user: newLoginUser(cred.UserHandle, webauthn.Credential{
				ID:        cred.CredentialID,
				PublicKey: cred.PublicKey,
				Flags:     webauthn.NewCredentialFlags(assertionFlags),
				Authenticator: webauthn.Authenticator{
					AAGUID:    cred.AAGUID,
					SignCount: uint32(cred.SignCount),
				},
			}),
		}
		return stored.user, nil
	}

	if _, _, err = s.wa.ValidatePasskeyLogin(handler, session, parsed); err != nil {
		if errors.Is(err, ErrIdentityPending) {
			return nil, ErrIdentityPending
		}
		return nil, fmt.Errorf("%w: assertion 验证: %v", ErrInvalidCeremony, err)
	}
	if stored == nil {
		return nil, fmt.Errorf("%w: credential 定位失败", ErrInvalidCeremony)
	}

	// sign_count 分治（DESIGN.md 第 5 节）：前值 > 0 强制单调递增，
	// 回退 = 克隆信号，拒绝并记录；前值恒 0（同步型 passkey）不校验、不回写。
	var signCount *int64
	if stored.record.SignCount > 0 {
		counter := int64(parsed.Response.AuthenticatorData.Counter)
		if counter <= stored.record.SignCount {
			log.Printf("authn: 克隆信号：credential_id=%s sign_count 回退（存储 %d，断言 %d），拒绝登录",
				base64.RawURLEncoding.EncodeToString(stored.record.CredentialID),
				stored.record.SignCount, counter)
			return nil, fmt.Errorf("%w: sign_count 回退", ErrInvalidCeremony)
		}
		signCount = &counter
	}

	if err := s.st.UpdateLoginSignals(ctx, stored.record.CredentialID, assertionBE, assertionBS, signCount); err != nil {
		return nil, fmt.Errorf("authn: 登录信号落库失败: %w", err)
	}

	return &Login{UserHandle: stored.record.UserHandle, BackedUp: assertionBE}, nil
}

// storedCredential 是 handler 闭包捕获的上下文：库验证通过后才落库，
// 需要存储记录做 sign_count 分治与白名单返回。
type storedCredential struct {
	record *store.Credential
	user   *loginUser
}
