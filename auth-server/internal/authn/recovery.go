package authn

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
)

// RecoveryRegistration 是找回挂新密钥成功后下发给客户端的白名单字段
// （保密红线第 7 条）。RecoveryCode 是轮换后的新码原文，只在本响应里
// 出现一次（用后即焚——旧码哈希已在同一事务作废）。
type RecoveryRegistration struct {
	CredentialID []byte
	BackedUp     bool   // BE flag
	RecoveryCode string // 新恢复码原文，仅此一次
}

// BeginRecoveryRegistration 为找回流程生成 creation options：恢复凭证
// （一次性 token）定位原 user handle，options 绑定该 handle 而非新生成
// ——这是恢复凭证的唯一权限（DESIGN.md 第 4 节找回流程）。此阶段只查
// 不消费 token，消费点在 verify。
func (s *Service) BeginRecoveryRegistration(token []byte) (*protocol.CredentialCreation, error) {
	handle, ok := s.rec.LookupToken(token)
	if !ok {
		return nil, fmt.Errorf("%w: 恢复凭证无效", ErrInvalidCeremony)
	}
	return s.beginRegistration(handle)
}

// FinishRecoveryRegistration 验证 attestation 并把新凭据挂到原
// user_handle，同事务轮换恢复码：消费恢复凭证（一次性，不论后续成败）
// → 解析/消费 challenge → CreateCredential 全量验证 → 校验 challenge
// 会话的 UserID 与凭证 handle 一致（防凭证错配）→ 生成新码 →
// AttachCredentialAndRotate 原子落库。新码原文只经返回值传递一次。
func (s *Service) FinishRecoveryRegistration(ctx context.Context, r *http.Request, token []byte) (*RecoveryRegistration, error) {
	handle, ok := s.rec.ConsumeToken(token)
	if !ok {
		return nil, fmt.Errorf("%w: 恢复凭证无效", ErrInvalidCeremony)
	}

	pcc, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		return nil, fmt.Errorf("%w: 解析 attestation 响应: %v", ErrInvalidCeremony, err)
	}

	session, ok := s.challenges.consume(pcc.Response.CollectedClientData.Challenge)
	if !ok {
		return nil, fmt.Errorf("%w: challenge 无效", ErrInvalidCeremony)
	}
	if !bytes.Equal(session.UserID, handle) {
		return nil, fmt.Errorf("%w: challenge 与恢复凭证不匹配", ErrInvalidCeremony)
	}

	cred, err := s.wa.CreateCredential(newAnonUser(handle), session, pcc)
	if err != nil {
		return nil, fmt.Errorf("%w: attestation 验证: %v", ErrInvalidCeremony, err)
	}
	if err := s.checkAttestationFormat(cred); err != nil {
		return nil, err
	}

	display, codeHash, err := s.rec.Generate()
	if err != nil {
		return nil, fmt.Errorf("authn: 生成恢复码失败: %w", err)
	}

	record := credentialRecord(cred, handle)
	if err := s.st.AttachCredentialAndRotate(ctx, record, codeHash); err != nil {
		return nil, fmt.Errorf("authn: 找回落库失败: %w", err)
	}

	return &RecoveryRegistration{CredentialID: cred.ID, BackedUp: record.BackedUp, RecoveryCode: display}, nil
}
