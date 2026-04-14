package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// RecoveryCode 对应 recovery_codes 表：一身份一码，只存恢复码的 SHA-256。
// 凡是需要"找回原文"的设计都直接拒绝（数据分级第 3 条）。
type RecoveryCode struct {
	UserHandle []byte
	CodeHash   []byte // 恢复码的 SHA-256
	CreatedAt  time.Time
	RotatedAt  *time.Time // 轮换后置位
}

// GetRecoveryCodeByHash 按 SHA-256 哈希取恢复码记录（兑换的唯一查询
// 入口）。不存在（含已轮换的旧哈希）返回 ErrNotFound——对外不区分
// "哈希不匹配"与"记录不存在"（保密红线第 6 条）。
func (s *Store) GetRecoveryCodeByHash(ctx context.Context, codeHash []byte) (*RecoveryCode, error) {
	rc := &RecoveryCode{CodeHash: codeHash}
	err := s.pool.QueryRow(ctx,
		`SELECT user_handle, created_at, rotated_at FROM recovery_codes WHERE code_hash = $1`,
		codeHash).
		Scan(&rc.UserHandle, &rc.CreatedAt, &rc.RotatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: 查询 recovery code 失败: %w", err)
	}
	return rc, nil
}

// AttachCredentialAndRotate 在一个事务内完成找回闭环的落库（DESIGN.md
// 第 4 节"找回"）：把新凭据挂到已有 identity，同时轮换恢复码
// （code_hash 换新、rotated_at 置位——用后即焚，旧哈希即刻作废）。
// 失败整体回滚，不允许"挂了新密钥但码没换"的半态。
func (s *Store) AttachCredentialAndRotate(ctx context.Context, c *Credential, newCodeHash []byte) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: 开启找回事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err = tx.Exec(ctx,
		`INSERT INTO credentials
		 (credential_id, user_handle, public_key, backed_up, backup_state,
		  aaguid, attachment, transports, sign_count)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.CredentialID, c.UserHandle, c.PublicKey, c.BackedUp, c.BackupState,
		c.AAGUID, c.Attachment, c.Transports, c.SignCount); err != nil {
		return fmt.Errorf("store: 找回挂新凭据失败: %w", err)
	}
	tag, err := tx.Exec(ctx,
		`UPDATE recovery_codes SET code_hash = $2, rotated_at = now()
		 WHERE user_handle = $1`,
		c.UserHandle, newCodeHash)
	if err != nil {
		return fmt.Errorf("store: 轮换恢复码失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: 轮换恢复码失败: %w", ErrNotFound)
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: 提交找回事务失败: %w", err)
	}
	return nil
}
