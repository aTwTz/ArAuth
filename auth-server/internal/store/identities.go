package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrNotFound 表示查询的记录不存在。对外错误响应不区分
// "哈希不匹配"与"记录不存在"（保密红线第 6 条），由上层统一兜底。
var ErrNotFound = errors.New("store: 记录不存在")

// Identity 对应 identities 表。user_handle 为 64 字节内随机数，
// 注册时塞进 WebAuthn user 字段，是定位身份的唯一锚点（不存任何用户名）。
type Identity struct {
	UserHandle  []byte
	CreatedAt   time.Time
	ActivatedAt *time.Time // 恢复码确认前为 NULL（pending）
}

// InsertIdentity 插入一条 pending 身份（activated_at 为 NULL）。
func (s *Store) InsertIdentity(ctx context.Context, userHandle []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO identities (user_handle) VALUES ($1)`, userHandle)
	if err != nil {
		return fmt.Errorf("store: 插入 identity 失败: %w", err)
	}
	return nil
}

// GetIdentity 按 user_handle 取身份，不存在时返回 ErrNotFound。
func (s *Store) GetIdentity(ctx context.Context, userHandle []byte) (*Identity, error) {
	id := &Identity{}
	err := s.pool.QueryRow(ctx,
		`SELECT user_handle, created_at, activated_at FROM identities WHERE user_handle = $1`,
		userHandle).
		Scan(&id.UserHandle, &id.CreatedAt, &id.ActivatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: 查询 identity 失败: %w", err)
	}
	return id, nil
}

// InsertRegistration 在一个事务内插入 pending identity、它的首条
// credential 与首枚恢复码的 SHA-256（codeHash）。注册闭环要求三者原子：
// 单独插 identity 可能留下永不可用的孤儿身份；恢复码不同步落库则
// pending 身份永远无法确认激活（DESIGN.md 第 4 节注册流程）。
func (s *Store) InsertRegistration(ctx context.Context, userHandle []byte, c *Credential, codeHash []byte) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: 开启注册事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err = tx.Exec(ctx,
		`INSERT INTO identities (user_handle) VALUES ($1)`, userHandle); err != nil {
		return fmt.Errorf("store: 插入 identity 失败: %w", err)
	}
	if _, err = tx.Exec(ctx,
		`INSERT INTO credentials
		 (credential_id, user_handle, public_key, backed_up, backup_state,
		  aaguid, attachment, transports, sign_count)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.CredentialID, userHandle, c.PublicKey, c.BackedUp, c.BackupState,
		c.AAGUID, c.Attachment, c.Transports, c.SignCount); err != nil {
		return fmt.Errorf("store: 插入 credential 失败: %w", err)
	}
	if _, err = tx.Exec(ctx,
		`INSERT INTO recovery_codes (user_handle, code_hash) VALUES ($1, $2)`,
		userHandle, codeHash); err != nil {
		return fmt.Errorf("store: 插入 recovery code 失败: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: 提交注册事务失败: %w", err)
	}
	return nil
}

// ActivateIdentity 把 pending identity 置为已激活（activated_at = now()）。
// 已激活或不存在时 0 行命中——confirm 是幂等操作，调用方已先行读取
// identity 做裁决，此处 0 行不视为错误（并发重复 confirm 天然无害）。
func (s *Store) ActivateIdentity(ctx context.Context, userHandle []byte) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE identities SET activated_at = now()
		 WHERE user_handle = $1 AND activated_at IS NULL`,
		userHandle); err != nil {
		return fmt.Errorf("store: 激活 identity 失败: %w", err)
	}
	return nil
}
