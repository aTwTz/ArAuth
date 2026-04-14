package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Credential 对应 credentials 表。公钥与元数据不是秘密（数据分级第 2 层）；
// BE/BS 只作提示元数据，flag 翻转容忍更新不拒绝（DESIGN.md 第 5 节）。
type Credential struct {
	CredentialID []byte
	UserHandle   []byte
	PublicKey    []byte // COSE 编码公钥
	BackedUp     bool   // BE flag
	BackupState  bool   // BS flag
	AAGUID       []byte
	Attachment   string
	Transports   []string
	SignCount    int64
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// InsertCredential 插入一条凭据。BE/BS、sign_count 的语义裁决在上层，
// 本方法只做写入。
func (s *Store) InsertCredential(ctx context.Context, c *Credential) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO credentials
		 (credential_id, user_handle, public_key, backed_up, backup_state,
		  aaguid, attachment, transports, sign_count)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.CredentialID, c.UserHandle, c.PublicKey, c.BackedUp, c.BackupState,
		c.AAGUID, c.Attachment, c.Transports, c.SignCount)
	if err != nil {
		return fmt.Errorf("store: 插入 credential 失败: %w", err)
	}
	return nil
}

const credentialColumns = `credential_id, user_handle, public_key, backed_up, backup_state,
	aaguid, attachment, transports, sign_count, created_at, last_used_at`

func scanCredential(row pgx.Row) (*Credential, error) {
	c := &Credential{}
	err := row.Scan(&c.CredentialID, &c.UserHandle, &c.PublicKey, &c.BackedUp,
		&c.BackupState, &c.AAGUID, &c.Attachment, &c.Transports, &c.SignCount,
		&c.CreatedAt, &c.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: 扫描 credential 失败: %w", err)
	}
	return c, nil
}

// GetCredential 按 credential_id 取凭据，不存在时返回 ErrNotFound。
func (s *Store) GetCredential(ctx context.Context, credentialID []byte) (*Credential, error) {
	return scanCredential(s.pool.QueryRow(ctx,
		`SELECT `+credentialColumns+` FROM credentials WHERE credential_id = $1`,
		credentialID))
}

// UpdateLoginSignals 登录验证通过后的信号落库：BE/BS 翻转容忍——断言
// flags 与存储不一致即更新存储，不拒绝（DESIGN.md 第 5 节）；last_used_at
// 刷新为当前时间。signCount 为 nil 时不回写 sign_count（同步型 passkey
// 恒为 0，规范允许，视为无操作）；非 nil 时的单调性裁决在 authn 完成，
// 本方法只做写入。
func (s *Store) UpdateLoginSignals(ctx context.Context, credentialID []byte, backedUp, backupState bool, signCount *int64) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE credentials
		 SET backed_up = $2, backup_state = $3, last_used_at = now(),
		     sign_count = CASE WHEN $4::BIGINT IS NULL THEN sign_count ELSE $4 END
		 WHERE credential_id = $1`,
		credentialID, backedUp, backupState, signCount)
	if err != nil {
		return fmt.Errorf("store: 更新登录信号失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListCredentialsByIdentity 取某身份下全部凭据，按创建时间升序。
func (s *Store) ListCredentialsByIdentity(ctx context.Context, userHandle []byte) ([]*Credential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+credentialColumns+` FROM credentials WHERE user_handle = $1 ORDER BY created_at`,
		userHandle)
	if err != nil {
		return nil, fmt.Errorf("store: 查询 credentials 失败: %w", err)
	}
	creds, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*Credential, error) {
		return scanCredential(row)
	})
	if err != nil {
		return nil, err
	}
	return creds, nil
}
