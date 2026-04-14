package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ExchangeCode 对应 exchange_codes 表：一次性、短 TTL，只存 SHA-256。
type ExchangeCode struct {
	CodeHash   []byte
	UserHandle []byte
	BackedUp   bool // 签发该 code 的登录所观察到的 BE flag
	ExpiresAt  time.Time
	UsedAt     *time.Time // 核销后置位
}

// InsertExchangeCode 插入一条 exchange code。
func (s *Store) InsertExchangeCode(ctx context.Context, ec *ExchangeCode) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO exchange_codes (code_hash, user_handle, backed_up, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		ec.CodeHash, ec.UserHandle, ec.BackedUp, ec.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: 插入 exchange code 失败: %w", err)
	}
	return nil
}

// ConsumeExchangeCode 原子核销一条 exchange code：单条 UPDATE 同时完成
// 存在性、未使用、未过期三项校验与 used_at 置位，天然防重放与并发双兑。
// 任何一项不满足（或记录不存在）都返回 ErrNotFound——对外不区分原因
// （保密红线第 6 条）。
func (s *Store) ConsumeExchangeCode(ctx context.Context, codeHash []byte) (*ExchangeCode, error) {
	ec := &ExchangeCode{CodeHash: codeHash}
	err := s.pool.QueryRow(ctx,
		`UPDATE exchange_codes SET used_at = now()
		 WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
		 RETURNING user_handle, backed_up, expires_at`,
		codeHash).
		Scan(&ec.UserHandle, &ec.BackedUp, &ec.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: 核销 exchange code 失败: %w", err)
	}
	return ec, nil
}
