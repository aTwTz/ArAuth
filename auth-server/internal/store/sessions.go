package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Session 对应 sessions 表：opaque token 的 SHA-256，可吊销（不碰 JWT）。
type Session struct {
	TokenHash  []byte
	UserHandle []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// InsertSession 插入一条会话。token 生成与哈希属于 internal/session，
// 本方法只做写入。
func (s *Store) InsertSession(ctx context.Context, sess *Session) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (token_hash, user_handle, expires_at)
		 VALUES ($1, $2, $3)`,
		sess.TokenHash, sess.UserHandle, sess.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: 插入 session 失败: %w", err)
	}
	return nil
}

// GetSession 按 token 哈希取一条未过期会话，不存在或已过期返回
// ErrNotFound——两者对外不做区分（保密红线第 6 条）。
func (s *Store) GetSession(ctx context.Context, tokenHash []byte) (*Session, error) {
	sess := &Session{TokenHash: tokenHash}
	err := s.pool.QueryRow(ctx,
		`SELECT user_handle, created_at, expires_at FROM sessions
		 WHERE token_hash = $1 AND expires_at > now()`,
		tokenHash).
		Scan(&sess.UserHandle, &sess.CreatedAt, &sess.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: 查询 session 失败: %w", err)
	}
	return sess, nil
}
