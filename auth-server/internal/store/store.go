package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 持有 Postgres 连接池，按表提供最小方法集。
// 本包只做数据存取，不含业务校验（那是 authn/session/recovery 的职责）。
type Store struct {
	pool *pgxpool.Pool
}

// New 用 dsn 建立连接池并做一次连通性检查。
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: 解析 DSN 失败: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: 连接数据库失败: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close 释放连接池。
func (s *Store) Close() {
	s.pool.Close()
}
