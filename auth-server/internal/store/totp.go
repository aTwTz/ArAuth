package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// RecoveryTOTP 是一身份一条的活跃 TOTP 找回记录。SecretCiphertext 是
// 带随机 nonce 的 AES-GCM 密文；明文种子和主密钥不属于数据层。
type RecoveryTOTP struct {
	UserHandle             []byte
	RecoveryID             string
	SecretCiphertext       []byte
	KeyVersion             int
	LastUsedStep           int64
	FailureWindowStartedAt *time.Time
	FailedAttempts         int
}

// UpsertRecoveryTOTP 只在 setup confirm 成功后调用。替换已有记录时保留
// created_at，并重置防重放和失败状态；begin 阶段不得调用本方法。
func (s *Store) UpsertRecoveryTOTP(ctx context.Context, rec *RecoveryTOTP) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO recovery_totp
		 (user_handle, recovery_id, secret_ciphertext, key_version, last_used_step)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (user_handle) DO UPDATE SET
		   recovery_id = EXCLUDED.recovery_id,
		   secret_ciphertext = EXCLUDED.secret_ciphertext,
		   key_version = EXCLUDED.key_version,
		   last_used_step = EXCLUDED.last_used_step,
		   failure_window_started_at = NULL,
		   failed_attempts = 0,
		   updated_at = now()`,
		rec.UserHandle, rec.RecoveryID, rec.SecretCiphertext, rec.KeyVersion, rec.LastUsedStep)
	if err != nil {
		return fmt.Errorf("store: 保存 TOTP 找回记录失败: %w", err)
	}
	return nil
}

// GetRecoveryTOTP 按非秘密定位符取活跃记录。不存在统一为 ErrNotFound。
func (s *Store) GetRecoveryTOTP(ctx context.Context, recoveryID string) (*RecoveryTOTP, error) {
	rec := &RecoveryTOTP{RecoveryID: recoveryID}
	err := s.pool.QueryRow(ctx,
		`SELECT user_handle, secret_ciphertext, key_version, last_used_step,
		        failure_window_started_at, failed_attempts
		 FROM recovery_totp WHERE recovery_id = $1`, recoveryID).
		Scan(&rec.UserHandle, &rec.SecretCiphertext, &rec.KeyVersion, &rec.LastUsedStep,
			&rec.FailureWindowStartedAt, &rec.FailedAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: 查询 TOTP 找回记录失败: %w", err)
	}
	return rec, nil
}

// ConsumeRecoveryTOTPStep 原子推进时间步。条件更新保证同一时间步的并发
// 请求至多一个成功，也禁止在较新时间步消费后回退使用旧动态码。
func (s *Store) ConsumeRecoveryTOTPStep(ctx context.Context, userHandle []byte, step int64) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE recovery_totp
		 SET last_used_step = $2, failure_window_started_at = NULL,
		     failed_attempts = 0, updated_at = now()
		 WHERE user_handle = $1 AND last_used_step < $2`,
		userHandle, step)
	if err != nil {
		return fmt.Errorf("store: 消费 TOTP 时间步失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordRecoveryTOTPFailure 原子记录一次错码。窗口过期时从 1 重新计数；
// 时间步消费成功会由 ConsumeRecoveryTOTPStep 清空该状态。
func (s *Store) RecordRecoveryTOTPFailure(ctx context.Context, userHandle []byte, now time.Time, window time.Duration) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE recovery_totp
		 SET failed_attempts = CASE
		       WHEN failure_window_started_at IS NULL
		         OR failure_window_started_at + make_interval(secs => $2::double precision) <= $3
		       THEN 1 ELSE failed_attempts + 1 END,
		     failure_window_started_at = CASE
		       WHEN failure_window_started_at IS NULL
		         OR failure_window_started_at + make_interval(secs => $2::double precision) <= $3
		       THEN $3 ELSE failure_window_started_at END,
		     updated_at = $3
		 WHERE user_handle = $1`,
		userHandle, window.Seconds(), now)
	if err != nil {
		return fmt.Errorf("store: 记录 TOTP 失败: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
