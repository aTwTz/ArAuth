-- +goose Up
-- TOTP 是恢复码之外的并行找回通道。种子只能以 AEAD 密文落库，主密钥由
-- 进程环境独立注入；recovery_id 只是高熵定位符，本身不是恢复凭证。
CREATE TABLE recovery_totp (
    user_handle              BYTEA PRIMARY KEY REFERENCES identities (user_handle),
    recovery_id              TEXT NOT NULL UNIQUE,
    secret_ciphertext        BYTEA NOT NULL,
    key_version              INTEGER NOT NULL CHECK (key_version > 0),
    last_used_step           BIGINT NOT NULL DEFAULT -1 CHECK (last_used_step >= -1),
    failure_window_started_at TIMESTAMPTZ,
    failed_attempts          INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE recovery_totp;
