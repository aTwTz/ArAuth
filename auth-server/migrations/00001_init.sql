-- +goose Up
-- 五张表的唯一权威出处：docs/DESIGN.md 第 3 节。不得加列减列；
-- 库内无秘密——恢复码与会话只存 SHA-256 哈希，任何表不得出现密钥材料列。

CREATE TABLE identities (
    user_handle  BYTEA PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ
);

CREATE TABLE credentials (
    credential_id BYTEA PRIMARY KEY,
    user_handle   BYTEA NOT NULL REFERENCES identities (user_handle),
    public_key    BYTEA NOT NULL, -- COSE 编码公钥
    backed_up     BOOLEAN NOT NULL, -- BE flag
    backup_state  BOOLEAN NOT NULL, -- BS flag
    aaguid        BYTEA NOT NULL,
    attachment    TEXT NOT NULL DEFAULT '',
    transports    TEXT[] NOT NULL DEFAULT '{}',
    sign_count    BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);

CREATE INDEX idx_credentials_user_handle ON credentials (user_handle);

CREATE TABLE recovery_codes (
    user_handle BYTEA PRIMARY KEY REFERENCES identities (user_handle),
    code_hash   BYTEA NOT NULL UNIQUE, -- 恢复码的 SHA-256，一身份一码
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at  TIMESTAMPTZ
);

CREATE TABLE sessions (
    token_hash  BYTEA PRIMARY KEY, -- opaque token 的 SHA-256
    user_handle BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE exchange_codes (
    code_hash   BYTEA PRIMARY KEY, -- exchange code 的 SHA-256
    user_handle BYTEA NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ
);

-- +goose Down
-- 按外键依赖逆序回滚。
DROP TABLE exchange_codes;
DROP TABLE sessions;
DROP TABLE recovery_codes;
DROP TABLE credentials;
DROP TABLE identities;
