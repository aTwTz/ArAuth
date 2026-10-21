// Package store 是 Postgres 数据层（pgx/v5）：identities、credentials、
// sessions、recovery_codes、recovery_totp、exchange_codes。恢复码与会话
// token 只存 SHA-256；TOTP 种子只存 AES-GCM 密文，主密钥始终在库外。
package store
