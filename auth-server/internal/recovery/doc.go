// Package recovery 负责一次性恢复码与可选 TOTP 两条并行找回通道。
// 恢复码只存 SHA-256 并用后即焚轮换；TOTP 种子只存 AEAD 密文，
// 两者验证成功都签发同一种一次性 recovery token。
package recovery
