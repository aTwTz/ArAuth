// Package authn 是 WebAuthn ceremony 的唯一裁决点：options/verify、
// BE/BS 提取、sign_count 分治策略。CBOR、attestation 解析与签名验证
// 一律经 go-webauthn/webauthn，禁止自写解析或自写验签。
package authn
