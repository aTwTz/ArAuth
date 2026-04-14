package main

// 虚拟验证器（virtual authenticator）：模拟一台平台验证器（Windows Hello /
// 安全芯片 / 手机）持有私钥并产出 WebAuthn attestation/assertion。
// 构造手法与 internal/authn 的测试 fixture 一致——这里只生成 ceremony
// 数据，解析与验签全部仍在 arauth 侧的 go-webauthn 内（纪律：禁止自写
// 解析/验签，约束的是服务端实现而非测试数据构造）。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// authenticator flags（WebAuthn §6.1）。与 go-webauthn protocol 包常量同值，
// 这里直接写字面值以免仅为几个常量引入整个 webauthn 依赖。
const (
	flagUserPresent    = 0x01 // UP
	flagUserVerified   = 0x04 // UV
	flagBackupEligible = 0x08 // BE
	flagBackupState    = 0x10 // BS
	flagAttestedCred   = 0x40 // AT
)

// authenticator 是一把虚拟 passkey：P-256 私钥 + 凭据 ID + AAGUID。
// 模拟 2026 年平台现实（DESIGN.md 第 5 节）：可同步 passkey，BE=BS=1。
type authenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	aaguid []byte
}

func newAuthenticator() (*authenticator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成验证器密钥失败: %w", err)
	}
	a := &authenticator{key: key, credID: make([]byte, 32), aaguid: make([]byte, 16)}
	if _, err := rand.Read(a.credID); err != nil {
		return nil, err
	}
	if _, err := rand.Read(a.aaguid); err != nil {
		return nil, err
	}
	return a, nil
}

// attestation 产出 credentials.create() 的响应 JSON（attestation 格式
// "none"——与平台默认一致；challenge 为 options 里下发的 base64url 原串）。
func (a *authenticator) attestation(rpID, origin, challenge string) ([]byte, error) {
	// COSE ES256 公钥：{1:2 (EC2), 3:-7 (ES256), -1:1 (P-256), -2:x, -3:y}
	coseKey, err := cbor.Marshal(map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: a.key.PublicKey.X.Bytes(),
		-3: a.key.PublicKey.Y.Bytes(),
	})
	if err != nil {
		return nil, fmt.Errorf("编码 COSE 公钥失败: %w", err)
	}

	// authenticator data：rpIdHash ‖ flags ‖ signCount ‖ attestedCredentialData。
	// signCount 恒 0：同步型 passkey 规范允许（DESIGN.md 第 5 节 sign_count 分治）。
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 0, 128)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flagUserPresent|flagUserVerified|flagBackupEligible|flagBackupState|flagAttestedCred)
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, a.aaguid...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(a.credID)))
	authData = append(authData, a.credID...)
	authData = append(authData, coseKey...)

	attestationObject, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		return nil, fmt.Errorf("编码 attestation object 失败: %w", err)
	}

	clientDataJSON, err := json.Marshal(map[string]any{
		"type":        "webauthn.create",
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}

	b64 := base64.RawURLEncoding.EncodeToString
	return json.Marshal(map[string]any{
		"id":    b64(a.credID),
		"rawId": b64(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientDataJSON),
			"attestationObject": b64(attestationObject),
			"transports":        []string{"internal"},
		},
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{},
	})
}

// assertion 产出 credentials.get() 的响应 JSON：
// authenticatorData = rpIdHash ‖ flags ‖ signCount（恒 0，同步 passkey），
// signature = ECDSA(authData ‖ SHA-256(clientDataJSON))。
// userHandle 为注册时下发的 64 字节 handle（discoverable 断言原样带回）。
func (a *authenticator) assertion(rpID, origin, challenge string, userHandle []byte) ([]byte, error) {
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 0, 64)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flagUserPresent|flagUserVerified|flagBackupEligible|flagBackupState)
	authData = binary.BigEndian.AppendUint32(authData, 0)

	clientDataJSON, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}

	clientDataHash := sha256.Sum256(clientDataJSON)
	digest := sha256.Sum256(append(authData, clientDataHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("签名断言失败: %w", err)
	}

	b64 := base64.RawURLEncoding.EncodeToString
	return json.Marshal(map[string]any{
		"id":    b64(a.credID),
		"rawId": b64(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientDataJSON),
			"authenticatorData": b64(authData),
			"signature":         b64(sig),
			"userHandle":        b64(userHandle),
		},
		"clientExtensionResults": map[string]any{},
	})
}
