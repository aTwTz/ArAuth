package authn

// 测试 fixture：手工构造合法（或按用例伪造）的 WebAuthn attestation 响应。
// 这里只做测试数据生成——ceremony 的解析与验证全部仍在 go-webauthn 内
// （纪律：禁止自写解析/验签，约束的是实现代码而非测试数据构造）。
// CBOR 编码使用 fxamacker/cbor（go-webauthn 的传递依赖，仅测试使用）。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

// b64url 编码为无填充 base64url（challenge 等字段的线上编码形态）。
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// fixtureSpec 描述要构造的 attestation 响应。
type fixtureSpec struct {
	rpID       string
	origin     string
	challenge  string // base64url，须与 options 下发的一致
	flags      protocol.AuthenticatorFlags
	forgedSig  bool // true 时用 packed 格式填垃圾签名（伪造签名用例）
	signCount  uint32
	attachment string
	transports []string
}

// buildAttestationResponse 生成一份 credential creation 响应 JSON，
// 返回凭据 ID 与私钥（供登录断言 fixture 复用同一把钥匙签名）。
// 默认使用 attestation 格式 "none"。
func buildAttestationResponse(t *testing.T, spec fixtureSpec) (body []byte, credentialID []byte, key *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("生成凭据 ID 失败: %v", err)
	}
	aaguid := make([]byte, 16)
	if _, err := rand.Read(aaguid); err != nil {
		t.Fatalf("生成 AAGUID 失败: %v", err)
	}

	// COSE ES256 公钥：{1:2 (EC2), 3:-7 (ES256), -1:1 (P-256), -2:x, -3:y}
	coseKey, err := cbor.Marshal(map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: key.PublicKey.X.Bytes(),
		-3: key.PublicKey.Y.Bytes(),
	})
	if err != nil {
		t.Fatalf("编码 COSE 公钥失败: %v", err)
	}

	// authenticator data：rpIdHash ‖ flags ‖ signCount ‖ attestedCredentialData
	rpIDHash := sha256.Sum256([]byte(spec.rpID))
	authData := make([]byte, 0, 128)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, byte(spec.flags))
	authData = binary.BigEndian.AppendUint32(authData, spec.signCount)
	authData = append(authData, aaguid...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credID)))
	authData = append(authData, credID...)
	authData = append(authData, coseKey...)

	var attStmt map[string]any
	format := "none"
	if spec.forgedSig {
		format = "packed"
		garbage := make([]byte, 64)
		if _, err := rand.Read(garbage); err != nil {
			t.Fatalf("生成垃圾签名失败: %v", err)
		}
		attStmt = map[string]any{"alg": -7, "sig": garbage}
	} else {
		attStmt = map[string]any{}
	}
	attestationObject, err := cbor.Marshal(map[string]any{
		"fmt":      format,
		"attStmt":  attStmt,
		"authData": authData,
	})
	if err != nil {
		t.Fatalf("编码 attestation object 失败: %v", err)
	}

	clientDataJSON, err := json.Marshal(map[string]any{
		"type":        "webauthn.create",
		"challenge":   spec.challenge,
		"origin":      spec.origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("编码 clientDataJSON 失败: %v", err)
	}

	b64 := base64.RawURLEncoding.EncodeToString
	response := map[string]any{
		"id":    b64(credID),
		"rawId": b64(credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientDataJSON),
			"attestationObject": b64(attestationObject),
			"transports":        spec.transports,
		},
		"authenticatorAttachment": spec.attachment,
		"clientExtensionResults":  map[string]any{},
	}
	body, err = json.Marshal(response)
	if err != nil {
		t.Fatalf("编码响应 JSON 失败: %v", err)
	}
	return body, credID, key
}

// assertionSpec 描述要构造的 assertion（登录）响应。
type assertionSpec struct {
	rpID       string
	origin     string
	challenge  string // base64url，须与 options 下发的一致
	flags      protocol.AuthenticatorFlags
	signCount  uint32
	userHandle []byte // 断言带回的 user handle（discoverable）
	badSig     bool   // true 时用另一把钥匙签名（伪造签名用例）
}

// buildAssertionResponse 用注册时的私钥生成一份 assertion 响应 JSON：
// authenticatorData = rpIdHash ‖ flags ‖ signCount（不含 attested data），
// signature = ECDSA(authData ‖ SHA-256(clientDataJSON))。
func buildAssertionResponse(t *testing.T, key *ecdsa.PrivateKey, credentialID []byte, spec assertionSpec) []byte {
	t.Helper()

	rpIDHash := sha256.Sum256([]byte(spec.rpID))
	authData := make([]byte, 0, 64)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, byte(spec.flags))
	authData = binary.BigEndian.AppendUint32(authData, spec.signCount)

	clientDataJSON, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   spec.challenge,
		"origin":      spec.origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("编码 clientDataJSON 失败: %v", err)
	}

	signingKey := key
	if spec.badSig {
		signingKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("生成伪造密钥失败: %v", err)
		}
	}
	clientDataHash := sha256.Sum256(clientDataJSON)
	digest := sha256.Sum256(append(authData, clientDataHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, signingKey, digest[:])
	if err != nil {
		t.Fatalf("签名断言失败: %v", err)
	}

	b64 := base64.RawURLEncoding.EncodeToString
	response := map[string]any{
		"id":    b64(credentialID),
		"rawId": b64(credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientDataJSON),
			"authenticatorData": b64(authData),
			"signature":         b64(sig),
			"userHandle":        b64(spec.userHandle),
		},
		"clientExtensionResults": map[string]any{},
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("编码响应 JSON 失败: %v", err)
	}
	return body
}
