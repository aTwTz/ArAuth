package authn

import (
	"encoding/base64"

	"github.com/go-webauthn/webauthn/webauthn"
)

// userHandleLen 是 user handle 的字节数：WebAuthn user.id 上限 64 字节，
// 全部用满、纯 crypto/rand（DESIGN.md 第 3 节）。
const userHandleLen = 64

// anonUser 实现 webauthn.User。极端匿名：无用户名，name/displayName
// 一律取 user handle 的 base64——它们只是展示字段，身份裁决永远只看 handle。
type anonUser struct {
	handle []byte
}

func newAnonUser(handle []byte) *anonUser {
	return &anonUser{handle: handle}
}

// WebAuthnID 返回 64 字节 user handle。
func (u *anonUser) WebAuthnID() []byte {
	return u.handle
}

// WebAuthnName 返回 handle 的 base64（匿名占位，不是用户名）。
func (u *anonUser) WebAuthnName() string {
	return base64.RawURLEncoding.EncodeToString(u.handle)
}

// WebAuthnDisplayName 同 WebAuthnName。
func (u *anonUser) WebAuthnDisplayName() string {
	return u.WebAuthnName()
}

// WebAuthnCredentials 注册新身份时永远为空（不做 excludeCredentials）。
func (u *anonUser) WebAuthnCredentials() []webauthn.Credential {
	return nil
}

// loginUser 是 discoverable 登录时喂给 go-webauthn 的用户视图：handle
// 取自存储记录（不信任断言带回的 userHandle——库会比对两者，不一致即
// 拒绝），credentials 只含本次断言命中的一条。
type loginUser struct {
	handle []byte
	cred   webauthn.Credential
}

func newLoginUser(handle []byte, cred webauthn.Credential) *loginUser {
	return &loginUser{handle: handle, cred: cred}
}

func (u *loginUser) WebAuthnID() []byte { return u.handle }

func (u *loginUser) WebAuthnName() string {
	return base64.RawURLEncoding.EncodeToString(u.handle)
}

func (u *loginUser) WebAuthnDisplayName() string { return u.WebAuthnName() }

func (u *loginUser) WebAuthnCredentials() []webauthn.Credential {
	return []webauthn.Credential{u.cred}
}
