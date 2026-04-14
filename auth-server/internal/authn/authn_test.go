package authn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/store"
)

const (
	testRPID   = "example.com"
	testOrigin = "https://a.example.com"
)

// fakeStore 记录 InsertRegistration / UpdateLoginSignals /
// AttachCredentialAndRotate 调用，供断言落库内容；GetCredential /
// GetIdentity 按注册时记录的内容回放。
type fakeStore struct {
	calls      int
	userHandle []byte
	cred       *store.Credential
	codeHash   []byte
	identity   *store.Identity
	err        error

	signalCalls int
	signalBE    bool
	signalBS    bool
	signalSC    *int64
	signalErr   error

	attached    []*store.Credential
	rotatedHash []byte
	attachErr   error
}

func (f *fakeStore) InsertRegistration(_ context.Context, userHandle []byte, c *store.Credential, codeHash []byte) error {
	f.calls++
	f.userHandle = userHandle
	f.cred = c
	f.codeHash = codeHash
	f.identity = &store.Identity{UserHandle: userHandle, CreatedAt: time.Now()} // 落库即 pending
	return f.err
}

func (f *fakeStore) GetCredential(_ context.Context, credentialID []byte) (*store.Credential, error) {
	if f.cred == nil || !bytes.Equal(f.cred.CredentialID, credentialID) {
		return nil, store.ErrNotFound
	}
	return f.cred, nil
}

func (f *fakeStore) GetIdentity(_ context.Context, userHandle []byte) (*store.Identity, error) {
	if f.identity == nil || !bytes.Equal(f.identity.UserHandle, userHandle) {
		return nil, store.ErrNotFound
	}
	return f.identity, nil
}

func (f *fakeStore) ActivateIdentity(_ context.Context, userHandle []byte) error {
	now := time.Now()
	f.identity.ActivatedAt = &now
	return nil
}

func (f *fakeStore) UpdateLoginSignals(_ context.Context, credentialID []byte, backedUp, backupState bool, signCount *int64) error {
	f.signalCalls++
	f.signalBE = backedUp
	f.signalBS = backupState
	f.signalSC = signCount
	return f.signalErr
}

func (f *fakeStore) AttachCredentialAndRotate(_ context.Context, c *store.Credential, newCodeHash []byte) error {
	if f.attachErr != nil {
		return f.attachErr
	}
	f.attached = append(f.attached, c)
	f.rotatedHash = newCodeHash
	return nil
}

// fakeRecovery 是 RecoveryGate 的测试实现：Generate 依次发固定展示串，
// token 用简单 map 模拟一次性语义。
type fakeRecovery struct {
	genCalls int
	genErr   error
	tokens   map[string][]byte
}

func newFakeRecovery() *fakeRecovery {
	return &fakeRecovery{tokens: map[string][]byte{}}
}

func (f *fakeRecovery) Generate() (string, []byte, error) {
	if f.genErr != nil {
		return "", nil, f.genErr
	}
	f.genCalls++
	display := fmt.Sprintf("test-code-%04d", f.genCalls)
	sum := sha256.Sum256([]byte(display))
	return display, sum[:], nil
}

// issueToken 直接放入一枚恢复凭证（模拟 redeem 成功后的状态）。
func (f *fakeRecovery) issueToken(token, userHandle []byte) {
	f.tokens[string(token)] = userHandle
}

func (f *fakeRecovery) LookupToken(token []byte) ([]byte, bool) {
	h, ok := f.tokens[string(token)]
	return h, ok
}

func (f *fakeRecovery) ConsumeToken(token []byte) ([]byte, bool) {
	h, ok := f.tokens[string(token)]
	delete(f.tokens, string(token))
	return h, ok
}

func newTestService(t *testing.T, st CredentialStore) *Service {
	t.Helper()
	return newTestServiceWith(t, st, newFakeRecovery())
}

func newTestServiceWith(t *testing.T, st CredentialStore, rec RecoveryGate) *Service {
	t.Helper()
	svc, err := New(&config.Config{
		RPID:         testRPID,
		RPOrigins:    []string{testOrigin, "https://b.example.com"},
		ChallengeTTL: 5 * time.Minute,
		PendingTTL:   24 * time.Hour,
	}, st, rec)
	if err != nil {
		t.Fatalf("authn.New 失败: %v", err)
	}
	return svc
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(&config.Config{}, &fakeStore{}, newFakeRecovery()); err == nil {
		t.Fatal("缺 RPID/RPOrigins 时 New 应报错")
	}
}

// TestBeginRegistrationShape 断言 options JSON 形状可被浏览器
// PublicKeyCredential.parseCreationOptionsFromJSON 消费：
// publicKey 包装、base64url 字段、residentKey/userVerification 必填。
func TestBeginRegistrationShape(t *testing.T) {
	svc := newTestService(t, &fakeStore{})

	creation, err := svc.BeginRegistration()
	if err != nil {
		t.Fatalf("BeginRegistration 失败: %v", err)
	}

	raw, err := json.Marshal(creation)
	if err != nil {
		t.Fatalf("序列化 options 失败: %v", err)
	}
	var doc struct {
		PublicKey struct {
			RP struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				DisplayName string `json:"displayName"`
			} `json:"user"`
			Challenge string `json:"challenge"`
			Selection struct {
				RequireResidentKey *bool  `json:"requireResidentKey"`
				ResidentKey        string `json:"residentKey"`
				UserVerification   string `json:"userVerification"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("options 不是合法 JSON: %v", err)
	}

	pk := doc.PublicKey
	if pk.RP.ID != testRPID {
		t.Errorf("rp.id = %q，期望 %q（显式下发，绝不省略）", pk.RP.ID, testRPID)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(pk.Challenge)
	if err != nil || len(challenge) == 0 {
		t.Errorf("challenge 不是合法 base64url: %q", pk.Challenge)
	}
	userID, err := base64.RawURLEncoding.DecodeString(pk.User.ID)
	if err != nil || len(userID) != userHandleLen {
		t.Errorf("user.id 应为 %d 字节 base64url，得到 %d 字节（err=%v）", userHandleLen, len(userID), err)
	}
	// 匿名：name/displayName 是 user handle 的 base64，不含任何用户名
	wantName := base64.RawURLEncoding.EncodeToString(userID)
	if pk.User.Name != wantName || pk.User.DisplayName != wantName {
		t.Errorf("name/displayName 应为 handle 的 base64: %q / %q", pk.User.Name, pk.User.DisplayName)
	}
	if pk.Selection.ResidentKey != "required" {
		t.Errorf("residentKey = %q，期望 required（discoverable）", pk.Selection.ResidentKey)
	}
	if pk.Selection.RequireResidentKey == nil || !*pk.Selection.RequireResidentKey {
		t.Error("requireResidentKey 应为 true")
	}
	if pk.Selection.UserVerification != "required" {
		t.Errorf("userVerification = %q，期望 required", pk.Selection.UserVerification)
	}
}

// TestFinishRegistrationHappyPath 走通 options → 合法 attestation → verify，
// 断言落库的 identity(pending) + credential 各一份，BE/BS 与 flags 一致。
func TestFinishRegistrationHappyPath(t *testing.T) {
	cases := map[string]struct {
		flags      protocol.AuthenticatorFlags
		wantBE     bool
		wantBS     bool
		signCount  uint32
		attachment string
		transports []string
	}{
		"同步 passkey（BE=1 BS=1）": {
			flags:      protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagAttestedCredentialData | protocol.FlagBackupEligible | protocol.FlagBackupState,
			wantBE:     true,
			wantBS:     true,
			signCount:  0, // 同步 passkey 恒 0（DESIGN.md 第 5 节）
			attachment: "platform",
			transports: []string{"internal", "hybrid"},
		},
		"设备绑定密钥（BE=0 BS=0）": {
			flags:      protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagAttestedCredentialData,
			wantBE:     false,
			wantBS:     false,
			signCount:  7,
			attachment: "cross-platform",
			transports: []string{"usb"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fst := &fakeStore{}
			svc := newTestService(t, fst)

			creation, err := svc.BeginRegistration()
			if err != nil {
				t.Fatalf("BeginRegistration 失败: %v", err)
			}

			body, credID, _ := buildAttestationResponse(t, fixtureSpec{
				rpID:       testRPID,
				origin:     testOrigin,
				challenge:  b64url(creation.Response.Challenge),
				flags:      tc.flags,
				signCount:  tc.signCount,
				attachment: tc.attachment,
				transports: tc.transports,
			})

			req := httptest.NewRequest("POST", "/register/verify", bytes.NewReader(body))
			regn, err := svc.FinishRegistration(context.Background(), req)
			if err != nil {
				t.Fatalf("FinishRegistration 失败: %v", err)
			}

			if fst.calls != 1 {
				t.Fatalf("InsertRegistration 调用 %d 次，期望 1", fst.calls)
			}
			if len(fst.userHandle) != userHandleLen {
				t.Errorf("user handle 长度 = %d，期望 %d", len(fst.userHandle), userHandleLen)
			}
			c := fst.cred
			if !bytes.Equal(c.CredentialID, credID) || !bytes.Equal(regn.CredentialID, credID) {
				t.Error("credential ID 与 fixture 不一致")
			}
			if !bytes.Equal(c.UserHandle, fst.userHandle) {
				t.Error("credential 未挂到新 identity 的 handle 上")
			}
			if c.BackedUp != tc.wantBE || c.BackupState != tc.wantBS {
				t.Errorf("BE/BS = %v/%v，期望 %v/%v（须与 attestation flags 一致）",
					c.BackedUp, c.BackupState, tc.wantBE, tc.wantBS)
			}
			if regn.BackedUp != tc.wantBE {
				t.Errorf("返回值 backed_up = %v，期望 %v", regn.BackedUp, tc.wantBE)
			}
			if len(c.PublicKey) == 0 {
				t.Error("COSE 公钥未提取")
			}
			if len(c.AAGUID) != 16 {
				t.Errorf("AAGUID 长度 = %d，期望 16", len(c.AAGUID))
			}
			if c.Attachment != tc.attachment {
				t.Errorf("attachment = %q，期望 %q", c.Attachment, tc.attachment)
			}
			if len(c.Transports) != len(tc.transports) || c.Transports[0] != tc.transports[0] {
				t.Errorf("transports = %v，期望 %v", c.Transports, tc.transports)
			}
			if c.SignCount != int64(tc.signCount) {
				t.Errorf("sign_count = %d，期望 %d", c.SignCount, tc.signCount)
			}
			// 恢复码发放：返回值带原文（仅此一次），落库的是 SHA-256 哈希
			if regn.RecoveryCode == "" {
				t.Error("注册 verify 应发放恢复码原文")
			}
			if len(fst.codeHash) != sha256.Size {
				t.Errorf("落库恢复码哈希应为 %d 字节，得到 %d", sha256.Size, len(fst.codeHash))
			}
			if bytes.Contains(fst.codeHash, []byte(regn.RecoveryCode)) {
				t.Error("恢复码原文不得出现在落库哈希中")
			}
			if len(regn.UserHandle) != userHandleLen {
				t.Errorf("UserHandle（内部字段）长度 = %d，期望 %d", len(regn.UserHandle), userHandleLen)
			}
		})
	}
}

// TestFinishRegistrationRejections：伪造签名、错 origin、未知/过期 challenge、
// 重放 challenge 全部拒绝，且统一为 ErrInvalidCeremony（不区分失败步骤）。
func TestFinishRegistrationRejections(t *testing.T) {
	validFlags := protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagAttestedCredentialData

	newValidBody := func(t *testing.T, svc *Service) []byte {
		t.Helper()
		creation, err := svc.BeginRegistration()
		if err != nil {
			t.Fatalf("BeginRegistration 失败: %v", err)
		}
		body, _, _ := buildAttestationResponse(t, fixtureSpec{
			rpID:      testRPID,
			origin:    testOrigin,
			challenge: b64url(creation.Response.Challenge),
			flags:     validFlags,
		})
		return body
	}

	finish := func(svc *Service, body []byte) error {
		req := httptest.NewRequest("POST", "/register/verify", bytes.NewReader(body))
		_, err := svc.FinishRegistration(context.Background(), req)
		return err
	}

	t.Run("伪造签名（packed 垃圾 sig）", func(t *testing.T) {
		fst := &fakeStore{}
		svc := newTestService(t, fst)
		creation, _ := svc.BeginRegistration()
		body, _, _ := buildAttestationResponse(t, fixtureSpec{
			rpID: testRPID, origin: testOrigin,
			challenge: b64url(creation.Response.Challenge),
			flags:     validFlags, forgedSig: true,
		})
		if err := finish(svc, body); !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("应拒绝伪造签名，得到: %v", err)
		}
		if fst.calls != 0 {
			t.Error("伪造签名不得落库")
		}
	})

	t.Run("错误 origin", func(t *testing.T) {
		fst := &fakeStore{}
		svc := newTestService(t, fst)
		creation, _ := svc.BeginRegistration()
		body, _, _ := buildAttestationResponse(t, fixtureSpec{
			rpID: testRPID, origin: "https://evil.example.net",
			challenge: b64url(creation.Response.Challenge),
			flags:     validFlags,
		})
		if err := finish(svc, body); !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("应拒绝白名单外 origin，得到: %v", err)
		}
		if fst.calls != 0 {
			t.Error("错 origin 不得落库")
		}
	})

	t.Run("未知 challenge", func(t *testing.T) {
		fst := &fakeStore{}
		svc := newTestService(t, fst)
		body, _, _ := buildAttestationResponse(t, fixtureSpec{
			rpID: testRPID, origin: testOrigin,
			challenge: base64.RawURLEncoding.EncodeToString([]byte("从未下发的 challenge")),
			flags:     validFlags,
		})
		if err := finish(svc, body); !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("应拒绝未知 challenge，得到: %v", err)
		}
	})

	t.Run("过期 challenge", func(t *testing.T) {
		fst := &fakeStore{}
		svc := newTestService(t, fst)
		body := newValidBody(t, svc)
		// 时钟快进到 TTL 之后
		svc.challenges.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
		if err := finish(svc, body); !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("应拒绝过期 challenge，得到: %v", err)
		}
		if fst.calls != 0 {
			t.Error("过期 challenge 不得落库")
		}
	})

	t.Run("重放同一 challenge", func(t *testing.T) {
		fst := &fakeStore{}
		svc := newTestService(t, fst)
		body := newValidBody(t, svc)
		if err := finish(svc, body); err != nil {
			t.Fatalf("首次 verify 应成功: %v", err)
		}
		if err := finish(svc, body); !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("重放应被拒绝，得到: %v", err)
		}
		if fst.calls != 1 {
			t.Errorf("重放后落库次数 = %d，期望仍为首秀的 1 次", fst.calls)
		}
	})

	t.Run("畸形请求体", func(t *testing.T) {
		svc := newTestService(t, &fakeStore{})
		if err := finish(svc, []byte("{不是 JSON")); !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("应拒绝畸形请求，得到: %v", err)
		}
	})
}

// TestFinishRegistrationStoreError：落库失败不算 ceremony 失败，
// 不得归一为 ErrInvalidCeremony（server 应回 500 而非 400）。
func TestFinishRegistrationStoreError(t *testing.T) {
	fst := &fakeStore{err: errors.New("db down")}
	svc := newTestService(t, fst)

	creation, _ := svc.BeginRegistration()
	body, _, _ := buildAttestationResponse(t, fixtureSpec{
		rpID: testRPID, origin: testOrigin,
		challenge: b64url(creation.Response.Challenge),
		flags:     protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagAttestedCredentialData,
	})
	req := httptest.NewRequest("POST", "/register/verify", bytes.NewReader(body))
	_, err := svc.FinishRegistration(context.Background(), req)
	if err == nil {
		t.Fatal("落库失败应返回错误")
	}
	if errors.Is(err, ErrInvalidCeremony) {
		t.Error("落库失败不得归一为 ErrInvalidCeremony")
	}
}
