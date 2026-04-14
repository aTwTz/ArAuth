package authn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/arithmaton/arauth/internal/config"
)

// newStrictService 构造打开 attestation 加固开关的 Service。
func newStrictService(t *testing.T, st CredentialStore) *Service {
	t.Helper()
	svc, err := New(&config.Config{
		RPID:              testRPID,
		RPOrigins:         []string{testOrigin},
		ChallengeTTL:      5 * time.Minute,
		PendingTTL:        24 * time.Hour,
		AttestationStrict: true,
	}, st, newFakeRecovery())
	if err != nil {
		t.Fatalf("authn.New 失败: %v", err)
	}
	return svc
}

// TestAttestationStrictRejectsNone 开关打开时 none 格式直接拒绝
// （fixture 构造的是 none attestation）；开关关闭时同一响应放行。
func TestAttestationStrictRejectsNone(t *testing.T) {
	run := func(t *testing.T, svc *Service) error {
		creation, err := svc.BeginRegistration()
		if err != nil {
			t.Fatalf("BeginRegistration 失败: %v", err)
		}
		body, _, _ := buildAttestationResponse(t, fixtureSpec{
			rpID:      testRPID,
			origin:    testOrigin,
			challenge: b64url(creation.Response.Challenge),
			flags:     protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagAttestedCredentialData,
		})
		req := httptest.NewRequest("POST", "/register/verify", bytes.NewReader(body))
		_, err = svc.FinishRegistration(context.Background(), req)
		return err
	}

	t.Run("开关开：none 拒绝", func(t *testing.T) {
		fst := &fakeStore{}
		err := run(t, newStrictService(t, fst))
		if !errors.Is(err, ErrInvalidCeremony) {
			t.Fatalf("strict 模式下 none 应归一 ErrInvalidCeremony，得到 %v", err)
		}
		// 拒绝须来自格式白名单裁决（CreateCredential 已通过），而非其他环节。
		if !strings.Contains(err.Error(), "白名单") {
			t.Fatalf("拒绝原因应为格式白名单，得到 %v", err)
		}
		if fst.calls != 0 {
			t.Error("拒绝路径不得落库")
		}
	})

	t.Run("开关关：none 放行", func(t *testing.T) {
		fst := &fakeStore{}
		if err := run(t, newTestService(t, fst)); err != nil {
			t.Fatalf("默认模式下 none 应放行: %v", err)
		}
		if fst.calls != 1 {
			t.Errorf("InsertRegistration 调用 %d 次，期望 1", fst.calls)
		}
	})
}

// TestAttestationStrictOptionsShape 开关打开时 options 声明 direct
// conveyance 与格式白名单（库配置层的客户端提示）。
func TestAttestationStrictOptionsShape(t *testing.T) {
	svc := newStrictService(t, &fakeStore{})
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
			Attestation        string   `json:"attestation"`
			AttestationFormats []string `json:"attestationFormats"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("options 不是合法 JSON: %v", err)
	}
	if doc.PublicKey.Attestation != "direct" {
		t.Errorf("attestation = %q，期望 direct", doc.PublicKey.Attestation)
	}
	want := map[string]bool{"apple": false, "android-key": false, "packed": false}
	for _, f := range doc.PublicKey.AttestationFormats {
		if _, ok := want[f]; ok {
			want[f] = true
		}
	}
	for f, seen := range want {
		if !seen {
			t.Errorf("attestationFormats 缺少 %q（得到 %v）", f, doc.PublicKey.AttestationFormats)
		}
	}

	// 默认模式不含这两个字段（行为与开关引入前完全一致）。
	svc = newTestService(t, &fakeStore{})
	creation, err = svc.BeginRegistration()
	if err != nil {
		t.Fatalf("BeginRegistration 失败: %v", err)
	}
	raw, _ = json.Marshal(creation)
	if bytes.Contains(raw, []byte("attestationFormats")) {
		t.Error("默认模式 options 不应含 attestationFormats")
	}
}
