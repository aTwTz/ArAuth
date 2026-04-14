package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/recovery"
)

func newTOTPHandlerServer(cfg *config.Config, rec *stubRedeemer, gate *stubGate, sess *stubSession, recorder *stubRecorder) *httptest.Server {
	return httptest.NewServer(New(cfg, &stubRegistrar{}, gate, &stubLogin{}, sess, rec, &stubLimiter{}, recorder))
}

func TestTOTPEnrollHTTP(t *testing.T) {
	rec := &stubRedeemer{totpSetup: &recovery.TOTPSetup{
		SetupToken: []byte("setup-token"),
		Secret:     "SECRET",
		URI:        "otpauth://totp/example",
		RecoveryID: "recovery-id",
	}}
	sess := &stubSession{authHandle: []byte("handle")}
	srv := newTOTPHandlerServer(&config.Config{TOTPFreshSessionTTL: 15 * time.Minute}, rec, &stubGate{ok: true}, sess, &stubRecorder{})
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/recovery/totp/enroll/begin", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var begin struct {
		SetupToken string `json:"setup_token"`
		Secret     string `json:"secret"`
		URI        string `json:"otpauth_uri"`
		RecoveryID string `json:"recovery_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&begin); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || begin.Secret != "SECRET" || begin.URI == "" || begin.RecoveryID != "recovery-id" {
		t.Fatalf("begin 响应异常: %d %+v", resp.StatusCode, begin)
	}
	if got, _ := base64.RawURLEncoding.DecodeString(begin.SetupToken); !bytes.Equal(got, []byte("setup-token")) {
		t.Error("setup_token 编码不符")
	}
	if sess.freshCalls != 1 || sess.freshMaxAge != 15*time.Minute || !bytes.Equal(rec.totpBeginGot, sess.authHandle) {
		t.Error("begin 未使用新鲜会话身份")
	}

	confirmBody := `{"setup_token":"` + base64.RawURLEncoding.EncodeToString([]byte("setup-token")) + `","code":"123456"}`
	resp, err = http.Post(srv.URL+"/recovery/totp/enroll/confirm", "application/json", strings.NewReader(confirmBody))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Equal(rec.totpConfirmHandle, sess.authHandle) ||
		!bytes.Equal(rec.totpConfirmGot, []byte("setup-token")) || rec.totpConfirmCode != "123456" {
		t.Fatalf("confirm 未按合同调用服务: %d", resp.StatusCode)
	}

	sess.authErr = errors.New("stale session")
	rec.totpBeginGot = nil
	resp, err = http.Post(srv.URL+"/recovery/totp/enroll/begin", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || rec.totpBeginGot != nil {
		t.Error("陈旧会话必须 401 且不得开始绑定")
	}

	sess.authErr = nil
	rec.totpConfirmErr = recovery.ErrInvalidTOTPSetup
	resp, err = http.Post(srv.URL+"/recovery/totp/enroll/confirm", "application/json", strings.NewReader(confirmBody))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("无效 setup/动态码状态码 = %d，期望 400", resp.StatusCode)
	}
}

func TestTOTPRedeemPoWBeforeRecovery(t *testing.T) {
	rec := &stubRedeemer{token: []byte("recovery-token")}
	gate := &stubGate{ok: false}
	recorder := &stubRecorder{}
	srv := newTOTPHandlerServer(&config.Config{}, rec, gate, &stubSession{}, recorder)
	defer srv.Close()
	body := `{"recovery_id":"id","code":"123456","pow_challenge":"Y2hhbGxlbmdl","pow_nonce":"bm9uY2U"}`

	post := func() *http.Response {
		t.Helper()
		resp, err := http.Post(srv.URL+"/recovery/totp/redeem", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := post()
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || rec.totpRedeemCalls != 0 {
		t.Fatal("PoW 失败不得读取或验证 TOTP")
	}

	gate.ok = true
	resp = post()
	var redeemed struct {
		Token string `json:"recovery_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&redeemed); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || rec.totpGotID != "id" || rec.totpGotCode != "123456" {
		t.Fatalf("TOTP 兑换调用异常: %d, id=%q code=%q", resp.StatusCode, rec.totpGotID, rec.totpGotCode)
	}
	if got, _ := base64.RawURLEncoding.DecodeString(redeemed.Token); !bytes.Equal(got, rec.token) {
		t.Error("recovery_token 编码不符")
	}

	rec.totpRedeemErr = recovery.ErrInvalidRedeem
	resp = post()
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("无效 TOTP 状态码 = %d，期望 401", resp.StatusCode)
	}
	if len(recorder.oks) != 3 || recorder.oks[0] || !recorder.oks[1] || !recorder.oks[2] {
		t.Errorf("PoW 自适应信号记录异常: %v", recorder.oks)
	}
}
