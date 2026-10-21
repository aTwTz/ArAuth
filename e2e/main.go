// arauth 端到端验收客户端：模拟浏览器 + 平台验证器，所有浏览器侧调用
// （包括恢复与 TOTP）只经 E2E_RP_URL 指向的依赖方参考服务，绝不直连 arauth。
// 覆盖 PoW、注册、confirm 前 TOTP 绑定、登录/exchange、第一方 cookie、
// 登录后 TOTP 更换、TOTP 找回与防重放、一次性恢复码找回轮换及身份稳定性。
// 任何一步失败即非零退出（scripts/e2e.sh 的验收依据）。
package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"time"
)

const (
	// arauthCookieName 是 arauth 的会话 cookie 名：依赖方服务给出的任何
	// 注册/登录响应里都不许出现它。
	arauthCookieName = "arauth_session"
	// 依赖方参考服务自己的两个第一方 cookie。
	rpSessionCookie = "rp_session"
	rpPendingCookie = "rp_pending"

	recoveryTokenHeader = "X-Arauth-Recovery-Token"
)

var b64 = base64.RawURLEncoding.EncodeToString

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatalf("E2E 失败: %v", err)
	}
	log.Println("E2E 全绿：注册 TOTP 绑定、登录后更换、TOTP/恢复码找回、防重放与身份轮换全部通过")
}

func run() error {
	rpURL := envOr("E2E_RP_URL", "https://localhost:18443")
	caFile := os.Getenv("E2E_CA_FILE")
	rpID := envOr("E2E_RPID", "localhost")
	origin := envOr("E2E_ORIGIN", "https://localhost")

	// rp 模拟浏览器与依赖方之间的唯一 HTTP 通道；caFile 同样适用于 https RP。
	rp, err := newClient(rpURL, caFile)
	if err != nil {
		return err
	}

	step("0. 依赖方健康检查（含其 arauth 上游）")
	if err := expectStatus(rp, "GET", "/health", nil, nil, 200); err != nil {
		return err
	}

	// ---------- 注册（浏览器 → 依赖方 → arauth） ----------

	step("1. 领取并求解 PoW challenge（经依赖方转发）")
	powChallenge, powNonce, err := fetchAndSolvePoW(rp)
	if err != nil {
		return err
	}

	step("2. 注册 options（PoW 门）")
	optsResp, err := rp.do("POST", "/register/options", map[string]string{
		"pow_challenge": powChallenge, "pow_nonce": powNonce,
	}, nil)
	if err != nil {
		return err
	}
	if optsResp.status != 200 {
		return fmt.Errorf("register/options 状态 %d: %s", optsResp.status, optsResp.body)
	}
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := optsResp.json(&opts); err != nil || opts.PublicKey.Challenge == "" || opts.PublicKey.User.ID == "" {
		return fmt.Errorf("register/options 响应畸形: %s", optsResp.body)
	}
	userHandle, err := base64.RawURLEncoding.DecodeString(opts.PublicKey.User.ID)
	if err != nil {
		return fmt.Errorf("user handle 解码失败: %w", err)
	}

	step("3. 注册 verify（虚拟验证器 attestation）+ 依赖方代持 pending 会话")
	auth1, err := newAuthenticator()
	if err != nil {
		return err
	}
	attestation, err := auth1.attestation(rpID, origin, opts.PublicKey.Challenge)
	if err != nil {
		return err
	}
	regResp, err := rp.do("POST", "/register/verify", attestation, nil)
	if err != nil {
		return err
	}
	if regResp.status != 200 {
		return fmt.Errorf("register/verify 状态 %d: %s", regResp.status, regResp.body)
	}
	if regResp.hasCookie(arauthCookieName) {
		return fmt.Errorf("依赖方 register/verify 响应里出现 arauth 会话 cookie")
	}
	if !regResp.hasCookie(rpPendingCookie) {
		return fmt.Errorf("依赖方 register/verify 未种 %s cookie（pending 代持钥匙）", rpPendingCookie)
	}
	var regBody struct {
		CredentialID string `json:"credential_id"`
		BackedUp     bool   `json:"backed_up"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := regResp.json(&regBody); err != nil || regBody.RecoveryCode == "" {
		return fmt.Errorf("register/verify 响应畸形（缺 recovery_code）: %s", regResp.body)
	}
	if regBody.CredentialID != b64(auth1.credID) {
		return fmt.Errorf("credential_id 与虚拟验证器不符")
	}
	if !regBody.BackedUp {
		return fmt.Errorf("backed_up 应为 true（虚拟验证器 BE=1）")
	}

	step("4. 注册 confirm 前绑定 TOTP（显式 register flow + rp_pending）")
	enroll1, err := enrollTOTP(rp, "register")
	if err != nil {
		return fmt.Errorf("注册期 TOTP 绑定失败: %w", err)
	}

	step("5. 注册确认（依赖方代持 cookie 转发 confirm → 激活）")
	if err := expectStatus(rp, "POST", "/register/confirm", nil, nil, 200); err != nil {
		return err
	}
	if _, ok := rp.cookies[rpPendingCookie]; ok {
		return fmt.Errorf("confirm 成功后 %s 钥匙应被清除", rpPendingCookie)
	}

	// ---------- 回访登录 + exchange 换发 ----------

	step("6. 登录 options → 断言 → verify/exchange")
	if err := loginWith(rp, auth1, rpID, origin, userHandle); err != nil {
		return err
	}

	step("7. 依赖方第一方 cookie 生效（whoami）")
	anon, err := newClient(rpURL, caFile) // 无 cookie 的干净"浏览器"
	if err != nil {
		return err
	}
	if err := expectStatus(anon, "GET", "/whoami", nil, nil, 401); err != nil {
		return fmt.Errorf("无 cookie whoami 应 401: %w", err)
	}
	if err := expectWhoami(rp, userHandle); err != nil {
		return err
	}

	// ---------- 登录后更换 TOTP，旧定位符/种子失效 ----------

	step("8. 登录后再次 enroll，更换 TOTP（显式 login flow + rp_session）")
	enroll2, err := enrollTOTP(rp, "login")
	if err != nil {
		return fmt.Errorf("登录后 TOTP 更换失败: %w", err)
	}
	if enroll2.Secret == enroll1.Secret || enroll2.RecoveryID == enroll1.RecoveryID {
		return fmt.Errorf("TOTP 更换后 seed/recovery_id 未同时更新")
	}

	step("9. 旧 recovery_id + 旧 seed 的下一时间步动态码兑换应 401")
	oldTOTPResp, _, err := redeemTOTPNext(rp, enroll1.RecoveryID, enroll1.Secret)
	if err != nil {
		return err
	}
	if oldTOTPResp.status != 401 {
		return fmt.Errorf("旧 TOTP 兑换状态 %d（期望 401）: %s", oldTOTPResp.status, oldTOTPResp.body)
	}

	// ---------- TOTP 找回：新 passkey + 恢复码轮换 + 动态码防重放 ----------

	step("10. 新 TOTP 下一时间步动态码兑换（PoW 门）")
	totpRedeemResp, usedTOTPCode, err := redeemTOTPNext(rp, enroll2.RecoveryID, enroll2.Secret)
	if err != nil {
		return err
	}
	if totpRedeemResp.status != 200 {
		return fmt.Errorf("新 TOTP 兑换状态 %d: %s", totpRedeemResp.status, totpRedeemResp.body)
	}
	totpRecoveryToken, err := recoveryTokenFrom(totpRedeemResp, "recovery/totp/redeem")
	if err != nil {
		return err
	}

	step("11. TOTP 恢复票据注册新 passkey + 恢复码轮换")
	auth2, recoveryCode2, err := recoverPasskey(rp, totpRecoveryToken, rpID, origin, userHandle, regBody.RecoveryCode)
	if err != nil {
		return fmt.Errorf("TOTP 找回注册失败: %w", err)
	}

	step("12. 同一 TOTP 动态码再次兑换必须 401（新 PoW，排除票据复用干扰）")
	replayResp, err := redeemTOTPCode(rp, enroll2.RecoveryID, usedTOTPCode)
	if err != nil {
		return err
	}
	if replayResp.status != 401 {
		return fmt.Errorf("TOTP 动态码重放状态 %d（期望 401）: %s", replayResp.status, replayResp.body)
	}

	step("13. TOTP 找回的新 passkey 登录 + whoami，身份不变")
	if err := loginWith(rp, auth2, rpID, origin, userHandle); err != nil {
		return fmt.Errorf("TOTP 找回的新密钥登录失败: %w", err)
	}
	if err := expectWhoami(rp, userHandle); err != nil {
		return fmt.Errorf("TOTP 找回后的身份检查失败: %w", err)
	}

	// ---------- 一次性恢复码回归：再挂一把新 passkey ----------

	step("14. 最新一次性恢复码兑换（PoW 门）")
	codeRedeemResp, err := redeemRecoveryCode(rp, recoveryCode2)
	if err != nil {
		return err
	}
	if codeRedeemResp.status != 200 {
		return fmt.Errorf("最新恢复码兑换状态 %d: %s", codeRedeemResp.status, codeRedeemResp.body)
	}
	codeRecoveryToken, err := recoveryTokenFrom(codeRedeemResp, "recovery/redeem")
	if err != nil {
		return err
	}

	step("15. 恢复码票据再注册一把新 passkey + 恢复码再次轮换")
	auth3, _, err := recoverPasskey(rp, codeRecoveryToken, rpID, origin, userHandle, recoveryCode2)
	if err != nil {
		return fmt.Errorf("恢复码找回注册失败: %w", err)
	}

	step("16. 已使用的旧恢复码再次兑换必须 401")
	oldCodeResp, err := redeemRecoveryCode(rp, recoveryCode2)
	if err != nil {
		return err
	}
	if oldCodeResp.status != 401 {
		return fmt.Errorf("旧恢复码重放状态 %d（期望 401）: %s", oldCodeResp.status, oldCodeResp.body)
	}

	step("17. 最终新 passkey 登录 + whoami，user_handle 始终不变")
	if err := loginWith(rp, auth3, rpID, origin, userHandle); err != nil {
		return fmt.Errorf("最终新密钥登录失败: %w", err)
	}
	if err := expectWhoami(rp, userHandle); err != nil {
		return fmt.Errorf("最终身份检查失败: %w", err)
	}

	return nil
}

// totpEnrollment 保存一次 enroll begin 返回的绑定材料。secret 只存在本测试
// 进程内，用于模拟用户认证器；不会写入日志或浏览器持久存储。
type totpEnrollment struct {
	SetupToken string `json:"setup_token"`
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
	RecoveryID string `json:"recovery_id"`
}

// enrollTOTP 完成 begin → confirm。flow 必须显式区分注册 pending 会话与登录
// rp_session，避免浏览器同时持有两类 cookie 时出现身份歧义。
func enrollTOTP(rp *client, flow string) (*totpEnrollment, error) {
	if flow != "register" && flow != "login" {
		return nil, fmt.Errorf("未知 TOTP enroll flow %q", flow)
	}
	beginPath := "/recovery/totp/enroll/begin?flow=" + flow
	beginResp, err := rp.do("POST", beginPath, map[string]string{}, nil) // 合同要求空 JSON：{}
	if err != nil {
		return nil, err
	}
	if beginResp.status != 200 {
		return nil, fmt.Errorf("TOTP enroll/begin 状态 %d: %s", beginResp.status, beginResp.body)
	}
	var setup totpEnrollment
	if err := beginResp.json(&setup); err != nil || setup.SetupToken == "" || setup.Secret == "" ||
		setup.OTPAuthURI == "" || setup.RecoveryID == "" {
		// begin 成功响应包含 seed，畸形时不把响应体写进日志。
		return nil, fmt.Errorf("TOTP enroll/begin 响应畸形或字段缺失")
	}
	code, err := totpCodeAt(setup.Secret, time.Now())
	if err != nil {
		return nil, err
	}
	confirmResp, err := rp.do("POST", "/recovery/totp/enroll/confirm?flow="+flow, map[string]string{
		"setup_token": setup.SetupToken, "code": code,
	}, nil)
	if err != nil {
		return nil, err
	}
	if confirmResp.status != 200 {
		return nil, fmt.Errorf("TOTP enroll/confirm 状态 %d: %s", confirmResp.status, confirmResp.body)
	}
	var confirmation struct {
		Status string `json:"status"`
	}
	if err := confirmResp.json(&confirmation); err != nil || confirmation.Status != "ok" {
		return nil, fmt.Errorf("TOTP enroll/confirm 响应畸形: %s", confirmResp.body)
	}
	return &setup, nil
}

// loginWith 走一轮完整登录：options → 断言 → verify（依赖方完成 exchange
// 换发），并逐步断言 cookie 纪律。
func loginWith(rp *client, a *authenticator, rpID, origin string, userHandle []byte) error {
	optsResp, err := rp.do("POST", "/login/options", nil, nil)
	if err != nil {
		return err
	}
	if optsResp.status != 200 {
		return fmt.Errorf("login/options 状态 %d: %s", optsResp.status, optsResp.body)
	}
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := optsResp.json(&opts); err != nil || opts.PublicKey.Challenge == "" {
		return fmt.Errorf("login/options 响应畸形: %s", optsResp.body)
	}

	assertion, err := a.assertion(rpID, origin, opts.PublicKey.Challenge, userHandle)
	if err != nil {
		return err
	}
	loginResp, err := rp.do("POST", "/login/verify", assertion, nil)
	if err != nil {
		return err
	}
	if loginResp.status != 200 {
		return fmt.Errorf("login/verify 状态 %d: %s", loginResp.status, loginResp.body)
	}
	if loginResp.hasCookie(arauthCookieName) {
		return fmt.Errorf("依赖方 login/verify 响应里出现 arauth 会话 cookie")
	}
	if !loginResp.hasCookie(rpSessionCookie) {
		return fmt.Errorf("依赖方 login/verify 未种 %s（exchange 换发失败？）", rpSessionCookie)
	}
	// exchange_code 是服务端票据，绝不下发给浏览器。
	var body map[string]any
	if err := loginResp.json(&body); err != nil {
		return fmt.Errorf("login/verify 响应畸形: %s", loginResp.body)
	}
	if _, leaked := body["exchange_code"]; leaked {
		return fmt.Errorf("依赖方 login/verify 响应泄露 exchange_code")
	}
	if _, leaked := body["user_handle"]; leaked {
		return fmt.Errorf("依赖方 login/verify 响应泄露 user_handle（应只在 whoami 给出）")
	}
	return nil
}

// expectWhoami 断言 RP 第一方会话返回的仍是注册时的匿名身份。
func expectWhoami(rp *client, userHandle []byte) error {
	whoResp, err := rp.do("GET", "/whoami", nil, nil)
	if err != nil {
		return err
	}
	if whoResp.status != 200 {
		return fmt.Errorf("whoami 状态 %d: %s", whoResp.status, whoResp.body)
	}
	var who struct {
		UserHandle string `json:"user_handle"`
	}
	if err := whoResp.json(&who); err != nil || who.UserHandle == "" {
		return fmt.Errorf("whoami 响应畸形: %s", whoResp.body)
	}
	if who.UserHandle != b64(userHandle) {
		return fmt.Errorf("whoami 的 user_handle 与注册 handle 不符")
	}
	return nil
}

// recoverPasskey 使用一次性恢复票据执行 options → attestation → verify，
// 并断言绑定原 user_handle、恢复码确实轮换。返回新验证器和最新恢复码。
func recoverPasskey(rp *client, recoveryToken, rpID, origin string, userHandle []byte, previousCode string) (*authenticator, string, error) {
	recOptsResp, err := rp.do("POST", "/recovery/options", nil,
		map[string]string{recoveryTokenHeader: recoveryToken})
	if err != nil {
		return nil, "", err
	}
	if recOptsResp.status != 200 {
		return nil, "", fmt.Errorf("recovery/options 状态 %d: %s", recOptsResp.status, recOptsResp.body)
	}
	var recOpts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := recOptsResp.json(&recOpts); err != nil || recOpts.PublicKey.Challenge == "" {
		return nil, "", fmt.Errorf("recovery/options 响应畸形: %s", recOptsResp.body)
	}
	if recOpts.PublicKey.User.ID != b64(userHandle) {
		return nil, "", fmt.Errorf("recovery/options 未绑定原 user_handle")
	}
	a, err := newAuthenticator()
	if err != nil {
		return nil, "", err
	}
	attestation, err := a.attestation(rpID, origin, recOpts.PublicKey.Challenge)
	if err != nil {
		return nil, "", err
	}
	recVerifyResp, err := rp.do("POST", "/recovery/verify", attestation,
		map[string]string{recoveryTokenHeader: recoveryToken})
	if err != nil {
		return nil, "", err
	}
	if recVerifyResp.status != 200 {
		return nil, "", fmt.Errorf("recovery/verify 状态 %d: %s", recVerifyResp.status, recVerifyResp.body)
	}
	var recBody struct {
		RecoveryCode string `json:"recovery_code"`
	}
	if err := recVerifyResp.json(&recBody); err != nil || recBody.RecoveryCode == "" {
		return nil, "", fmt.Errorf("recovery/verify 响应畸形（缺新 recovery_code）: %s", recVerifyResp.body)
	}
	if recBody.RecoveryCode == previousCode {
		return nil, "", fmt.Errorf("恢复码未轮换（新旧相同）")
	}
	return a, recBody.RecoveryCode, nil
}

// fetchAndSolvePoW 领取 challenge 并求解，返回可提交的 base64url 字段对。
func fetchAndSolvePoW(c *client) (challenge, nonce string, err error) {
	resp, err := c.do("GET", "/pow/challenge", nil, nil)
	if err != nil {
		return "", "", err
	}
	if resp.status != 200 {
		return "", "", fmt.Errorf("pow/challenge 状态 %d: %s", resp.status, resp.body)
	}
	var powResp struct {
		Challenge  string `json:"challenge"`
		Difficulty int    `json:"difficulty"`
	}
	if err := resp.json(&powResp); err != nil || powResp.Challenge == "" || powResp.Difficulty <= 0 {
		return "", "", fmt.Errorf("pow/challenge 响应畸形: %s", resp.body)
	}
	raw, err := base64.RawURLEncoding.DecodeString(powResp.Challenge)
	if err != nil {
		return "", "", fmt.Errorf("challenge 解码失败: %w", err)
	}
	return powResp.Challenge, b64(solvePoW(raw, powResp.Difficulty)), nil
}

// redeemTOTPNext 先求 PoW，再按请求时的下一时间步生成动态码。这样无需
// sleep 30 秒，也不会误用 enroll confirm 已消费的时间步；服务器当前 ±1
// 步窗口同时覆盖请求跨越时间步边界的情况。返回实际提交的码供重放断言。
func redeemTOTPNext(c *client, recoveryID, secret string) (*response, string, error) {
	challenge, nonce, err := fetchAndSolvePoW(c)
	if err != nil {
		return nil, "", err
	}
	code, err := totpCodeAt(secret, time.Now().Add(totpPeriod))
	if err != nil {
		return nil, "", err
	}
	resp, err := postTOTPRedeem(c, recoveryID, code, challenge, nonce)
	return resp, code, err
}

// redeemTOTPCode 使用固定动态码和一份新 PoW 兑换，供同一时间步重放测试。
func redeemTOTPCode(c *client, recoveryID, code string) (*response, error) {
	challenge, nonce, err := fetchAndSolvePoW(c)
	if err != nil {
		return nil, err
	}
	return postTOTPRedeem(c, recoveryID, code, challenge, nonce)
}

func postTOTPRedeem(c *client, recoveryID, code, challenge, nonce string) (*response, error) {
	return c.do("POST", "/recovery/totp/redeem", map[string]string{
		"recovery_id": recoveryID, "code": code,
		"pow_challenge": challenge, "pow_nonce": nonce,
	}, nil)
}

// redeemRecoveryCode 走一轮一次性恢复码兑换（自带 PoW），状态码由调用方断言。
func redeemRecoveryCode(c *client, code string) (*response, error) {
	challenge, nonce, err := fetchAndSolvePoW(c)
	if err != nil {
		return nil, err
	}
	return c.do("POST", "/recovery/redeem", map[string]string{
		"recovery_code": code, "pow_challenge": challenge, "pow_nonce": nonce,
	}, nil)
}

// recoveryTokenFrom 从已确认 200 的恢复兑换响应中提取一次性恢复票据。
func recoveryTokenFrom(resp *response, operation string) (string, error) {
	var body struct {
		RecoveryToken string `json:"recovery_token"`
	}
	if err := resp.json(&body); err != nil || body.RecoveryToken == "" {
		return "", fmt.Errorf("%s 响应畸形: %s", operation, resp.body)
	}
	return body.RecoveryToken, nil
}

// expectStatus 发起调用并断言状态码。
func expectStatus(c *client, method, path string, body any, headers map[string]string, want int) error {
	resp, err := c.do(method, path, body, headers)
	if err != nil {
		return err
	}
	if resp.status != want {
		return fmt.Errorf("%s %s 状态 %d（期望 %d）: %s", method, path, resp.status, want, resp.body)
	}
	return nil
}

func step(msg string) {
	log.Printf("== %s", msg)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
