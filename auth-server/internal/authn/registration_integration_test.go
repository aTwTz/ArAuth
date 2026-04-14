//go:build integration

// 集成测试：连 compose 开发库（独立 schema 隔离），走完整注册闭环
// options → 合法 attestation → verify，断言库中 identity(pending) +
// credential 各一行、BE/BS 与 attestation flags 一致（验收标准 1）。
// 运行：go test -tags integration ./internal/authn/（需先 docker compose up -d postgres）

package authn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/store"
)

// recoveryHashOf 与 fakeRecovery.Generate 的哈希口径一致：SHA-256(展示串)。
func recoveryHashOf(display string) []byte {
	sum := sha256.Sum256([]byte(display))
	return sum[:]
}

const migrationsDir = "../../migrations"

func setupIntegration(t *testing.T) (context.Context, *store.Store) {
	t.Helper()

	dsn := os.Getenv("ARAUTH_TEST_DSN")
	if dsn == "" {
		dsn = "postgres://arauth:arauth-dev@localhost:5432/arauth"
	}
	ctx := context.Background()

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("连接数据库失败: %v", err)
	}
	t.Cleanup(func() { admin.Close() })

	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("生成随机数失败: %v", err)
	}
	schema := "regtest_" + hex.EncodeToString(suffix)
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("建测试 schema 失败: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.ExecContext(context.Background(),
			`DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
			t.Errorf("清理 schema 失败: %v", err)
		}
	})

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("解析 DSN 失败: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	scoped := u.String()

	db, err := sql.Open("pgx", scoped)
	if err != nil {
		t.Fatalf("连接数据库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := goose.Up(db, migrationsDir); err != nil {
		t.Fatalf("goose up 失败: %v", err)
	}

	st, err := store.New(ctx, scoped)
	if err != nil {
		t.Fatalf("store.New 失败: %v", err)
	}
	t.Cleanup(st.Close)
	return ctx, st
}

func TestRegistrationFullCycle(t *testing.T) {
	ctx, st := setupIntegration(t)

	svc, err := New(&config.Config{
		RPID:         testRPID,
		RPOrigins:    []string{testOrigin},
		ChallengeTTL: 5 * time.Minute,
		PendingTTL:   24 * time.Hour,
	}, st, newFakeRecovery())
	if err != nil {
		t.Fatalf("authn.New 失败: %v", err)
	}

	creation, err := svc.BeginRegistration()
	if err != nil {
		t.Fatalf("BeginRegistration 失败: %v", err)
	}

	flags := protocol.FlagUserPresent | protocol.FlagUserVerified |
		protocol.FlagAttestedCredentialData | protocol.FlagBackupEligible | protocol.FlagBackupState
	body, credID, _ := buildAttestationResponse(t, fixtureSpec{
		rpID:       testRPID,
		origin:     testOrigin,
		challenge:  b64url(creation.Response.Challenge),
		flags:      flags,
		attachment: "platform",
		transports: []string{"internal"},
	})

	req := httptest.NewRequest("POST", "/register/verify", bytes.NewReader(body))
	regn, err := svc.FinishRegistration(ctx, req)
	if err != nil {
		t.Fatalf("FinishRegistration 失败: %v", err)
	}
	if !regn.BackedUp {
		t.Error("返回 backed_up = false，期望 true（BE=1）")
	}

	// 库中应有 identity(pending) + credential 各一行
	cred, err := st.GetCredential(ctx, credID)
	if err != nil {
		t.Fatalf("GetCredential 失败: %v", err)
	}
	id, err := st.GetIdentity(ctx, cred.UserHandle)
	if err != nil {
		t.Fatalf("GetIdentity 失败: %v", err)
	}
	if id.ActivatedAt != nil {
		t.Error("identity 应为 pending（activated_at 为 NULL，确认归 /register/confirm）")
	}
	// 注册事务应同时落恢复码哈希（recovery_codes 一行）
	rc, err := st.GetRecoveryCodeByHash(ctx, recoveryHashOf(regn.RecoveryCode))
	if err != nil {
		t.Fatalf("注册后应能按哈希查到恢复码: %v", err)
	}
	if !bytes.Equal(rc.UserHandle, id.UserHandle) {
		t.Error("恢复码未挂到新 identity")
	}
	if regn.RecoveryCode == "" {
		t.Error("注册 verify 应发放恢复码原文（仅此一次）")
	}
	if !cred.BackedUp || !cred.BackupState {
		t.Errorf("BE/BS = %v/%v，期望 true/true（与 attestation flags 一致）",
			cred.BackedUp, cred.BackupState)
	}
	if len(cred.PublicKey) == 0 || len(cred.AAGUID) != 16 {
		t.Error("COSE 公钥 / AAGUID 落库不完整")
	}
	if cred.Attachment != "platform" || len(cred.Transports) != 1 || cred.Transports[0] != "internal" {
		t.Errorf("attachment/transports 落库不符: %q %v", cred.Attachment, cred.Transports)
	}

	list, err := st.ListCredentialsByIdentity(ctx, id.UserHandle)
	if err != nil {
		t.Fatalf("ListCredentialsByIdentity 失败: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("新身份凭据数 = %d，期望 1", len(list))
	}
}
