//go:build integration

// 集成测试：连 compose 开发库，在随机命名的独立 schema 内跑
// 迁移 up/down 与 identities/credentials 的 CRUD，不污染默认 public schema。
// 运行：go test -tags integration ./internal/store/（需先 docker compose up -d postgres）

package store_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/arithmaton/arauth/internal/store"
)

const migrationsDir = "../../migrations"

// setup 建独立 schema 并跑 goose up，返回可用 Store 与清理函数。
func setup(t *testing.T) (context.Context, *store.Store, *sql.DB) {
	t.Helper()

	dsn := testDSN(t)
	ctx := context.Background()

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("连接数据库失败: %v", err)
	}
	t.Cleanup(func() { admin.Close() })

	schema := "storetest_" + randHex(t, 8)
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("建测试 schema 失败: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.ExecContext(context.Background(),
			`DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
			t.Errorf("清理 schema 失败: %v", err)
		}
	})

	scoped := withSearchPath(t, dsn, schema)
	db, err := sql.Open("pgx", scoped)
	if err != nil {
		t.Fatalf("连接数据库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := goose.Up(db, migrationsDir); err != nil {
		t.Fatalf("goose up 失败: %v", err)
	}

	s, err := store.New(ctx, scoped)
	if err != nil {
		t.Fatalf("store.New 失败: %v", err)
	}
	t.Cleanup(s.Close)

	return ctx, s, db
}

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("ARAUTH_TEST_DSN")
	if dsn == "" {
		// 默认指向 compose 开发库（.env.example 中的纯本地开发值）。
		dsn = "postgres://arauth:arauth-dev@localhost:5432/arauth"
	}
	return dsn
}

// withSearchPath 给 DSN 追加 search_path，把迁移与测试隔离进测试 schema。
func withSearchPath(t *testing.T, dsn, schema string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("解析 DSN 失败: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("生成随机数失败: %v", err)
	}
	return hex.EncodeToString(b)
}

// TestMigrationsUpDown 验证 up 建出全部六张表、down 到 0 全部回滚。
func TestMigrationsUpDown(t *testing.T) {
	ctx, _, db := setup(t)

	tables := []string{"identities", "credentials", "recovery_codes", "sessions", "exchange_codes", "recovery_totp"}
	for _, table := range tables {
		if !tableExists(t, ctx, db, table) {
			t.Errorf("up 后表 %s 不存在", table)
		}
	}

	if err := goose.DownTo(db, migrationsDir, 0); err != nil {
		t.Fatalf("goose down 失败: %v", err)
	}
	for _, table := range tables {
		if tableExists(t, ctx, db, table) {
			t.Errorf("down 后表 %s 仍存在", table)
		}
	}
}

func tableExists(t *testing.T, ctx context.Context, db *sql.DB, table string) bool {
	t.Helper()
	var exists bool
	err := db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = current_schema() AND tablename = $1)`,
		table).Scan(&exists)
	if err != nil {
		t.Fatalf("检查表 %s 失败: %v", table, err)
	}
	return exists
}

// TestIdentityCRUD 验证 identity 的写入与读取。
func TestIdentityCRUD(t *testing.T) {
	ctx, s, _ := setup(t)

	handle, err := randBytes(64)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetIdentity(ctx, handle); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("未插入时应返回 ErrNotFound，得到: %v", err)
	}

	if err := s.InsertIdentity(ctx, handle); err != nil {
		t.Fatalf("InsertIdentity 失败: %v", err)
	}

	id, err := s.GetIdentity(ctx, handle)
	if err != nil {
		t.Fatalf("GetIdentity 失败: %v", err)
	}
	if hex.EncodeToString(id.UserHandle) != hex.EncodeToString(handle) {
		t.Error("user_handle 回读不一致")
	}
	if id.ActivatedAt != nil {
		t.Error("新插入身份应处于 pending（activated_at 为 NULL）")
	}
}

// TestCredentialCRUD 验证 credential 的写入、按 ID 读取与按身份列举。
func TestCredentialCRUD(t *testing.T) {
	ctx, s, _ := setup(t)

	handle, err := randBytes(64)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertIdentity(ctx, handle); err != nil {
		t.Fatalf("InsertIdentity 失败: %v", err)
	}

	credID, err := randBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	aaguid, err := randBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{
		CredentialID: credID,
		UserHandle:   handle,
		PublicKey:    []byte{0xa5, 0x01, 0x02}, // 示意性 COSE 字节，语义由 authn 裁决
		BackedUp:     true,                     // BE=1（可同步 passkey）
		BackupState:  true,                     // BS=1
		AAGUID:       aaguid,
		Attachment:   "platform",
		Transports:   []string{"internal", "hybrid"},
		SignCount:    0,
	}
	if err := s.InsertCredential(ctx, cred); err != nil {
		t.Fatalf("InsertCredential 失败: %v", err)
	}

	got, err := s.GetCredential(ctx, credID)
	if err != nil {
		t.Fatalf("GetCredential 失败: %v", err)
	}
	if !got.BackedUp || !got.BackupState {
		t.Error("BE/BS 回读不一致")
	}
	if len(got.Transports) != 2 || got.Transports[0] != "internal" {
		t.Errorf("transports 回读不一致: %v", got.Transports)
	}
	if got.LastUsedAt != nil {
		t.Error("新凭据 last_used_at 应为 NULL")
	}

	list, err := s.ListCredentialsByIdentity(ctx, handle)
	if err != nil {
		t.Fatalf("ListCredentialsByIdentity 失败: %v", err)
	}
	if len(list) != 1 || hex.EncodeToString(list[0].CredentialID) != hex.EncodeToString(credID) {
		t.Fatalf("按身份列举结果不符: %+v", list)
	}

	if _, err := s.GetCredential(ctx, []byte("不存在的凭据")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("不存在时应返回 ErrNotFound，得到: %v", err)
	}
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("生成随机数失败: %w", err)
	}
	return b, nil
}
