package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/store"
)

// fakeStore 按哈希回放恢复码记录。
type fakeStore struct {
	codeHash   []byte
	userHandle []byte
	err        error
}

func (f *fakeStore) GetRecoveryCodeByHash(_ context.Context, codeHash []byte) (*store.RecoveryCode, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.codeHash == nil || string(f.codeHash) != string(codeHash) {
		return nil, store.ErrNotFound
	}
	return &store.RecoveryCode{UserHandle: f.userHandle, CodeHash: f.codeHash}, nil
}

func newTestService(st Store) *Service {
	return New(&config.Config{RecoveryTokenTTL: 5 * time.Minute}, st)
}

// TestGenerateFormat：128 位熵、base32 无填充 26 字符、4 字符分组、
// 哈希是原文（归一化后）的 SHA-256。展示串是唯一出现原文的地方。
func TestGenerateFormat(t *testing.T) {
	display, hash, err := Generate()
	if err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}

	compact := strings.ReplaceAll(display, "-", "")
	if len(compact) != 26 {
		t.Errorf("base32 串长度 = %d，期望 26（128 位）", len(compact))
	}
	if compact != strings.ToLower(compact) {
		t.Errorf("展示串应为小写: %q", display)
	}
	groups := strings.Split(display, "-")
	if len(groups) != 7 { // 26 = 4×6 + 2
		t.Errorf("分组数 = %d，期望 7: %q", len(groups), display)
	}

	raw, err := normalize(display)
	if err != nil {
		t.Fatalf("展示串应可归一化: %v", err)
	}
	if len(raw) != codeLen {
		t.Errorf("归一化后长度 = %d，期望 %d", len(raw), codeLen)
	}
	sum := sha256.Sum256(raw)
	if string(sum[:]) != string(hash) {
		t.Error("hash 不是恢复码原文的 SHA-256")
	}
}

// TestGenerateUnique：两次生成不得相同（crypto/rand 直出）。
func TestGenerateUnique(t *testing.T) {
	a, _, _ := Generate()
	b, _, _ := Generate()
	if a == b {
		t.Error("两次生成的恢复码相同")
	}
}

// TestNormalize：大小写混杂、带/不带横线、含空格都应归一到同一哈希。
func TestNormalize(t *testing.T) {
	display, hash, err := Generate()
	if err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	compact := strings.ReplaceAll(display, "-", "")

	variants := map[string]string{
		"原样":   display,
		"大写":   strings.ToUpper(display),
		"无横线":  compact,
		"混排空格": strings.ReplaceAll(display, "-", " "),
	}
	for name, v := range variants {
		raw, err := normalize(v)
		if err != nil {
			t.Errorf("%s（%q）应归一化成功: %v", name, v, err)
			continue
		}
		sum := sha256.Sum256(raw)
		if string(sum[:]) != string(hash) {
			t.Errorf("%s 归一化哈希不一致", name)
		}
	}

	bad := []string{"", "!!!!", compact + "a", compact[:len(compact)-1]}
	for _, v := range bad {
		if _, err := normalize(v); !errors.Is(err, ErrInvalidRedeem) {
			t.Errorf("畸形输入 %q 应归一为 ErrInvalidRedeem，得到: %v", v, err)
		}
	}
}

// TestRedeemHappyPath：正确码 → 签发恢复凭证，凭证可 Lookup/Consume
// 到原 user handle。
func TestRedeemHappyPath(t *testing.T) {
	display, hash, _ := Generate()
	fst := &fakeStore{codeHash: hash, userHandle: []byte("handle-甲")}
	svc := newTestService(fst)

	token, err := svc.Redeem(context.Background(), display)
	if err != nil {
		t.Fatalf("Redeem 失败: %v", err)
	}
	if len(token) != tokenLen {
		t.Errorf("恢复凭证长度 = %d，期望 %d", len(token), tokenLen)
	}

	handle, ok := svc.LookupToken(token)
	if !ok || string(handle) != "handle-甲" {
		t.Errorf("LookupToken = %q, %v", handle, ok)
	}
}

// TestRedeemRejections：错码、畸形码、库错误统一 ErrInvalidRedeem，
// 不区分原因。
func TestRedeemRejections(t *testing.T) {
	_, hash, _ := Generate()
	fst := &fakeStore{codeHash: hash, userHandle: []byte("handle")}
	svc := newTestService(fst)

	if _, err := svc.Redeem(context.Background(), "aaaa-bbbb-cccc"); !errors.Is(err, ErrInvalidRedeem) {
		t.Errorf("错误码应 ErrInvalidRedeem，得到: %v", err)
	}
	if _, err := svc.Redeem(context.Background(), "不是恢复码"); !errors.Is(err, ErrInvalidRedeem) {
		t.Errorf("畸形码应 ErrInvalidRedeem，得到: %v", err)
	}

	fstErr := &fakeStore{err: errors.New("db down")}
	if _, err := newTestService(fstErr).Redeem(context.Background(), display(t)); !errors.Is(err, ErrInvalidRedeem) {
		t.Errorf("库错误应归一 ErrInvalidRedeem，得到: %v", err)
	}
}

// display 生成一枚合法展示串（错误注入用例的占位码）。
func display(t *testing.T) string {
	t.Helper()
	d, _, err := Generate()
	if err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	return d
}

// TestTokenOneTime：Consume 一次性——取出即作废，重放失败。
func TestTokenOneTime(t *testing.T) {
	d, hash, _ := Generate()
	svc := newTestService(&fakeStore{codeHash: hash, userHandle: []byte("handle")})
	token, err := svc.Redeem(context.Background(), d)
	if err != nil {
		t.Fatalf("Redeem 失败: %v", err)
	}

	if _, ok := svc.ConsumeToken(token); !ok {
		t.Fatal("首次 Consume 应成功")
	}
	if _, ok := svc.ConsumeToken(token); ok {
		t.Error("重放 Consume 应失败（一次性）")
	}
	if _, ok := svc.LookupToken(token); ok {
		t.Error("Consume 后 Lookup 应失败")
	}
}

// TestTokenExpiry：TTL 后 Lookup/Consume 均失败。
func TestTokenExpiry(t *testing.T) {
	d, hash, _ := Generate()
	svc := newTestService(&fakeStore{codeHash: hash, userHandle: []byte("handle")})
	token, _ := svc.Redeem(context.Background(), d)

	svc.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	if _, ok := svc.LookupToken(token); ok {
		t.Error("过期凭证 Lookup 应失败")
	}
	if _, ok := svc.ConsumeToken(token); ok {
		t.Error("过期凭证 Consume 应失败")
	}
}

// TestTokenUnknown：未签发/乱码 token 一律失败。
func TestTokenUnknown(t *testing.T) {
	svc := newTestService(&fakeStore{})
	if _, ok := svc.LookupToken([]byte("没签发过")); ok {
		t.Error("未知 token Lookup 应失败")
	}
	if _, ok := svc.ConsumeToken([]byte("没签发过")); ok {
		t.Error("未知 token Consume 应失败")
	}
}

// TestBase32Alphabet 防止 base32 编码形态漂移（无填充、RFC 4648 字母表）。
func TestBase32Alphabet(t *testing.T) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	raw := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if got := enc.EncodeToString(raw); len(got) != 26 || strings.ContainsAny(got, "=0189") {
		t.Errorf("base32 编码形态异常: %q", got)
	}
}
