package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/store"
)

// codeLen 是恢复码的字节数：128 位 crypto/rand（DESIGN.md 第 2 节"根"层）。
// 128 位熵下 SHA-256 足够，不装 argon2/bcrypt（DESIGN.md 第 10 节）。
const codeLen = 16

// tokenLen 是恢复凭证（一次性 token）的字节数：256 位 crypto/rand。
const tokenLen = 32

// ErrInvalidRedeem 表示恢复输入无效（恢复码/TOTP 不存在、已轮换、
// 已消费、被节流或格式不对）。对外不区分原因，由 server 统一映射为 401。
var ErrInvalidRedeem = errors.New("recovery: 恢复码无效")

// Store 是 recovery 对数据层的最小依赖：兑换只需按哈希查码。
// 轮换写入在 authn 的恢复注册事务里完成（AttachCredentialAndRotate）。
type Store interface {
	GetRecoveryCodeByHash(ctx context.Context, codeHash []byte) (*store.RecoveryCode, error)
}

// Generate 生成一枚新恢复码，返回分组展示串（原文，仅此一次经返回值
// 传递）与入库用的 SHA-256。展示串为 base32 小写、4 字符分组（人类可抄）。
// 原文绝不落库、绝不进日志（数据分级第 3 条）。
func Generate() (display string, hash []byte, err error) {
	raw := make([]byte, codeLen)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("recovery: 生成恢复码失败: %w", err)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	display = group4(strings.ToLower(enc))
	sum := sha256.Sum256(raw)
	return display, sum[:], nil
}

// group4 把 base32 串按 4 字符分组、横线连接（展示形态）。
func group4(s string) string {
	var b strings.Builder
	for i, c := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// normalize 把用户输入的恢复码归一化回 16 字节原文：去横线/空格、
// 统一大写后按 base32（无填充）解码。格式不合法即 ErrInvalidRedeem——
// 与"码不存在"对外不可区分。
func normalize(code string) ([]byte, error) {
	compact := strings.NewReplacer("-", "", " ", "").Replace(code)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(compact))
	if err != nil || len(raw) != codeLen {
		return nil, ErrInvalidRedeem
	}
	return raw, nil
}

// Service 负责恢复码兑换与恢复凭证（一次性 token）的签发/消费。
type Service struct {
	st        Store
	totpStore TOTPStore
	cfg       *config.Config
	mu        sync.Mutex
	tokens    map[string]tokenEntry
	setups    map[string]totpSetupEntry
	ttl       time.Duration
	now       func() time.Time // 可注入时钟，测试用
}

type tokenEntry struct {
	userHandle []byte
	expires    time.Time
}

// New 构建恢复服务。ttl 为恢复凭证的存活时长（一次性、短 TTL，
// 进程内 map 足够——与 challenge/PoW 同形态，不装 Redis）。
func New(cfg *config.Config, st Store) *Service {
	totpStore, _ := st.(TOTPStore)
	return &Service{
		st:        st,
		totpStore: totpStore,
		cfg:       cfg,
		tokens:    make(map[string]tokenEntry),
		setups:    make(map[string]totpSetupEntry),
		ttl:       cfg.RecoveryTokenTTL,
		now:       time.Now,
	}
}

// Generate 实现 authn.RecoveryGate，委托包级 Generate（恢复码生成不
// 依赖服务状态）。
func (s *Service) Generate() (display string, hash []byte, err error) {
	return Generate()
}

// Redeem 验证恢复码并签发恢复凭证。码原文只用于归一化与哈希，哈希查库；
// 任何失败（格式/不存在/已轮换）统一 ErrInvalidRedeem。恢复凭证是
// 一次性 token：唯一权限是把新凭据挂到原 user_handle（authn 裁决）。
func (s *Service) Redeem(ctx context.Context, code string) (token []byte, err error) {
	raw, err := normalize(code)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	rc, err := s.st.GetRecoveryCodeByHash(ctx, sum[:])
	if err != nil {
		// 不存在/已轮换与其他内部错误对外不可区分（保密红线第 6 条）。
		return nil, fmt.Errorf("%w: %v", ErrInvalidRedeem, err)
	}

	return s.issueToken(rc.UserHandle)
}

// issueToken 是恢复码与 TOTP 共用的唯一恢复资格签发点。
func (s *Service) issueToken(userHandle []byte) (token []byte, err error) {
	token = make([]byte, tokenLen)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("recovery: 生成恢复凭证失败: %w", err)
	}
	s.putToken(token, userHandle)
	return token, nil
}

// LookupToken 查询恢复凭证对应的 user handle，不消费（恢复 options
// 阶段用——verify 才是一次性消费点）。
func (s *Service) LookupToken(token []byte) (userHandle []byte, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.tokens[tokenKey(token)]
	if !ok || s.now().After(entry.expires) {
		return nil, false
	}
	return entry.userHandle, true
}

// ConsumeToken 取出恢复凭证对应的 user handle 并立即作废（一次性，
// 不论后续成败——与 PoW "验一次即作废"同判，失败需重新 redeem）。
func (s *Service) ConsumeToken(token []byte) (userHandle []byte, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tokenKey(token)
	entry, ok := s.tokens[key]
	if !ok {
		return nil, false
	}
	delete(s.tokens, key)
	if s.now().After(entry.expires) {
		return nil, false
	}
	return entry.userHandle, true
}

// putToken 暂存恢复凭证（存哈希不存原文，惰性清理过期条目）。
func (s *Service) putToken(token, userHandle []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, e := range s.tokens {
		if now.After(e.expires) {
			delete(s.tokens, k)
		}
	}
	s.tokens[tokenKey(token)] = tokenEntry{
		userHandle: userHandle,
		expires:    now.Add(s.ttl),
	}
}

// tokenKey 取 token 的 SHA-256 作为 map key：内存态也不留凭证原文。
func tokenKey(token []byte) string {
	sum := sha256.Sum256(token)
	return string(sum[:])
}
