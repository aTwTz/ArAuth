package pow

import (
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"
)

// challengeSize 是 challenge 的字节长度（DESIGN.md 第 6 节：32 字节随机数）。
const challengeSize = 32

// Service 是 PoW challenge 的签发与校验服务：进程内 map 暂存
// challenge → {签发时难度, 过期时刻}，TTL 一次性，不落库、不跨进程
// （单容器部署，见 DESIGN.md 第 6 节；不引入 Redis）。
type Service struct {
	mu      sync.Mutex
	entries map[string]entry // key 为 challenge 的原始字节
	// difficulty 是签发时难度的取值函数：静态构造时恒为构造参数，
	// 挂自适应控制器后随失败率滑动。Verify 不受影响——
	// 在途 challenge 按签发时钉住的难度校验。
	difficulty func() int
	ttl        time.Duration
	now        func() time.Time // 可注入时钟，测试用
}

type entry struct {
	difficulty int // 签发时的难度：运行中改配置不影响在途 challenge
	expires    time.Time
}

// New 创建 Service。difficulty 为前缀零位数（1–256，由 config 保证为正），
// ttl 为 challenge 存活时长。难度默认恒定；接自适应控制器时用
// SetDifficultySource 替换取值来源。
func New(difficulty int, ttl time.Duration) *Service {
	return &Service{
		entries:    make(map[string]entry),
		difficulty: func() int { return difficulty },
		ttl:        ttl,
		now:        time.Now,
	}
}

// SetDifficultySource 把签发难度的取值来源换成自适应控制器（失败率
// 驱动升降挡）。只影响此后签发的 challenge；在途 challenge
// 的难度在签发时已钉住进条目，校验路径不变。
func (s *Service) SetDifficultySource(source func() int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.difficulty = source
}

// Issue 签发一个新 challenge 并返回其原始字节与当前难度。
// crypto/rand.Read 在所有支持的平台上保证填满且返回 nil。
func (s *Service) Issue() (challenge []byte, difficulty int) {
	challenge = make([]byte, challengeSize)
	_, _ = rand.Read(challenge)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpired()
	d := s.difficulty()
	s.entries[string(challenge)] = entry{
		difficulty: d,
		expires:    s.now().Add(s.ttl),
	}
	return challenge, d
}

// Verify 校验 SHA-256(challenge ‖ nonce) 的前 N 位是否为零（N 取签发时
// 难度），并消费 challenge——验一次即作废，不论对错（DESIGN.md 第 6 节）。
// 消费先于校验：否则同一 challenge 可被无限次试 nonce，PoW 形同虚设。
// challenge 不存在、已过期、前缀不对，对外一律只体现为 false，不做区分
// （保密红线第 6 条）。
func (s *Service) Verify(challenge, nonce []byte) bool {
	s.mu.Lock()
	e, ok := s.entries[string(challenge)]
	if ok {
		delete(s.entries, string(challenge))
	}
	s.mu.Unlock()

	if !ok || s.now().After(e.expires) {
		return false
	}

	buf := make([]byte, 0, len(challenge)+len(nonce))
	buf = append(buf, challenge...)
	buf = append(buf, nonce...)
	sum := sha256.Sum256(buf)
	return hasLeadingZeroBits(sum[:], e.difficulty)
}

// hasLeadingZeroBits 逐位检查 b 的前 n 位是否全零（支持非整字节位数）。
func hasLeadingZeroBits(b []byte, n int) bool {
	for i := 0; i < n; i++ {
		if b[i/8]&(0x80>>(i%8)) != 0 {
			return false
		}
	}
	return true
}

// purgeExpired 惰性清理过期条目，调用时必须已持锁。
func (s *Service) purgeExpired() {
	now := s.now()
	for k, e := range s.entries {
		if now.After(e.expires) {
			delete(s.entries, k)
		}
	}
}
