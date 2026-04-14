package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/arithmaton/arauth/internal/config"
)

// Tier 标识限流档位：注册系/恢复兑换/exchange/PoW 领取走严格档，
// 登录端点走宽松档（正常用户也频繁触发）。
type Tier int

const (
	// TierStrict 严格档：凭空造身份与票据兑换类端点。
	TierStrict Tier = iota
	// TierLenient 宽松档：登录端点（禁止挂 PoW，限流是唯一防线，
	// DESIGN.md 第 6 节）。
	TierLenient
)

// ipEntryTTL 是单 IP 限流器的空闲存活时长：超过此时间没有任何请求的
// IP 条目在下次惰性清理时回收（令牌早已回满，回收不放宽限流语义）。
const ipEntryTTL = 10 * time.Minute

// Limiter 是 per-IP 令牌桶限流器：进程内 map 暂存（单容器部署，与
// challenge 同形态，不引入 Redis），惰性过期清理。
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*ipEntry
	strict  rate.Limit
	lenient rate.Limit
	sBurst  int
	lBurst  int
	now     func() time.Time // 可注入时钟，测试用
}

type ipEntry struct {
	strict  *rate.Limiter
	lenient *rate.Limiter
	lastHit time.Time
}

// NewLimiter 从 config 构建限流器。速率/突发两档参数全部由 config 下发，
// 此处不出现字面量（数据分级第 5 条）。
func NewLimiter(cfg *config.Config) *Limiter {
	return &Limiter{
		entries: make(map[string]*ipEntry),
		strict:  rate.Limit(cfg.RateStrictRPS),
		lenient: rate.Limit(cfg.RateLenientRPS),
		sBurst:  cfg.RateStrictBurst,
		lBurst:  cfg.RateLenientBurst,
		now:     time.Now,
	}
}

// Allow 报告该 IP 在该档是否放行；拒绝时返回建议的重试等待时长（供
// Retry-After 响应头），该时长是"再等多久会有一个令牌可用"的上取整。
func (l *Limiter) Allow(ip string, tier Tier) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	e := l.entry(ip)
	lim := e.strict
	if tier == TierLenient {
		lim = e.lenient
	}
	l.mu.Unlock()

	now := l.now()
	rsv := lim.ReserveN(now, 1)
	if !rsv.OK() {
		// 突发为正的限速器下单个令牌的预订必然成功，走到这里说明
		// 配置被改成了 burst=0——保守拒绝。
		return false, time.Second
	}
	if d := rsv.DelayFrom(now); d > 0 {
		rsv.Cancel() // 不放行就不消耗未来的令牌
		return false, d
	}
	return true, 0
}

// entry 取或建该 IP 的限流器对，并顺手惰性清理过期条目。调用时持锁。
func (l *Limiter) entry(ip string) *ipEntry {
	now := l.now()
	for k, e := range l.entries {
		if now.Sub(e.lastHit) > ipEntryTTL {
			delete(l.entries, k)
		}
	}
	e, ok := l.entries[ip]
	if !ok {
		e = &ipEntry{
			strict:  rate.NewLimiter(l.strict, l.sBurst),
			lenient: rate.NewLimiter(l.lenient, l.lBurst),
		}
		l.entries[ip] = e
	}
	e.lastHit = now
	return e
}
