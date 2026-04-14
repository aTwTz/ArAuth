package ratelimit

import (
	"sync"

	"github.com/arithmaton/arauth/internal/config"
)

// Adaptive 是 PoW 自适应难度控制器：以注册 options 与恢复兑换两处
// PoW 门的验证成败为信号，按定长滚动窗口评估失败率——窗口集满
// window 个结果时评估一次：失败率 ≥ up 升一位（封顶 max），≤ down
// 降一位（托底 min），随后清零进入下一窗口（评估粒度=窗口，天然
// 迟滞，同一批失败不会连续跳多档）。难度只影响新签发的 challenge，
// 在途 challenge 按签发时难度校验（pow.Service 保证）。
type Adaptive struct {
	mu       sync.Mutex
	current  int
	min, max int
	window   int
	up, down float64
	total    int // 当前窗口内已记录的验证结果数
	failures int
}

// NewAdaptive 从 config 构建控制器，初始难度取 cfg.PoWDifficulty
// （config.Load 已校验 min ≤ 初始 ≤ max）。
func NewAdaptive(cfg *config.Config) *Adaptive {
	return &Adaptive{
		current: cfg.PoWDifficulty,
		min:     cfg.PoWMinDifficulty,
		max:     cfg.PoWMaxDifficulty,
		window:  cfg.PoWAdaptiveWindow,
		up:      cfg.PoWAdaptiveUp,
		down:    cfg.PoWAdaptiveDown,
	}
}

// Record 记录一次 PoW 验证结果（ok=true 为解出）。挂点只有注册
// options 与恢复兑换两处（DESIGN.md 第 6 节），由 server 调用。
func (a *Adaptive) Record(ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.total++
	if !ok {
		a.failures++
	}
	if a.total < a.window {
		return
	}
	rate := float64(a.failures) / float64(a.total)
	switch {
	case rate >= a.up && a.current < a.max:
		a.current++
	case rate <= a.down && a.current > a.min:
		a.current--
	}
	a.total, a.failures = 0, 0
}

// Difficulty 返回当前难度（供 pow.Service 在签发时取值钉住）。
func (a *Adaptive) Difficulty() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current
}
