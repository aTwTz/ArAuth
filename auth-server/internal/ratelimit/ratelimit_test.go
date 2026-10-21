package ratelimit

import (
	"testing"
	"time"

	"github.com/arithmaton/arauth/internal/config"
)

// testConfig 构造限流/自适应测试用配置：小突发便于快速触发拒绝，
// 小窗口便于快速评估升/降挡。
func testConfig() *config.Config {
	return &config.Config{
		PoWDifficulty:     21,
		PoWMinDifficulty:  20,
		PoWMaxDifficulty:  22,
		PoWAdaptiveWindow: 4,
		PoWAdaptiveUp:     0.5,
		PoWAdaptiveDown:   0.1,
		RateStrictRPS:     1,
		RateStrictBurst:   2,
		RateLenientRPS:    10,
		RateLenientBurst:  4,
	}
}

// TestLimiterTriggersAndRecovers 突发耗尽后拒绝且给出等待时长，
// 时钟推进一个周期后恢复放行。
func TestLimiterTriggersAndRecovers(t *testing.T) {
	l := NewLimiter(testConfig())
	now := time.Now()
	l.now = func() time.Time { return now }

	// 突发 2：前两次放行，第三次拒绝。
	for i := 0; i < 2; i++ {
		if ok, _ := l.Allow("1.1.1.1", TierStrict); !ok {
			t.Fatalf("第 %d 次请求（突发内）应放行", i+1)
		}
	}
	ok, retry := l.Allow("1.1.1.1", TierStrict)
	if ok {
		t.Fatal("突发耗尽后应拒绝")
	}
	if retry <= 0 || retry > time.Second {
		t.Errorf("Retry-After 等待 = %v，期望 (0, 1s]", retry)
	}

	// 推进 2 秒（速率 1/s），令牌回满后恢复放行。
	now = now.Add(2 * time.Second)
	if ok, _ := l.Allow("1.1.1.1", TierStrict); !ok {
		t.Fatal("令牌补充后应恢复放行")
	}
}

// TestLimiterTiersAndIPsIndependent 两档互不影响、不同 IP 互不影响。
func TestLimiterTiersAndIPsIndependent(t *testing.T) {
	l := NewLimiter(testConfig())

	// 打满严格档突发。
	for i := 0; i < 2; i++ {
		l.Allow("1.1.1.1", TierStrict)
	}
	if ok, _ := l.Allow("1.1.1.1", TierStrict); ok {
		t.Fatal("严格档应已耗尽")
	}
	// 同 IP 宽松档不受影响。
	if ok, _ := l.Allow("1.1.1.1", TierLenient); !ok {
		t.Fatal("同 IP 的宽松档不应受严格档耗尽影响")
	}
	// 不同 IP 严格档不受影响。
	if ok, _ := l.Allow("2.2.2.2", TierStrict); !ok {
		t.Fatal("其他 IP 不应受影响")
	}
}

// TestAdaptiveStepUpAndDown 失败率超阈值升挡、回落降挡，初始值不变。
func TestAdaptiveStepUpAndDown(t *testing.T) {
	a := NewAdaptive(testConfig())
	if a.Difficulty() != 21 {
		t.Fatalf("初始难度 = %d，期望 21", a.Difficulty())
	}

	// 窗口 4：全失败（失败率 1.0 ≥ 0.5）→ 升 1 位。
	for i := 0; i < 4; i++ {
		a.Record(false)
	}
	if a.Difficulty() != 22 {
		t.Fatalf("全失败窗口后难度 = %d，期望 22", a.Difficulty())
	}

	// 全成功（失败率 0 ≤ 0.1）→ 降 1 位。
	for i := 0; i < 4; i++ {
		a.Record(true)
	}
	if a.Difficulty() != 21 {
		t.Fatalf("全成功窗口后难度 = %d，期望 21", a.Difficulty())
	}
}

// TestAdaptiveCeiling 失败率持续超阈值也只到上限为止。
func TestAdaptiveCeiling(t *testing.T) {
	a := NewAdaptive(testConfig()) // max 22
	for w := 0; w < 5; w++ {
		for i := 0; i < 4; i++ {
			a.Record(false)
		}
	}
	if a.Difficulty() != 22 {
		t.Fatalf("触顶后难度 = %d，期望封顶 22", a.Difficulty())
	}
}

// TestAdaptiveFloor 失败率持续低迷也只到下限为止。
func TestAdaptiveFloor(t *testing.T) {
	a := NewAdaptive(testConfig()) // min 20
	for w := 0; w < 5; w++ {
		for i := 0; i < 4; i++ {
			a.Record(true)
		}
	}
	if a.Difficulty() != 20 {
		t.Fatalf("触底后难度 = %d，期望托底 20", a.Difficulty())
	}
}

// TestAdaptiveMiddleBandHolds 失败率落在迟滞带内（down < rate < up）不动作。
func TestAdaptiveMiddleBandHolds(t *testing.T) {
	a := NewAdaptive(testConfig())
	// 窗口 4 中 1 个失败：失败率 0.25，介于 0.1 与 0.5 之间。
	for i := 0; i < 3; i++ {
		a.Record(true)
	}
	a.Record(false)
	if a.Difficulty() != 21 {
		t.Fatalf("迟滞带内难度 = %d，期望不变 21", a.Difficulty())
	}
}

// TestAdaptivePartialWindowNoEval 窗口未集满不评估。
func TestAdaptivePartialWindowNoEval(t *testing.T) {
	a := NewAdaptive(testConfig())
	for i := 0; i < 3; i++ { // 窗口 4，只喂 3 个全失败
		a.Record(false)
	}
	if a.Difficulty() != 21 {
		t.Fatalf("窗口未集满不应评估，难度 = %d，期望 21", a.Difficulty())
	}
}
