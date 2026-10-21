package pow

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

// solve 用递增 counter 暴搜满足 difficulty 前缀零的 nonce，测试专用。
func solve(t *testing.T, challenge []byte, difficulty int) []byte {
	t.Helper()
	nonce := make([]byte, 8)
	for i := uint64(0); ; i++ {
		binary.BigEndian.PutUint64(nonce, i)
		buf := append(append([]byte{}, challenge...), nonce...)
		sum := sha256.Sum256(buf)
		if hasLeadingZeroBits(sum[:], difficulty) {
			return nonce
		}
		if i > 1<<24 {
			t.Fatalf("难度 %d 下 %d 次内未搜到解", difficulty, i)
		}
	}
}

func TestVerifyValidSolution(t *testing.T) {
	svc := New(8, time.Minute)
	challenge, difficulty := svc.Issue()
	if len(challenge) != challengeSize {
		t.Fatalf("challenge 长度 = %d，期望 %d", len(challenge), challengeSize)
	}
	if difficulty != 8 {
		t.Fatalf("下发难度 = %d，期望 8", difficulty)
	}
	if !svc.Verify(challenge, solve(t, challenge, difficulty)) {
		t.Fatal("有效解应通过")
	}
}

func TestVerifyWrongPrefix(t *testing.T) {
	svc := New(8, time.Minute)
	challenge, _ := svc.Issue()
	// 找一个前缀零不足 8 位的 nonce。
	nonce := make([]byte, 8)
	for i := uint64(0); ; i++ {
		binary.BigEndian.PutUint64(nonce, i)
		buf := append(append([]byte{}, challenge...), nonce...)
		sum := sha256.Sum256(buf)
		if !hasLeadingZeroBits(sum[:], 8) {
			break
		}
	}
	if svc.Verify(challenge, nonce) {
		t.Fatal("前缀零不足应失败")
	}
}

func TestVerifyReplay(t *testing.T) {
	svc := New(8, time.Minute)
	challenge, difficulty := svc.Issue()
	nonce := solve(t, challenge, difficulty)
	if !svc.Verify(challenge, nonce) {
		t.Fatal("首次有效解应通过")
	}
	if svc.Verify(challenge, nonce) {
		t.Fatal("同一 challenge 重放必须失败")
	}
}

// TestVerifyConsumedOnFailure 验证失败的校验同样消费 challenge
// （验一次即作废，不论对错——否则同一 challenge 可被无限试 nonce）。
func TestVerifyConsumedOnFailure(t *testing.T) {
	svc := New(8, time.Minute)
	challenge, difficulty := svc.Issue()
	// 先用错误 nonce 消费。
	if svc.Verify(challenge, []byte{0xff, 0xff, 0xff}) {
		t.Fatal("错误 nonce 不应通过")
	}
	// 再拿正确解来也应失败：challenge 已被上一次校验作废。
	if svc.Verify(challenge, solve(t, challenge, difficulty)) {
		t.Fatal("challenge 应在首次校验后即作废")
	}
}

func TestVerifyExpired(t *testing.T) {
	svc := New(8, time.Minute)
	now := time.Now()
	svc.now = func() time.Time { return now }
	challenge, difficulty := svc.Issue()
	nonce := solve(t, challenge, difficulty)

	now = now.Add(2 * time.Minute) // 越过 TTL（1 分钟）
	if svc.Verify(challenge, nonce) {
		t.Fatal("过期 challenge 应失败")
	}
}

func TestVerifyUnknownChallenge(t *testing.T) {
	svc := New(8, time.Minute)
	if svc.Verify(make([]byte, challengeSize), []byte{0x00}) {
		t.Fatal("未签发的 challenge 应失败")
	}
}

// solveExact 暴搜"恰好 n 个前导零"（满足 n、不满足 n+1）的 nonce。
func solveExact(t *testing.T, challenge []byte, n int) []byte {
	t.Helper()
	nonce := make([]byte, 8)
	for i := uint64(0); ; i++ {
		binary.BigEndian.PutUint64(nonce, i)
		buf := append(append([]byte{}, challenge...), nonce...)
		sum := sha256.Sum256(buf)
		if hasLeadingZeroBits(sum[:], n) && !hasLeadingZeroBits(sum[:], n+1) {
			return nonce
		}
		if i > 1<<24 {
			t.Fatalf("恰好 %d 个前导零在 %d 次内未搜到", n, i)
		}
	}
}

// TestDifficultyBoundary 恰好 N 个前导零的 nonce：难度 N 通过、N+1 失败。
func TestDifficultyBoundary(t *testing.T) {
	const n = 10

	svcN := New(n, time.Minute)
	chN, _ := svcN.Issue()
	if !svcN.Verify(chN, solveExact(t, chN, n)) {
		t.Fatalf("恰好 %d 个前导零在难度 %d 下应通过", n, n)
	}

	svcN1 := New(n+1, time.Minute)
	chN1, _ := svcN1.Issue()
	if svcN1.Verify(chN1, solveExact(t, chN1, n)) {
		t.Fatalf("恰好 %d 个前导零在难度 %d 下应失败", n, n+1)
	}
}

// TestIssuedDifficultyPinned 运行中调整难度不影响已签发的 challenge。
func TestIssuedDifficultyPinned(t *testing.T) {
	svc := New(4, time.Minute)
	challenge, _ := svc.Issue()
	nonce := solve(t, challenge, 4)
	svc.SetDifficultySource(func() int { return 200 }) // 模拟运行中调高难度
	if !svc.Verify(challenge, nonce) {
		t.Fatal("签发后调难度不应影响在途 challenge")
	}
}

// TestDifficultySourceAffectsNewChallenges 动态难度只影响新签发的
// challenge：换源后 Issue 返回新难度，旧条目仍按签发时难度校验。
func TestDifficultySourceAffectsNewChallenges(t *testing.T) {
	svc := New(4, time.Minute)
	old, d0 := svc.Issue()
	if d0 != 4 {
		t.Fatalf("初始难度 = %d，期望 4", d0)
	}
	svc.SetDifficultySource(func() int { return 9 })
	_, d1 := svc.Issue()
	if d1 != 9 {
		t.Fatalf("换源后难度 = %d，期望 9", d1)
	}
	// 旧 challenge 仍按签发时难度 4 校验。
	if !svc.Verify(old, solve(t, old, 4)) {
		t.Fatal("换源后旧 challenge 仍应按签发时难度通过")
	}
}
