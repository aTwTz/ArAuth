package authn

import (
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// challengeStore 是 WebAuthn ceremony 会话的进程内暂存：key 为 challenge
// （base64url），值为 SessionData 与过期时刻。一次性消费（取出即删），
// TTL 由 config 下发。不持久化——challenge 本就是 5 分钟一次性值，
// 进程内 map 足够（不引入 Redis）。
type challengeStore struct {
	mu      sync.Mutex
	entries map[string]challengeEntry
	ttl     time.Duration
	now     func() time.Time // 可注入时钟，测试用
}

type challengeEntry struct {
	session webauthn.SessionData
	expires time.Time
}

func newChallengeStore(ttl time.Duration) *challengeStore {
	return &challengeStore{
		entries: make(map[string]challengeEntry),
		ttl:     ttl,
		now:     time.Now,
	}
}

// put 暂存一份 ceremony 会话。
func (s *challengeStore) put(session webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpired()
	s.entries[session.Challenge] = challengeEntry{
		session: session,
		expires: s.now().Add(s.ttl),
	}
}

// consume 按 challenge 取出会话并立即删除（一次性，防重放）。
// 不存在或已过期均返回 false——两者对外不做区分（保密红线第 6 条）。
func (s *challengeStore) consume(challenge string) (webauthn.SessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[challenge]
	if !ok {
		return webauthn.SessionData{}, false
	}
	delete(s.entries, challenge)
	if s.now().After(entry.expires) {
		return webauthn.SessionData{}, false
	}
	return entry.session, true
}

// purgeExpired 惰性清理过期条目，调用时必须已持锁。
func (s *challengeStore) purgeExpired() {
	now := s.now()
	for k, e := range s.entries {
		if now.After(e.expires) {
			delete(s.entries, k)
		}
	}
}
