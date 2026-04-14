package authn

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestChallengeStoreOneTime(t *testing.T) {
	cs := newChallengeStore(5 * time.Minute)
	session := webauthn.SessionData{Challenge: "abc", UserID: []byte("handle")}

	cs.put(session)

	got, ok := cs.consume("abc")
	if !ok {
		t.Fatal("首次 consume 应成功")
	}
	if string(got.UserID) != "handle" {
		t.Errorf("UserID = %q，期望 handle", got.UserID)
	}

	if _, ok := cs.consume("abc"); ok {
		t.Error("重复 consume 应失败（一次性，防重放）")
	}
}

func TestChallengeStoreExpiry(t *testing.T) {
	cs := newChallengeStore(5 * time.Minute)
	cs.put(webauthn.SessionData{Challenge: "abc"})

	// 时钟快进到 TTL 之后
	cs.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	if _, ok := cs.consume("abc"); ok {
		t.Error("过期 challenge 应消费失败")
	}
}

func TestChallengeStorePurge(t *testing.T) {
	cs := newChallengeStore(5 * time.Minute)
	cs.put(webauthn.SessionData{Challenge: "old"})

	cs.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	cs.put(webauthn.SessionData{Challenge: "new"}) // put 触发惰性清理

	if len(cs.entries) != 1 {
		t.Errorf("清理后条目 = %d，期望 1", len(cs.entries))
	}
	if _, ok := cs.entries["old"]; ok {
		t.Error("过期条目应被清理")
	}
}

func TestChallengeStoreUnknown(t *testing.T) {
	cs := newChallengeStore(5 * time.Minute)
	if _, ok := cs.consume("从未存在"); ok {
		t.Error("未知 challenge 应消费失败")
	}
}
