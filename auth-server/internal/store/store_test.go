package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestNewInvalidDSN 不触库：非法 DSN 应在解析阶段报错。
func TestNewInvalidDSN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s, err := New(ctx, "不是合法连接串")
	if err == nil {
		s.Close()
		t.Fatal("非法 DSN 应当报错")
	}
	if !strings.Contains(err.Error(), "store:") {
		t.Fatalf("错误信息应带 store: 前缀，得到: %v", err)
	}
}
