package main

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 附录 B 的 SHA1 向量。ASCII 种子 "12345678901234567890"
// 同时以 Base32 无填充形式经过在线流程使用的 totpCodeAt，验证 6 位截断与前导零。
func TestTOTPRFC6238SHA1Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	secretText := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	tests := []struct {
		unix  int64
		want8 string
	}{
		{unix: 59, want8: "94287082"},
		{unix: 1111111109, want8: "07081804"},
		{unix: 1111111111, want8: "14050471"},
		{unix: 1234567890, want8: "89005924"},
		{unix: 2000000000, want8: "69279037"},
		{unix: 20000000000, want8: "65353130"},
	}
	for _, tc := range tests {
		t.Run(time.Unix(tc.unix, 0).UTC().String(), func(t *testing.T) {
			at := time.Unix(tc.unix, 0)
			counter := uint64(tc.unix / int64(totpPeriod/time.Second))
			if got := hotp(secret, counter, 8); got != tc.want8 {
				t.Fatalf("8 位 RFC 6238 动态码 = %q，期望 %q", got, tc.want8)
			}
			got6, err := totpCodeAt(secretText, at)
			if err != nil {
				t.Fatalf("生成 6 位动态码失败: %v", err)
			}
			if want6 := tc.want8[len(tc.want8)-totpDigits:]; got6 != want6 {
				t.Fatalf("6 位 RFC 6238 动态码 = %q，期望 %q", got6, want6)
			}
		})
	}
}

func TestTOTPCodeRejectsInvalidBase32(t *testing.T) {
	if _, err := totpCodeAt("not-base32!", time.Unix(59, 0)); err == nil {
		t.Fatal("非法 Base32 secret 应返回错误")
	}
}
