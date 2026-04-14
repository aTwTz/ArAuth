package main

import (
	"crypto/hmac"
	"crypto/sha1" // RFC 6238 默认互操作算法；这里仅用于测试客户端动态码。
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	totpPeriod = 30 * time.Second
	totpDigits = 6
)

// totpCodeAt 按 RFC 6238 的 SHA1/6 位/30 秒参数生成动态码。
// 服务端下发的 secret 是 Base32 无填充文本；这里不引入认证器或 TOTP 第三方库。
func totpCodeAt(secretText string, at time.Time) (string, error) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secretText))
	if err != nil {
		return "", fmt.Errorf("TOTP secret Base32 解码失败: %w", err)
	}
	defer clear(secret)
	counter := uint64(at.Unix() / int64(totpPeriod/time.Second))
	return hotp(secret, counter, totpDigits), nil
}

// hotp 实现 RFC 4226 动态截断。digits 独立成参数，以便单测直接覆盖
// RFC 6238 附录 B 的 8 位 SHA1 固定向量；在线流程固定使用 6 位。
func hotp(secret []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(buf[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for i := 0; i < digits; i++ {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%modulus)
}
