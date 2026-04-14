// Package session 实现 opaque token 会话：签发 256 位随机 token、
// 服务器只存 SHA-256、httpOnly Cookie 写入，以及一次性 exchange code。
// 不使用 JWT。
package session
