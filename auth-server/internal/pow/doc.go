// Package pow 实现 PoW：challenge 签发（进程内 map + TTL，不落库）、
// 解校验、难度配置。仅挂注册与恢复兑换（一次性恢复码或 TOTP），登录不挂。
package pow
