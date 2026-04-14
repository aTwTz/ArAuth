// Package ratelimit 提供 per-IP 限流（x/time/rate）与自适应难度信号，
// 与 PoW 互补：登录靠限流，注册与恢复兑换靠 PoW。
package ratelimit
