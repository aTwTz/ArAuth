// arauth 进程入口：只做装配（config → store → authn → server → HTTP），
// 不含业务逻辑。
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/arithmaton/arauth/internal/authn"
	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/pow"
	"github.com/arithmaton/arauth/internal/ratelimit"
	"github.com/arithmaton/arauth/internal/recovery"
	"github.com/arithmaton/arauth/internal/server"
	"github.com/arithmaton/arauth/internal/session"
	"github.com/arithmaton/arauth/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("arauth: 配置加载失败: %v", err)
	}

	ctx := context.Background()
	st, err := store.New(ctx, cfg.DSN)
	if err != nil {
		log.Fatalf("arauth: 数据层初始化失败: %v", err)
	}
	defer st.Close()

	recoverySvc := recovery.New(cfg, st)

	authnSvc, err := authn.New(cfg, st, recoverySvc)
	if err != nil {
		log.Fatalf("arauth: WebAuthn 初始化失败: %v", err)
	}

	powSvc := pow.New(cfg.PoWDifficulty, cfg.PoWChallengeTTL)

	// per-IP 限流 + PoW 自适应难度（失败率驱动，只影响新签发
	// challenge 的取值来源，在途 challenge 按签发时难度校验）。
	limiter := ratelimit.NewLimiter(cfg)
	adaptive := ratelimit.NewAdaptive(cfg)
	powSvc.SetDifficultySource(adaptive.Difficulty)

	sessSvc := session.New(cfg, st)

	log.Printf("arauth: 监听 %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, server.New(cfg, authnSvc, powSvc, authnSvc, sessSvc, recoverySvc, limiter, adaptive)); err != nil {
		log.Fatalf("arauth: HTTP 服务退出: %v", err)
	}
}
