#!/usr/bin/env bash
# 端到端验收：起 compose 全栈（含依赖方参考服务）→ 模拟浏览器全链路
# （PoW → 注册并绑定 TOTP → confirm → 登录 → 登录后更换 TOTP → exchange →
# 依赖方 cookie 生效 → TOTP/恢复码双找回轮换）。任何一步失败即非零退出。
#
# 前置：Docker（compose v2.24+，override 用了 !reset）、Go ≥ 1.26、curl、openssl。
# 独立 compose project（arauth-e2e）与独立回环端口，默认不干扰开发栈。
set -euo pipefail
cd "$(dirname "$0")/.."

# 允许调用方覆盖高位端口；origins 必须和浏览器实际入口一致。
# shellcheck disable=SC1091
set -a; . scripts/e2e.env; set +a
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18080}"
E2E_HTTPS_PORT="${E2E_HTTPS_PORT:-18443}"
ARAUTH_RP_ORIGINS="https://localhost:${E2E_HTTPS_PORT}"
RP_URL="https://localhost:${E2E_HTTPS_PORT}"
export E2E_HTTP_PORT E2E_HTTPS_PORT ARAUTH_RP_ORIGINS

PROJECT=arauth-e2e
COMPOSE=(docker compose -p "$PROJECT" --env-file scripts/e2e.env
	-f docker-compose.yml -f scripts/e2e.compose.yml)
TMP_DIR="$(mktemp -d)"
TLS_DIR="$TMP_DIR/tls"
CA_FILE="$TLS_DIR/ca.crt"
export E2E_TLS_DIR="$TLS_DIR"

cleanup() {
	"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
	rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# 端口预检：被占时尽早给出清晰错误，不停止调用方已有的服务。
for port in "$E2E_HTTP_PORT" "$E2E_HTTPS_PORT"; do
	if curl -s -o /dev/null --max-time 2 "http://localhost:$port/" ||
		curl -sk -o /dev/null --max-time 2 "https://localhost:$port/"; then
		echo "端口 $port 已被占用。请通过 E2E_HTTP_PORT/E2E_HTTPS_PORT 选择空闲端口。" >&2
		exit 1
	fi
done

echo "== 生成 e2e 一次性 CA 与 localhost 证书（仅本测试栈使用，跑完即销毁）"
mkdir -p "$TLS_DIR"
openssl genrsa -out "$TLS_DIR/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$TLS_DIR/ca.key" -days 1 \
	-subj "/CN=arauth-e2e-local-ca" -out "$TLS_DIR/ca.crt"
openssl genrsa -out "$TLS_DIR/server.key" 2048 2>/dev/null
openssl req -new -key "$TLS_DIR/server.key" -subj "/CN=localhost" \
	-out "$TLS_DIR/server.csr"
openssl x509 -req -in "$TLS_DIR/server.csr" -CA "$TLS_DIR/ca.crt" \
	-CAkey "$TLS_DIR/ca.key" -CAcreateserial -days 1 \
	-extfile <(printf 'subjectAltName=DNS:localhost') \
	-out "$TLS_DIR/server.crt" 2>/dev/null

echo "== 构建并起全栈（postgres → migrate → arauth → service-server → nginx）"
# GOPROXY 透传（构建期代理属区域网络形态，不写死进仓库交付物）。
# 优先级：调用方环境变量 > 仓库根 .env > compose 默认官方代理。
if [ -z "${GOPROXY:-}" ] && [ -f .env ]; then
	gp=$(grep -E '^GOPROXY=' .env | tail -1 | cut -d= -f2- || true)
	[ -n "$gp" ] && export GOPROXY="$gp"
fi
"${COMPOSE[@]}" up -d --build

echo "== 等待公共服务就绪（/health 由 RP 检查 arauth 上游；暂用 -k 探活）"
for i in $(seq 1 90); do
	if curl -sk --max-time 2 "$RP_URL/health" | grep -q '"status":"ok"'; then
		break
	fi
	if [ "$i" = 90 ]; then
		echo "公共服务 90 秒内未就绪" >&2
		"${COMPOSE[@]}" logs >&2 || true
		exit 1
	fi
	sleep 1
done

echo "== 校验 TLS 信任链（客户端显式信任一次性 CA，不用 -k 跑链路）"
curl -s --cacert "$CA_FILE" --max-time 5 "$RP_URL/health" | grep -q '"status":"ok"'

echo "== 构建 e2e 客户端到临时目录"
go -C e2e build -o "$TMP_DIR/e2e" .

echo "== 跑端到端链路（虚拟验证器 + 逐步断言）"
E2E_RP_URL="$RP_URL" \
E2E_CA_FILE="$CA_FILE" \
E2E_RPID="$ARAUTH_RPID" \
E2E_ORIGIN="$ARAUTH_RP_ORIGINS" \
	"$TMP_DIR/e2e"

echo "== scripts/e2e.sh 全绿"
