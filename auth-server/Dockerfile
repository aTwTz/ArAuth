# arauth 组件镜像：build context 固定为 auth-server/，不依赖仓库根目录，
# 也不会把 service-server、service-web 或 e2e 打进镜像。
# 目标 arauth：scratch 单二进制（默认目标）。
# 目标 migrate：scratch + goose CLI（与 go.mod 锁定的 goose/v3 同源构建，
# 版本天然一致）+ migrations/，compose 中作一次性迁移服务。
FROM golang:1.26-alpine AS build
# GOPROXY 走构建参数：默认官方代理，受限网络可 --build-arg 覆盖
# （如 https://goproxy.cn,direct），不把区域网络形态写死进镜像。
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/arauth ./cmd/arauth \
 && CGO_ENABLED=0 GOBIN=/out go install github.com/pressly/goose/v3/cmd/goose@v3.28.0
# goose CLI 用 go install@version 而非从本 module 构建：cmd/goose 传递引入
# mysql/ydb 等多方言驱动，从本 module 构建会把这些无关依赖污染进 go.sum。
# 版本号须与 go.mod 中 pressly/goose/v3 保持一致（升级时两处同步）。

FROM scratch AS arauth
COPY --from=build /out/arauth /arauth
# 非 root 运行（scratch 无 /etc/passwd，用数值 UID）。
USER 65534
ENTRYPOINT ["/arauth"]

FROM scratch AS migrate
COPY --from=build /out/goose /goose
COPY --from=build /src/migrations/ /migrations/
USER 65534
ENTRYPOINT ["/goose"]
