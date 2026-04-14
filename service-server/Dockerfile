# service-server 参考服务：静态编译，最终镜像只含二进制与 CA 根证书。
FROM golang:1.26-alpine AS build
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/service-server .

FROM scratch
COPY --from=build /out/service-server /service-server
# HTTPS 上游仍做完整证书校验；scratch 自身不带系统根证书。
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65534
ENTRYPOINT ["/service-server"]
