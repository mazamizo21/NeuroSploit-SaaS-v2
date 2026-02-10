# TazoSploit Tunnel Gateway - WireGuard VPN Gateway
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true

COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o tunnel-gateway .

# Runtime
FROM alpine:3.19

RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    ip6tables \
    iproute2 \
    bash \
    curl

COPY --from=builder /build/tunnel-gateway /usr/local/bin/tunnel-gateway

# Create WireGuard data directory
RUN mkdir -p /etc/wireguard

EXPOSE 51820/udp
EXPOSE 8080/tcp

ENTRYPOINT ["tunnel-gateway"]
