FROM golang:1.21-bookworm AS builder

WORKDIR /app
COPY . /app
RUN go build ./cmd/socks5-server


FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /app/socks5-server .
ENTRYPOINT ["/app/socks5-server"]
