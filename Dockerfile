FROM golang:alpine AS builder

WORKDIR /app
COPY . /app
RUN go build ./cmd/socks5-server


FROM alpine:3.17
COPY --from=builder /app/socks5-server /socks5-server
ENTRYPOINT ["/socks5-server"]
