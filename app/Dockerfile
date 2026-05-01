# ── Build stage ──────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache dependency layer separately from source
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -ldflags="-w -s -extldflags=-static" \
      -trimpath \
      -o /out/server \
      ./cmd/server

# ── Runtime stage ─────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache \
        ca-certificates \
        tzdata \
        wget    # used by healthcheck

# Non-root user
RUN addgroup -g 1001 app && adduser -u 1001 -G app -s /bin/sh -D app

COPY --from=builder /out/server /usr/local/bin/server

# /certs is mounted from the consul-tmpl-certs volume at runtime
RUN mkdir -p /certs && chown app:app /certs

USER app

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/server"]
