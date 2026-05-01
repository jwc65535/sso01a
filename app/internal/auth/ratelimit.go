package auth

// IPRateLimiter — per-IP token bucket rate limiting middleware.
//
// SINGLE-MODULE COMPROMISE: if the Apache reverse proxy is bypassed and an
// attacker reaches the Go backend directly, this limiter is the last line of
// defense before the token/cert endpoints.  It mirrors the Apache limits so
// neither layer alone is the single point of failure.
//
// Uses golang.org/x/time/rate (already in go.mod) — token bucket algorithm.
// Each IP gets its own bucket; buckets are evicted after idleTTL inactivity.

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const idleTTL = 5 * time.Minute

// ipState holds the limiter and last-seen time for one IP address.
type ipState struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter maintains per-IP rate limiters and exposes an HTTP middleware.
type IPRateLimiter struct {
	mu      sync.Mutex
	ips     map[string]*ipState
	r       rate.Limit // tokens per second
	burst   int
	cleanup *time.Ticker
	done    chan struct{}
}

// NewIPRateLimiter creates a limiter with the given steady-state rate and burst.
//
// Example: NewIPRateLimiter(rate.Every(time.Minute/5), 3)
// = 5 tokens/minute, burst of 3.
func NewIPRateLimiter(r rate.Limit, burst int) *IPRateLimiter {
	rl := &IPRateLimiter{
		ips:   make(map[string]*ipState),
		r:     r,
		burst: burst,
		done:  make(chan struct{}),
	}
	rl.cleanup = time.NewTicker(idleTTL)
	go rl.evict()
	return rl
}

// Stop terminates the background eviction goroutine.  Call this during
// application shutdown to release the goroutine's resources.
func (rl *IPRateLimiter) Stop() {
	rl.cleanup.Stop()
	close(rl.done)
}

func (rl *IPRateLimiter) limiterFor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	st, ok := rl.ips[ip]
	if !ok {
		st = &ipState{limiter: rate.NewLimiter(rl.r, rl.burst)}
		rl.ips[ip] = st
	}
	st.lastSeen = time.Now()
	return st.limiter
}

func (rl *IPRateLimiter) evict() {
	for {
		select {
		case <-rl.cleanup.C:
			cutoff := time.Now().Add(-idleTTL)
			rl.mu.Lock()
			for ip, st := range rl.ips {
				if st.lastSeen.Before(cutoff) {
					delete(rl.ips, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.done:
			return
		}
	}
}

// Middleware returns a chi-compatible middleware that enforces the rate limit.
// On limit exceeded: 429 Too Many Requests with Retry-After header.
func (rl *IPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := realIP(r)
		if !rl.limiterFor(ip).Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited","detail":"too many requests — try again in 60 seconds"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// realIP extracts the client IP after chi's RealIP middleware has run.
// X-Real-IP is set by Apache (ProxyPreserveHost On + our explicit header).
// Falls back to RemoteAddr if neither header is present.
func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	// RemoteAddr is "host:port"; strip the port.
	ip := r.RemoteAddr
	if i := len(ip) - 1; i >= 0 {
		for i > 0 && ip[i] != ':' {
			i--
		}
		if i > 0 {
			return ip[:i]
		}
	}
	return ip
}
