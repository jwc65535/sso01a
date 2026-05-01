package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"golang.org/x/time/rate"

	"github.com/pquerna/otp"
	"github.com/sso01a/app/internal/auth"
	"github.com/sso01a/app/internal/config"
	ssoCrypto "github.com/sso01a/app/internal/crypto"
	"github.com/sso01a/app/internal/db"
	"github.com/sso01a/app/internal/handler"
	"github.com/sso01a/app/internal/ldap"
	"github.com/sso01a/app/internal/vault"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	// ── Config ───────────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log.Info("config loaded", "env", cfg.App.Env, "port", cfg.App.Port)

	// ── JWT signing key (memguard-protected) ─────────────────────────────────
	ks, err := ssoCrypto.NewEphemeralKeyStore()
	if err != nil {
		return err
	}
	defer ks.Destroy()
	log.Info("JWT signing key generated", "kid", ks.KID(), "alg", "ES256")

	issuer := auth.NewIssuer(ks, cfg.JWT.Issuer, cfg.JWT.Audience, cfg.JWT.TTL)

	ctx := context.Background()

	// ── Vault client ──────────────────────────────────────────────────────────
	vaultClient, err := vault.New(vault.Config{
		Addr:     cfg.Vault.Addr,
		Token:    cfg.Vault.Token,
		PKIMount: cfg.Vault.PKIMount,
		PKIRole:  cfg.Vault.PKIRole,
		CertTTL:  cfg.Vault.CertTTL,
	})
	if err != nil {
		return err
	}
	if err := vaultClient.Ping(ctx); err != nil {
		log.Warn("Vault ping failed at startup (will retry on demand)", "err", err)
	} else {
		log.Info("Vault connected", "addr", cfg.Vault.Addr)
	}

	// ── TOTP passphrase generator + key manager ───────────────────────────────
	masterSecret, err := cfg.TOTPMasterSecret()
	if err != nil {
		return err
	}
	if masterSecret == "" {
		return fmt.Errorf("TOTP master secret is empty — check %s", cfg.TOTP.MasterSecretFile)
	}
	totpAlgo := otp.AlgorithmSHA256
	switch cfg.TOTP.Algorithm {
	case "SHA1":
		totpAlgo = otp.AlgorithmSHA1
	case "SHA512":
		totpAlgo = otp.AlgorithmSHA512
	}
	totpDigits := otp.DigitsEight
	if cfg.TOTP.Digits == 6 {
		totpDigits = otp.DigitsSix
	}
	passGen := ssoCrypto.NewPassphraseGen(masterSecret, totpAlgo, totpDigits, cfg.TOTP.Period)
	keyMgr := ssoCrypto.NewKeyManager(passGen)
	log.Info("TOTP passphrase generator ready", "period", cfg.TOTP.Period, "digits", cfg.TOTP.Digits)

	keyHandler := handler.NewKeyHandler(keyMgr, vaultClient)

	// ── Per-user x509 connection factory ─────────────────────────────────────
	// Fetch the Vault CA chain once at startup so we can verify PG server certs.
	// The chain changes only on CA rotation; restart the service to pick up a new one.
	var userConnFactory *db.UserConnFactory
	caChain, err := vaultClient.ReadCAChain(ctx)
	if err != nil {
		log.Warn("cannot read Vault CA chain — per-user DB connections disabled", "err", err)
	} else {
		userConnFactory, err = db.NewUserConnFactory(
			cfg.Postgres.UserConnHost,
			cfg.Postgres.UserConnPort,
			cfg.Postgres.UserConnDBName,
			caChain,
			keyMgr,
		)
		if err != nil {
			log.Warn("cannot build user connection factory — per-user DB connections disabled", "err", err)
		} else {
			// Wire the factory into the key handler so it can cache the cert after issuance.
			keyHandler.SetConnFactory(userConnFactory)
			log.Info("per-user DB connection factory ready",
				"host", cfg.Postgres.UserConnHost,
				"port", cfg.Postgres.UserConnPort,
				"db", cfg.Postgres.UserConnDBName,
			)
		}
	}

	// ── LDAP client ─────────────────────────────────────────────────────────
	ldapClient := ldap.New(cfg.LDAP.Host, cfg.LDAP.Port, cfg.LDAP.BaseDN)
	if err := ldapClient.Ping(); err != nil {
		log.Warn("LDAP ping failed at startup (will retry on demand)", "err", err)
	} else {
		log.Info("LDAP connected", "addr", cfg.LDAP.Host+":"+cfg.LDAP.Port)
	}

	// ── PostgreSQL pool ──────────────────────────────────────────────────────
	var dbClient *db.Client
	if cfg.Postgres.DSN != "" {
		dbClient, err = db.New(ctx, cfg.Postgres.DSN, cfg.Postgres.AppPasswordFile)
		if err != nil {
			log.Warn("PostgreSQL pool init failed (non-fatal in dev)", "err", err)
		} else {
			defer dbClient.Close()
			log.Info("PostgreSQL pool ready")
		}
	} else {
		log.Warn("POSTGRES_DSN not set — database features disabled")
	}

	// ── Rate limiters ─────────────────────────────────────────────────────────
	// Per-IP token bucket limiters applied to sensitive endpoints.
	// These are independent of Apache's mod_ratelimit — defense-in-depth if the
	// SP is bypassed or the backend is exposed directly during development.
	//
	// Token endpoint: 5 requests/minute, burst 3.
	// Rationale: a browser makes at most 1–2 calls per SAML login sequence.
	// Burst of 3 handles retry on transient network errors without letting
	// a scanner get more than 3 rapid-fire attempts.
	tokenRL := auth.NewIPRateLimiter(rate.Every(12*time.Second), 3) // 5/min
	defer tokenRL.Stop()

	// Cert issuance: 2 requests/5 minutes, burst 1.
	// Rationale: key generation + Argon2id + Vault round-trip is expensive.
	// Legitimate users call this once per session; burst of 1 prevents batching.
	certRL := auth.NewIPRateLimiter(rate.Every(150*time.Second), 1) // 2/5min
	defer certRL.Stop()

	// ── Router ───────────────────────────────────────────────────────────────
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.RequestID)
	r.Use(requestLogger(log))
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	// Public endpoints
	r.Get("/healthz", handler.Health)

	// JWKS — public, no auth
	r.Get("/api/.well-known/jwks.json", handler.JWKS(ks))

	// Token endpoint — must be called through the Shibboleth SP.
	// Rate limiter applied BEFORE ShibbolethRequired so scanners are dropped
	// before we evaluate headers.
	r.With(tokenRL.Middleware, auth.ShibbolethRequired).
		Post("/api/token", handler.Token(issuer, log))

	// Authenticated API routes — require valid JWT Bearer token
	r.Group(func(r chi.Router) {
		r.Use(auth.BearerAuth(issuer))

		r.Get("/api/userinfo", handler.UserInfo)

		// Certificate issuance — rate limited independently from the token endpoint.
		// POST /api/cert/issue → IssueResponse{Certificate, IssuingCA, CAChain, …}
		r.With(certRL.Middleware).Post("/api/cert/issue", keyHandler.Issue)

		// Request signing — unlocks sealed private key for this request only.
		// POST /api/sign {payload: base64url} → SignResponse{signature: base64url}
		r.Post("/api/sign", keyHandler.Sign)

		// Session management and audit log — per-user x509-authenticated DB connections.
		if userConnFactory != nil {
			sh := handler.NewSessionsHandler(userConnFactory)
			r.Get("/api/sessions", sh.ListSessions)
			r.Get("/api/sessions/{jti}", sh.GetSession)
			r.Delete("/api/sessions/{jti}", sh.RevokeSession)
			r.Get("/api/audit", sh.ListAudit)
		}

		_ = ldapClient
		_ = dbClient
	})

	// ── HTTP server ───────────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:         ":" + cfg.App.Port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Info("server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	select {
	case err := <-serverErr:
		return err
	case sig := <-quit:
		log.Info("shutdown signal received", "signal", sig)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown failed", "err", err)
		return err
	}

	// Memguard destruction — zero all sealed private keys and mlock'd buffers.
	// Called AFTER srv.Shutdown() so no in-flight request is still calling
	// Unlock().  This satisfies the destruction guarantee documented in
	// keymanager.go and SECURITY.md §6 (Memguard Destruction Guarantees).
	if keyMgr != nil {
		keyMgr.Purge()
	}

	log.Info("server stopped")
	return nil
}

// requestLogger is a chi-compatible structured logging middleware.
func requestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			start := time.Now()
			defer func() {
				log.Info("request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", ww.Status(),
					"bytes", ww.BytesWritten(),
					"duration_ms", time.Since(start).Milliseconds(),
					"request_id", chimiddleware.GetReqID(r.Context()),
				)
			}()
			next.ServeHTTP(ww, r)
		})
	}
}
