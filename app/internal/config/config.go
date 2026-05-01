package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// mustReadSecret reads a Docker secret file and trims whitespace.
// Returns "" if the file does not exist (caller validates).
func mustReadSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading secret file %s: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// Config holds all runtime configuration loaded from environment variables.
// No config file: docker-compose and .env supply everything.
type Config struct {
	App      AppConfig
	JWT      JWTConfig
	Postgres PostgresConfig
	LDAP     LDAPConfig
	Vault    VaultConfig
	TOTP     TOTPConfig
}

type AppConfig struct {
	Port string
	Env  string // "development" | "production"
}

type JWTConfig struct {
	Issuer   string
	Audience []string
	TTL      time.Duration
}

type PostgresConfig struct {
	DSN             string
	AppPasswordFile string // Docker secret path

	// UserConnHost/Port/DBName are used by db.UserConnFactory for per-user
	// certificate-authenticated connections.  These typically point at the same
	// server as DSN but are specified separately because the service account
	// (DSN) and the user cert connections may use different PG listen addresses
	// (e.g. a pgbouncer passthrough for service, direct TCP for cert auth).
	UserConnHost   string // PG_HOST, default "postgres"
	UserConnPort   string // PG_PORT, default "5432"
	UserConnDBName string // PG_DBNAME, default "sso"
}

type LDAPConfig struct {
	Host   string
	Port   string
	BaseDN string
	BindDN string // optional read-only service account for attribute queries
}

type VaultConfig struct {
	Addr     string // e.g. "http://vault:8200"
	Token    string // dev: root token; prod: AppRole secret-id from Docker secret
	PKIMount string // intermediate CA mount, e.g. "pki_int"
	PKIRole  string // signing role, e.g. "user-cert"
	CertTTL  string // max cert lifetime, e.g. "4h"
}

// TOTPConfig controls the TOTP-based passphrase generator used to seal
// private keys in memguard Enclaves.  TOTP_MASTER_SECRET is the only secret;
// it must be supplied via Docker secrets (not .env in production).
type TOTPConfig struct {
	MasterSecretFile string // Docker secret file, e.g. /run/secrets/totp_master_secret
	Algorithm        string // SHA1 | SHA256 | SHA512 (default SHA256)
	Digits           int    // 6 or 8 (default 8)
	Period           uint   // seconds per window (default 30)
}

// Load reads configuration from the environment.
// Returns an error if any required variable is missing or invalid.
func Load() (*Config, error) {
	ttlSec, err := strconv.Atoi(env("JWT_TTL", "3600"))
	if err != nil {
		return nil, fmt.Errorf("JWT_TTL must be an integer: %w", err)
	}

	totpDigits, err := strconv.Atoi(env("TOTP_DIGITS", "8"))
	if err != nil {
		return nil, fmt.Errorf("TOTP_DIGITS must be an integer: %w", err)
	}
	totpPeriod, err := strconv.Atoi(env("TOTP_PERIOD", "30"))
	if err != nil {
		return nil, fmt.Errorf("TOTP_PERIOD must be an integer: %w", err)
	}

	aud := env("JWT_AUDIENCE", "https://app.sso.local")
	audiences := strings.Split(aud, ",")
	for i := range audiences {
		audiences[i] = strings.TrimSpace(audiences[i])
	}

	cfg := &Config{
		App: AppConfig{
			Port: env("APP_PORT", "8080"),
			Env:  env("APP_ENV", "development"),
		},
		JWT: JWTConfig{
			Issuer:   env("JWT_ISSUER", "https://sp.sso.local"),
			Audience: audiences,
			TTL:      time.Duration(ttlSec) * time.Second,
		},
		Postgres: PostgresConfig{
			DSN:             env("POSTGRES_DSN", ""),
			AppPasswordFile: env("POSTGRES_APP_PASSWORD_FILE", "/run/secrets/postgres_app_password"),
			UserConnHost:    env("PG_HOST", "postgres"),
			UserConnPort:    env("PG_PORT", "5432"),
			UserConnDBName:  env("PG_DBNAME", "sso"),
		},
		LDAP: LDAPConfig{
			Host:   env("LDAP_HOST", "ldap"),
			Port:   env("LDAP_PORT", "1389"),
			BaseDN: env("LDAP_BASE_DN", "dc=sso,dc=local"),
		},
		Vault: VaultConfig{
			Addr:     env("VAULT_ADDR", "http://vault:8200"),
			Token:    env("VAULT_TOKEN", ""),
			PKIMount: env("VAULT_PKI_INT_MOUNT", "pki_int"),
			PKIRole:  env("VAULT_PKI_ROLE", "user-cert"),
			CertTTL:  env("VAULT_CERT_TTL", "4h"),
		},
		TOTP: TOTPConfig{
			MasterSecretFile: env("TOTP_MASTER_SECRET_FILE", "/run/secrets/totp_master_secret"),
			Algorithm:        env("TOTP_ALGORITHM", "SHA256"),
			Digits:           totpDigits,
			Period:           uint(totpPeriod),
		},
	}

	return cfg, nil
}

// TOTPMasterSecret reads the master secret from the configured Docker secret file.
func (c *Config) TOTPMasterSecret() (string, error) {
	return mustReadSecret(c.TOTP.MasterSecretFile)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
