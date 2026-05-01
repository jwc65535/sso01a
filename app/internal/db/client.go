package db

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Client wraps a pgx connection pool.
type Client struct {
	pool *pgxpool.Pool
}

// New opens a pgxpool connection pool.
//
// dsn is a libpq-style DSN (e.g. "host=postgres port=5432 dbname=sso user=sso_app sslmode=disable").
// If passwordFile is non-empty, the file is read and its content appended as
// "password=<secret>" — this keeps credentials out of the DSN env var.
func New(ctx context.Context, dsn, passwordFile string) (*Client, error) {
	if passwordFile != "" {
		pw, err := readSecret(passwordFile)
		if err != nil {
			return nil, fmt.Errorf("reading db password: %w", err)
		}
		dsn = dsn + " password=" + pw
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing DSN: %w", err)
	}

	cfg.MaxConns = 10
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating pgx pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}

	return &Client{pool: pool}, nil
}

// Pool returns the underlying pgxpool.Pool for direct use in handlers/repos.
func (c *Client) Pool() *pgxpool.Pool { return c.pool }

// Ping verifies the pool can acquire a connection.
func (c *Client) Ping(ctx context.Context) error {
	return c.pool.Ping(ctx)
}

// Close drains and closes all pool connections.
func (c *Client) Close() { c.pool.Close() }

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\n\r"), nil
}
