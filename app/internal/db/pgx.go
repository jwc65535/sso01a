package db

// pgx.go — per-user PostgreSQL connections authenticated with x509 client certs
//
// DESIGN RATIONALE — why not a per-user pool?
// ────────────────────────────────────────────
// pgxpool holds a fixed *tls.Config for the lifetime of the pool.  Presenting
// a different client certificate per user therefore requires a distinct
// connection, not a pool checkout.  A single ephemeral *pgx.Conn is opened
// per request, used under the user's role, then closed.
//
// For typical SSO workloads (low RPS, high trust per request) this is the
// correct trade-off: pool complexity and per-user memory cost outweigh the
// ~5 ms TLS handshake overhead.
//
// PRIVATE KEY LIFECYCLE WITHIN THIS FILE
// ───────────────────────────────────────
//  1. KeyManager.OpenPrivateKey() decrypts the sealed Enclave into a LockedBuffer.
//  2. We build a tls.Certificate with PrivateKey = *ecdsa.PrivateKey.
//  3. The TLS handshake uses the key to sign a CertificateVerify message.
//  4. cleanup() is called immediately after ConnectConfig() returns, destroying
//     the LockedBuffer (zeroed + unpinned mlock'd pages).
//  5. The *ecdsa.PrivateKey.D scalar remains in Go heap until the next GC
//     collection — an unavoidable Go runtime limitation noted in keystore.go.
//
// POSTGRESQL SETUP REQUIRED
// ─────────────────────────
// 1. pg_hba.conf — cert auth for the sso database:
//      hostssl  sso  all  0.0.0.0/0  cert  clientcert=verify-full  map=cert
//
// 2. pg_ident.conf — map cert CN straight to a PG login role:
//      cert  /^(.*)$  \1
//    (The login role name equals the cert CN, i.e. the LDAP uid.)
//
// 3. At enrolment time, create the user's PG login role and grant it a
//    shared data role (so privileges are managed at the role level, not
//    per-user):
//      CREATE ROLE "jsmith" LOGIN;
//      GRANT sso_data TO "jsmith";
//
// 4. Vault's intermediate CA (the cert issuer) must be in postgresql.conf's
//    ssl_ca_file so PG can verify the client cert chain.
//
// ROW-LEVEL SECURITY
// ──────────────────
// Tables in the sso schema enforce RLS policies keyed on current_user, giving
// defence-in-depth beyond the SET ROLE switch:
//
//   CREATE POLICY user_isolation ON sso.user_sessions
//       USING (uid = current_user);
//   ALTER TABLE sso.user_sessions ENABLE ROW LEVEL SECURITY;

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"

	ssoCrypto "github.com/sso01a/app/internal/crypto"
)

// UserConnFactory opens per-user PostgreSQL connections authenticated with the
// user's x509 client certificate.  Call Conn() once per request; the returned
// UserConn must be closed when the request finishes.
type UserConnFactory struct {
	host   string // PG hostname — must match the server cert CN/SAN
	port   string // PG port, e.g. "5432"
	dbname string // database name, e.g. "sso"

	caPool *x509.CertPool    // Vault CA chain — verifies the PG server cert
	km     *ssoCrypto.KeyManager

	// certCache is an in-process cache of uid → PEM cert.
	// Populated by StoreCert() at enrolment time; queried by Conn().
	// In production this would be backed by LDAP or the service-level pool.
	mu        sync.RWMutex
	certCache map[string]string
}

// NewUserConnFactory builds a factory.  caChainPEM is the PEM bundle returned
// by vault.Client.ReadCAChain(); it becomes the root of trust for verifying
// the PostgreSQL server certificate (sslmode=verify-full semantics).
func NewUserConnFactory(
	host, port, dbname string,
	caChainPEM string,
	km *ssoCrypto.KeyManager,
) (*UserConnFactory, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caChainPEM)) {
		return nil, fmt.Errorf("db: no valid CA certificates in caChainPEM")
	}
	return &UserConnFactory{
		host:      host,
		port:      port,
		dbname:    dbname,
		caPool:    pool,
		km:        km,
		certCache: make(map[string]string),
	}, nil
}

// StoreCert caches the PEM-encoded certificate for uid.  Call this after
// a successful /api/cert/issue so subsequent requests can retrieve it.
func (f *UserConnFactory) StoreCert(uid, certPEM string) {
	f.mu.Lock()
	f.certCache[uid] = certPEM
	f.mu.Unlock()
}

// HasCert reports whether a certificate is cached for uid.
func (f *UserConnFactory) HasCert(uid string) bool {
	f.mu.RLock()
	_, ok := f.certCache[uid]
	f.mu.RUnlock()
	return ok
}

// RemoveCert removes the cached certificate for uid (e.g. on cert revocation).
func (f *UserConnFactory) RemoveCert(uid string) {
	f.mu.Lock()
	delete(f.certCache, uid)
	f.mu.Unlock()
}

// UserConn is a single PostgreSQL connection authenticated with a user's
// x509 client certificate.  The role is assumed via SET ROLE immediately
// after the connection is established.
//
// UserConn is NOT safe for concurrent use.  Create one per goroutine/request.
type UserConn struct {
	conn *pgx.Conn
	uid  string
	role string // sanitized PG role name derived from the cert CN
}

// Conn opens a new authenticated connection for uid.
//
// Prerequisites:
//   - uid has a sealed private key in the KeyManager (via /api/cert/issue)
//   - uid has a cached certificate (via StoreCert)
//   - A matching PostgreSQL login role exists (e.g. "jsmith" LOGIN)
//
// The caller MUST call Close() when the request is done; connections are not
// pooled and the server-side resources will leak if Close() is skipped.
//
// Role assumption: after the TCP+TLS connection is established, Conn issues
// SET ROLE to switch from the login role (uid) to the application data role
// derived from the cert CN.  This minimises the blast radius if a connection
// is somehow hijacked after the handshake.
func (f *UserConnFactory) Conn(ctx context.Context, uid string) (*UserConn, error) {
	// 1. Retrieve the cached certificate.
	f.mu.RLock()
	certPEM, ok := f.certCache[uid]
	f.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("db: no certificate found for uid=%s (enrolment required)", uid)
	}

	// 2. Decode PEM → DER bytes for tls.Certificate.
	certDER, err := pemToDER(certPEM)
	if err != nil {
		return nil, fmt.Errorf("db: decoding cert PEM for uid=%s: %w", uid, err)
	}

	// 3. Parse the certificate to extract the CN for role derivation.
	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("db: parsing certificate for uid=%s: %w", uid, err)
	}
	role, err := roleForCN(x509Cert.Subject.CommonName)
	if err != nil {
		return nil, fmt.Errorf("db: role for uid=%s: %w", uid, err)
	}

	// 4. Unlock the private key for the duration of the TLS handshake.
	//    cleanup() is called immediately after ConnectConfig() returns so the
	//    LockedBuffer's mlock'd pages are zeroed as soon as the handshake ends.
	priv, cleanup, err := f.km.OpenPrivateKey(uid)
	if err != nil {
		return nil, fmt.Errorf("db: unlocking private key for uid=%s: %w", uid, err)
	}

	// 5. Build tls.Certificate in memory — no temp files.
	//    *ecdsa.PrivateKey implements crypto.Signer, which is what tls.Certificate
	//    expects for PrivateKey.  No type assertion needed.
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	// 6. TLS config with verify-full semantics:
	//    - RootCAs: Vault CA chain (validates the PG server certificate)
	//    - ServerName: must match PG server cert CN or SAN
	//    - MinVersion TLS 1.3: removes CBC cipher suites and older attack surface
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      f.caPool,
		ServerName:   f.host,
		MinVersion:   tls.VersionTLS13,
	}

	// 7. Parse connection config and replace pgx's built-in TLS config with ours.
	//    sslmode=require tells pgx to use TLS; our TLSConfig provides the actual
	//    verification logic (equivalent to sslmode=verify-full).
	connStr := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s sslmode=require",
		f.host, f.port, f.dbname, uid,
	)
	cfg, err := pgx.ParseConfig(connStr)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("db: parsing connection config: %w", err)
	}
	cfg.TLSConfig = tlsConfig

	// 8. Connect.  cleanup() is deferred until after ConnectConfig so the
	//    private key is available for the TLS CertificateVerify exchange.
	conn, err := pgx.ConnectConfig(ctx, cfg)
	cleanup() // LockedBuffer zeroed; *ecdsa.PrivateKey lives in heap until GC
	if err != nil {
		return nil, fmt.Errorf("db: connecting as uid=%s: %w", uid, err)
	}

	// 9. Assume the user's PostgreSQL role.
	//    The role name is already validated in roleForCN() (only [a-z0-9_]).
	//    pgx.Identifier.Sanitize() double-quotes and escapes it as a safety net.
	//    SET ROLE cannot be parameterised ($1) — PostgreSQL rejects it.
	_, err = conn.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize())
	if err != nil {
		_ = conn.Close(ctx)
		return nil, fmt.Errorf("db: SET ROLE %q for uid=%s: %w (role must exist in PG)", role, uid, err)
	}

	return &UserConn{conn: conn, uid: uid, role: role}, nil
}

// Conn returns the raw *pgx.Conn for query execution.
func (uc *UserConn) Conn() *pgx.Conn { return uc.conn }

// UID returns the authenticated user identifier.
func (uc *UserConn) UID() string { return uc.uid }

// Role returns the PostgreSQL role assumed for this connection.
func (uc *UserConn) Role() string { return uc.role }

// Close closes the underlying connection and releases server-side resources.
// Always call this, typically via defer, immediately after opening.
func (uc *UserConn) Close(ctx context.Context) error {
	return uc.conn.Close(ctx)
}

// WithTx executes fn inside a single transaction that is automatically
// committed or rolled back.  The transaction inherits the role set by Conn(),
// so all statements within fn execute under the user's PG role.
//
// RLS policies on the underlying tables provide a second layer of isolation
// keyed on current_user, which equals the role set here.
func (uc *UserConn) WithTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := uc.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

// ── helpers ───────────────────────────────────────────────────────────────────

// pemToDER decodes the first CERTIFICATE block from a PEM bundle.
func pemToDER(certPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block found")
	}
	return block.Bytes, nil
}
