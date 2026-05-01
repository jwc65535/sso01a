package db

// postgres.go — CRUD operations executed under the authenticated user's role.
//
// ISOLATION GUARANTEE
// ───────────────────
// Every function in this file accepts a *UserConn whose role is already set to
// the caller's PostgreSQL role (e.g. "u_jsmith").  Two enforcement layers
// prevent a user from touching another user's rows:
//
//  1. SET ROLE in UserConnFactory.Conn() — queries run as the user's PG role.
//
//  2. Row-Level Security policies on every table — an additional server-side
//     guard that fires even if the application role is misconfigured:
//
//       ALTER TABLE sso.user_sessions ENABLE ROW LEVEL SECURITY;
//       CREATE POLICY own_sessions ON sso.user_sessions
//           USING (uid = current_user);
//
//       ALTER TABLE sso.audit_log ENABLE ROW LEVEL SECURITY;
//       CREATE POLICY own_audit ON sso.audit_log
//           USING (uid = current_user);
//
// TAMPER-PROOF uid COLUMN
// ───────────────────────
// INSERT statements use current_user for the uid column rather than an
// application-supplied value.  This means the application cannot forge a log
// entry or session record for a different user, even if the handler is buggy.
//
//   CREATE OR REPLACE FUNCTION sso.set_uid()
//   RETURNS TRIGGER LANGUAGE plpgsql AS $$
//   BEGIN
//     NEW.uid := current_user;
//     RETURN NEW;
//   END; $$;
//
//   CREATE TRIGGER trg_set_uid BEFORE INSERT ON sso.user_sessions
//       FOR EACH ROW EXECUTE FUNCTION sso.set_uid();
//   CREATE TRIGGER trg_set_uid BEFORE INSERT ON sso.audit_log
//       FOR EACH ROW EXECUTE FUNCTION sso.set_uid();

import (
	"context"
	"fmt"
	"time"
)

// ── user_sessions ─────────────────────────────────────────────────────────────

// Session represents a row in sso.user_sessions.
type Session struct {
	ID         int64
	UID        string    // set by DB trigger (current_user), not the application
	JTI        string    // JWT ID — matches the jwt.RegisteredClaims.ID field
	CertSerial string    // hex serial of the bound x509 cert (from cnf.x5t#S256)
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Revoked    bool
}

// CreateSession inserts a new session.  uid is sourced from current_user by
// a BEFORE INSERT trigger — the role (not the application) owns the record.
func CreateSession(ctx context.Context, uc *UserConn, jti, certSerial string, issuedAt, expiresAt time.Time) (*Session, error) {
	row := uc.Conn().QueryRow(ctx,
		`INSERT INTO sso.user_sessions (uid, jti, cert_serial, issued_at, expires_at)
		 VALUES (current_user, $1, $2, $3, $4)
		 RETURNING id, uid, jti, cert_serial, issued_at, expires_at, revoked`,
		jti, certSerial, issuedAt, expiresAt,
	)
	var s Session
	if err := row.Scan(&s.ID, &s.UID, &s.JTI, &s.CertSerial, &s.IssuedAt, &s.ExpiresAt, &s.Revoked); err != nil {
		return nil, fmt.Errorf("db: create session: %w", err)
	}
	return &s, nil
}

// GetSession fetches a single session by JWT ID.
// RLS ensures only the authenticated user's own session is visible.
func GetSession(ctx context.Context, uc *UserConn, jti string) (*Session, error) {
	row := uc.Conn().QueryRow(ctx,
		`SELECT id, uid, jti, cert_serial, issued_at, expires_at, revoked
		   FROM sso.user_sessions
		  WHERE jti = $1`,
		jti,
	)
	var s Session
	if err := row.Scan(&s.ID, &s.UID, &s.JTI, &s.CertSerial, &s.IssuedAt, &s.ExpiresAt, &s.Revoked); err != nil {
		return nil, fmt.Errorf("db: get session jti=%s: %w", jti, err)
	}
	return &s, nil
}

// ListSessions returns all active sessions for the authenticated user, newest
// first.  RLS filters rows by uid = current_user before ORDER BY runs.
func ListSessions(ctx context.Context, uc *UserConn) ([]Session, error) {
	rows, err := uc.Conn().Query(ctx,
		`SELECT id, uid, jti, cert_serial, issued_at, expires_at, revoked
		   FROM sso.user_sessions
		  WHERE revoked = false
		    AND expires_at > NOW()
		  ORDER BY issued_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list sessions: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UID, &s.JTI, &s.CertSerial, &s.IssuedAt, &s.ExpiresAt, &s.Revoked); err != nil {
			return nil, fmt.Errorf("db: scan session: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// RevokeSession marks a session revoked.  RLS on user_sessions prevents
// revoking another user's session — the UPDATE silently matches 0 rows and
// we surface that as a distinct error.
func RevokeSession(ctx context.Context, uc *UserConn, jti string) error {
	tag, err := uc.Conn().Exec(ctx,
		`UPDATE sso.user_sessions SET revoked = true WHERE jti = $1`,
		jti,
	)
	if err != nil {
		return fmt.Errorf("db: revoke session jti=%s: %w", jti, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("db: session jti=%s not found (or belongs to a different user)", jti)
	}
	return nil
}

// ── audit_log ─────────────────────────────────────────────────────────────────

// AuditEntry represents a row in sso.audit_log.
type AuditEntry struct {
	ID        int64
	UID       string // set by DB trigger, tamper-proof
	Action    string
	Detail    string
	CreatedAt time.Time
}

// CreateAuditEntry appends an audit record.  uid is sourced from current_user
// by a BEFORE INSERT trigger — the application cannot fabricate a different
// actor in the audit log.
func CreateAuditEntry(ctx context.Context, uc *UserConn, action, detail string) (*AuditEntry, error) {
	row := uc.Conn().QueryRow(ctx,
		`INSERT INTO sso.audit_log (uid, action, detail)
		 VALUES (current_user, $1, $2)
		 RETURNING id, uid, action, detail, created_at`,
		action, detail,
	)
	var e AuditEntry
	if err := row.Scan(&e.ID, &e.UID, &e.Action, &e.Detail, &e.CreatedAt); err != nil {
		return nil, fmt.Errorf("db: create audit entry action=%s: %w", action, err)
	}
	return &e, nil
}

// ListAuditEntries returns recent audit entries for the authenticated user.
// limit is clamped to [1, 100].  RLS filters by uid = current_user.
func ListAuditEntries(ctx context.Context, uc *UserConn, limit int) ([]AuditEntry, error) {
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := uc.Conn().Query(ctx,
		`SELECT id, uid, action, detail, created_at
		   FROM sso.audit_log
		  ORDER BY created_at DESC
		  LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list audit entries: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UID, &e.Action, &e.Detail, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan audit entry: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
