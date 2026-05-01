-- =============================================================================
-- postgres/init/02-roles.sql
-- Role infrastructure and Row-Level Security for the SSO application.
-- Executed during initdb (trust mode) — no passwords set here.
--
-- ROLE HIERARCHY
-- ──────────────
-- sso_admin   (superuser — owns db and all objects; bypasses RLS by default)
--   └─ sso_app     (Golang server; BYPASSRLS; full CRUD on app tables)
--   └─ sso_auditor (read-only; BYPASSRLS; sees all rows for audit)
--   └─ <username>  (per-user; created by provision_user_role(); RLS-filtered)
--
-- ROW LEVEL SECURITY DESIGN
-- ──────────────────────────
-- enrolled_certs:
--   • RLS enabled.  Generic SELECT policy: username = current_user.
--   • sso_app BYPASSRLS — can read/write all rows.
--   • sso_auditor BYPASSRLS — can read all rows.
--   • Per-user roles: see only their own cert rows.
--
-- sessions:
--   • Same design as enrolled_certs.
--
-- auth_events:
--   • No RLS — access controlled purely by GRANT.
--   • sso_app: INSERT only (append-only audit log; even the app cannot update).
--   • sso_auditor: SELECT only.
--   • Per-user roles: no access (audit log is admin-only).
--
-- SECURITY INVARIANT
-- ──────────────────
-- A user whose cert is compromised can at most authenticate AS that user's role.
-- They see only their own rows (RLS), cannot INSERT to auth_events, cannot
-- access other users' sessions or certs.  The blast radius of a stolen cert is
-- bounded to one user's read-view — NOT a data exfiltration path.
-- =============================================================================

\connect sso

-- ── Revoke default public privileges ─────────────────────────────────────────
-- By default PostgreSQL grants CREATE on public schema to all roles.
-- Remove that so only sso_admin can create objects.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL    ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- ── sso_app: Golang application service account ───────────────────────────────
-- Connects via:
--   DEV:  scram-sha-256 password (pg_hba.conf "host sso sso_app ... scram-sha-256")
--   PROD: client certificate with CN=sso_app (Vault-issued, hostssl cert auth)
--
-- BYPASSRLS: the app manages certs and sessions for ALL users; it must read
-- every row without RLS filtering.  This is granted deliberately and should NOT
-- be given to per-user roles.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sso_app') THEN
        CREATE ROLE sso_app
            NOINHERIT
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            BYPASSRLS
            LOGIN;
    ELSE
        -- Idempotent: ensure BYPASSRLS is set on existing role.
        ALTER ROLE sso_app BYPASSRLS;
    END IF;
END $$;

GRANT CONNECT ON DATABASE sso TO sso_app;
GRANT USAGE   ON SCHEMA public TO sso_app;

-- Cert registry: full CRUD (manages enrolment, rotation, revocation).
GRANT SELECT, INSERT, UPDATE ON enrolled_certs TO sso_app;
-- Sessions: full CRUD (creates, refreshes, revokes sessions).
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO sso_app;
-- Audit log: INSERT only.  The app appends events but never modifies them.
GRANT INSERT ON auth_events TO sso_app;
-- Sequences (for gen_random_uuid() — used by pgcrypto, not sequences, but
-- add this for any future sequence-backed columns).
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sso_app;

-- ── sso_auditor: read-only audit access ──────────────────────────────────────
-- BYPASSRLS: auditors must see all rows across all users.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sso_auditor') THEN
        CREATE ROLE sso_auditor
            NOINHERIT
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            BYPASSRLS
            LOGIN;
    ELSE
        ALTER ROLE sso_auditor BYPASSRLS;
    END IF;
END $$;

GRANT CONNECT ON DATABASE sso TO sso_auditor;
GRANT USAGE   ON SCHEMA public TO sso_auditor;
GRANT SELECT  ON enrolled_certs TO sso_auditor;
GRANT SELECT  ON auth_events    TO sso_auditor;
-- sso_auditor intentionally has NO access to sessions (live session data is
-- sensitive; auditors need the event log, not the live session state).

-- ── Row-Level Security ────────────────────────────────────────────────────────
-- Enable RLS on tables that hold per-user data.
-- Policies are generic (applied to all roles lacking BYPASSRLS), so no
-- per-user policy creation is needed — provision_user_role() just grants SELECT.

ALTER TABLE enrolled_certs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions        ENABLE ROW LEVEL SECURITY;

-- Generic SELECT policy: a role can only see rows where username = current_user.
-- Applies to every role that has SELECT privilege and lacks BYPASSRLS.
CREATE POLICY user_sees_own_certs ON enrolled_certs
    FOR SELECT
    USING (username = current_user);

CREATE POLICY user_sees_own_sessions ON sessions
    FOR SELECT
    USING (username = current_user);

-- ── provision_user_role(p_username): create a per-user PostgreSQL role ────────
-- Called by the Golang app at SAML-driven enrolment time.
-- The role name MUST exactly match the CN in the user's x509 certificate
-- (enforced by pg_ident.conf ssl map: CN → role name verbatim).
--
-- Privilege model for provisioned roles
-- ──────────────────────────────────────
--   CONNECT  on database sso        — can connect at all
--   USAGE    on schema public       — can reference objects in the schema
--   SELECT   on enrolled_certs      — read own certs (filtered by RLS)
--   SELECT   on sessions            — read own sessions (filtered by RLS)
--   No INSERT/UPDATE/DELETE         — the app writes on the user's behalf
--   No access to auth_events        — audit log is admin/auditor-only
--
-- SECURITY DEFINER: runs as sso_admin so it can CREATE ROLE and GRANT.
-- Only sso_app has EXECUTE privilege — end users cannot call this directly.
CREATE OR REPLACE FUNCTION provision_user_role(p_username TEXT)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
BEGIN
    -- Strict username validation: lowercase alphanumeric, hyphen, underscore.
    -- Max 63 chars (PostgreSQL identifier limit).
    -- Rejects: spaces, dots, @, SQL injection attempts, superuser-sounding names.
    IF p_username !~ '^[a-z][a-z0-9_-]{0,62}$' THEN
        RAISE EXCEPTION
            'Invalid username ''%'': must match ^[a-z][a-z0-9_-]{0,62}$',
            p_username;
    END IF;

    -- Guard against provisioning roles that would collide with system or
    -- service accounts.  This is belt-and-suspenders — Vault PKI role's
    -- allowed_domains already prevents issuing certs with these CNs.
    IF p_username IN ('postgres', 'sso_admin', 'sso_app', 'sso_auditor',
                      'public', 'pg_monitor', 'pg_read_all_data',
                      'pg_write_all_data', 'pg_read_all_settings') THEN
        RAISE EXCEPTION
            'Cannot provision reserved role name: %', p_username;
    END IF;

    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = p_username) THEN
        -- Create with NOINHERIT to prevent accidental privilege escalation
        -- via group membership.  LOGIN is required for cert auth.
        EXECUTE format(
            'CREATE ROLE %I '
            'NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION '
            'LOGIN',
            p_username
        );

        -- Connect and schema access.
        EXECUTE format('GRANT CONNECT ON DATABASE sso TO %I', p_username);
        EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', p_username);

        -- Read-only access to own rows (RLS policies above enforce the filtering).
        EXECUTE format('GRANT SELECT ON enrolled_certs TO %I', p_username);
        EXECUTE format('GRANT SELECT ON sessions TO %I', p_username);

        -- No grant on auth_events — audit log is not user-readable.

        RAISE NOTICE 'Provisioned role: %', p_username;
    ELSE
        -- Idempotent: ensure minimum grants exist even if the role was created
        -- by a previous (possibly incomplete) call.
        EXECUTE format('GRANT CONNECT ON DATABASE sso TO %I', p_username);
        EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', p_username);
        EXECUTE format('GRANT SELECT ON enrolled_certs TO %I', p_username);
        EXECUTE format('GRANT SELECT ON sessions TO %I', p_username);

        RAISE NOTICE 'Role already exists, grants refreshed: %', p_username;
    END IF;
END;
$$;

-- Only the Golang app (sso_app) may call provision_user_role.
-- End users connecting via cert auth cannot invoke this directly because:
--   1. They connect as their own role (e.g., "alice"), not as sso_app.
--   2. SECURITY DEFINER means it runs as sso_admin, not the caller.
REVOKE ALL ON FUNCTION provision_user_role(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION provision_user_role(TEXT) TO sso_app;

-- ── deprovision_user_role(p_username): revoke access on cert revocation ───────
-- Called by the Golang app when a user's cert is revoked and their session
-- should be terminated.  Does NOT drop the role (preserves the audit trail
-- in enrolled_certs / auth_events); it only revokes CONNECT so they cannot
-- establish new connections.  Existing connections are not killed — that
-- requires `SELECT pg_terminate_backend(pid)` from sso_admin.
CREATE OR REPLACE FUNCTION deprovision_user_role(p_username TEXT)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
BEGIN
    IF p_username !~ '^[a-z][a-z0-9_-]{0,62}$' THEN
        RAISE EXCEPTION 'Invalid username: %', p_username;
    END IF;

    IF EXISTS (SELECT FROM pg_roles WHERE rolname = p_username) THEN
        EXECUTE format('REVOKE CONNECT ON DATABASE sso FROM %I', p_username);
        RAISE NOTICE 'CONNECT revoked for role: %', p_username;
    ELSE
        RAISE NOTICE 'Role does not exist (already deprovisioned?): %', p_username;
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION deprovision_user_role(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION deprovision_user_role(TEXT) TO sso_app;
