# PostgreSQL Role Model: One Role per User, Groups via `current_user`

## John W. Carbone
### Quantum Logic Corporation

---

## Model Constraints

1. Every user gets exactly one PostgreSQL role (`LOGIN`, named after the user).
2. Every group gets exactly one PostgreSQL role (`NOLOGIN`, named after the group).
3. A user must belong to at least one group.
4. A group must have at least one user.
5. `session_user` — the logged-in role — identifies the **individual**.
6. `current_user` — the role active after `SET ROLE` — identifies the **group**.

This maps naturally to the way most organizations already think: people have identities, people belong to departments, departments own data.

---

## Schema

### Roles

```sql
-- ── Groups (NOLOGIN: cannot authenticate directly) ────────────────────────
CREATE ROLE grp_engineering  NOLOGIN;
CREATE ROLE grp_finance       NOLOGIN;
CREATE ROLE grp_operations    NOLOGIN;

-- ── Users (LOGIN: one role per person) ───────────────────────────────────
CREATE ROLE alice LOGIN PASSWORD '...';
CREATE ROLE bob   LOGIN PASSWORD '...';
CREATE ROLE carol LOGIN PASSWORD '...';

-- ── Membership (users → groups; enforces constraint 3 and 4) ─────────────
GRANT grp_engineering TO alice;          -- alice is in engineering
GRANT grp_finance      TO bob;           -- bob is in finance
GRANT grp_engineering TO carol;         -- carol is in engineering
GRANT grp_operations  TO carol;         -- carol is also in operations
```

Membership is many-to-many. The constraints ("at least one") are enforced by application logic and tooling at provisioning time — PostgreSQL itself has no `GRANT ... REQUIRE MEMBER` syntax.

### Enforcing constraints at provision time

```sql
-- View: groups with no members (violates constraint 4)
CREATE VIEW empty_groups AS
SELECT r.rolname AS group_name
FROM   pg_roles r
WHERE  NOT r.rolcanlogin                      -- is a group role
  AND  r.rolname LIKE 'grp\_%'               -- naming convention
  AND  NOT EXISTS (
           SELECT 1 FROM pg_auth_members m
           WHERE  m.roleid = r.oid
       );

-- View: users with no group membership (violates constraint 3)
CREATE VIEW ungrouped_users AS
SELECT r.rolname AS user_name
FROM   pg_roles r
WHERE  r.rolcanlogin                          -- is a user role
  AND  NOT EXISTS (
           SELECT 1 FROM pg_auth_members m
           JOIN   pg_roles g ON g.oid = m.roleid
           WHERE  m.member  = r.oid
             AND  NOT g.rolcanlogin           -- parent is a group role
             AND  g.rolname LIKE 'grp\_%'
       );
```

Run these checks in CI or as part of the provisioning step that creates/removes roles.

---

## Data Tables

Every table that needs group-scoped isolation carries a `group_` column stamped at insert time with `DEFAULT current_user`.

```sql
CREATE TABLE documents (
    id       BIGSERIAL    PRIMARY KEY,
    group_   TEXT         NOT NULL DEFAULT current_user,
    owner    TEXT         NOT NULL DEFAULT session_user,
    title    TEXT         NOT NULL,
    body     TEXT
);

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;   -- applies to table owners too
```

`group_` is the group that owns the row. `owner` is the individual who created it.

---

## Row-Level Security Policies

### Read: see only your group's rows

```sql
CREATE POLICY doc_select ON documents
    FOR SELECT
    USING (group_ = current_user);
```

A user who has `SET ROLE grp_engineering` sees only engineering rows. The same user with `SET ROLE grp_operations` (if they are a member) sees only operations rows.

### Write: insert stamps the current group; update/delete restricted to the owning group

```sql
CREATE POLICY doc_insert ON documents
    FOR INSERT
    WITH CHECK (
        group_ = current_user       -- row must be stamped with the active group
        AND owner = session_user    -- individual is always the authenticated user
    );

CREATE POLICY doc_update ON documents
    FOR UPDATE
    USING  (group_ = current_user)  -- can only touch rows belonging to active group
    WITH CHECK (group_ = current_user);

CREATE POLICY doc_delete ON documents
    FOR DELETE
    USING (group_ = current_user);
```

---

## Switching Groups

A user activates a group by running `SET LOCAL ROLE` inside a transaction. The application does this after JWT or SAML validation.

```sql
-- alice connects; session_user = 'alice' for the entire session.

BEGIN;
SET LOCAL ROLE grp_engineering;

SELECT current_user;    -- grp_engineering
SELECT session_user;    -- alice

INSERT INTO documents (title, body)
    VALUES ('Architecture notes', '...');
-- group_ = 'grp_engineering', owner = 'alice'  (stamped automatically)

SELECT id, title FROM documents;
-- Returns only engineering rows.

COMMIT;
-- SET LOCAL ROLE is automatically reset. current_user = alice again.
```

If alice also belongs to `grp_operations`:

```sql
BEGIN;
SET LOCAL ROLE grp_operations;

SELECT * FROM documents;
-- Returns only operations rows — engineering rows not visible.

COMMIT;
```

Trying to switch to a group alice is not a member of raises an error immediately:

```sql
SET LOCAL ROLE grp_finance;
-- ERROR:  permission denied to set role "grp_finance"
```

---

## Audit Log

Because `current_user` changes with `SET ROLE` and `session_user` does not, the audit table captures both dimensions in a single row:

```sql
CREATE TABLE audit_log (
    id          BIGSERIAL    PRIMARY KEY,
    recorded_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    user_       TEXT         NOT NULL DEFAULT session_user,   -- individual
    group_      TEXT         NOT NULL DEFAULT current_user,   -- active group
    action      TEXT         NOT NULL,
    target_id   BIGINT
);
```

A trigger keeps it automatic:

```sql
CREATE FUNCTION audit_documents() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO audit_log (action, target_id)
    VALUES (TG_OP, COALESCE(NEW.id, OLD.id));
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER trg_audit_documents
    AFTER INSERT OR UPDATE OR DELETE ON documents
    FOR EACH ROW EXECUTE FUNCTION audit_documents();
```

Sample audit output after alice works in engineering and carol works in both engineering and operations:

```
user_   group_            action   target_id
------  ----------------  -------  ---------
alice   grp_engineering   INSERT   1
alice   grp_engineering   UPDATE   1
carol   grp_engineering   INSERT   2
carol   grp_operations    INSERT   3
```

`session_user` (user_) gives you the individual accountability trail. `current_user` (group_) gives you the data-domain trail.

---

## Application Integration

The application's connection role must be granted the right to switch into any group role it may use on behalf of users. The typical setup:

```sql
-- Application service role (used for connection pooling)
CREATE ROLE app_service LOGIN PASSWORD '...';

-- app_service is granted into every group so it can SET ROLE to any of them.
GRANT grp_engineering TO app_service;
GRANT grp_finance      TO app_service;
GRANT grp_operations  TO app_service;
```

The application resolves the group from the JWT or SAML assertion, then for each request:

```
1. Borrow connection from pool  (session_user = 'app_service')
2. BEGIN
3. SET LOCAL ROLE <resolved_group>  (current_user = e.g. 'grp_engineering')
4. Execute business queries          (RLS enforces group isolation automatically)
5. INSERT INTO audit_log ...         (session_user and current_user stamped)
6. COMMIT                            (SET LOCAL ROLE reset automatically)
7. Return connection to pool         (clean state; no lingering role switch)
```

With this pattern the application never writes `WHERE group_ = $1` — RLS handles it. The role model itself is the authorization layer.

---

## Summary

| Variable | Value | Used for |
|----------|-------|----------|
| `session_user` | `alice` | Individual identity, accountability, audit |
| `current_user` | `grp_engineering` | Group identity, data scoping, RLS |
| `DEFAULT session_user` | column default | Stamps who created the row |
| `DEFAULT current_user` | column default | Stamps which group owns the row |
| `SET LOCAL ROLE <group>` | per-transaction | Activates group scope; auto-resets on commit |
