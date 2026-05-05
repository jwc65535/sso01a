# Groups
## John W. Carbone
## Quantum Logic Corporation

---


Groups in sso01a control **which rows a user can see and write**. They are not a role-based access control (RBAC) system — they do not grant or deny access to endpoints, features, or operations. Every authenticated user can perform the same operations; groups determine only which data those operations touch.

---

## What a Group Is

A group is a named set of users that jointly own a partition of the application data. Every data row belongs to exactly one group. A user who activates a group sees that group's rows and no others. The application issues no `WHERE group = ?` clauses — the database enforces the boundary automatically via Row Level Security.

A group exists in two places simultaneously:

| Layer | Representation | Purpose |
|---|---|---|
| OpenLDAP | `groupOfNames` entry; `cn` is a UUID v7 | Membership authority — who belongs |
| PostgreSQL | `NOLOGIN` role; role name is the same UUID v7 | Enforcement — data isolation via RLS |

Both must exist for a group to be usable. The UUID must match exactly between layers.

---

## Identifiers and Names

Every group has two distinct attributes that serve different purposes:

| Attribute | Value | Where stored | Purpose |
|---|---|---|---|
| **ID** | UUID v7, e.g. `019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f` | LDAP `cn`; PostgreSQL role name | Stable, opaque, permanent identifier |
| **Name** | Human-readable, e.g. `grp_engineering` | LDAP `description`; PostgreSQL `COMMENT ON ROLE` | Label for display, logs, and operations |

The UUID is the identifier used by every layer of the system — LDAP DNs, `memberOf` attributes, SAML assertions, JWTs, `SET LOCAL ROLE`, the `group_` column, and audit records. The name is never used as an identifier; it is a label that can be changed without touching any data or role membership.

The UUID v7 format is:

```
[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}
```

It is time-ordered (most-significant bits carry a millisecond timestamp), globally unique, and 36 characters — well within PostgreSQL's 63-character identifier limit. Because it contains hyphens it must always be double-quoted when used as a PostgreSQL identifier: `"019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f"`.

The human-readable name follows the pattern `grp_[a-z][a-z0-9_]{0,58}` as a convention for readability, but it is not validated or used as an identifier by any system component.

---

## OpenLDAP: groupOfNames

OpenLDAP is the **membership authority**. It answers: *which users belong to which group?* Nothing else in the system writes group membership.

### Directory structure

```
dc=sso,dc=local
├── ou=users            — one entry per user (inetOrgPerson + ssoUser)
└── ou=groups           — one entry per group (groupOfNames)
```

### Group entry

```ldif
dn: cn=019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f,ou=groups,dc=sso,dc=local
objectClass: groupOfNames
objectClass: top
cn: 019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f
description: grp_engineering
member: uid=alice,ou=users,dc=sso,dc=local
member: uid=carol,ou=users,dc=sso,dc=local
```

- `cn` is the UUID v7 — the stable, permanent identifier for this group.
- `description` is the human-readable name. It can be changed at any time without affecting any downstream system.
- `member` lists the full DNs of member users.

### memberof overlay

The `memberof` slapd module maintains a `memberOf` attribute on each user entry, pointing back to every group that user belongs to. This is the attribute the IdP reads at login time.

```
alice's LDAP entry:
  uid: alice
  memberOf: cn=019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f,ou=groups,dc=sso,dc=local
```

When a user is added to or removed from a `groupOfNames` entry, the overlay updates their `memberOf` attribute automatically. The IdP reads `memberOf` — it does not scan all group entries.

The UUID in `memberOf` is extracted directly from the DN string. No additional LDAP lookup is required to obtain the group identifier.

### Group membership rules

- A group must have at least one `member`. The `empty_groups` PostgreSQL view surfaces violations.
- A user may belong to any number of groups.
- Membership changes in LDAP take effect on the user's **next login**. Existing JWTs are unaffected until they expire.

---

## PostgreSQL Role Model

### One login role per user

Each user is exactly one PostgreSQL `LOGIN` role. The role name matches the user's `uid` in LDAP and the `CN` in their x509 client certificate. There are no shared login roles and no application service accounts.

```
alice  LOGIN NOINHERIT   — authenticates directly with x509 cert
bob    LOGIN NOINHERIT   — authenticates directly with x509 cert
```

`NOINHERIT` means alice does not silently gain a group role's privileges by being a member. She must explicitly activate the group with `SET LOCAL ROLE`.

### One role per group

Each group is exactly one PostgreSQL `NOLOGIN` role whose name is the group's UUID v7. It cannot authenticate directly. It holds the table-level grants. Users activate it with `SET LOCAL ROLE`. Its human-readable name is stored as a role comment in `pg_shdescription`.

```sql
-- The role name is the UUID.
CREATE ROLE "019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f" NOLOGIN NOINHERIT ...;

-- The human-readable name is a comment, stored in pg_shdescription.
COMMENT ON ROLE "019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f" IS 'grp_engineering';
```

The comment is queryable:

```sql
SELECT rolname,
       pg_catalog.shobj_description(oid, 'pg_authid') AS name
FROM   pg_roles
WHERE  rolname = '019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f';
```

### group_registry table

Because `pg_roles` does not expose comments and UUID-named roles are indistinguishable from other roles by name pattern alone, a `group_registry` table is the authoritative list of all provisioned group role IDs.

```sql
CREATE TABLE group_registry (
    id          UUID        PRIMARY KEY,        -- UUID v7; matches the PostgreSQL role name
    name        TEXT        NOT NULL UNIQUE,    -- human-readable label, e.g. 'grp_engineering'
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

`provision_group_role()` inserts into this table. `deprovision_group_role()` deletes from it. Constraint views and deprovisioning queries join against it to identify group roles without relying on name patterns.

### Membership

`provision_user_role()` grants the group role (by UUID) to the user role:

```sql
GRANT "019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f" TO alice;
```

This gives alice the ability to `SET LOCAL ROLE "019257ab-..."`. It does not grant her any table access until she does.

### Role hierarchy

```
sso_admin        SUPERUSER — owns the database; provisioning and maintenance only
  └─ sso_auditor BYPASSRLS LOGIN — read-only audit access across all groups
  └─ "019257ab-..."  NOLOGIN — grp_engineering; holds table grants; RLS-filtered
  └─ "019257ac-..."  NOLOGIN — grp_finance; holds table grants; RLS-filtered
       └─ alice   LOGIN — member of 019257ab (grp_engineering)
       └─ bob     LOGIN — member of 019257ac (grp_finance)
       └─ carol   LOGIN — member of 019257ab and 019257ac
```

### Grants

Table grants go to group roles (by UUID), not to user roles. User roles receive only the minimum required to connect:

```sql
-- User role: connect and access schema only
GRANT CONNECT ON DATABASE sso    TO alice;
GRANT USAGE   ON SCHEMA   public TO alice;

-- Group role: data access (activated by SET LOCAL ROLE)
GRANT SELECT, INSERT, UPDATE, DELETE ON enrolled_certs TO "019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f";
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions        TO "019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f";
GRANT INSERT                         ON audit_log        TO "019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f";
-- Also grant SELECT on group_registry so the role can resolve its own name.
GRANT SELECT                         ON group_registry   TO "019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f";
```

---

## SET ROLE: Activating a Group

A user authenticates to PostgreSQL with their x509 certificate. At that point:

```
session_user = 'alice'   — set at authentication; never changes
current_user = 'alice'   — starts the same as session_user
```

To perform a group-scoped operation, the application issues `SET LOCAL ROLE` with the group's UUID:

```sql
SET LOCAL ROLE "019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f";
```

Now, for the duration of the current transaction:

```
session_user = 'alice'                                  — authenticated individual
current_user = '019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f'  — active group
```

`SET LOCAL` scopes the switch to the transaction. It reverts automatically at `COMMIT` or `ROLLBACK`.

`SET ROLE` without `LOCAL` is not used. Even on non-pooled connections, it leaves the session in an unexpected state if the application does not explicitly reset it.

Alice can only `SET LOCAL ROLE "<uuid>"` because she holds that role via `GRANT`. A user who is not a member of a group role cannot activate it — PostgreSQL enforces this independently of RLS.

---

## Data Tables

Every group-isolated table carries two stamped columns:

```sql
group_  TEXT  NOT NULL  DEFAULT current_user   -- UUID of the group that owns this row
owner   TEXT  NOT NULL  DEFAULT session_user   -- uid of the user who wrote this row
```

These are set by the database at INSERT time, after `SET LOCAL ROLE` has taken effect. The application never supplies them. Because users authenticate directly (no service account), `session_user` is the real individual.

`group_` uses a trailing underscore to avoid the PostgreSQL reserved word `group`.

### Example: enrolled_certs

```sql
CREATE TABLE enrolled_certs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username        TEXT        NOT NULL,
    group_          TEXT        NOT NULL DEFAULT current_user,
    owner           TEXT        NOT NULL DEFAULT session_user,
    serial          TEXT        NOT NULL UNIQUE,
    thumbprint      TEXT        NOT NULL UNIQUE,
    public_cert_pem TEXT        NOT NULL,
    device_fp       TEXT,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ
);
```

When alice calls `SET LOCAL ROLE "019257ab-..."` and then inserts a cert record, the database stamps:

```
group_  = '019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f'   ← DEFAULT current_user (UUID)
owner   = 'alice'                                    ← DEFAULT session_user
```

To display the human-readable group name alongside a row, join with `group_registry`:

```sql
SELECT e.username, g.name AS group_name, e.owner, e.issued_at
FROM   enrolled_certs e
JOIN   group_registry g ON g.id::text = e.group_;
```

---

## Row Level Security

RLS policies key on `current_user` — the active group UUID. No application code filters by group; the database does it. The policies are identical in structure to a name-based design; the only difference is that `current_user` resolves to a UUID.

```sql
ALTER TABLE enrolled_certs ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrolled_certs FORCE ROW LEVEL SECURITY;

CREATE POLICY certs_select ON enrolled_certs
    FOR SELECT
    USING (group_ = current_user);

CREATE POLICY certs_insert ON enrolled_certs
    FOR INSERT
    WITH CHECK (
        group_ = current_user    -- row must belong to the active group
        AND owner = session_user -- individual identity cannot be forged
    );

CREATE POLICY certs_update ON enrolled_certs
    FOR UPDATE
    USING  (group_ = current_user)
    WITH CHECK (group_ = current_user);

CREATE POLICY certs_delete ON enrolled_certs
    FOR DELETE
    USING (group_ = current_user);
```

`FORCE ROW LEVEL SECURITY` ensures the policies apply even to `sso_admin` (the table owner).

No UUID or name appears in any policy. `current_user` resolves to whichever group UUID is active at query time. A new group is covered by existing policies the moment its role exists; no SQL change is needed.

`sso_auditor` has `BYPASSRLS` for read-only cross-group audit queries. It is not used by the application for normal request handling.

---

## Multi-Group Users

Carol belongs to both groups. Each request operates in exactly one group context. At `POST /api/token`, carol specifies which group she wants for that session using the group's UUID:

```json
{ "group": "019257ac-7c3d-7000-9f4e-1a2b3c4d5e6f" }
```

The token handler validates that this UUID is in carol's LDAP membership list and embeds it as the `grp` claim in the JWT. Every subsequent request in that session uses that group's context. To switch groups, carol obtains a new token specifying the other UUID.

If carol belongs to only one group, the token handler selects it automatically and no request body is needed.

---

## SAML Attribute Pipeline

Group UUIDs travel from LDAP to the application through the SAML assertion:

```
OpenLDAP
  groupOfNames entries; cn = UUID v7
  memberof overlay writes memberOf (containing UUID in DN) onto user entries

IdP (SimpleSAMLphp)
  reads memberOf at login
  → authproc step 25: extract cn (UUID) from each memberOf DN
  → validate each extracted value against UUID v7 format regex
  → reject login if no valid UUIDs remain
  → release as ssoGroups attribute (OID urn:oid:1.3.6.1.4.1.99999.1.4)

SP (Shibboleth)
  attribute-map.xml maps OID → id="ssoGroups"
  ShibUseHeaders On delivers ssoGroups as HTTP header (semicolon-separated UUIDs)

Go app (POST /api/token)
  reads ssoGroups header
  splits on ";" and validates each value against reGroupID (UUID v7 regex)
  resolves active group UUID (single: automatic; multiple: from request body)
  issues JWT with grp claim containing the UUID

Go app (subsequent requests)
  BearerAuth middleware validates JWT
  stores grp claim (UUID) in context via ContextWithGroup

WithGroupTx (db/group_tx.go)
  reads UUID from context
  validates against reGroupID regex
  issues SET LOCAL ROLE "<uuid>" via pgx.Identifier{group}.Sanitize()
  executes fn(tx) under group context
```

### IdP authproc step 25 (updated)

The regex changes from matching the `grp_` prefix to matching the UUID v7 format:

```php
25 => [
    'class' => 'core:PHP',
    'code'  => '
        $memberOf = $attributes["memberOf"] ?? [];
        $groups = [];
        $uuidV7 = \'/^cn=([0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}),/i\';
        foreach ($memberOf as $dn) {
            if (preg_match($uuidV7, $dn, $m)) {
                $groups[] = $m[1];
            }
        }
        if (empty($groups)) {
            throw new \SimpleSAML\Error\Exception(
                "Login denied: user has no application group membership."
            );
        }
        $attributes["ssoGroups"] = $groups;
        unset($attributes["memberOf"]);
    ',
],
```

### Go validation regex (updated)

```go
// reGroupID matches a UUID v7: time-ordered, version bit = 7, variant bits = 10xx.
var reGroupID = regexp.MustCompile(
    `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)
```

This replaces `reGroupName` in `token.go` and `reGroupRole` in `group_tx.go`.

---

## Provisioning a New Group

Both steps are required. The UUID v7 is generated by the provisioning tool before either step.

**1. Add to LDAP** (admin operation):

```ldif
dn: cn=019257ad-7c3d-7000-9f4e-1a2b3c4d5e6f,ou=groups,dc=sso,dc=local
objectClass: groupOfNames
objectClass: top
cn: 019257ad-7c3d-7000-9f4e-1a2b3c4d5e6f
description: grp_legal
member: uid=carol,ou=users,dc=sso,dc=local
```

**2. Create the PostgreSQL role** (admin operation, run as `sso_admin`):

```sql
SELECT provision_group_role(
    '019257ad-7c3d-7000-9f4e-1a2b3c4d5e6f'::UUID,
    'grp_legal'
);

SELECT provision_user_role(
    'carol',
    ARRAY['019257ad-7c3d-7000-9f4e-1a2b3c4d5e6f'::UUID]
);
```

`provision_group_role()` creates the `NOLOGIN` role, sets its `COMMENT`, applies table grants, and inserts a row into `group_registry`. No code changes are needed anywhere else.

### provision_group_role signature

```sql
CREATE OR REPLACE FUNCTION provision_group_role(p_id UUID, p_name TEXT)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_catalog AS $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = p_id::text) THEN
        EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT', p_id);
        EXECUTE format('COMMENT ON ROLE %I IS %L', p_id, p_name);

        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON enrolled_certs TO %I', p_id);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON sessions        TO %I', p_id);
        EXECUTE format('GRANT INSERT                         ON audit_log        TO %I', p_id);
        EXECUTE format('GRANT SELECT                         ON group_registry   TO %I', p_id);

        INSERT INTO group_registry (id, name) VALUES (p_id, p_name);
        RAISE NOTICE 'Provisioned group role: % (%)', p_id, p_name;
    ELSE
        -- Idempotent: update the name and refresh grants.
        EXECUTE format('COMMENT ON ROLE %I IS %L', p_id, p_name);
        UPDATE group_registry SET name = p_name WHERE id = p_id;
        RAISE NOTICE 'Group role already exists, name updated: % (%)', p_id, p_name;
    END IF;
END; $$;
```

### provision_user_role signature

```sql
CREATE OR REPLACE FUNCTION provision_user_role(p_username TEXT, p_groups UUID[])
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_catalog AS $$
DECLARE
    _g UUID;
BEGIN
    -- ... validation and CREATE ROLE as before ...

    IF array_length(p_groups, 1) IS NULL THEN
        RAISE EXCEPTION 'provision_user_role: p_groups must be non-empty for user ''%''', p_username;
    END IF;

    FOREACH _g IN ARRAY p_groups LOOP
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = _g::text) THEN
            RAISE EXCEPTION 'Group role ''%'' does not exist — call provision_group_role first.', _g;
        END IF;
        EXECUTE format('GRANT %I TO %I', _g, p_username);
    END LOOP;
END; $$;
```

### Renaming a group

A group can be renamed without touching any data rows, role memberships, or JWTs. Only the labels change:

```sql
-- Update the PostgreSQL comment (pg_shdescription).
COMMENT ON ROLE "019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f" IS 'grp_platform';

-- Update group_registry.
UPDATE group_registry SET name = 'grp_platform'
WHERE  id = '019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f';
```

```ldif
dn: cn=019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f,ou=groups,dc=sso,dc=local
changetype: modify
replace: description
description: grp_platform
```

All existing rows with `group_ = '019257ab-...'` remain valid. All existing JWTs with `grp = '019257ab-...'` remain valid. `SET LOCAL ROLE "019257ab-..."` continues to work. The name change is purely cosmetic.

---

## Resolving a Group Name

Because the identifier everywhere is a UUID, any display of group information requires a join against `group_registry`.

```sql
-- Resolve a single group UUID to its name.
SELECT name FROM group_registry WHERE id = '019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f';

-- Audit log with readable group names.
SELECT a.recorded_at,
       a.individual,
       g.name  AS group_name,
       a.table_name,
       a.operation
FROM   audit_log      a
JOIN   group_registry g ON g.id::text = a.active_group
ORDER  BY a.recorded_at DESC;

-- enrolled_certs with readable group names.
SELECT e.username, g.name AS group_name, e.serial, e.issued_at
FROM   enrolled_certs e
JOIN   group_registry g ON g.id::text = e.group_;
```

The Go application can maintain an in-process cache of `group_registry` to resolve UUIDs to names for API responses without a per-request query.

---

## Constraint Views

The constraint views join against `group_registry` rather than matching on a name pattern.

```sql
-- Groups registered in group_registry that have no login-capable members.
-- Must return zero rows in a healthy system.
CREATE VIEW empty_groups AS
SELECT gr.id, gr.name
FROM   group_registry gr
WHERE  NOT EXISTS (
    SELECT 1
    FROM   pg_auth_members m
    JOIN   pg_roles        r ON r.oid = m.roleid
    JOIN   pg_roles        u ON u.oid = m.member
    WHERE  r.rolname = gr.id::text
      AND  u.rolcanlogin
);

-- Login roles that hold no membership in any group_registry role.
-- Excludes sso_auditor and system roles. Must return zero rows.
CREATE VIEW ungrouped_users AS
SELECT r.rolname AS user_name
FROM   pg_roles r
WHERE  r.rolcanlogin
  AND  r.rolname NOT IN ('sso_auditor', 'postgres')
  AND  r.rolname NOT LIKE 'pg_%'
  AND  NOT EXISTS (
    SELECT 1
    FROM   pg_auth_members m
    JOIN   pg_roles        g  ON g.oid  = m.roleid
    JOIN   group_registry  gr ON gr.id::text = g.rolname
    WHERE  m.member = r.oid
);
```

---

## Group Lifecycle Operations

### Removing a user from a group

**1. Remove from LDAP:**

```ldif
dn: cn=019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f,ou=groups,dc=sso,dc=local
changetype: modify
delete: member
member: uid=alice,ou=users,dc=sso,dc=local
```

The `memberof` overlay automatically removes the corresponding `memberOf` value from alice's entry.

**2. Revoke the PostgreSQL group membership:**

```sql
REVOKE "019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f" FROM alice;
```

Alice's existing JWT remains valid until it expires. Her next login will not include the group UUID in `ssoGroups`.

### Deprovisioning a group

`deprovision_user_role()` identifies the group roles held by a user by joining against `group_registry`, not by matching on a name pattern:

```sql
FOR _g IN
    SELECT r.rolname
    FROM   pg_auth_members m
    JOIN   pg_roles        r  ON r.oid = m.roleid
    JOIN   group_registry  gr ON gr.id::text = r.rolname
    WHERE  m.member = (SELECT oid FROM pg_roles WHERE rolname = p_username)
LOOP
    EXECUTE format('REVOKE %I FROM %I', _g, p_username);
END LOOP;
```

---

## Audit

A `SECURITY INVOKER` trigger (`fn_audit_stamp`) fires on INSERT, UPDATE, and DELETE on `enrolled_certs` and `sessions`. It writes one row to `audit_log` per DML event:

```sql
individual   TEXT  DEFAULT session_user   -- 'alice' — the authenticated user
active_group TEXT  DEFAULT current_user   -- UUID of the active group
```

`active_group` stores the UUID. To display the human-readable name, join with `group_registry` as shown in the Resolving a Group Name section above.

The trigger must be `SECURITY INVOKER` (the default). With `SECURITY DEFINER`, both columns would evaluate to the function owner's identity (`sso_admin`), destroying all attribution.

---

## Dev Seed

The dev seed (`postgres/init/03-dev-seed.sql`) uses fixed UUIDs so the development environment is reproducible:

```sql
-- Fixed UUIDs for dev groups (generated once; committed to the repo).
DO $$
DECLARE
    _eng  UUID := '019257ab-7c3d-7000-9f4e-1a2b3c4d5e6f';
    _fin  UUID := '019257ac-7c3d-7000-9f4e-1a2b3c4d5e6f';
BEGIN
    PERFORM provision_group_role(_eng, 'grp_engineering');
    PERFORM provision_group_role(_fin, 'grp_finance');

    PERFORM provision_user_role('alice', ARRAY[_eng]);
    PERFORM provision_user_role('bob',   ARRAY[_fin]);

    -- group_ is supplied explicitly because the seed runs as sso_admin,
    -- so DEFAULT current_user would stamp 'sso_admin', not a group UUID.
    INSERT INTO enrolled_certs (username, group_, serial, thumbprint, ...)
    VALUES
        ('alice', _eng::text, 'de:ad:00:00:00:00:00:01', ...),
        ('bob',   _fin::text, 'de:ad:00:00:00:00:00:02', ...)
    ON CONFLICT (serial) DO NOTHING;
END $$;
```

The corresponding LDAP bootstrap entries (`ldap/bootstrap/00-dit-base.ldif` and `03-group-members.ldif`) use the same fixed UUIDs as `cn` values.

---

## Invariant Summary

| Invariant | Where enforced |
|---|---|
| One login role per user | `provision_user_role()` — creates `LOGIN` role; no shared accounts |
| No service accounts | Design — `UserConnFactory` authenticates as the user's own role |
| User belongs to at least one group | `provision_user_role()` — rejects empty UUID array; IdP rejects no-group logins |
| Group has at least one user | `empty_groups` view (uses `group_registry`); asserted in dev seed |
| Group roles cannot log in | `provision_group_role()` — always creates `NOLOGIN` |
| Group isolation | RLS `USING (group_ = current_user)` on all data tables |
| Row stamping | `DEFAULT current_user` (UUID) and `DEFAULT session_user` (uid) — set by the database |
| Audit attribution | `fn_audit_stamp` SECURITY INVOKER trigger |
| UUID is the stable identifier | LDAP `cn` = PostgreSQL role name = JWT `grp` claim = `group_` column value |
| Human-readable name is a label only | LDAP `description` + PostgreSQL `COMMENT ON ROLE` (pg_shdescription) + `group_registry.name` |
| Group name changes require no data migration | UUID carries identity; name is cosmetic at every layer |
| LDAP ↔ PostgreSQL sync | Operational requirement; `WithGroupTx` fails at `SET LOCAL ROLE` if PG role is missing |
