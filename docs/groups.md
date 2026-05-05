# Groups

Groups in sso01a control **which rows a user can see and write**. They are not a role-based access control (RBAC) system — they do not grant or deny access to endpoints, features, or operations. Every authenticated user can perform the same operations; groups determine only which data those operations touch.

---

## What a Group Is

A group is a named set of users that jointly own a partition of the application data. Every data row belongs to exactly one group. A user who activates a group sees that group's rows and no others. The application issues no `WHERE group = ?` clauses — the database enforces the boundary automatically via Row Level Security.

A group exists in two places simultaneously:

| Layer | Representation | Purpose |
|---|---|---|
| OpenLDAP | `groupOfNames` entry under `ou=groups` | Membership authority — who belongs |
| PostgreSQL | `NOLOGIN` role named `grp_<name>` | Enforcement — data isolation via RLS |

Both must exist for a group to be usable. The names must match exactly.

---

## Naming Convention

Group names follow a single pattern across all layers:

```
grp_[a-z][a-z0-9_]{0,58}
```

Examples: `grp_engineering`, `grp_finance`, `grp_legal`

The `grp_` prefix distinguishes group roles from user login roles in PostgreSQL system tables, LDAP directory listings, and audit logs. It is enforced by `provision_group_role()` in SQL and by `reGroupRole` / `reGroupName` regexes in Go.

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
dn: cn=grp_engineering,ou=groups,dc=sso,dc=local
objectClass: groupOfNames
objectClass: top
cn: grp_engineering
description: Engineering team
member: uid=alice,ou=users,dc=sso,dc=local
member: uid=carol,ou=users,dc=sso,dc=local
```

Each `member` value is the full DN of a user entry. The `cn` value is the group name — it must match the PostgreSQL role name exactly.

### memberof overlay

The `memberof` slapd module maintains a `memberOf` attribute on each user entry, pointing back to every group that user belongs to. This is the attribute the IdP reads at login time.

```
alice's LDAP entry:
  uid: alice
  memberOf: cn=grp_engineering,ou=groups,dc=sso,dc=local
```

When a user is added to or removed from a `groupOfNames` entry, the overlay updates their `memberOf` attribute automatically. The IdP reads `memberOf` — it does not scan all group entries.

### Group membership rules

- A group must have at least one `member`. The `empty_groups` PostgreSQL view surfaces violations.
- A user may belong to any number of groups.
- Membership changes in LDAP take effect on the user's **next login**. Existing sessions and JWTs are unaffected until they expire.

---

## PostgreSQL Role Model

### One login role per user

Each user is exactly one PostgreSQL `LOGIN` role. The role name matches the user's `uid` in LDAP and the `CN` in their x509 client certificate. There are no shared login roles and no application service accounts.

```
alice  LOGIN NOINHERIT   — authenticates directly with x509 cert
bob    LOGIN NOINHERIT   — authenticates directly with x509 cert
```

`NOINHERIT` means alice does not silently gain `grp_engineering`'s privileges just by being a member. She must explicitly activate the group.

### One role per group

Each group is exactly one PostgreSQL `NOLOGIN` role. It cannot authenticate directly. It holds the table-level grants (SELECT, INSERT, UPDATE, DELETE). Users activate it with `SET LOCAL ROLE`.

```
grp_engineering  NOLOGIN NOINHERIT   — holds data grants; cannot log in
grp_finance      NOLOGIN NOINHERIT   — holds data grants; cannot log in
```

### Membership

`provision_user_role()` grants the group role to the user role:

```sql
GRANT grp_engineering TO alice;
```

This gives alice the ability to `SET LOCAL ROLE grp_engineering`. It does not grant her any table access until she does.

### Role hierarchy

```
sso_admin        SUPERUSER — owns the database; provisioning only
  └─ sso_auditor BYPASSRLS LOGIN — read-only audit access across all groups
  └─ grp_engineering  NOLOGIN — holds table grants; RLS-filtered
  └─ grp_finance      NOLOGIN — holds table grants; RLS-filtered
       └─ alice   LOGIN — member of grp_engineering
       └─ bob     LOGIN — member of grp_finance
       └─ carol   LOGIN — member of grp_engineering and grp_finance
```

### Grants

Table grants go to group roles, not to user roles. User roles receive only the minimum required to connect:

```sql
-- User role: connect and access schema only
GRANT CONNECT ON DATABASE sso      TO alice;
GRANT USAGE   ON SCHEMA   public   TO alice;

-- Group role: data access (activated by SET LOCAL ROLE)
GRANT SELECT, INSERT, UPDATE, DELETE ON enrolled_certs TO grp_engineering;
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions        TO grp_engineering;
GRANT INSERT                         ON audit_log        TO grp_engineering;
```

---

## SET ROLE: Activating a Group

A user authenticates to PostgreSQL with their x509 certificate. At that point:

```
session_user = 'alice'   — set at authentication; never changes
current_user = 'alice'   — starts the same as session_user
```

To perform a group-scoped operation, the application issues:

```sql
SET LOCAL ROLE grp_engineering;
```

Now, for the duration of the current transaction:

```
session_user = 'alice'           — still the authenticated individual
current_user = 'grp_engineering' — the active group
```

`SET LOCAL` scopes the switch to the transaction. It reverts automatically at `COMMIT` or `ROLLBACK`. The connection returns to `session_user = current_user = 'alice'` after the transaction ends.

`SET ROLE` without `LOCAL` is not used. Even on non-pooled connections, it leaves the session in an unexpected state if the application does not explicitly reset it.

Alice can only `SET LOCAL ROLE grp_engineering` because she holds that role via `GRANT`. A user who is not a member of a group role cannot activate it — PostgreSQL enforces this before RLS is even consulted.

---

## Data Tables

Every group-isolated table carries two stamped columns:

```sql
group_  TEXT  NOT NULL  DEFAULT current_user   -- which group owns this row
owner   TEXT  NOT NULL  DEFAULT session_user   -- which user wrote this row
```

These are set by the database at INSERT time, after `SET LOCAL ROLE` has taken effect. The application never supplies them. Because users authenticate directly (no service account), `session_user` is the real individual — alice, bob — not a proxy.

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

When alice calls `SET LOCAL ROLE grp_engineering` and then inserts a cert record, the database stamps:

```
group_  = 'grp_engineering'   ← DEFAULT current_user
owner   = 'alice'             ← DEFAULT session_user
```

---

## Row Level Security

RLS policies key on `current_user` — the active group. No application code filters by group; the database does it.

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

No group name appears in any policy. `current_user` resolves to whichever group is active at query time. A new group — `grp_legal`, say — is covered by existing policies the moment its role exists; no SQL change is needed.

`sso_auditor` has `BYPASSRLS` for read-only cross-group audit queries. It is not used by the application for normal request handling.

---

## Multi-Group Users

Carol belongs to both `grp_engineering` and `grp_finance`. Each request operates in exactly one group context. At `POST /api/token`, carol specifies which group she wants for that session:

```json
{ "group": "grp_finance" }
```

The token handler validates that `grp_finance` is in carol's LDAP membership list and embeds it as the `grp` claim in the JWT. Every subsequent request in that session uses the finance group context. To switch groups, carol obtains a new token specifying the other group.

If carol belongs to only one group, the token handler selects it automatically and no request body is needed.

---

## SAML Attribute Pipeline

Group names travel from LDAP to the application through the SAML assertion:

```
OpenLDAP
  groupOfNames member attributes
  → memberof overlay → memberOf on user entry

IdP (SimpleSAMLphp)
  reads memberOf at login
  → authproc step 25: extract cn from each DN
  → filter: keep only names matching ^grp_[a-z][a-z0-9_]{0,58}$
  → reject login if no groups remain
  → release as ssoGroups attribute (OID urn:oid:1.3.6.1.4.1.99999.1.4)

SP (Shibboleth)
  attribute-map.xml maps OID → id="ssoGroups"
  ShibUseHeaders On delivers ssoGroups as HTTP header
  multiple groups are semicolon-separated

Go app (POST /api/token)
  reads ssoGroups header
  validates each value against reGroupName regex
  resolves active group (single: automatic; multiple: from request body)
  issues JWT with grp claim

Go app (subsequent requests)
  BearerAuth middleware validates JWT
  stores grp claim in context via ContextWithGroup

WithGroupTx (db/group_tx.go)
  reads group from context
  validates against reGroupRole regex
  issues SET LOCAL ROLE <group>
  executes fn(tx) under group context
```

---

## Provisioning a New Group

Both steps are required:

**1. Add to LDAP** (admin operation):

```ldif
dn: cn=grp_legal,ou=groups,dc=sso,dc=local
objectClass: groupOfNames
objectClass: top
cn: grp_legal
description: Legal team
member: uid=carol,ou=users,dc=sso,dc=local
```

**2. Create the PostgreSQL role** (admin operation, run as `sso_admin`):

```sql
PERFORM provision_group_role('grp_legal');
-- Grants table privileges to grp_legal.

PERFORM provision_user_role('carol', ARRAY['grp_legal']);
-- Grants grp_legal to carol's login role.
```

No code changes are needed. RLS policies, audit triggers, and constraint views all apply to the new group immediately.

---

## Constraint Views

Two views in `postgres/init/02-roles.sql` enforce the group invariants:

```sql
-- Groups with no members — must always return zero rows.
SELECT * FROM empty_groups;

-- Users with no group membership — must always return zero rows.
SELECT * FROM ungrouped_users;
```

`03-dev-seed.sql` asserts both views return zero rows at the end of initialization. These views use `LIKE 'grp\_%'` — no specific group name appears in the SQL.

---

## Audit

A `SECURITY INVOKER` trigger (`fn_audit_stamp`) fires on INSERT, UPDATE, and DELETE on `enrolled_certs` and `sessions`. It writes one row to `audit_log` per DML event:

```sql
individual   TEXT  DEFAULT session_user   -- 'alice' — the authenticated user
active_group TEXT  DEFAULT current_user   -- 'grp_engineering' — the active group
```

Because the trigger is `SECURITY INVOKER` (the default), `session_user` and `current_user` evaluate to their actual values at the time of the DML — not the function owner's identity. `SECURITY DEFINER` must not be used on this trigger.

---

## Invariant Summary

| Invariant | Where enforced |
|---|---|
| One login role per user | `provision_user_role()` — validates name; creates `LOGIN` role |
| No service accounts | Design — `UserConnFactory` authenticates as the user's own role |
| User belongs to at least one group | `provision_user_role()` — rejects empty groups array; IdP rejects no-group logins |
| Group has at least one user | `empty_groups` view; asserted in `03-dev-seed.sql` |
| Group roles cannot log in | `provision_group_role()` — always creates `NOLOGIN` |
| Group isolation | RLS policies on `enrolled_certs` and `sessions` |
| Row stamping | `DEFAULT current_user` and `DEFAULT session_user` — set by the database |
| Audit attribution | `fn_audit_stamp` SECURITY INVOKER trigger |
| Group naming | `^grp_[a-z][a-z0-9_]{0,58}$` — enforced in SQL and Go |
| LDAP ↔ PostgreSQL sync | Operational requirement; `WithGroupTx` fails if PG role is missing |
