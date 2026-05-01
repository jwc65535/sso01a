FROM postgres:16-alpine

# pg_hba.conf and postgresql.conf are installed by 00-hba.sh AFTER initdb runs.
# Mounting them directly over $PGDATA would be ignored because initdb regenerates
# those files.  Instead, we copy them as templates and let 00-hba.sh apply them.
COPY config/pg_hba.conf      /etc/postgresql/pg_hba.conf.template
COPY config/postgresql.conf  /etc/postgresql/postgresql.conf.template

# Init scripts run in alphabetical order during the first container start:
#   00-hba.sh     — install pg_hba.conf, pg_ident.conf ssl map, SSL settings
#   01-schema.sql — create tables (enrolled_certs, auth_events, sessions)
#   02-roles.sql  — create roles + RLS policies + provision_user_role()
#   03-dev-seed.sql — dev-only seed data (alice, bob)
COPY init/ /docker-entrypoint-initdb.d/

# openssl: used by bootstrap scripts that generate or inspect server TLS certs.
RUN apk add --no-cache openssl

EXPOSE 5432
