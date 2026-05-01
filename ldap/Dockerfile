# =============================================================================
# ldap/Dockerfile
#
# Extends bitnami/openldap:2 with:
#   • Custom ssoUser schema (ssoDeviceFingerprint, ssoCertThumbprint)
#   • Dedicated entrypoint that applies cn=config ACLs via SASL EXTERNAL
#     (requires running as root before bitnami's run.sh drops privileges)
#   • openssl for sample certificate generation during first-run init
#   • ldap-utils (ldapmodify/ldapadd) for runtime cert-push operations
#
# SECURITY NOTE
# ─────────────
# The container runs as root during FIRST-RUN ONLY so that SASL EXTERNAL
# on ldapi:// has rootDN authority over cn=config. Once ACLs are written,
# the sentinel /bitnami/openldap/.sso-configured is created and subsequent
# starts use bitnami's standard (non-root) run.sh.
# Private keys and passphrases are NEVER written to any LDAP attribute.
# =============================================================================
FROM bitnami/openldap:2

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl \
        ldap-utils \
        gosu \
    && rm -rf /var/lib/apt/lists/*

# ── Schema ────────────────────────────────────────────────────────────────────
# sso.ldif is applied to cn=config by entrypoint.sh (not by bitnami's setup)
COPY schema/sso.ldif      /etc/ldap/schema/sso.ldif

# ── ACL ───────────────────────────────────────────────────────────────────────
COPY acl/                 /etc/ldap/acl/

# ── Bootstrap data LDIF ───────────────────────────────────────────────────────
# bitnami's setup.sh loads files from /docker-entrypoint-initdb.d/ using
# ldapadd as the data-tree admin. Data-only LDIF goes here.
COPY bootstrap/           /docker-entrypoint-initdb.d/

# ── Scripts ───────────────────────────────────────────────────────────────────
COPY scripts/             /etc/ldap/scripts/
RUN  chmod +x /etc/ldap/scripts/*.sh

EXPOSE 1389 1636

ENTRYPOINT ["/etc/ldap/scripts/entrypoint.sh"]
CMD []
