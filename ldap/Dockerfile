# =============================================================================
# ldap/Dockerfile
#
# Builds a custom OpenLDAP container from debian:bookworm-slim with:
#   • Custom ssoUser schema (ssoDeviceFingerprint, ssoCertThumbprint)
#   • Dedicated entrypoint that applies cn=config ACLs via SASL EXTERNAL
#   • openssl for sample certificate generation during first-run init
#   • ldap-utils (ldapmodify/ldapadd) for runtime cert-push operations
#
# SINGLE-MODULE COMPROMISE ANALYSIS
# ──────────────────────────────────
# This container stores only public certificates and LDAP metadata.
# If fully owned, an attacker can:
#   CAN:  Read userCertificate (DER-encoded public cert — not secret)
#   CAN:  Modify ssoCertThumbprint / ssoDeviceFingerprint (DoS: breaks enrolment)
#   CAN:  Delete user entries (DoS: prevents authentication)
#   CANNOT: Retrieve any private key (none stored here)
#   CANNOT: Forge JWTs (no signing key here)
#   CANNOT: Authenticate as a user without a valid x509 client cert + private key
#   CANNOT: Access Vault, PostgreSQL, or the Go app directly
#
# SECURITY NOTE
# ─────────────
# The container runs slapd as root during FIRST-RUN ONLY so SASL EXTERNAL
# on ldapi:// has rootDN authority over cn=config. Once ACLs are written,
# the sentinel /var/lib/ldap-sentinel/.sso-configured is set and subsequent
# starts exec slapd as the openldap user.
# Private keys and passphrases are NEVER written to any LDAP attribute.
#
# BASE IMAGE CHOICE
# ─────────────────
# Previously used bitnami/openldap:2, which was removed from Docker Hub.
# Now uses debian:bookworm-slim + slapd from the Debian package repository.
# dpkg-reconfigure slapd is called at first-run (runtime) from entrypoint.sh
# using the actual admin password from the Docker secret — never baked into
# the image.  This avoids any third-party wrapper image dependency.
# =============================================================================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install slapd without initial configuration (no_configuration=true prevents
# postinst from running dpkg-reconfigure, so no stale config is baked in).
# dpkg-reconfigure is called at container first-run with the real admin password.
RUN echo "slapd slapd/no_configuration boolean true" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        slapd \
        ldap-utils \
        openssl \
        gosu \
 && rm -rf /var/lib/apt/lists/*

# Ensure the ldapi socket directory exists with correct ownership.
# /var/run is typically tmpfs in containers, so the entrypoint re-creates
# this directory on every start before starting slapd.
RUN mkdir -p /var/run/slapd \
 && chown openldap:openldap /var/run/slapd

# ── Schema ────────────────────────────────────────────────────────────────────
# sso.ldif is loaded into cn=config via SASL EXTERNAL during first-run.
COPY schema/sso.ldif      /etc/ldap/schema/sso.ldif

# ── ACL ───────────────────────────────────────────────────────────────────────
COPY acl/                 /etc/ldap/acl/

# ── Bootstrap data LDIF ───────────────────────────────────────────────────────
# entrypoint.sh loads these via ldapmodify after first-run slapd init.
COPY bootstrap/           /etc/ldap/bootstrap/

# ── Scripts ───────────────────────────────────────────────────────────────────
COPY scripts/             /etc/ldap/scripts/
RUN  chmod +x /etc/ldap/scripts/*.sh

# ── Tests ─────────────────────────────────────────────────────────────────────
COPY tests/               /etc/ldap/tests/
RUN  chmod +x /etc/ldap/tests/*.sh

EXPOSE 1389

ENTRYPOINT ["/etc/ldap/scripts/entrypoint.sh"]
CMD []
