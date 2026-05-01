FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

# ── System packages ───────────────────────────────────────────────────────────
# gettext-base:          provides envsubst (used in init.sh to process shibboleth2.xml)
# ssl-cert:              installs snakeoil self-signed cert for dev HTTPS
# libapache2-mod-shib:   Shibboleth SP Apache module + shibd daemon + shib-keygen
RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 \
        libapache2-mod-shib \
        curl \
        ca-certificates \
        openssl \
        gettext-base \
        ssl-cert \
    && rm -rf /var/lib/apt/lists/*

# ── Apache modules ─────────────────────────────────────────────────────────────
RUN a2enmod \
        ssl \
        rewrite \
        headers \
        proxy \
        proxy_http \
        shib

# Remove the default site; the vhosts are bind-mounted at runtime
RUN a2dissite 000-default default-ssl 2>/dev/null; true

# ── Shibboleth SP key directory (generated at first boot, persisted in shib-keys volume) ──
RUN mkdir -p /etc/shibboleth/keys && chmod 700 /etc/shibboleth/keys

# ── Runtime directories for shibd ─────────────────────────────────────────────
RUN mkdir -p /var/run/shibboleth /var/log/shibboleth /var/cache/shibboleth \
    && chown _shibd:_shibd /var/run/shibboleth /var/log/shibboleth /var/cache/shibboleth 2>/dev/null || true

# ── Health check endpoint ──────────────────────────────────────────────────────
RUN mkdir -p /var/www/html && echo "ok" > /var/www/html/healthz

# ── Entrypoint ─────────────────────────────────────────────────────────────────
COPY scripts/init.sh /init.sh
RUN chmod +x /init.sh

EXPOSE 80 443

ENTRYPOINT ["/init.sh"]
