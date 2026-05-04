FROM php:8.2-apache

ARG SIMPLESAMLPHP_VERSION=2.3.11

# ── System packages ───────────────────────────────────────────────────────────
# openssl:      generate the self-signed IdP SAML signing certificate
# libicu-dev:   PHP intl extension (required by SSP 2.x)
# libzip-dev:   PHP zip extension (required by SSP 2.x)
# libldap2-dev: PHP ldap extension (required by SSP ldap module)
# unzip:        extract SSP tarball
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        openssl \
        libicu-dev \
        libzip-dev \
        libldap2-dev \
        unzip \
    && docker-php-ext-install intl zip ldap \
    && a2enmod rewrite headers \
    && rm -rf /var/lib/apt/lists/*

# ── SimpleSAMLphp ─────────────────────────────────────────────────────────────
RUN curl -fsSL \
      "https://github.com/simplesamlphp/simplesamlphp/releases/download/v${SIMPLESAMLPHP_VERSION}/simplesamlphp-${SIMPLESAMLPHP_VERSION}-full.tar.gz" \
      -o /tmp/ssp.tar.gz \
    && mkdir -p /var/simplesamlphp \
    && tar xzf /tmp/ssp.tar.gz --strip-components=1 -C /var/simplesamlphp \
    && rm /tmp/ssp.tar.gz \
    && chown -R www-data:www-data /var/simplesamlphp

# ── Apache vhost ──────────────────────────────────────────────────────────────
# Run on port 8880 (not 80) so it does not conflict with the Shibboleth SP
# when both containers share the host network (network_mode: host).
COPY config/apache-idp.conf /etc/apache2/sites-available/simplesamlphp.conf
RUN sed -i 's/Listen 80/Listen 8880/' /etc/apache2/ports.conf \
    && a2dissite 000-default 2>/dev/null || true \
    && a2ensite simplesamlphp

# ── Runtime directories ───────────────────────────────────────────────────────
# config/ and metadata/ are bind-mounted at runtime (read-only, from idp/config
# and idp/metadata host directories).
# cert/ is a named volume (idp-cert) so the self-signed cert survives restarts.
# data/ is for SSP session data and is writable at runtime.
RUN mkdir -p \
        /var/simplesamlphp/config \
        /var/simplesamlphp/metadata \
        /var/simplesamlphp/cert \
        /var/simplesamlphp/data \
    && chown -R www-data:www-data \
        /var/simplesamlphp/config \
        /var/simplesamlphp/metadata \
        /var/simplesamlphp/cert \
        /var/simplesamlphp/data

# ── Entrypoint ────────────────────────────────────────────────────────────────
COPY scripts/init.sh /init.sh
RUN chmod +x /init.sh

EXPOSE 8880

ENTRYPOINT ["/init.sh"]
