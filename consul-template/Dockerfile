# Extract the consul-template binary from the official scratch-based image.
FROM hashicorp/consul-template:0.39 AS ct-bin

FROM alpine:3.20

# openssl   — PEM→DER conversion and SHA-256 thumbprint computation in push script
# openldap-clients — ldapmodify / ldapsearch to push certs to OpenLDAP
# bash      — push script uses bash (arrays, subshells, process substitution)
# curl      — healthcheck / manual diagnostics
# ca-certificates — trust anchors for Vault TLS in production
RUN apk add --no-cache \
        openssl \
        openldap-clients \
        bash \
        curl \
        ca-certificates

COPY --from=ct-bin /bin/consul-template /usr/local/bin/consul-template

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["-config=/etc/consul-template/config/consul-template.hcl"]
