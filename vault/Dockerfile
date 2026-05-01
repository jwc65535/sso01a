# Pass-through — we use the official image for the vault service.
# This Dockerfile exists so the build context can provide helper scripts
# and policies that are COPY'd into derived images when needed.
# For local dev the compose file uses `image: hashicorp/vault:1.17` directly.
FROM hashicorp/vault:1.17

# Scripts are mounted via bind-mounts in dev mode;
# this layer makes them available if building a self-contained image for CI.
COPY scripts/ /vault/scripts/
COPY policies/ /vault/policies/
COPY agent/   /vault/agent/

RUN chmod +x /vault/scripts/*.sh
