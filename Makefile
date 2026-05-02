# Makefile — sso01a zero-trust authentication stack
# Requires: docker, docker-compose (v2), openssl, curl, jq

COMPOSE     := docker compose
PROJECT     := sso01a
VAULT_ADDR  ?= https://localhost:8200
VAULT_TOKEN ?= $(shell cat secrets/vault-root-token.txt 2>/dev/null)

# Colour helpers
RED    := \033[0;31m
GREEN  := \033[0;32m
YELLOW := \033[0;33m
CYAN   := \033[0;36m
RESET  := \033[0m

.PHONY: help
help: ## Show this help
	@awk 'BEGIN{FS=":.*##"; printf "$(CYAN)%-20s$(RESET) %s\n","Target","Description"} \
	      /^[a-zA-Z_-]+:.*##/{printf "$(GREEN)%-20s$(RESET) %s\n",$$1,$$2}' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

.PHONY: up
up: ## Bring all services up (detached)
	$(COMPOSE) -p $(PROJECT) up -d
	@echo "$(GREEN)Stack is up. Tail logs with: make logs$(RESET)"

.PHONY: down
down: ## Stop all services (preserve volumes)
	$(COMPOSE) -p $(PROJECT) down

.PHONY: restart
restart: down up ## Restart the full stack

.PHONY: clean
clean: ## Destroy containers, volumes, and generated PKI material — DESTRUCTIVE
	@echo "$(RED)This will destroy all volumes and generated certificates.$(RESET)"
	@read -r -p "Type 'yes' to confirm: " confirm && [ "$$confirm" = "yes" ]
	$(COMPOSE) -p $(PROJECT) down -v --remove-orphans
	rm -rf pki/certs/* secrets/ postgres/ssl/*.pem
	@echo "$(YELLOW)All persistent state removed.$(RESET)"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

.PHONY: logs
logs: ## Tail logs for all services
	$(COMPOSE) -p $(PROJECT) logs -f

.PHONY: logs-%
logs-%: ## Tail logs for a specific service  (e.g. make logs-vault)
	$(COMPOSE) -p $(PROJECT) logs -f $*

# ---------------------------------------------------------------------------
# Bootstrap — run once before the first `make up`
# ---------------------------------------------------------------------------

.PHONY: bootstrap
bootstrap: _check-deps _gen-secrets pki-bootstrap ## Full first-run bootstrap — starts infra, initialises, then brings up all services
	@# Phase 1: bring up the three infra services in parallel
	@echo "$(CYAN)Phase 1: Starting vault, ldap, postgres...$(RESET)"
	$(COMPOSE) -p $(PROJECT) up -d vault ldap postgres
	@# Wait for Vault (dev mode is fast — usually < 10 s)
	@echo "$(CYAN)Waiting for Vault (up to 90 s)...$(RESET)"
	@elapsed=0; \
	until $(COMPOSE) -p $(PROJECT) exec -T vault \
	        sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status 2>/dev/null | grep -q "Initialized.*true"'; do \
	    elapsed=$$((elapsed + 3)); \
	    [ $$elapsed -ge 90 ] && echo "$(RED)Vault did not become ready$(RESET)" && exit 1; \
	    sleep 3; \
	done
	@echo "$(GREEN)Vault ready.$(RESET)"
	@# Phase 2: run PKI bootstrap inside the running Vault container
	@$(MAKE) -s vault-init
	@# Phase 3: wait for LDAP first-run init, then start Vault Agent
	@$(MAKE) -s ldap-bootstrap
	@echo "$(CYAN)Starting vault-agent...$(RESET)"
	$(COMPOSE) -p $(PROJECT) up -d vault-agent
	@echo "$(CYAN)Waiting for vault-agent token (up to 60 s)...$(RESET)"
	@elapsed=0; \
	until $(COMPOSE) -p $(PROJECT) exec -T vault-agent \
	        test -f /vault/agent-token/agent.token 2>/dev/null; do \
	    elapsed=$$((elapsed + 3)); \
	    [ $$elapsed -ge 60 ] && echo "$(RED)Vault Agent did not write token$(RESET)" && exit 1; \
	    sleep 3; \
	done
	@echo "$(GREEN)Vault Agent ready.$(RESET)"
	@# Phase 4: set sso_app password + copy CA chain from vault-agent to postgres/ssl/
	@$(MAKE) -s postgres-bootstrap
	@# Phase 5: bring up all remaining services
	@echo "$(CYAN)Phase 5: Starting remaining services (consul-template, idp, app, sp, client)...$(RESET)"
	$(COMPOSE) -p $(PROJECT) up -d
	@echo ""
	@echo "$(GREEN)Bootstrap complete!$(RESET)"
	@echo "  Tail logs : make logs"
	@echo "  Run tests : make test-flow  (after adding sp.sso.local to /etc/hosts)"
	@echo "  SP cert   : make sp-cert-extract  (then restart IdP)"

.PHONY: bootstrap-all
bootstrap-all: ## Fully automated first-run bootstrap via shell script (equivalent to 'make bootstrap')
	bash scripts/bootstrap-all.sh

.PHONY: _gen-secrets
_gen-secrets: ## Generate Docker secret files (passwords, seeds) and ensure .env exists
	@[ -f .env ] || { cp .env.example .env; echo "$(YELLOW).env created from .env.example — review before production use$(RESET)"; }
	@mkdir -p secrets
	@[ -f secrets/ldap_admin_password.txt ]         || openssl rand -base64 32 > secrets/ldap_admin_password.txt
	@[ -f secrets/ldap_cert_writer_password.txt ]   || openssl rand -base64 32 > secrets/ldap_cert_writer_password.txt
	@[ -f secrets/postgres_admin_password.txt ]     || openssl rand -base64 32 > secrets/postgres_admin_password.txt
	@[ -f secrets/postgres_app_password.txt ]       || openssl rand -base64 32 > secrets/postgres_app_password.txt
	@[ -f secrets/ssp_admin_password.txt ]          || openssl rand -base64 32 > secrets/ssp_admin_password.txt
	@[ -f secrets/vault-root-token.txt ]            || openssl rand -hex 16 > secrets/vault-root-token.txt
	@# TOTP master secret — 48 random bytes (64 base64 chars) used as Argon2id input
	@[ -f secrets/totp_master_secret.txt ]          || openssl rand -base64 48 > secrets/totp_master_secret.txt
	@# Sync vault root token into .env if present
	@if grep -q '^VAULT_DEV_ROOT_TOKEN_ID=' .env 2>/dev/null; then \
	    sed -i "s|^VAULT_DEV_ROOT_TOKEN_ID=.*|VAULT_DEV_ROOT_TOKEN_ID=$$(cat secrets/vault-root-token.txt)|" .env; \
	fi
	@chmod 644 secrets/*.txt
	@echo "$(GREEN)Secret files ready.$(RESET)"

.PHONY: pki-bootstrap
pki-bootstrap: ## Bootstrap root CA and generate Vault TLS certificates
	bash pki/scripts/bootstrap-ca.sh

.PHONY: vault-init
vault-init: ## Initialise Vault dev token + run full PKI bootstrap
	@echo "$(CYAN)Running Vault bootstrap (dev mode)...$(RESET)"
	@# Install bash + jq in the Alpine-based vault container (lost on restart, only needed here)
	$(COMPOSE) -p $(PROJECT) exec -T vault sh -c \
	    "apk update -q >/dev/null 2>&1 && apk add -q --no-cache bash jq >/dev/null 2>&1 || true"
	$(COMPOSE) -p $(PROJECT) exec \
	    -e VAULT_ADDR=http://127.0.0.1:8200 \
	    -e VAULT_TOKEN=$(shell cat secrets/vault-root-token.txt 2>/dev/null || echo devroot) \
	    -e DOMAIN=$(shell grep ^DOMAIN .env 2>/dev/null | cut -d= -f2 || echo sso.local) \
	    -e APP_ENV=$(shell grep ^APP_ENV .env 2>/dev/null | cut -d= -f2 || echo development) \
	    vault bash /vault/scripts/init.sh
	@echo "$(GREEN)Vault PKI bootstrap complete.$(RESET)"

.PHONY: vault-status
vault-status: ## Show Vault seal status and PKI summary
	@echo "── Vault status ──────────────────────────────────────────"
	@VAULT_ADDR=$(VAULT_ADDR) VAULT_TOKEN=$(VAULT_TOKEN) vault status || true
	@echo "── Intermediate CA issuer ────────────────────────────────"
	@VAULT_ADDR=$(VAULT_ADDR) VAULT_TOKEN=$(VAULT_TOKEN) \
	    vault read -format=json pki_int/cert/ca 2>/dev/null \
	    | jq -r '.data | "  Serial: \(.serial_number)\n  Expires: \(.expiration | todate)"' || true
	@echo "── Policies ──────────────────────────────────────────────"
	@VAULT_ADDR=$(VAULT_ADDR) VAULT_TOKEN=$(VAULT_TOKEN) vault policy list 2>/dev/null | grep -v '^$' | sed 's/^/  /' || true

.PHONY: ldap-bootstrap
ldap-bootstrap: ## Wait for LDAP first-run init to complete (entrypoint handles it automatically)
	@echo "$(CYAN)Waiting for LDAP first-run initialisation...$(RESET)"
	@until $(COMPOSE) -p $(PROJECT) exec -T ldap \
	    ldapsearch -x -H ldap://localhost:1389 \
	    -b "$$(grep ^LDAP_BASE_DN .env 2>/dev/null | cut -d= -f2- || echo dc=sso,dc=local)" \
	    -D "cn=admin,$$(grep ^LDAP_BASE_DN .env 2>/dev/null | cut -d= -f2- || echo dc=sso,dc=local)" \
	    -w "$$(cat secrets/ldap_admin_password.txt 2>/dev/null)" \
	    '(objectClass=organizationalUnit)' dn 2>/dev/null | grep -q '^dn:'; do \
	    sleep 3; \
	done
	@echo "$(GREEN)LDAP is ready.$(RESET)"

.PHONY: postgres-bootstrap
postgres-bootstrap: ## Set sso_app password and copy Vault CA chain into postgres/ssl/
	@echo "$(CYAN)Setting sso_app password...$(RESET)"
	@APP_PW="$$(cat secrets/postgres_app_password.txt 2>/dev/null)"; \
	ADMIN_PW="$$(cat secrets/postgres_admin_password.txt 2>/dev/null)"; \
	if [ -z "$$APP_PW" ]; then \
	    echo "$(RED)secrets/postgres_app_password.txt missing — run make _gen-secrets first$(RESET)"; \
	    exit 1; \
	fi; \
	$(COMPOSE) -p $(PROJECT) exec -T \
	    -e PGPASSWORD="$$ADMIN_PW" \
	    postgres \
	    psql -U "$${POSTGRES_ADMIN_USER:-sso_admin}" -d "$${POSTGRES_DB:-sso}" \
	    -c "ALTER ROLE sso_app PASSWORD '$$APP_PW';"
	@echo "$(CYAN)Copying Vault CA chain to postgres/ssl/...$(RESET)"
	@mkdir -p postgres/ssl
	@if $(COMPOSE) -p $(PROJECT) exec -T vault-agent \
	        test -f /vault/rendered/ca-chain.pem 2>/dev/null; then \
	    $(COMPOSE) -p $(PROJECT) exec -T vault-agent \
	        cat /vault/rendered/ca-chain.pem > postgres/ssl/ca-chain.pem; \
	    echo "$(GREEN)CA chain written to postgres/ssl/ca-chain.pem$(RESET)"; \
	else \
	    echo "$(YELLOW)vault-agent not ready yet; CA chain not copied.$(RESET)"; \
	    echo "$(YELLOW)Re-run 'make postgres-bootstrap' after vault-agent is healthy.$(RESET)"; \
	fi
	@echo "$(GREEN)PostgreSQL bootstrap complete.$(RESET)"

.PHONY: postgres-crl-update
postgres-crl-update: ## Refresh the CRL in postgres/ssl/ from vault-agent rendered output
	@$(COMPOSE) -p $(PROJECT) exec -T vault-agent cat /vault/rendered/crl.pem \
	    > postgres/ssl/crl.pem
	@$(COMPOSE) -p $(PROJECT) exec -T \
	    -e PGPASSWORD="$$(cat secrets/postgres_admin_password.txt 2>/dev/null)" \
	    postgres \
	    psql -U "$${POSTGRES_ADMIN_USER:-sso_admin}" -d "$${POSTGRES_DB:-sso}" \
	    -c "SELECT pg_reload_conf();"
	@echo "$(GREEN)CRL updated and PostgreSQL reloaded.$(RESET)"

# ---------------------------------------------------------------------------
# Certificate rotation
# ---------------------------------------------------------------------------

.PHONY: cert-rotate
cert-rotate: ## Rotate all user x509 certificates via Vault PKI
	@echo "$(CYAN)Triggering certificate rotation...$(RESET)"
	bash vault/scripts/rotate-certs.sh
	@echo "$(GREEN)Certificate rotation complete. Consul Template will push new certs to LDAP.$(RESET)"

.PHONY: cert-rotate-user
cert-rotate-user: ## Rotate a single user's certificate  (USER=<cn> required)
	@[ -n "$(USER)" ] || (echo "$(RED)Usage: make cert-rotate-user USER=alice$(RESET)" && exit 1)
	bash vault/scripts/rotate-certs.sh --user "$(USER)"

.PHONY: cert-push-now
cert-push-now: ## Force an immediate LDAP cert sync (runs the rendered push script directly)
	@echo "$(CYAN)Triggering immediate LDAP cert push...$(RESET)"
	$(COMPOSE) -p $(PROJECT) exec consul-template bash /vault/rendered/ldap-cert-push.sh

.PHONY: cert-status
cert-status: ## Show current certificate expiry for all issued certs
	@VAULT_ADDR=$(VAULT_ADDR) VAULT_TOKEN=$(VAULT_TOKEN) \
	  vault list pki/certs 2>/dev/null | tail -n +3 | while read serial; do \
	    expiry=$$(vault read -format=json pki/cert/$$serial | jq -r '.data.expiration'); \
	    echo "  serial=$$serial  expires=$$(date -d @$$expiry 2>/dev/null || date -r $$expiry)"; \
	  done

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------

.PHONY: test
test: test-unit test-integration ## Run all tests

.PHONY: test-unit
test-unit: ## Run Golang unit tests
	cd app && go test ./... -short -count=1 -race

.PHONY: test-flow
test-flow: ## End-to-end smoke test: JWT issuance → userinfo → sessions → cert issue
	@echo "$(CYAN)Running end-to-end auth flow tests...$(RESET)"
	bash tests/scripts/test-flow.sh
	@echo "$(CYAN)Running Go integration tests against live stack...$(RESET)"
	cd tests && TEST_STACK_RUNNING=1 go test ./integration/ -v -count=1 -timeout 120s

.PHONY: security-test
security-test: ## Run security validation test suite (stack must be running)
	@echo "$(CYAN)Running security validation tests...$(RESET)"
	cd tests && TEST_STACK_RUNNING=1 SP_BASE_URL=https://${SP_HOSTNAME:-sp.sso.local} \
	    go test ./integration/ -v -run TestSecurity -count=1 -timeout 120s

.PHONY: harden
harden: ## Apply post-bootstrap Vault hardening (audit backend, cert TTL, blast-radius checks)
	@echo "$(CYAN)Running Vault security hardening...$(RESET)"
	@TOKEN="$$(cat secrets/vault-root-token.txt 2>/dev/null || echo devroot)"; \
	$(COMPOSE) -p $(PROJECT) exec -T \
	    -e VAULT_ADDR=http://vault:8200 \
	    -e VAULT_TOKEN="$$TOKEN" \
	    -e VAULT_CERT_TTL="$${VAULT_CERT_TTL:-1h}" \
	    -e VAULT_MAX_CERT_TTL="$${VAULT_MAX_CERT_TTL:-4h}" \
	    vault sh /vault/scripts/harden-vault.sh
	@echo "$(GREEN)Vault hardening complete. Review docs/SECURITY.md for next steps.$(RESET)"

.PHONY: security-audit
security-audit: ## Print current security posture: policies, auth methods, cert expiry
	@echo "$(CYAN)── Vault policies ──────────────────────────────────────────$(RESET)"
	@VAULT_ADDR=$(VAULT_ADDR) VAULT_TOKEN=$(VAULT_TOKEN) vault policy list 2>/dev/null \
	    | sed 's/^/  /' || echo "  (vault unreachable)"
	@echo "$(CYAN)── Vault auth methods ──────────────────────────────────────$(RESET)"
	@VAULT_ADDR=$(VAULT_ADDR) VAULT_TOKEN=$(VAULT_TOKEN) vault auth list -format=json 2>/dev/null \
	    | jq -r 'keys[]' | sed 's/^/  /' || echo "  (vault unreachable)"
	@echo "$(CYAN)── Vault audit devices ─────────────────────────────────────$(RESET)"
	@VAULT_ADDR=$(VAULT_ADDR) VAULT_TOKEN=$(VAULT_TOKEN) vault audit list 2>/dev/null \
	    | sed 's/^/  /' || echo "  (none enabled — run: make harden)"
	@echo "$(CYAN)── PKI role TTL ─────────────────────────────────────────────$(RESET)"
	@VAULT_ADDR=$(VAULT_ADDR) VAULT_TOKEN=$(VAULT_TOKEN) \
	    vault read -format=json pki_int/roles/user-cert 2>/dev/null \
	    | jq -r '.data | "  ttl=\(.ttl) max_ttl=\(.max_ttl) key_type=\(.key_type) key_bits=\(.key_bits)"' \
	    || echo "  (role not found)"
	@echo "$(CYAN)── PostgreSQL TLS connections ───────────────────────────────$(RESET)"
	@$(COMPOSE) -p $(PROJECT) exec -T postgres \
	    psql -U "$${POSTGRES_ADMIN_USER:-sso_admin}" -d "$${POSTGRES_DB:-sso}" \
	    -At -c "SELECT count(*) || ' non-TLS connections (want 0)' FROM pg_stat_ssl JOIN pg_stat_activity USING (pid) WHERE ssl IS NOT TRUE AND datname='sso';" \
	    2>/dev/null || echo "  (postgres unreachable)"

.PHONY: test-integration
test-integration: test-ldap-acl test-saml test-mtls ## Run integration tests (stack must be running)

.PHONY: test-saml
test-saml: ## Smoke-test SAML authentication flow
	bash tests/scripts/test-saml.sh

.PHONY: test-mtls
test-mtls: ## Smoke-test mTLS client-certificate authentication to PostgreSQL
	bash tests/scripts/test-mtls.sh

.PHONY: test-ldap-acl
test-ldap-acl: ## Verify LDAP ACL rules (stack must be running)
	@LDAP_HOST=localhost \
	 LDAP_PORT=1389 \
	 LDAP_BASE_DN=$$(grep ^LDAP_BASE_DN .env 2>/dev/null | cut -d= -f2- || echo dc=sso,dc=local) \
	 LDAP_ADMIN_PASSWORD=$$(cat secrets/ldap_admin_password.txt 2>/dev/null) \
	 LDAP_CERT_WRITER_PASSWORD=$$(cat secrets/ldap_cert_writer_password.txt 2>/dev/null) \
	 bash ldap/tests/verify-acl.sh

.PHONY: sp-cert-extract
sp-cert-extract: ## Extract SP signing cert (base64 DER) for saml20-sp-remote.php certData
	@echo "$(CYAN)Extracting SP signing certificate...$(RESET)"
	@$(COMPOSE) -p $(PROJECT) exec -T sp \
	    openssl x509 -in /etc/shibboleth/keys/sp-signing.crt -outform DER \
	    | base64 -w0
	@echo ""
	@echo "$(GREEN)Paste the above string as 'certData' in idp/metadata/saml20-sp-remote.php$(RESET)"
	@echo "$(YELLOW)Then set 'validate.authnrequest' => true and run: docker compose restart idp$(RESET)"

.PHONY: test-jwt
test-jwt: ## Validate a JWT cnf/x5t#S256 round-trip
	@curl -fsk https://localhost/api/token-info \
	  -H "Authorization: Bearer $$(cat secrets/test-jwt.txt 2>/dev/null)" | jq .

# ---------------------------------------------------------------------------
# Development helpers
# ---------------------------------------------------------------------------

.PHONY: shell-%
shell-%: ## Open a shell in a running service  (e.g. make shell-app)
	$(COMPOSE) -p $(PROJECT) exec $* /bin/sh

.PHONY: vault-ui
vault-ui: ## Open Vault UI in the default browser (requires VAULT_TOKEN)
	@echo "Vault UI: $(VAULT_ADDR)/ui"
	@echo "Root token: $(VAULT_TOKEN)"
	@xdg-open $(VAULT_ADDR)/ui 2>/dev/null || open $(VAULT_ADDR)/ui 2>/dev/null || true

.PHONY: lint
lint: ## Run linters (Go vet, golangci-lint)
	cd app && go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 && cd app && golangci-lint run ./... || \
	  echo "$(YELLOW)golangci-lint not found; skipping.$(RESET)"

.PHONY: fmt
fmt: ## Format Go source files
	cd app && gofmt -w .

.PHONY: build
build: ## Build all Docker images (no cache)
	$(COMPOSE) -p $(PROJECT) build --no-cache

.PHONY: pull
pull: ## Pull latest base images
	$(COMPOSE) -p $(PROJECT) pull

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

.PHONY: _check-deps
_check-deps:
	@command -v docker       >/dev/null 2>&1 || (echo "$(RED)docker not found$(RESET)" && exit 1)
	@command -v openssl      >/dev/null 2>&1 || (echo "$(RED)openssl not found$(RESET)" && exit 1)
	@command -v jq           >/dev/null 2>&1 || (echo "$(RED)jq not found$(RESET)" && exit 1)
	@echo "$(GREEN)Dependency check passed.$(RESET)"
