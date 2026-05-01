#!/bin/sh
# consul-template/scripts/entrypoint.sh
#
# Starts consul-template and sends SIGHUP every 30 minutes to force a
# re-render even when Vault's PKI lease TTL events don't fire.
#
# Why SIGHUP?
#   consul-template reacts to lease changes from Vault automatically, but it
#   won't re-query an already-live lease until it expires.  In our PKI setup,
#   the cert list lease can live for hours.  A periodic SIGHUP forces a full
#   dependency re-evaluation so LDAP stays in sync within ≤30 minutes of any
#   cert change, without relying solely on Vault eventing.
#
# Signal forwarding:
#   SIGTERM / SIGINT are forwarded to consul-template for clean shutdown.
#   The periodic SIGHUP subshell exits automatically when consul-template dies.
set -e

# Start consul-template with all arguments passed to this entrypoint.
consul-template "$@" &
CT_PID=$!

# Forward SIGTERM/SIGINT to consul-template so `docker stop` / Ctrl-C work.
trap 'kill -TERM "${CT_PID}" 2>/dev/null' TERM INT

# Periodic re-render loop runs in a background subshell.
# It exits automatically when consul-template's PID disappears.
(
    while kill -0 "${CT_PID}" 2>/dev/null; do
        sleep 1800
        if kill -0 "${CT_PID}" 2>/dev/null; then
            kill -HUP "${CT_PID}" 2>/dev/null || true
            printf '[entrypoint] Sent SIGHUP to consul-template (pid=%s) — 30-min sync.\n' \
                "${CT_PID}"
        fi
    done
) &

# Wait for consul-template to exit and propagate its exit code.
wait "${CT_PID}"
