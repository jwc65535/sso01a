// Package integration contains end-to-end tests for the sso01a authentication stack.
//
// These tests require the full Docker Compose stack to be running.
// Set TEST_STACK_RUNNING=1 to enable; omit to skip all tests in CI pipelines
// that don't start the stack.
//
// Run against a live stack:
//
//	TEST_STACK_RUNNING=1 go test ./integration/ -v -run TestAuth -count=1
//
// The tests bypass the Shibboleth SP and call the Go backend directly
// (assumed to be at APP_BACKEND_URL, default http://localhost:8080).
// This simulates what the SP does: set uid/ssoCertThumbprint headers.
package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

func skipUnlessStackRunning(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_STACK_RUNNING") == "" {
		t.Skip("Set TEST_STACK_RUNNING=1 to run integration tests")
	}
}

func backendURL() string {
	if u := os.Getenv("APP_BACKEND_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:8080"
}

func spURL() string {
	if u := os.Getenv("SP_BASE_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	hostname := os.Getenv("SP_HOSTNAME")
	if hostname == "" {
		hostname = "sp.sso.local"
	}
	return "https://" + hostname
}

// insecureClient skips TLS verification — only for dev/self-signed certs.
var insecureClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// directClient calls the backend without TLS.
var directClient = &http.Client{Timeout: 10 * time.Second}

func doJSON(t *testing.T, client *http.Client, method, url string, headers map[string]string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var br io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		br = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, br)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, url, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request %s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp, m
}

// issueTestJWT calls /api/token directly on the backend (bypassing Shibboleth)
// with a fake uid header.  Valid only in dev mode.
func issueTestJWT(t *testing.T, uid string) string {
	t.Helper()
	url := backendURL() + "/api/token"
	resp, body := doJSON(t, directClient, http.MethodPost, url,
		map[string]string{
			"uid":                uid,
			"mail":               uid + "@sso.local",
			"ssoCertThumbprint":  "sha256:test" + fmt.Sprintf("%056d", 0),
			"ssoEnrolledAt":      fmt.Sprintf("%d", time.Now().Unix()),
		},
		map[string]string{"fingerprint": "test-fp-" + uid},
	)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/token status=%d body=%v", resp.StatusCode, body)
	}
	tok, _ := body["token"].(string)
	if tok == "" {
		t.Fatalf("POST /api/token returned no token: %v", body)
	}
	return tok
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestHealthEndpoint(t *testing.T) {
	skipUnlessStackRunning(t)

	resp, body := doJSON(t, directClient, http.MethodGet, backendURL()+"/healthz", nil, nil)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status=%d", resp.StatusCode)
	}
	if status, _ := body["status"].(string); status != "ok" {
		t.Errorf("expected status=ok, got %q (body=%v)", status, body)
	}
	t.Logf("GET /healthz → %v", body)
}

func TestJWKSEndpoint(t *testing.T) {
	skipUnlessStackRunning(t)

	resp, body := doJSON(t, directClient, http.MethodGet,
		backendURL()+"/api/.well-known/jwks.json", nil, nil)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/.well-known/jwks.json status=%d", resp.StatusCode)
	}
	keys, _ := body["keys"].([]any)
	if len(keys) == 0 {
		t.Fatal("JWKS contains no keys")
	}
	key, _ := keys[0].(map[string]any)
	t.Logf("JWKS key: kty=%v, crv=%v, kid=%v", key["kty"], key["crv"], key["kid"])

	if key["kty"] != "EC" {
		t.Errorf("expected kty=EC, got %v", key["kty"])
	}
	if key["crv"] != "P-256" {
		t.Errorf("expected crv=P-256, got %v", key["crv"])
	}
	if key["kid"] == "" || key["kid"] == nil {
		t.Error("kid must be non-empty")
	}
}

func TestTokenIssuanceAndUserInfo(t *testing.T) {
	skipUnlessStackRunning(t)

	uid := "alice"
	jwt := issueTestJWT(t, uid)
	t.Logf("JWT issued for uid=%s (first 40 chars): %s…", uid, jwt[:min(40, len(jwt))])

	// Verify JWT has three segments.
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d segments (want 3)", len(parts))
	}

	// Call /api/userinfo with the JWT.
	resp, body := doJSON(t, directClient, http.MethodGet,
		backendURL()+"/api/userinfo",
		map[string]string{"Authorization": "Bearer " + jwt},
		nil,
	)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/userinfo status=%d body=%v", resp.StatusCode, body)
	}

	t.Logf("userinfo: %v", body)

	if sub, _ := body["uid"].(string); sub != uid {
		t.Errorf("expected uid=%q, got %q", uid, sub)
	}

	// cnf/cert_thumbprint must be present (RFC 7800 proof-of-possession).
	if tp, _ := body["cert_thumbprint"].(string); tp == "" {
		t.Error("cert_thumbprint (cnf claim) missing from userinfo")
	}

	// device_fingerprint must be bound.
	if fp, _ := body["device_fingerprint"].(string); fp == "" {
		t.Error("device_fingerprint missing from userinfo")
	}
}

func TestTokenRequiresCertThumbprint(t *testing.T) {
	skipUnlessStackRunning(t)

	// Token issuance without ssoCertThumbprint must return 403.
	resp, body := doJSON(t, directClient, http.MethodPost,
		backendURL()+"/api/token",
		map[string]string{
			"uid":  "alice",
			"mail": "alice@sso.local",
			// ssoCertThumbprint intentionally absent
		},
		map[string]string{"fingerprint": "test-fp"},
	)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 without cert thumbprint, got %d (body=%v)", resp.StatusCode, body)
	}
	t.Logf("POST /api/token (no thumbprint) → %d %v", resp.StatusCode, body)
}

func TestBearerAuthRequired(t *testing.T) {
	skipUnlessStackRunning(t)

	// /api/userinfo without any auth must return 401.
	resp, body := doJSON(t, directClient, http.MethodGet,
		backendURL()+"/api/userinfo", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d (body=%v)", resp.StatusCode, body)
	}
}

func TestSPHealthViaHTTP(t *testing.T) {
	skipUnlessStackRunning(t)

	// The SP exposes /healthz on port 80 (no HTTPS redirect).
	sp := spURL()
	// Switch to HTTP for the healthz probe.
	httpSP := strings.Replace(sp, "https://", "http://", 1)

	resp, body := doJSON(t, directClient, http.MethodGet, httpSP+"/healthz", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Skipf("SP healthz unreachable at %s (add SP_HOSTNAME to /etc/hosts): %v", httpSP, body)
	}
	if status, _ := body["status"].(string); status != "ok" {
		t.Errorf("SP /healthz status=%q (want ok)", status)
	}
	t.Logf("SP HTTP /healthz → %v", body)
}

func TestSPTokenRequiresShibboleth(t *testing.T) {
	skipUnlessStackRunning(t)

	// POST /api/token through the SP without a Shibboleth session must:
	// - Return 302/303 (redirect to IdP), OR
	// - Return 401 (if the SP returns an error page rather than redirecting).
	// Never 200 — that would mean Shibboleth is not enforcing the guard.
	sp := spURL()

	req, err := http.NewRequest(http.MethodPost, sp+"/api/token",
		strings.NewReader(`{"fingerprint":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Do NOT follow redirects — we want to see the 302.
	c := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Skipf("SP unreachable: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("SP POST /api/token (no session) → %d %s", resp.StatusCode, resp.Header.Get("Location"))

	if resp.StatusCode == http.StatusOK {
		t.Error("SP allowed unauthenticated POST /api/token — Shibboleth guard broken")
	} else {
		t.Logf("Shibboleth guard active: status=%d", resp.StatusCode)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
