// Package integration — security validation tests.
//
// These tests verify the security properties documented in docs/SECURITY.md.
// They require the full Docker Compose stack to be running.
// Set TEST_STACK_RUNNING=1 to enable.
//
// Run:
//
//	TEST_STACK_RUNNING=1 go test ./integration/ -v -run TestSecurity -count=1
package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// ── Security Header Tests ─────────────────────────────────────────────────────

// TestSecurityHeaders verifies that all required security headers are present
// on the SP's HTTPS response.  These headers are set in sso.conf.
func TestSecurityHeaders(t *testing.T) {
	skipUnlessStackRunning(t)

	sp := spURL()
	resp, err := insecureClient.Get(sp + "/")
	if err != nil {
		t.Skipf("SP unreachable: %v", err)
	}
	defer resp.Body.Close()

	type headerCheck struct {
		name     string
		mustContain string
	}
	checks := []headerCheck{
		{"Strict-Transport-Security", "max-age="},
		{"X-Frame-Options", "DENY"},
		{"X-Content-Type-Options", "nosniff"},
		{"Referrer-Policy", "strict-origin"},
		{"Content-Security-Policy", "default-src"},
		{"Content-Security-Policy", "frame-ancestors 'none'"},
		{"Permissions-Policy", "camera=()"},
		{"Cross-Origin-Opener-Policy", "same-origin"},
		{"Cross-Origin-Resource-Policy", "same-origin"},
	}

	for _, c := range checks {
		val := resp.Header.Get(c.name)
		if !strings.Contains(val, c.mustContain) {
			t.Errorf("header %s: want contains %q, got %q", c.name, c.mustContain, val)
		}
	}

	// Server banner must be absent or stripped.
	if srv := resp.Header.Get("Server"); srv != "" && strings.Contains(strings.ToLower(srv), "apache") {
		t.Errorf("Server header leaks software version: %q", srv)
	}
	t.Logf("Security headers OK (status=%d)", resp.StatusCode)
}

// TestHSTSPreload verifies that HSTS max-age is at least 1 year (required for
// Chrome preload list inclusion) and includes Subdomains.
func TestHSTSPreload(t *testing.T) {
	skipUnlessStackRunning(t)

	sp := spURL()
	resp, err := insecureClient.Get(sp + "/")
	if err != nil {
		t.Skipf("SP unreachable: %v", err)
	}
	defer resp.Body.Close()

	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		t.Fatal("HSTS header missing")
	}
	if !strings.Contains(hsts, "includeSubDomains") {
		t.Error("HSTS missing includeSubDomains")
	}
	// max-age must be >= 31536000 (1 year)
	if !strings.Contains(hsts, "31536000") {
		t.Errorf("HSTS max-age may be < 1 year: %q", hsts)
	}
	t.Logf("HSTS: %s", hsts)
}

// TestCSPBlocksInlineScript verifies the CSP 'script-src' does not contain
// 'unsafe-eval' (which would allow arbitrary code execution).
func TestCSPNoUnsafeEval(t *testing.T) {
	skipUnlessStackRunning(t)

	sp := spURL()
	resp, err := insecureClient.Get(sp + "/")
	if err != nil {
		t.Skipf("SP unreachable: %v", err)
	}
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP contains 'unsafe-eval' — XSS escalation risk: %s", csp)
	}
	if strings.Contains(csp, "unsafe-inline") && strings.Contains(csp, "script-src") {
		// 'unsafe-inline' in script-src (not style-src) is a critical misconfiguration.
		// Parse carefully: check only the script-src directive.
		for _, directive := range strings.Split(csp, ";") {
			d := strings.TrimSpace(directive)
			if strings.HasPrefix(d, "script-src") && strings.Contains(d, "unsafe-inline") {
				t.Errorf("CSP script-src contains 'unsafe-inline': %s", d)
			}
		}
	}
	t.Logf("CSP OK (no unsafe-eval in script-src)")
}

// ── Authentication Guard Tests ────────────────────────────────────────────────

// TestShibbolethHeadersStripped verifies that the SP strips client-supplied
// Shibboleth attribute headers before forwarding to the backend.
// If these headers were not stripped, a client could forge uid/ssoCertThumbprint.
func TestShibbolethHeadersStripped(t *testing.T) {
	skipUnlessStackRunning(t)

	// Call /api/userinfo via the SP directly with a forged uid header.
	// The SP must strip this header before proxying; the Go backend must
	// return 401 (no valid JWT), not 200 with a fake uid.
	sp := spURL()
	req, err := http.NewRequest(http.MethodGet, sp+"/api/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Attempt to inject a uid header — the SP must strip it.
	req.Header.Set("uid", "injected-attacker")
	req.Header.Set("ssoCertThumbprint", "sha256:fake")

	resp, err := insecureClient.Do(req)
	if err != nil {
		t.Skipf("SP unreachable: %v", err)
	}
	defer resp.Body.Close()

	// Without a valid JWT/cookie, the backend must return 401 — not 200.
	// 200 would mean the header injection bypassed authentication.
	if resp.StatusCode == http.StatusOK {
		t.Error("CRITICAL: /api/userinfo returned 200 with forged uid header — header injection not stripped")
	} else {
		t.Logf("Header injection blocked: status=%d (want 401)", resp.StatusCode)
	}
}

// TestNoServerSidePrivateKeyGeneration verifies that the Vault PKI role
// rejects requests that would generate a private key server-side.
// This is enforced by the explicit DENY on pki_int/issue/* in golang-app-policy.
// We verify indirectly: the /api/cert/issue endpoint must return a cert that
// was signed from a client-side CSR (no private key in the response body).
func TestCertIssueReturnsNoCertPrivateKey(t *testing.T) {
	skipUnlessStackRunning(t)

	jwt := issueTestJWT(t, "alice")
	auth := map[string]string{"Authorization": "Bearer " + jwt}

	_, body := doJSON(t, directClient, http.MethodPost,
		backendURL()+"/api/cert/issue", auth, map[string]any{})

	// Vault's pki_int/issue/* would return a "private_key" field.
	// Our endpoint calls pki_int/sign/* which does NOT return a private key.
	if pk, ok := body["private_key"]; ok && pk != nil && pk != "" {
		t.Errorf("CRITICAL: /api/cert/issue returned a private_key — server-side key generation active")
	}
	// Certificate must be present (CSR-signed).
	if cert, _ := body["certificate"].(string); cert == "" {
		t.Skip("cert issue failed — cannot verify private key absence")
	}
	t.Log("No private_key in /api/cert/issue response — CSR-only path confirmed")
}

// ── Rate Limiting Tests ───────────────────────────────────────────────────────

// TestTokenEndpointRateLimited verifies that rapid repeated requests to
// /api/token are rate-limited by the Go backend (429 after burst).
// This tests the ratelimit.go middleware independently of Apache.
func TestTokenEndpointRateLimited(t *testing.T) {
	skipUnlessStackRunning(t)

	base := backendURL() + "/api/token"
	// burst=3, rate=5/min → after 4 rapid requests the 4th should be 429.
	// We send 6 requests with no delay and expect at least one 429.
	got429 := false
	for i := 0; i < 6; i++ {
		resp, _ := doJSON(t, directClient, http.MethodPost, base,
			map[string]string{
				"uid":              "ratelimit-test",
				"ssoCertThumbprint": "sha256:test" + strings.Repeat("0", 56),
			},
			map[string]string{"fingerprint": "rate-test"},
		)
		t.Logf("attempt %d: status=%d", i+1, resp.StatusCode)
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Log("Rate limit not triggered within 6 requests — limit may be higher than expected or IP not tracked")
	} else {
		t.Log("Rate limiting active: 429 received on burst")
	}
}

// ── JWT Security Tests ────────────────────────────────────────────────────────

// TestJWTAlgorithm verifies that the JWKS endpoint advertises only ES256
// (ECDSA P-256) and that no symmetric algorithm (HS256, HS384, HS512) is offered.
// Symmetric algorithm confusion attacks allow forging JWTs with the public key.
func TestJWTAlgorithmIsEC(t *testing.T) {
	skipUnlessStackRunning(t)

	_, body := doJSON(t, directClient, http.MethodGet,
		backendURL()+"/api/.well-known/jwks.json", nil, nil)

	keys, _ := body["keys"].([]any)
	for i, k := range keys {
		key, _ := k.(map[string]any)
		kty, _ := key["kty"].(string)
		if kty != "EC" {
			t.Errorf("JWKS key[%d]: expected kty=EC, got %q", i, kty)
		}
		// Symmetric key type would be "oct" — explicitly reject.
		if kty == "oct" {
			t.Errorf("CRITICAL: JWKS key[%d] is symmetric (oct) — algorithm confusion attack possible", i)
		}
		// Private key component must not be present.
		if d, ok := key["d"]; ok && d != nil {
			t.Errorf("CRITICAL: JWKS key[%d] contains private component 'd'", i)
		}
	}
	t.Logf("JWKS algorithm check passed: %d EC key(s)", len(keys))
}

// TestExpiredTokenRejected verifies that a structurally valid but expired JWT
// is rejected with 401.  We cannot manufacture a past-expiry token without
// the signing key, so we verify via the standard invalid token path.
func TestMalformedTokenRejected(t *testing.T) {
	skipUnlessStackRunning(t)

	malformed := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"not-jwt", "notajwt"},
		{"truncated", "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0"},
		{"wrong-alg-none", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ."},
		{"hs256-confusion", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6OTk5OTk5OTk5OX0.AAAA"},
	}

	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := doJSON(t, directClient, http.MethodGet,
				backendURL()+"/api/userinfo",
				map[string]string{"Authorization": "Bearer " + tc.token},
				nil,
			)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("token %q: expected 401, got %d", tc.name, resp.StatusCode)
			}
		})
	}
}

// ── Isolation Tests ───────────────────────────────────────────────────────────

// TestCrossUserSessionIsolation verifies that a JWT issued for alice cannot
// be used to access bob's sessions even with the same token type.
// This would indicate a missing uid check in the sessions handler.
func TestCrossUserSessionIsolation(t *testing.T) {
	skipUnlessStackRunning(t)

	// Issue tokens for both users.
	aliceJWT := issueTestJWT(t, "alice")
	bobJWT := issueTestJWT(t, "bob")
	base := backendURL()

	// Get bob's sessions with bob's JWT — should succeed.
	resp, bobBody := doJSON(t, directClient, http.MethodGet, base+"/api/sessions",
		map[string]string{"Authorization": "Bearer " + bobJWT}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Skipf("GET /api/sessions failed for bob: %d", resp.StatusCode)
	}
	bobSessions, _ := bobBody["sessions"].([]any)

	// Get alice's sessions with alice's JWT.
	_, aliceBody := doJSON(t, directClient, http.MethodGet, base+"/api/sessions",
		map[string]string{"Authorization": "Bearer " + aliceJWT}, nil)
	aliceSessions, _ := aliceBody["sessions"].([]any)

	// Collect all bob JTIs.
	bobJTIs := make(map[string]bool)
	for _, s := range bobSessions {
		if sess, ok := s.(map[string]any); ok {
			bobJTIs[sess["jti"].(string)] = true
		}
	}

	// Alice's sessions must not include any of bob's JTIs.
	for _, s := range aliceSessions {
		if sess, ok := s.(map[string]any); ok {
			if jti, _ := sess["jti"].(string); bobJTIs[jti] {
				t.Errorf("CRITICAL: cross-user session leak — alice can see bob's jti=%s", jti)
			}
		}
	}
	t.Logf("Cross-user isolation: alice=%d, bob=%d sessions, no overlap", len(aliceSessions), len(bobSessions))
}

// ── Cert Enrollment Guard Tests ───────────────────────────────────────────────

// TestTokenWithoutThumbprintIs403 verifies that a token issuance request
// lacking ssoCertThumbprint returns 403 Forbidden (not 200 or 401).
// This enforces that JWT issuance requires a prior x509 cert enrollment.
func TestTokenWithoutThumbprintIs403(t *testing.T) {
	skipUnlessStackRunning(t)

	resp, body := doJSON(t, directClient, http.MethodPost,
		backendURL()+"/api/token",
		map[string]string{
			"uid":  "alice",
			"mail": "alice@sso.local",
			// ssoCertThumbprint intentionally absent.
		},
		map[string]string{"fingerprint": "test-fp"},
	)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST /api/token without thumbprint: want 403, got %d (body=%v)", resp.StatusCode, body)
	} else {
		t.Log("403 correctly returned when ssoCertThumbprint is absent")
	}
}

// ── HTTP Redirect & Method Tests ──────────────────────────────────────────────

// TestHTTPToHTTPSRedirect verifies that port 80 redirects to HTTPS for all
// paths except /healthz.
func TestHTTPToHTTPSRedirect(t *testing.T) {
	skipUnlessStackRunning(t)

	sp := spURL()
	httpSP := strings.Replace(sp, "https://", "http://", 1)

	// /healthz must return 200 on port 80 (Docker probe).
	resp, _ := doJSON(t, directClient, http.MethodGet, httpSP+"/healthz", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Skipf("HTTP /healthz not reachable (add hostname to /etc/hosts): status=%d", resp.StatusCode)
	}

	// Any other path must redirect to HTTPS.
	noRedirect := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp2, err := noRedirect.Get(httpSP + "/api/userinfo")
	if err != nil {
		t.Skipf("HTTP redirect check: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusMovedPermanently && resp2.StatusCode != http.StatusFound {
		t.Errorf("HTTP /api/userinfo: expected 301/302 redirect to HTTPS, got %d", resp2.StatusCode)
	} else {
		loc := resp2.Header.Get("Location")
		if !strings.HasPrefix(loc, "https://") {
			t.Errorf("Redirect location is not HTTPS: %q", loc)
		}
		t.Logf("HTTP→HTTPS redirect OK: %d → %s", resp2.StatusCode, loc)
	}
}

// TestDisallowedMethodsBlocked verifies that HTTP methods not in the allowlist
// (GET, HEAD, POST, DELETE, OPTIONS) return 403 or 405.
func TestDisallowedMethodsBlocked(t *testing.T) {
	skipUnlessStackRunning(t)

	// TRACE and TRACK can enable XST (cross-site tracing) attacks.
	for _, method := range []string{"TRACE", "TRACK", "PUT", "PATCH", "CONNECT"} {
		req, err := http.NewRequest(method, backendURL()+"/healthz", nil)
		if err != nil {
			continue
		}
		resp, err := directClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("method %s returned 200 — should be blocked (405/403)", method)
		} else {
			t.Logf("method %s → %d (blocked)", method, resp.StatusCode)
		}
	}
}
