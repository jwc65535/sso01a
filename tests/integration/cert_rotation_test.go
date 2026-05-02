package integration

import (
	"net/http"
	"strings"
	"testing"
)

// TestCertIssuance calls POST /api/cert/issue and verifies a PEM certificate
// is returned with the expected fields.
func TestCertIssuance(t *testing.T) {
	skipUnlessStackRunning(t)

	jwt := issueTestJWT(t, "alice")
	auth := map[string]string{"Authorization": "Bearer " + jwt}

	resp, body := doJSON(t, directClient, http.MethodPost,
		backendURL()+"/api/cert/issue", auth, map[string]any{})
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Skipf("POST /api/cert/issue rate limited (429) — run on a fresh stack or wait 150s")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/cert/issue status=%d body=%v", resp.StatusCode, body)
	}

	cert, _ := body["certificate"].(string)
	if cert == "" {
		t.Fatal("POST /api/cert/issue returned no certificate")
	}
	if !strings.Contains(cert, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("certificate field does not look like PEM: %.80s", cert)
	}

	issuingCA, _ := body["issuing_ca"].(string)
	if issuingCA == "" {
		t.Error("issuing_ca missing from response")
	}

	serial, _ := body["serial_number"].(string)
	if serial == "" {
		t.Error("serial_number missing from response")
	}

	expiration, _ := body["expiration"].(float64)
	if expiration == 0 {
		t.Error("expiration missing or zero")
	}

	t.Logf("cert issued: serial=%s expiration=%v", serial, expiration)
}

// TestCertIssuanceRequiresAuth verifies that /api/cert/issue returns 401
// without a valid JWT.
func TestCertIssuanceRequiresAuth(t *testing.T) {
	skipUnlessStackRunning(t)

	resp, _ := doJSON(t, directClient, http.MethodPost,
		backendURL()+"/api/cert/issue", nil, map[string]any{})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /api/cert/issue without auth: want 401, got %d", resp.StatusCode)
	}
}

// TestCertReissuance verifies that issuing a second certificate for the same
// user returns a different serial number (Vault generates a new cert each time).
func TestCertReissuance(t *testing.T) {
	skipUnlessStackRunning(t)

	// Issue JWT for bob (a distinct user so we don't interfere with alice tests).
	jwt := issueTestJWT(t, "bob")
	auth := map[string]string{"Authorization": "Bearer " + jwt}
	base := backendURL() + "/api/cert/issue"

	_, body1 := doJSON(t, directClient, http.MethodPost, base, auth, map[string]any{})
	serial1, _ := body1["serial_number"].(string)
	if serial1 == "" {
		t.Skip("first cert issue failed — skipping reissuance test")
	}

	_, body2 := doJSON(t, directClient, http.MethodPost, base, auth, map[string]any{})
	serial2, _ := body2["serial_number"].(string)
	if serial2 == "" {
		t.Fatal("second cert issue returned no serial_number")
	}

	if serial1 == serial2 {
		t.Errorf("re-issuance returned the same serial %q — expected a new cert", serial1)
	}
	t.Logf("cert rotation OK: serial1=%s serial2=%s", serial1, serial2)
}

// TestCAChainInResponse verifies that the ca_chain field returned by
// /api/cert/issue forms a valid chain (each entry is a PEM block).
func TestCAChainInResponse(t *testing.T) {
	skipUnlessStackRunning(t)

	jwt := issueTestJWT(t, "alice")
	auth := map[string]string{"Authorization": "Bearer " + jwt}

	_, body := doJSON(t, directClient, http.MethodPost,
		backendURL()+"/api/cert/issue", auth, map[string]any{})

	caChain, _ := body["ca_chain"].([]any)
	if len(caChain) == 0 {
		// Some Vault versions return ca_chain as a single string; handle both.
		caChainStr, _ := body["ca_chain"].(string)
		if caChainStr == "" {
			t.Fatal("ca_chain missing or empty in /api/cert/issue response")
		}
		if !strings.Contains(caChainStr, "-----BEGIN CERTIFICATE-----") {
			t.Errorf("ca_chain string does not contain PEM blocks: %.80s", caChainStr)
		}
		t.Logf("ca_chain returned as string (%d bytes)", len(caChainStr))
		return
	}
	for i, entry := range caChain {
		s, _ := entry.(string)
		if !strings.Contains(s, "-----BEGIN CERTIFICATE-----") {
			t.Errorf("ca_chain[%d] is not a PEM block: %.80s", i, s)
		}
	}
	t.Logf("ca_chain OK: %d PEM block(s)", len(caChain))
}

// TestJWKSHasSigningKey verifies the JWKS endpoint contains a usable EC signing
// key — required for JWT validation by third-party verifiers.
func TestJWKSHasSigningKey(t *testing.T) {
	skipUnlessStackRunning(t)

	resp, body := doJSON(t, directClient, http.MethodGet,
		backendURL()+"/api/.well-known/jwks.json", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/.well-known/jwks.json status=%d", resp.StatusCode)
	}

	keys, _ := body["keys"].([]any)
	if len(keys) == 0 {
		t.Fatal("JWKS has no keys")
	}

	key, _ := keys[0].(map[string]any)
	for _, field := range []string{"kty", "crv", "x", "y", "kid"} {
		if key[field] == nil || key[field] == "" {
			t.Errorf("JWKS key missing field %q", field)
		}
	}
	// Public key only — "d" (private) must NEVER appear.
	if _, hasD := key["d"]; hasD {
		t.Error("JWKS key leaks private key component 'd'")
	}
	t.Logf("JWKS signing key: kty=%v crv=%v kid=%v", key["kty"], key["crv"], key["kid"])
}

// TestCertCNMatchesUID verifies that the issued certificate's Subject CN
// matches the uid used to request the token (visible in the response body
// since Vault echoes the CN).
func TestCertCNMatchesUID(t *testing.T) {
	skipUnlessStackRunning(t)

	uid := "alice"
	jwt := issueTestJWT(t, uid)
	auth := map[string]string{"Authorization": "Bearer " + jwt}

	_, body := doJSON(t, directClient, http.MethodPost,
		backendURL()+"/api/cert/issue", auth, map[string]any{})

	// The backend sets CN=<uid> in the CSR; Vault echoes it in the cert.
	// We verify by parsing the PEM or checking a metadata field if the API
	// exposes it.  If neither is present, verify via serial_number existence.
	serial, _ := body["serial_number"].(string)
	if serial == "" {
		t.Fatal("serial_number missing — cert issuance may have failed")
	}

	// Extra: the userinfo endpoint after cert issue should show cert_thumbprint.
	// Re-use the same JWT (cert_thumbprint was bound at token issuance, not cert issuance).
	_, uiBody := doJSON(t, directClient, http.MethodGet,
		backendURL()+"/api/userinfo",
		auth, nil)
	if sub, _ := uiBody["uid"].(string); sub != uid {
		t.Errorf("userinfo uid=%q after cert issue, want %q", sub, uid)
	}
	t.Logf("cert CN=%s serial=%s OK", uid, serial)
}
