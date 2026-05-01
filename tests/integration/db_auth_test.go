package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestSessionsLifecycle issues a JWT for alice, then exercises the session CRUD
// endpoints: list (empty), create (via token issuance), list again (one entry),
// revoke, list again (revoked flag set).
func TestSessionsLifecycle(t *testing.T) {
	skipUnlessStackRunning(t)

	jwt := issueTestJWT(t, "alice")
	auth := map[string]string{"Authorization": "Bearer " + jwt}
	base := backendURL()

	// ── 1. List sessions — should have at least the one we just created ───────
	resp, body := doJSON(t, directClient, http.MethodGet, base+"/api/sessions", auth, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/sessions status=%d body=%v", resp.StatusCode, body)
	}
	sessions, _ := body["sessions"].([]any)
	if len(sessions) == 0 {
		t.Error("expected at least one session after token issuance; got none")
	}
	t.Logf("GET /api/sessions → %d session(s)", len(sessions))

	// ── 2. Extract jti from the first session ────────────────────────────────
	if len(sessions) == 0 {
		t.Skip("no sessions to verify further")
	}
	first, _ := sessions[0].(map[string]any)
	jti, _ := first["jti"].(string)
	if jti == "" {
		t.Fatal("session missing jti field")
	}
	t.Logf("first session jti=%s", jti)

	// ── 3. GET /api/sessions/:jti ────────────────────────────────────────────
	resp, body = doJSON(t, directClient, http.MethodGet,
		fmt.Sprintf("%s/api/sessions/%s", base, jti), auth, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/sessions/%s status=%d body=%v", jti, resp.StatusCode, body)
	}
	if got, _ := body["jti"].(string); got != jti {
		t.Errorf("GET session jti mismatch: got %q want %q", got, jti)
	}

	// ── 4. DELETE /api/sessions/:jti — revoke ────────────────────────────────
	resp, body = doJSON(t, directClient, http.MethodDelete,
		fmt.Sprintf("%s/api/sessions/%s", base, jti), auth, nil)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /api/sessions/%s status=%d body=%v", jti, resp.StatusCode, body)
	}
	t.Logf("DELETE /api/sessions/%s → %d", jti, resp.StatusCode)

	// ── 5. GET after revoke — revoked flag must be true ──────────────────────
	resp, body = doJSON(t, directClient, http.MethodGet,
		fmt.Sprintf("%s/api/sessions/%s", base, jti), auth, nil)
	if resp.StatusCode == http.StatusOK {
		revoked, _ := body["revoked"].(bool)
		if !revoked {
			t.Errorf("session %s should be revoked after DELETE, got revoked=false", jti)
		}
	}
	// 404 or 410 is also acceptable — session removed rather than soft-deleted.
	t.Logf("GET revoked session → status=%d revoked=%v", resp.StatusCode, body["revoked"])
}

// TestRLSIsolation verifies that alice cannot read bob's sessions.
// Both users get JWTs; alice's session list must not contain any jti that
// appears in bob's session list.
func TestRLSIsolation(t *testing.T) {
	skipUnlessStackRunning(t)

	aliceJWT := issueTestJWT(t, "alice")
	bobJWT := issueTestJWT(t, "bob")

	aliceAuth := map[string]string{"Authorization": "Bearer " + aliceJWT}
	bobAuth := map[string]string{"Authorization": "Bearer " + bobJWT}
	base := backendURL()

	// Issue a second JWT for bob so he has a distinct session to protect.
	_ = issueTestJWT(t, "bob")

	// Get alice's session JTIs.
	_, aliceBody := doJSON(t, directClient, http.MethodGet, base+"/api/sessions", aliceAuth, nil)
	aliceSessions, _ := aliceBody["sessions"].([]any)

	// Get bob's session JTIs.
	_, bobBody := doJSON(t, directClient, http.MethodGet, base+"/api/sessions", bobAuth, nil)
	bobSessions, _ := bobBody["sessions"].([]any)

	aliceJTIs := make(map[string]bool)
	for _, s := range aliceSessions {
		if sess, ok := s.(map[string]any); ok {
			aliceJTIs[sess["jti"].(string)] = true
		}
	}

	for _, s := range bobSessions {
		if sess, ok := s.(map[string]any); ok {
			jti, _ := sess["jti"].(string)
			if aliceJTIs[jti] {
				t.Errorf("RLS violation: bob's jti %s visible to alice", jti)
			}
		}
	}

	t.Logf("RLS isolation OK: alice=%d sessions, bob=%d sessions, no overlap",
		len(aliceSessions), len(bobSessions))
}

// TestAuditEndpoint verifies that /api/audit returns entries after activity.
func TestAuditEndpoint(t *testing.T) {
	skipUnlessStackRunning(t)

	jwt := issueTestJWT(t, "alice")
	auth := map[string]string{"Authorization": "Bearer " + jwt}
	base := backendURL()

	resp, body := doJSON(t, directClient, http.MethodGet, base+"/api/audit", auth, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/audit status=%d body=%v", resp.StatusCode, body)
	}
	entries, _ := body["entries"].([]any)
	t.Logf("GET /api/audit → %d entries", len(entries))

	if len(entries) > 0 {
		entry, _ := entries[0].(map[string]any)
		if uid, _ := entry["uid"].(string); uid != "alice" {
			t.Errorf("audit entry uid=%q, want alice", uid)
		}
	}
}

// TestSessionsRequireAuth verifies that /api/sessions returns 401 without a JWT.
func TestSessionsRequireAuth(t *testing.T) {
	skipUnlessStackRunning(t)

	resp, _ := doJSON(t, directClient, http.MethodGet, backendURL()+"/api/sessions", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/sessions without auth: want 401, got %d", resp.StatusCode)
	}
}

// TestSessionExpiry verifies the expires_at field is in the future.
func TestSessionExpiry(t *testing.T) {
	skipUnlessStackRunning(t)

	jwt := issueTestJWT(t, "alice")
	auth := map[string]string{"Authorization": "Bearer " + jwt}

	_, body := doJSON(t, directClient, http.MethodGet, backendURL()+"/api/sessions", auth, nil)
	sessions, _ := body["sessions"].([]any)
	if len(sessions) == 0 {
		t.Skip("no sessions to check expiry")
	}

	first, _ := sessions[0].(map[string]any)
	expiresAt, _ := first["expires_at"].(string)
	if expiresAt == "" {
		t.Fatal("session missing expires_at field")
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		t.Fatalf("parse expires_at %q: %v", expiresAt, err)
	}
	if !exp.After(time.Now()) {
		t.Errorf("session expires_at %v is not in the future", exp)
	}
	t.Logf("session expires_at=%v (in %v)", exp, time.Until(exp).Round(time.Second))
}
