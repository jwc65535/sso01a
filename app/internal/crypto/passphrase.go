package crypto

// SEPARATION OF DUTIES — the three secrets
// ─────────────────────────────────────────
//
//  Secret A — Master secret (TOTP_MASTER_SECRET env / Docker secret)
//    • Lives ONLY in Docker secrets.  NOT in Vault, NOT in PostgreSQL, NOT in LDAP.
//    • Used to derive a deterministic per-user TOTP seed (HMAC-SHA256).
//    • If A alone is compromised: attacker knows per-user TOTP seeds but has no
//      private key ciphertext (keys live only in memguard Enclaves, not on disk).
//
//  Secret B — Encrypted private key ciphertext (memguard Enclave)
//    • Lives ONLY in process memory, on mlock'd non-swappable pages.
//    • The AES-256-GCM key is derived from the current TOTP passphrase — it
//      changes every period seconds and is never written anywhere.
//    • If B alone is compromised (e.g. RAM dump): attacker gets AES ciphertext
//      but not the decryption key (no masterSecret → no TOTP seed → no AES key).
//
//  Compromise requires A ∩ B simultaneously — neither alone suffices.
//
// TIME-BASED ROTATION
// ────────────────────
// The passphrase changes every period (default 30) seconds.  The Argon2id-
// derived AES key changes with it.  An attacker who later obtains the
// ciphertext cannot decrypt it without knowing BOTH the masterSecret AND the
// exact TOTP window at which the key was sealed.  The stored counter (in the
// Enclave header) reveals the window, so this protection is meaningful only if
// the masterSecret is not also compromised.
//
// The unlockSkew in keymanager.go controls the usability ↔ security tradeoff:
// a larger skew makes keys usable for longer but widens the brute-force window
// when both A and B are simultaneously compromised.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// PassphraseGen generates per-user time-based passphrases for private-key
// encryption.  The per-user TOTP seed is derived deterministically from
// masterSecret — no per-user state needs to be persisted.
type PassphraseGen struct {
	masterSecret []byte
	algorithm    otp.Algorithm
	digits       otp.Digits
	period       uint
}

// NewPassphraseGen constructs a generator.  Call with values from TOTP_* env vars:
//   masterSecret — TOTP_MASTER_SECRET (must be non-empty, 32+ chars recommended)
//   algorithm    — otp.AlgorithmSHA256  (TOTP_ALGORITHM=SHA256)
//   digits       — otp.DigitsEight      (TOTP_DIGITS=8)
//   period       — 30                   (TOTP_PERIOD=30)
func NewPassphraseGen(masterSecret string, algorithm otp.Algorithm, digits otp.Digits, period uint) *PassphraseGen {
	return &PassphraseGen{
		masterSecret: []byte(masterSecret),
		algorithm:    algorithm,
		digits:       digits,
		period:       period,
	}
}

// ForUser returns the current TOTP passphrase for uid.
// Changes every period seconds.
func (g *PassphraseGen) ForUser(uid string) (string, error) {
	return g.codeAt(uid, g.Counter(time.Now()))
}

// ValidateForUser checks whether code is a valid current passphrase for uid.
// Accepts the current and one adjacent window (Skew=1) to tolerate clock drift.
func (g *PassphraseGen) ValidateForUser(uid, code string) (bool, error) {
	return totp.ValidateCustom(code, g.userSecret(uid), time.Now(), totp.ValidateOpts{
		Period:    g.period,
		Skew:      1,
		Digits:    g.digits,
		Algorithm: g.algorithm,
	})
}

// Counter returns floor(t.Unix() / period) — the TOTP window index for time t.
func (g *PassphraseGen) Counter(t time.Time) uint64 {
	return uint64(t.Unix()) / uint64(g.period)
}

// Period returns the configured TOTP window size in seconds.
func (g *PassphraseGen) Period() uint { return g.period }

// ── package-private: used by KeyManager in keymanager.go ─────────────────────

// userSecret derives the per-user TOTP secret from the master secret:
//   HMAC-SHA256(masterSecret, uid) → base32 (no padding)
// Output is 256-bit — far above the RFC 6238 recommended minimum.
// The derivation is deterministic: no per-user secret storage is needed.
func (g *PassphraseGen) userSecret(uid string) string {
	mac := hmac.New(sha256.New, g.masterSecret)
	mac.Write([]byte(uid))
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac.Sum(nil))
}

// codeAt returns the TOTP passphrase for uid at the given counter value.
// Used by KeyManager.Unlock to try multiple windows during drift recovery.
func (g *PassphraseGen) codeAt(uid string, counter uint64) (string, error) {
	// Reconstruct an equivalent time: start of the window = counter × period.
	windowStart := time.Unix(int64(counter*uint64(g.period)), 0)
	code, err := totp.GenerateCodeCustom(g.userSecret(uid), windowStart, totp.ValidateOpts{
		Period:    g.period,
		Digits:    g.digits,
		Algorithm: g.algorithm,
	})
	if err != nil {
		return "", fmt.Errorf("TOTP for uid=%s counter=%d: %w", uid, counter, err)
	}
	return code, nil
}
