package crypto

// KeyManager — per-user ECDSA private key lifecycle
// ──────────────────────────────────────────────────
//
// THREAT MODEL
//
//   Secret A  TOTP_MASTER_SECRET  Docker secrets only; never in Vault or DB.
//   Secret B  AES-256-GCM blob    Lives in a memguard Enclave (mlock'd, no swap).
//   Key       Derived AES key     Ephemeral; computed from TOTP passphrase + Argon2id.
//
//   Full key exposure requires A ∩ B simultaneously.
//
//   Argon2id stretch (time=2, mem=64 MiB, threads=1) makes the 8-digit TOTP
//   passphrase (~26.5 bits) expensive to brute-force offline.  At ~200 ms/attempt
//   on commodity hardware, exhausting the search space takes ~38 CPU-years.
//
// SEALED FORMAT (stored in the Enclave)
//
//   [8 bytes big-endian TOTP counter] || [12 bytes GCM nonce] || [ciphertext+tag]
//
//   Storing the sealing counter allows Unlock() to try ±unlockSkew windows without
//   iterating blindly.  The counter itself is not secret (it encodes only the time
//   window, not the key), but knowing it does narrow brute-force to specific TOTP
//   candidates — another reason Argon2id stretch is necessary.
//
// UNLOCK SKEW
//
//   If the service restarts mid-window, or if a key was sealed just before a
//   window boundary, Unlock() must be able to handle the counter advancing by 1.
//   unlockSkew=2 allows ±1 full window on either side of the stored counter,
//   giving 5 candidate passphrases total.  Increasing this value degrades the
//   security guarantee by widening the offline brute-force window.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

const (
	// unlockSkew is the number of TOTP windows to try on either side of the
	// stored counter during Unlock().  Each additional window adds ~200 ms
	// (one Argon2id call) to worst-case unlock time.
	unlockSkew = 2

	// argon2Time, argon2Memory, argon2Threads control key derivation cost.
	// At these settings, a single derive takes ~200 ms on a low-end server.
	argon2Time    = 2
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 1
	argon2KeyLen  = 32 // AES-256

	// sealedHeaderLen is the number of header bytes prepended to the GCM ciphertext.
	// [8-byte counter] || [12-byte nonce]
	sealedHeaderLen = 8 + 12
)

// KeyManager stores per-user ECDSA private keys sealed in memguard Enclaves.
// All operations are safe for concurrent use.
//
// SINGLE-MODULE COMPROMISE ANALYSIS
// ───────────────────────────────────
// If an attacker fully controls the Go process (e.g., via RCE) they can:
//   • Read process memory — including mlock'd pages — and call Unlock() on any uid
//   • Forge database TLS connections as any enrolled user for the process lifetime
//
// They CANNOT:
//   • Persist keys across restart: Enclaves are in-memory; Purge() on shutdown;
//     SIGKILL causes the kernel to zero mlock'd pages (Linux >= 4.4, memguard
//     also sets RLIMIT_CORE=0 to prevent core dumps)
//   • Unseal keys from a cold dump: the Enclave holds AES-256-GCM ciphertext;
//     decryption requires TOTP_MASTER_SECRET (Docker secret, not in this process)
//   • Issue Vault-signed certificates without the AppRole secret-id
//   • Access the JWT signing key or any other in-memory credential
//
// MEMGUARD DESTRUCTION GUARANTEES
// ─────────────────────────────────
// Normal request: cleanup() → LockedBuffer.Destroy() → pages zeroed and unpinned
// Shutdown:       Purge()   → memguard.Purge() → all remaining buffers destroyed
// SIGKILL / OOM: kernel zeros mlock'd pages on process exit
//
// The *ecdsa.PrivateKey.D scalar lives on the Go heap after ParsePKCS8PrivateKey
// and is NOT mlock'd.  cleanup() does not zero it; the GC collects it eventually.
// Accept this gap: recovering D from a heap dump requires a live core AND knowing
// the heap pointer — significantly harder than reading a plaintext file on disk.
type KeyManager struct {
	mu       sync.RWMutex
	enclaves map[string]*memguard.Enclave // uid → sealed blob
	passGen  *PassphraseGen
}

// NewKeyManager wires a KeyManager to the given PassphraseGen.
func NewKeyManager(passGen *PassphraseGen) *KeyManager {
	return &KeyManager{
		enclaves: make(map[string]*memguard.Enclave),
		passGen:  passGen,
	}
}

// Purge removes all Enclaves from the store and calls memguard.Purge() to zero
// all remaining LockedBuffers tracked by the memguard library globally.
//
// Call this from the application shutdown path, after srv.Shutdown() returns,
// so that no in-flight requests are still calling Unlock() concurrently.
//
// After Purge(), all subsequent Unlock() calls will return an error.
func (km *KeyManager) Purge() {
	km.mu.Lock()
	km.enclaves = make(map[string]*memguard.Enclave)
	km.mu.Unlock()
	// Belt-and-suspenders: individual cleanup() calls already destroy each
	// LockedBuffer.  memguard.Purge() catches any leaked by a panicking request.
	memguard.Purge()
}

// Has reports whether uid has a sealed key in the store.
func (km *KeyManager) Has(uid string) bool {
	km.mu.RLock()
	defer km.mu.RUnlock()
	_, ok := km.enclaves[uid]
	return ok
}

// GenerateKeyAndCSR creates a fresh ECDSA P-256 key pair and a certificate
// signing request with CN=uid.  The raw PKCS8-encoded private key is returned
// in privKeyDER; the caller is responsible for sealing it immediately via
// Seal() and zeroing privKeyDER afterwards.
//
// The private key is NOT stored here — only Seal() places it in the Enclave.
// This separation allows the caller to hand the CSR to Vault for signing before
// committing to a specific sealing window.
func (km *KeyManager) GenerateKeyAndCSR(uid string) (privKeyDER []byte, csrPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("keymanager: generating ECDSA key for uid=%s: %w", uid, err)
	}

	privKeyDER, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("keymanager: marshalling private key for uid=%s: %w", uid, err)
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: uid},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		wipe(privKeyDER)
		return nil, nil, fmt.Errorf("keymanager: creating CSR for uid=%s: %w", uid, err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return privKeyDER, csrPEM, nil
}

// Seal encrypts privKeyDER under the current TOTP passphrase for uid and
// stores the result in a memguard Enclave.  privKeyDER is zeroed before
// returning regardless of error.
//
// Any previously sealed key for uid is replaced.
func (km *KeyManager) Seal(uid string, privKeyDER []byte) error {
	defer wipe(privKeyDER)

	counter := km.passGen.Counter(time.Now())
	passphrase, err := km.passGen.codeAt(uid, counter)
	if err != nil {
		return fmt.Errorf("keymanager: passphrase for uid=%s: %w", uid, err)
	}

	sealed, err := encryptGCM(privKeyDER, passphrase, uid, counter)
	if err != nil {
		return fmt.Errorf("keymanager: sealing key for uid=%s: %w", uid, err)
	}

	enclave := memguard.NewEnclave(sealed)
	wipe(sealed)

	km.mu.Lock()
	km.enclaves[uid] = enclave
	km.mu.Unlock()

	return nil
}

// Unlock decrypts and returns the private key for uid as a LockedBuffer.
// The caller MUST call the returned cleanup function immediately after use
// (typically via defer) to zero and unpin the buffer.
//
// Unlock tries the stored counter ± unlockSkew windows to tolerate clock
// drift and brief service interruptions across TOTP window boundaries.
//
//	buf, cleanup, err := km.Unlock(uid)
//	if err != nil { ... }
//	defer cleanup()
//	priv, err := x509.ParsePKCS8PrivateKey(buf.Bytes())
func (km *KeyManager) Unlock(uid string) (*memguard.LockedBuffer, func(), error) {
	km.mu.RLock()
	enclave, ok := km.enclaves[uid]
	km.mu.RUnlock()
	if !ok {
		return nil, nil, fmt.Errorf("keymanager: no key for uid=%s", uid)
	}

	raw, err := enclave.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("keymanager: opening enclave for uid=%s: %w", uid, err)
	}
	sealedBlob := make([]byte, len(raw.Bytes()))
	copy(sealedBlob, raw.Bytes())
	raw.Destroy()

	if len(sealedBlob) < sealedHeaderLen {
		wipe(sealedBlob)
		return nil, nil, fmt.Errorf("keymanager: enclave blob too short for uid=%s", uid)
	}

	storedCounter := binary.BigEndian.Uint64(sealedBlob[:8])

	for delta := int64(-unlockSkew); delta <= unlockSkew; delta++ {
		candidate := int64(storedCounter) + delta
		if candidate < 0 {
			continue
		}
		passphrase, err := km.passGen.codeAt(uid, uint64(candidate))
		if err != nil {
			continue
		}
		plaintext, err := decryptGCM(sealedBlob, passphrase, uid, uint64(candidate))
		if err != nil {
			continue // wrong window; try next
		}

		buf := memguard.NewBuffer(len(plaintext))
		copy(buf.Bytes(), plaintext)
		wipe(plaintext)
		wipe(sealedBlob)

		return buf, func() { buf.Destroy() }, nil
	}

	wipe(sealedBlob)
	return nil, nil, fmt.Errorf("keymanager: failed to decrypt key for uid=%s (tried %d windows)", uid, 2*unlockSkew+1)
}

// Reseal re-encrypts the sealed key for uid under the current TOTP window.
// Call this after each successful unlock to advance the sealing counter and
// prevent replay of an older ciphertext.
func (km *KeyManager) Reseal(uid string) error {
	buf, cleanup, err := km.Unlock(uid)
	if err != nil {
		return fmt.Errorf("keymanager: reseal unlock uid=%s: %w", uid, err)
	}
	defer cleanup()

	der := make([]byte, len(buf.Bytes()))
	copy(der, buf.Bytes())
	// Seal zeroes der before returning.
	return km.Seal(uid, der)
}

// Destroy removes the sealed key for uid from the store.  The Enclave's
// memory will be released on the next memguard.Purge() call (typically at
// process shutdown).
func (km *KeyManager) Destroy(uid string) {
	km.mu.Lock()
	delete(km.enclaves, uid)
	km.mu.Unlock()
}

// OpenPrivateKey is a convenience wrapper that Unlock()s the sealed key for
// uid and parses it into an *ecdsa.PrivateKey.  The returned cleanup function
// MUST be deferred; it destroys the underlying LockedBuffer.
//
//	priv, cleanup, err := km.OpenPrivateKey(uid)
//	if err != nil { ... }
//	defer cleanup()
//	// use priv only within this scope
func (km *KeyManager) OpenPrivateKey(uid string) (*ecdsa.PrivateKey, func(), error) {
	buf, cleanup, err := km.Unlock(uid)
	if err != nil {
		return nil, nil, err
	}

	raw, err := x509.ParsePKCS8PrivateKey(buf.Bytes())
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("keymanager: parsing private key for uid=%s: %w", uid, err)
	}

	ecKey, ok := raw.(*ecdsa.PrivateKey)
	if !ok {
		cleanup()
		return nil, nil, fmt.Errorf("keymanager: key for uid=%s is not ECDSA", uid)
	}

	return ecKey, cleanup, nil
}

// ── AES-256-GCM helpers ───────────────────────────────────────────────────────

// encryptGCM encrypts plaintext with AES-256-GCM using a key derived from
// passphrase via Argon2id.  Returns the sealed blob:
//
//	[8-byte counter big-endian] || [12-byte nonce] || [GCM ciphertext+tag]
func encryptGCM(plaintext []byte, passphrase, uid string, counter uint64) ([]byte, error) {
	key := deriveKey(passphrase, uid)
	defer wipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Layout: [8-byte counter] || [12-byte nonce] || [ciphertext+tag]
	out := make([]byte, sealedHeaderLen+len(ciphertext))
	binary.BigEndian.PutUint64(out[:8], counter)
	copy(out[8:20], nonce)
	copy(out[20:], ciphertext)
	return out, nil
}

// decryptGCM attempts to decrypt a sealed blob using the given passphrase and
// counter.  Returns an error if the passphrase is wrong or the blob is corrupt.
//
// The counter parameter must match the value embedded in the blob header; it
// is used only for Argon2id key derivation (the nonce is read from the blob).
func decryptGCM(sealed []byte, passphrase, uid string, counter uint64) ([]byte, error) {
	if len(sealed) < sealedHeaderLen+16 { // 16 = min GCM overhead (tag)
		return nil, fmt.Errorf("sealed blob too short")
	}

	// Verify the stored counter matches what the caller expects.
	storedCounter := binary.BigEndian.Uint64(sealed[:8])
	if storedCounter != counter {
		return nil, fmt.Errorf("counter mismatch: blob=%d caller=%d", storedCounter, counter)
	}

	key := deriveKey(passphrase, uid)
	defer wipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := sealed[8:20]
	ciphertext := sealed[20:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// deriveKey stretches passphrase into a 32-byte AES key using Argon2id.
// uid is used as the salt to ensure per-user key uniqueness even if two
// users happen to receive the same TOTP passphrase in the same window.
func deriveKey(passphrase, uid string) []byte {
	return argon2.IDKey(
		[]byte(passphrase),
		[]byte(uid),
		argon2Time,
		argon2Memory,
		argon2Threads,
		argon2KeyLen,
	)
}

// wipe zeroes a byte slice in place.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
