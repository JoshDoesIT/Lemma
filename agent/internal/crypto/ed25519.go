// Package crypto wraps Go's stdlib Ed25519 + PEM/PKIX primitives in the
// shape Lemma's evidence verifier needs: load a SubjectPublicKeyInfo
// PEM, then verify a hex-encoded signature over a hex-encoded entry hash.
//
// Mirrors the verify side of src/lemma/services/crypto.py — sign side is
// not implemented here (the agent only verifies in this slice).
package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadPublicKey decodes a PEM-encoded SubjectPublicKeyInfo block and
// returns the contained Ed25519 public key. Anything else (RSA, ECDSA,
// raw 32-byte unwrapped key, malformed PEM) is rejected with a clear
// error rather than silently coerced.
func LoadPublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("crypto: empty PEM input")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("crypto: no PEM block found")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse PKIX SubjectPublicKeyInfo: %w", err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("crypto: public key is %T, want ed25519.PublicKey", pubAny)
	}
	return pub, nil
}

// LoadPublicKeyByID walks the immediate subdirectories of keysDir
// looking for a file named `<signerKeyID>.public.pem`. Returns the PEM
// bytes when found. The envelope itself does not name the producer
// directory (its storage record's actor is the writer module, not the
// key namespace), so the agent treats keysDir as a flat trust store.
// signer_key_id is a SHA-256 prefix of the public-key bytes, so
// collisions across producers are not a concern in practice.
func LoadPublicKeyByID(keysDir, signerKeyID string) ([]byte, error) {
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, fmt.Errorf("read keys-dir %s: %w", keysDir, err)
	}
	candidate := signerKeyID + ".public.pem"
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(keysDir, e.Name(), candidate)
		data, err := os.ReadFile(path)
		if err == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("public key not found for key_id %s under %s", signerKeyID, keysDir)
}

// VerifyEntryHash reports whether sig (hex) is a valid Ed25519 signature
// over the 32 raw bytes of entryHashHex (also hex), under pub. Returns
// false on any decode error so callers don't have to distinguish
// "malformed input" from "valid input that doesn't verify."
//
// Lemma's signing path signs the 32-byte SHA-256 entry hash directly —
// no second canonicalisation, no double-hashing.
func VerifyEntryHash(pub ed25519.PublicKey, entryHashHex, sigHex string) bool {
	hash, err := hex.DecodeString(entryHashHex)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, hash, sig)
}
