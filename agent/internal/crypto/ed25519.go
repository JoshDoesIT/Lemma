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
