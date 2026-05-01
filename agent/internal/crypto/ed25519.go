// Package crypto wraps Go's stdlib Ed25519 + PEM/PKIX primitives in the
// shape Lemma's evidence verifier and signer need: load PEM public and
// private keys, sign and verify hex-encoded signatures over hex-encoded
// entry hashes.
//
// Mirrors src/lemma/services/crypto.py.
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

// LoadPrivateKey decodes a PKCS#8 PEM block and returns the contained
// Ed25519 private key. Anything else (RSA, ECDSA, encrypted, raw seed
// PEM, malformed) is rejected with a clear error rather than coerced.
//
// Mirrors Python's `serialization.load_pem_private_key(pem, password=None)`
// path used by `crypto._load_private_by_key_id` in
// `src/lemma/services/crypto.py`.
func LoadPrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("crypto: empty PEM input")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("crypto: no PEM block found")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse PKCS#8 private key: %w", err)
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("crypto: private key is %T, want ed25519.PrivateKey", privAny)
	}
	return priv, nil
}

// SignEntryHash signs the 32 raw bytes of entryHashHex with priv and
// returns the lowercase-hex signature (128 chars). Empty string on
// hex-decode failure — callers should validate the entry hash shape
// before calling.
func SignEntryHash(priv ed25519.PrivateKey, entryHashHex string) string {
	hash, err := hex.DecodeString(entryHashHex)
	if err != nil {
		return ""
	}
	sig := ed25519.Sign(priv, hash)
	return hex.EncodeToString(sig)
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
