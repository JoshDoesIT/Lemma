// Package keystore reads the on-disk producer key layout Python's
// `crypto.generate_keypair` writes:
//
//	<keysDir>/<producer>/meta.json
//	<keysDir>/<producer>/<key_id>.private.pem
//	<keysDir>/<producer>/<key_id>.public.pem
//
// The agent uses the lifecycle for two things:
//
//   - Sign side: resolve the currently-ACTIVE key id (LoadActive).
//   - Verify side: detect REVOKED keys and apply the same
//     `signed_at >= revoked_at` flip rule Python's
//     EvidenceLog.verify_entry uses (LoadLifecycle + RevokedAt).
//
// Sign-side enforcement (refusing to sign with a non-ACTIVE key) is
// deferred — Python's crypto.sign doesn't enforce it either, so adding
// it here would create a parity gap in the other direction.
package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JoshDoesIT/Lemma/agent/internal/crypto"
)

// LifecycleRecord mirrors src/lemma/services/crypto.py::KeyRecord on
// the wire. Field declaration order matches Python's Pydantic model so
// `json.MarshalIndent` produces meta.json byte-compatible with what
// `_write_lifecycle` writes.
type LifecycleRecord struct {
	KeyID          string     `json:"key_id"`
	Status         string     `json:"status"`
	ActivatedAt    time.Time  `json:"activated_at"`
	RetiredAt      *time.Time `json:"retired_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	RevokedReason  string     `json:"revoked_reason"`
	SuccessorKeyID string     `json:"successor_key_id"`
}

// Lifecycle is the on-disk meta.json shape.
type Lifecycle struct {
	Keys []LifecycleRecord `json:"keys"`
}

// LoadActive returns the ACTIVE key_id from <keysDir>/<producer>/meta.json.
// Errors when the file is missing, malformed, or contains no ACTIVE record.
func LoadActive(keysDir, producer string) (string, error) {
	path := filepath.Join(keysDir, producer, "meta.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("keystore: read %s: %w", path, err)
	}
	var lc Lifecycle
	if err := json.Unmarshal(data, &lc); err != nil {
		return "", fmt.Errorf("keystore: parse %s: %w", path, err)
	}
	for _, rec := range lc.Keys {
		if rec.Status == "ACTIVE" {
			return rec.KeyID, nil
		}
	}
	return "", fmt.Errorf("keystore: no ACTIVE key on file for producer %q in %s",
		producer, keysDir)
}

// LoadLifecycle returns the full lifecycle from <keysDir>/<producer>/meta.json.
// Returns ok=false (no error) when the file does not exist — callers
// treat that as "no local revocation source for this producer," same as
// Python's crypto.read_lifecycle returning an empty lifecycle for an
// unknown producer.
func LoadLifecycle(keysDir, producer string) (Lifecycle, bool, error) {
	path := filepath.Join(keysDir, producer, "meta.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Lifecycle{}, false, nil
		}
		return Lifecycle{}, false, fmt.Errorf("keystore: read %s: %w", path, err)
	}
	var lc Lifecycle
	if err := json.Unmarshal(data, &lc); err != nil {
		return Lifecycle{}, false, fmt.Errorf("keystore: parse %s: %w", path, err)
	}
	return lc, true, nil
}

// RevokedAt looks up keyID in the lifecycle. Returns
// (revokedAt, reason, true) only when the record exists, status is
// REVOKED, and revoked_at is set. Mirrors Python evidence_log.py:313-319
// — RETIRED records do not trigger a revocation, only REVOKED ones do.
func (l Lifecycle) RevokedAt(keyID string) (time.Time, string, bool) {
	for _, rec := range l.Keys {
		if rec.KeyID != keyID {
			continue
		}
		if rec.Status != "REVOKED" {
			return time.Time{}, "", false
		}
		if rec.RevokedAt == nil {
			return time.Time{}, "", false
		}
		return *rec.RevokedAt, rec.RevokedReason, true
	}
	return time.Time{}, "", false
}

// LoadPrivateKey reads <keysDir>/<producer>/<keyID>.private.pem and
// returns the parsed Ed25519 private key.
func LoadPrivateKey(keysDir, producer, keyID string) (ed25519.PrivateKey, error) {
	path := filepath.Join(keysDir, producer, keyID+".private.pem")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keystore: read %s: %w", path, err)
	}
	priv, err := crypto.LoadPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
	}
	if len(priv) == 0 {
		return nil, errors.New("keystore: empty private key after parse")
	}
	return priv, nil
}

// SafeProducer mirrors Python crypto._safe_producer at line 40: replace
// "/" → "_" and " " → "_" so producer names with slashes or spaces
// can't escape the keys directory.
func SafeProducer(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "/", "_"), " ", "_")
}

// GenerateKeypair mints an Ed25519 keypair for producer under keysDir,
// or returns the existing ACTIVE key_id when one is already present
// (idempotent — matches Python crypto.generate_keypair lines 186-211).
//
// Returns the resulting key_id and a `created` flag — true when a fresh
// keypair was minted, false on the idempotent early-return path.
func GenerateKeypair(keysDir, producer string) (keyID string, created bool, err error) {
	producerDir := filepath.Join(keysDir, SafeProducer(producer))
	if err := os.MkdirAll(producerDir, 0o755); err != nil {
		return "", false, fmt.Errorf("keystore: mkdir %s: %w", producerDir, err)
	}

	lc, _, err := LoadLifecycle(keysDir, SafeProducer(producer))
	if err != nil {
		return "", false, err
	}
	for _, rec := range lc.Keys {
		if rec.Status == "ACTIVE" {
			return rec.KeyID, false, nil
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", false, fmt.Errorf("keystore: generate ed25519: %w", err)
	}
	keyID = computeKeyID(pub)

	if err := writeKeypairFiles(producerDir, keyID, priv, pub); err != nil {
		return "", false, err
	}

	// Truncate to microsecond precision so the timestamp matches
	// Pydantic's ISO 8601 output (Python uses microseconds, Go's
	// stdlib would otherwise emit nanoseconds).
	now := time.Now().UTC().Truncate(time.Microsecond)
	lc.Keys = append(lc.Keys, LifecycleRecord{
		KeyID:       keyID,
		Status:      "ACTIVE",
		ActivatedAt: now,
	})
	if err := writeMeta(producerDir, lc); err != nil {
		return "", false, err
	}
	return keyID, true, nil
}

// computeKeyID mirrors Python crypto._compute_key_id_from_public_bytes:
// "ed25519:" + sha256(raw_public).hex()[:16].
func computeKeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(h[:])[:16]
}

// RotateKey retires the producer's current ACTIVE key and mints a fresh
// one. Returns the new ACTIVE key_id. Mirrors Python crypto.rotate_key
// (src/lemma/services/crypto.py:298-327): the prior ACTIVE record gets
// status=RETIRED + retired_at + successor_key_id; a new record is
// appended with status=ACTIVE + activated_at. Errors when no ACTIVE
// record exists (nothing to rotate from).
func RotateKey(keysDir, producer string) (string, error) {
	producerDir := filepath.Join(keysDir, SafeProducer(producer))
	lc, ok, err := LoadLifecycle(keysDir, SafeProducer(producer))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("keystore: no lifecycle on file for producer %q in %s",
			producer, keysDir)
	}

	activeIdx := -1
	for i, rec := range lc.Keys {
		if rec.Status == "ACTIVE" {
			activeIdx = i
			break
		}
	}
	if activeIdx == -1 {
		return "", fmt.Errorf("keystore: no ACTIVE key on file for producer %q in %s — nothing to rotate",
			producer, keysDir)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("keystore: generate ed25519: %w", err)
	}
	newID := computeKeyID(pub)

	if err := writeKeypairFiles(producerDir, newID, priv, pub); err != nil {
		return "", err
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	lc.Keys[activeIdx].Status = "RETIRED"
	lc.Keys[activeIdx].RetiredAt = &now
	lc.Keys[activeIdx].SuccessorKeyID = newID
	lc.Keys = append(lc.Keys, LifecycleRecord{
		KeyID:       newID,
		Status:      "ACTIVE",
		ActivatedAt: now,
	})
	if err := writeMeta(producerDir, lc); err != nil {
		return "", err
	}
	return newID, nil
}

// RevokeKey marks a specific key_id as REVOKED with the supplied reason
// and a current timestamp. Mirrors Python crypto.revoke_key
// (src/lemma/services/crypto.py:439-456). Errors on empty reason,
// missing producer, or unknown key_id.
func RevokeKey(keysDir, producer, keyID, reason string) (LifecycleRecord, error) {
	if reason == "" {
		return LifecycleRecord{}, errors.New("keystore: revoke_key requires a non-empty reason")
	}
	producerDir := filepath.Join(keysDir, SafeProducer(producer))
	lc, ok, err := LoadLifecycle(keysDir, SafeProducer(producer))
	if err != nil {
		return LifecycleRecord{}, err
	}
	if !ok {
		return LifecycleRecord{}, fmt.Errorf("keystore: no lifecycle on file for producer %q in %s",
			producer, keysDir)
	}

	idx := -1
	for i, rec := range lc.Keys {
		if rec.KeyID == keyID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return LifecycleRecord{}, fmt.Errorf("keystore: key %q not found in lifecycle for producer %q",
			keyID, producer)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	lc.Keys[idx].Status = "REVOKED"
	lc.Keys[idx].RevokedAt = &now
	lc.Keys[idx].RevokedReason = reason
	if err := writeMeta(producerDir, lc); err != nil {
		return LifecycleRecord{}, err
	}
	return lc.Keys[idx], nil
}

func writeKeypairFiles(producerDir, keyID string, priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	privPEM, err := encodePrivatePKCS8(priv)
	if err != nil {
		return err
	}
	pubPEM, err := encodePublicPKIX(pub)
	if err != nil {
		return err
	}
	privPath := filepath.Join(producerDir, keyID+".private.pem")
	pubPath := filepath.Join(producerDir, keyID+".public.pem")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return fmt.Errorf("keystore: write private PEM: %w", err)
	}
	if err := os.Chmod(privPath, 0o600); err != nil {
		return fmt.Errorf("keystore: chmod private PEM: %w", err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		return fmt.Errorf("keystore: write public PEM: %w", err)
	}
	return nil
}

func writeMeta(producerDir string, lc Lifecycle) error {
	metaBytes, err := json.MarshalIndent(lc, "", "  ")
	if err != nil {
		return fmt.Errorf("keystore: marshal meta: %w", err)
	}
	metaPath := filepath.Join(producerDir, "meta.json")
	if err := os.WriteFile(metaPath, metaBytes, 0o644); err != nil {
		return fmt.Errorf("keystore: write meta.json: %w", err)
	}
	return nil
}

func encodePrivatePKCS8(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("keystore: marshal PKCS#8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func encodePublicPKIX(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("keystore: marshal PKIX: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
