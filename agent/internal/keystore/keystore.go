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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/JoshDoesIT/Lemma/agent/internal/crypto"
)

// LifecycleRecord mirrors src/lemma/services/crypto.py::KeyRecord on
// the wire. Only the fields the verify+sign paths read are parsed here;
// everything else (activated_at, retired_at, successor_key_id) is
// ignored so future schema additions don't break the agent.
type LifecycleRecord struct {
	KeyID         string     `json:"key_id"`
	Status        string     `json:"status"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedReason string     `json:"revoked_reason,omitempty"`
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
