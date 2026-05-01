// Package keystore reads the on-disk producer key layout Python's
// `crypto.generate_keypair` writes:
//
//	<keysDir>/<producer>/meta.json
//	<keysDir>/<producer>/<key_id>.private.pem
//	<keysDir>/<producer>/<key_id>.public.pem
//
// In this slice the agent only resolves the currently-ACTIVE key for
// signing. Full ACTIVE/RETIRED/REVOKED enforcement (refusing to sign
// with a non-ACTIVE key, etc.) is deferred to a later #25 slice.
package keystore

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/JoshDoesIT/Lemma/agent/internal/crypto"
)

// LifecycleRecord mirrors src/lemma/services/crypto.py::KeyRecord on the wire.
type LifecycleRecord struct {
	KeyID  string `json:"key_id"`
	Status string `json:"status"`
	// Other fields (activated_at, retired_at, revoked_at, revoked_reason,
	// successor_key_id) are not needed for the sign path; they're left
	// unparsed so future schema additions don't break the agent.
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
