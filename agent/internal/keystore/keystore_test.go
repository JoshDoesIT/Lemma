package keystore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// PKCS#8 PEM matching the public-key fixture used elsewhere
// (seed = bytes(range(32))).
const fixturePrivPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f
-----END PRIVATE KEY-----
`

const fixtureKeyID = "ed25519:56475aa75463474c"

// metaActiveOnly is a minimal real-world meta.json with one ACTIVE
// record. Schema mirrors what `crypto.generate_keypair` writes today.
const metaActiveOnly = `{
  "keys": [
    {
      "key_id": "ed25519:56475aa75463474c",
      "status": "ACTIVE",
      "activated_at": "2026-01-01T00:00:00Z",
      "retired_at": null,
      "revoked_at": null,
      "revoked_reason": "",
      "successor_key_id": ""
    }
  ]
}
`

// metaRotated has one RETIRED key followed by a fresh ACTIVE key — the
// shape Python writes after `crypto.rotate_key`.
const metaRotated = `{
  "keys": [
    {
      "key_id": "ed25519:retired00abcdef00",
      "status": "RETIRED",
      "activated_at": "2025-12-01T00:00:00Z",
      "retired_at": "2026-01-01T00:00:00Z",
      "revoked_at": null,
      "revoked_reason": "",
      "successor_key_id": "ed25519:56475aa75463474c"
    },
    {
      "key_id": "ed25519:56475aa75463474c",
      "status": "ACTIVE",
      "activated_at": "2026-01-01T00:00:00Z",
      "retired_at": null,
      "revoked_at": null,
      "revoked_reason": "",
      "successor_key_id": ""
    }
  ]
}
`

const metaNoActive = `{
  "keys": [
    {
      "key_id": "ed25519:retired00abcdef00",
      "status": "RETIRED",
      "activated_at": "2025-12-01T00:00:00Z",
      "retired_at": "2026-01-01T00:00:00Z",
      "revoked_at": null,
      "revoked_reason": "",
      "successor_key_id": ""
    }
  ]
}
`

// writeKeystore lays out a keys directory the way Python writes one:
//
//	<keysDir>/<producer>/meta.json
//	<keysDir>/<producer>/<key_id>.private.pem
func writeKeystore(t *testing.T, producer, meta, privPEM, keyID string) string {
	t.Helper()
	dir := t.TempDir()
	prodDir := filepath.Join(dir, producer)
	if err := os.MkdirAll(prodDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prodDir, "meta.json"), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
	if privPEM != "" {
		path := filepath.Join(prodDir, keyID+".private.pem")
		if err := os.WriteFile(path, []byte(privPEM), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadActiveReturnsActiveKeyID(t *testing.T) {
	dir := writeKeystore(t, "Lemma", metaActiveOnly, "", "")
	id, err := LoadActive(dir, "Lemma")
	if err != nil {
		t.Fatalf("LoadActive: %v", err)
	}
	if id != fixtureKeyID {
		t.Errorf("LoadActive = %q, want %q", id, fixtureKeyID)
	}
}

func TestLoadActiveAfterRotationReturnsTheNewActiveKey(t *testing.T) {
	dir := writeKeystore(t, "Lemma", metaRotated, "", "")
	id, err := LoadActive(dir, "Lemma")
	if err != nil {
		t.Fatalf("LoadActive: %v", err)
	}
	if id != fixtureKeyID {
		t.Errorf("LoadActive = %q, want the post-rotation ACTIVE key %q",
			id, fixtureKeyID)
	}
}

func TestLoadActiveErrorsWhenNoActiveRecord(t *testing.T) {
	dir := writeKeystore(t, "Lemma", metaNoActive, "", "")
	_, err := LoadActive(dir, "Lemma")
	if err == nil {
		t.Fatal("expected error when no ACTIVE record, got nil")
	}
	if !strings.Contains(err.Error(), "active") &&
		!strings.Contains(err.Error(), "ACTIVE") {
		t.Errorf("error should mention ACTIVE; got %v", err)
	}
}

func TestLoadActiveErrorsWhenMetaMissing(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "Lemma"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := LoadActive(dir, "Lemma")
	if err == nil {
		t.Fatal("expected error when meta.json missing, got nil")
	}
}

func TestLoadActiveErrorsWhenMetaMalformed(t *testing.T) {
	dir := writeKeystore(t, "Lemma", "{not json", "", "")
	if _, err := LoadActive(dir, "Lemma"); err == nil {
		t.Fatal("expected error on malformed meta.json, got nil")
	}
}

func TestLoadPrivateKeyReadsAndParsesPEM(t *testing.T) {
	dir := writeKeystore(t, "Lemma", metaActiveOnly, fixturePrivPEM, fixtureKeyID)
	priv, err := LoadPrivateKey(dir, "Lemma", fixtureKeyID)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if len(priv) != 64 {
		t.Errorf("expected 64-byte Ed25519 private key, got %d", len(priv))
	}
}

func TestLoadPrivateKeyErrorsWhenFileMissing(t *testing.T) {
	dir := writeKeystore(t, "Lemma", metaActiveOnly, "", "") // no PEM
	if _, err := LoadPrivateKey(dir, "Lemma", fixtureKeyID); err == nil {
		t.Fatal("expected error when private PEM missing, got nil")
	}
}
