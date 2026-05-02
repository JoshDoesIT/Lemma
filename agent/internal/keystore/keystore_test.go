package keystore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoshDoesIT/Lemma/agent/internal/crypto"
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

// metaRevoked carries one REVOKED record for the fixture key. revoked_at
// uses the +00:00 form Python's datetime.isoformat() emits.
const metaRevoked = `{
  "keys": [
    {
      "key_id": "ed25519:56475aa75463474c",
      "status": "REVOKED",
      "activated_at": "2025-12-01T00:00:00+00:00",
      "retired_at": null,
      "revoked_at": "2026-01-15T12:00:00+00:00",
      "revoked_reason": "key compromise",
      "successor_key_id": ""
    }
  ]
}
`

// metaRevokedZSuffix is the same as metaRevoked but with Z-suffix
// timestamps (some toolchains write that variant).
const metaRevokedZSuffix = `{
  "keys": [
    {
      "key_id": "ed25519:56475aa75463474c",
      "status": "REVOKED",
      "activated_at": "2025-12-01T00:00:00Z",
      "retired_at": null,
      "revoked_at": "2026-01-15T12:00:00Z",
      "revoked_reason": "rotated",
      "successor_key_id": ""
    }
  ]
}
`

// metaRevokedNullTimestamp documents a defensive case: a record marked
// REVOKED without a revoked_at timestamp. RevokedAt() must return false.
const metaRevokedNullTimestamp = `{
  "keys": [
    {
      "key_id": "ed25519:56475aa75463474c",
      "status": "REVOKED",
      "activated_at": "2025-12-01T00:00:00Z",
      "retired_at": null,
      "revoked_at": null,
      "revoked_reason": "missing timestamp",
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

// LoadLifecycle + RevokedAt tests --------------------------------------

func TestLoadLifecycleReturnsPopulatedRecords(t *testing.T) {
	dir := writeKeystore(t, "Lemma", metaRevoked, "", "")
	lc, ok, err := LoadLifecycle(dir, "Lemma")
	if err != nil {
		t.Fatalf("LoadLifecycle: %v", err)
	}
	if !ok {
		t.Fatal("LoadLifecycle ok=false for an existing meta.json")
	}
	if len(lc.Keys) != 1 {
		t.Fatalf("expected 1 record, got %d", len(lc.Keys))
	}
	if lc.Keys[0].Status != "REVOKED" {
		t.Errorf("Status = %q, want REVOKED", lc.Keys[0].Status)
	}
	if lc.Keys[0].RevokedAt == nil {
		t.Error("RevokedAt is nil for a REVOKED record")
	}
}

func TestLoadLifecycleReturnsNotOkWhenFileMissing(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "Lemma"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, ok, err := LoadLifecycle(dir, "Lemma")
	if err != nil {
		t.Fatalf("LoadLifecycle should not error on missing file, got %v", err)
	}
	if ok {
		t.Error("ok=true for a missing meta.json")
	}
}

func TestLoadLifecycleErrorsOnMalformedJSON(t *testing.T) {
	dir := writeKeystore(t, "Lemma", "{not json", "", "")
	_, _, err := LoadLifecycle(dir, "Lemma")
	if err == nil {
		t.Fatal("expected error on malformed meta.json, got nil")
	}
}

func TestRevokedAtReturnsTrueForRevokedKey(t *testing.T) {
	dir := writeKeystore(t, "Lemma", metaRevoked, "", "")
	lc, _, _ := LoadLifecycle(dir, "Lemma")
	ts, reason, ok := lc.RevokedAt(fixtureKeyID)
	if !ok {
		t.Fatal("RevokedAt returned ok=false for a REVOKED record")
	}
	if reason != "key compromise" {
		t.Errorf("reason = %q, want %q", reason, "key compromise")
	}
	// 2026-01-15T12:00:00 UTC.
	if ts.UTC().Year() != 2026 || ts.UTC().Month() != 1 || ts.UTC().Day() != 15 {
		t.Errorf("revokedAt = %v, want 2026-01-15", ts)
	}
}

func TestRevokedAtReturnsFalseForActiveKey(t *testing.T) {
	dir := writeKeystore(t, "Lemma", metaActiveOnly, "", "")
	lc, _, _ := LoadLifecycle(dir, "Lemma")
	if _, _, ok := lc.RevokedAt(fixtureKeyID); ok {
		t.Error("RevokedAt should return ok=false for an ACTIVE key")
	}
}

func TestRevokedAtReturnsFalseForRetiredKey(t *testing.T) {
	// Only REVOKED flips. RETIRED is a wire-format status but doesn't
	// trigger violations (mirrors evidence_log.py:313-319).
	dir := writeKeystore(t, "Lemma", metaRotated, "", "")
	lc, _, _ := LoadLifecycle(dir, "Lemma")
	if _, _, ok := lc.RevokedAt("ed25519:retired00abcdef00"); ok {
		t.Error("RevokedAt should return ok=false for a RETIRED key")
	}
}

func TestRevokedAtReturnsFalseWhenRevokedAtIsNull(t *testing.T) {
	dir := writeKeystore(t, "Lemma", metaRevokedNullTimestamp, "", "")
	lc, _, _ := LoadLifecycle(dir, "Lemma")
	if _, _, ok := lc.RevokedAt(fixtureKeyID); ok {
		t.Error("RevokedAt should return ok=false when revoked_at is null")
	}
}

func TestRevokedAtReturnsFalseForUnknownKey(t *testing.T) {
	dir := writeKeystore(t, "Lemma", metaRevoked, "", "")
	lc, _, _ := LoadLifecycle(dir, "Lemma")
	if _, _, ok := lc.RevokedAt("ed25519:unknown"); ok {
		t.Error("RevokedAt should return ok=false for an unknown key_id")
	}
}

func TestRevokedAtAcceptsZSuffixTimestamps(t *testing.T) {
	dir := writeKeystore(t, "Lemma", metaRevokedZSuffix, "", "")
	lc, _, err := LoadLifecycle(dir, "Lemma")
	if err != nil {
		t.Fatalf("LoadLifecycle with Z-suffix: %v", err)
	}
	ts, _, ok := lc.RevokedAt(fixtureKeyID)
	if !ok {
		t.Fatal("RevokedAt ok=false for Z-suffix timestamp")
	}
	if ts.UTC().Year() != 2026 || ts.UTC().Month() != 1 || ts.UTC().Day() != 15 {
		t.Errorf("revokedAt parsed wrong: %v", ts)
	}
}

// SafeProducer + GenerateKeypair tests ----------------------------------

func TestSafeProducerReplacesSlashAndSpace(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Lemma", "Lemma"},
		{"foo/bar", "foo_bar"},
		{"a b c", "a_b_c"},
		{"path/with spaces", "path_with_spaces"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := SafeProducer(tc.in); got != tc.want {
			t.Errorf("SafeProducer(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGenerateKeypairOnEmptyDirCreatesAllArtifacts(t *testing.T) {
	dir := t.TempDir()
	keyID, created, err := GenerateKeypair(dir, "Lemma")
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if !created {
		t.Error("created=false on first call; expected true")
	}
	if !strings.HasPrefix(keyID, "ed25519:") {
		t.Errorf("key_id %q missing ed25519: prefix", keyID)
	}
	if len(keyID) != len("ed25519:")+16 {
		t.Errorf("key_id %q has wrong length (want prefix + 16 hex)", keyID)
	}

	prodDir := filepath.Join(dir, "Lemma")
	priv := filepath.Join(prodDir, keyID+".private.pem")
	pub := filepath.Join(prodDir, keyID+".public.pem")
	meta := filepath.Join(prodDir, "meta.json")
	for _, p := range []string{priv, pub, meta} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("missing file %s: %v", p, err)
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", p)
		}
	}

	// Private PEM must be 0o600 regardless of umask.
	info, _ := os.Stat(priv)
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("private PEM mode %o, want 0600", mode)
	}
}

func TestGenerateKeypairIsIdempotentOnSecondCall(t *testing.T) {
	dir := t.TempDir()
	first, created1, err := GenerateKeypair(dir, "Lemma")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if !created1 {
		t.Fatal("first call should have created")
	}

	// Capture artifact contents to confirm the second call doesn't touch them.
	prodDir := filepath.Join(dir, "Lemma")
	priv1, _ := os.ReadFile(filepath.Join(prodDir, first+".private.pem"))
	meta1, _ := os.ReadFile(filepath.Join(prodDir, "meta.json"))

	second, created2, err := GenerateKeypair(dir, "Lemma")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if created2 {
		t.Error("second call created=true; expected idempotent skip")
	}
	if first != second {
		t.Errorf("idempotent call returned a different key_id: %q vs %q",
			first, second)
	}

	priv2, _ := os.ReadFile(filepath.Join(prodDir, second+".private.pem"))
	meta2, _ := os.ReadFile(filepath.Join(prodDir, "meta.json"))
	if string(priv1) != string(priv2) {
		t.Error("private PEM mutated on idempotent call")
	}
	if string(meta1) != string(meta2) {
		t.Error("meta.json mutated on idempotent call")
	}
}

func TestGenerateKeypairWritesACTIVERecordInMeta(t *testing.T) {
	dir := t.TempDir()
	keyID, _, err := GenerateKeypair(dir, "Lemma")
	if err != nil {
		t.Fatal(err)
	}
	lc, ok, err := LoadLifecycle(dir, "Lemma")
	if err != nil || !ok {
		t.Fatalf("LoadLifecycle: ok=%v err=%v", ok, err)
	}
	if len(lc.Keys) != 1 {
		t.Fatalf("expected 1 record, got %d", len(lc.Keys))
	}
	rec := lc.Keys[0]
	if rec.KeyID != keyID {
		t.Errorf("record key_id %q, want %q", rec.KeyID, keyID)
	}
	if rec.Status != "ACTIVE" {
		t.Errorf("status %q, want ACTIVE", rec.Status)
	}
	if rec.ActivatedAt.IsZero() {
		t.Error("activated_at is zero")
	}
}

func TestGenerateKeypairProducesUsableKey(t *testing.T) {
	dir := t.TempDir()
	keyID, _, err := GenerateKeypair(dir, "Lemma")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := LoadPrivateKey(dir, "Lemma", keyID)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	// Sign a known hash; verify with the matching public PEM via crypto.
	hashHex := "70199efb59c00012139c6498d6d6c387e901d77e81ecc39b4b76a4d2b4e8bc42"
	sigHex := crypto.SignEntryHash(priv, hashHex)
	if sigHex == "" {
		t.Fatal("SignEntryHash returned empty")
	}
	pubPath := filepath.Join(dir, "Lemma", keyID+".public.pem")
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.LoadPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("LoadPublicKey on freshly minted PEM: %v", err)
	}
	if !crypto.VerifyEntryHash(pub, hashHex, sigHex) {
		t.Error("freshly minted keypair fails sign+verify round-trip")
	}
}

func TestGenerateKeypairIntegratesWithLoadActive(t *testing.T) {
	dir := t.TempDir()
	keyID, _, err := GenerateKeypair(dir, "Lemma")
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadActive(dir, "Lemma")
	if err != nil {
		t.Fatalf("LoadActive: %v", err)
	}
	if got != keyID {
		t.Errorf("LoadActive=%q, GenerateKeypair=%q", got, keyID)
	}
}

func TestGenerateKeypairUsesSafeProducerForOnDiskName(t *testing.T) {
	dir := t.TempDir()
	keyID, _, err := GenerateKeypair(dir, "Foo Bar/Producer")
	if err != nil {
		t.Fatal(err)
	}
	safeDir := filepath.Join(dir, "Foo_Bar_Producer")
	if _, err := os.Stat(safeDir); err != nil {
		t.Errorf("expected sanitised dir %s, got: %v", safeDir, err)
	}
	if _, err := os.Stat(filepath.Join(safeDir, keyID+".private.pem")); err != nil {
		t.Errorf("private PEM not at sanitised path: %v", err)
	}
}
