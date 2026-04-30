package crl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoshDoesIT/Lemma/agent/internal/crypto"
)

// Deterministic CRL fixture signed with the same Ed25519 keypair the
// verifier package's tests use (seed = bytes(range(32))). Generation
// procedure is documented in the Slice G plan.
const (
	fixturePEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
-----END PUBLIC KEY-----
`
	fixtureIssuerKeyID = "ed25519:56475aa75463474c"
	fixtureRevokedKey  = "ed25519:revoked0000abcdef"
	fixtureRevokedAt   = "2026-01-15T12:00:00+00:00"

	fixtureCRLJSON = `{"producer":"Lemma","issued_at":"2026-01-16T00:00:00+00:00","revocations":[{"key_id":"ed25519:revoked0000abcdef","revoked_at":"2026-01-15T12:00:00+00:00","reason":"leaked"}],"issuer_key_id":"ed25519:56475aa75463474c","signature":"5726619662d9929df141f1e6e35bc389ca7329052f65a71b07bb188a3d1de658ee2ed9fa50443ee8af536f2d60bfc3a93161335cbd98a32f4a329963ee390207"}`
)

func writeFixtureCRL(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "crl.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestLoadParsesValidCRL(t *testing.T) {
	path := writeFixtureCRL(t, fixtureCRLJSON)
	list, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if list.Producer != "Lemma" {
		t.Errorf("Producer = %q, want Lemma", list.Producer)
	}
	if list.IssuerKeyID != fixtureIssuerKeyID {
		t.Errorf("IssuerKeyID = %q, want %q", list.IssuerKeyID, fixtureIssuerKeyID)
	}
	if len(list.Revocations) != 1 {
		t.Fatalf("expected 1 revocation, got %d", len(list.Revocations))
	}
	rev := list.Revocations[0]
	if rev.KeyID != fixtureRevokedKey {
		t.Errorf("Revocations[0].KeyID = %q", rev.KeyID)
	}
	if rev.Reason != "leaked" {
		t.Errorf("Revocations[0].Reason = %q", rev.Reason)
	}
	if rev.RevokedAt.IsZero() {
		t.Error("Revocations[0].RevokedAt is zero")
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/crl.json"); err == nil {
		t.Error("expected error on missing file, got nil")
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	path := writeFixtureCRL(t, "{not json")
	if _, err := Load(path); err == nil {
		t.Error("expected error on malformed JSON, got nil")
	}
}

func TestVerifySignatureAcceptsKnownGoodCRL(t *testing.T) {
	path := writeFixtureCRL(t, fixtureCRLJSON)
	list, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	pub, err := crypto.LoadPublicKey([]byte(fixturePEM))
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if !list.VerifySignature(pub) {
		t.Error("VerifySignature rejected a known-good CRL")
	}
}

func TestVerifySignatureRejectsTamperedSignature(t *testing.T) {
	tampered := strings.Replace(fixtureCRLJSON,
		`"signature":"5726`,
		`"signature":"6726`, 1)
	if tampered == fixtureCRLJSON {
		t.Fatal("test bug: signature substring not found")
	}
	path := writeFixtureCRL(t, tampered)
	list, _ := Load(path)
	pub, _ := crypto.LoadPublicKey([]byte(fixturePEM))
	if list.VerifySignature(pub) {
		t.Error("VerifySignature accepted a tampered signature")
	}
}

func TestVerifySignatureRejectsTamperedRevocation(t *testing.T) {
	// Change the reason field — canonical bytes change → signature
	// no longer covers them.
	tampered := strings.Replace(fixtureCRLJSON, `"leaked"`, `"oops"`, 1)
	if tampered == fixtureCRLJSON {
		t.Fatal("test bug: reason substring not found")
	}
	path := writeFixtureCRL(t, tampered)
	list, _ := Load(path)
	pub, _ := crypto.LoadPublicKey([]byte(fixturePEM))
	if list.VerifySignature(pub) {
		t.Error("VerifySignature accepted a CRL with tampered revocation field")
	}
}

func TestVerifySignatureRejectsTamperedProducer(t *testing.T) {
	tampered := strings.Replace(fixtureCRLJSON, `"producer":"Lemma"`, `"producer":"Okta"`, 1)
	if tampered == fixtureCRLJSON {
		t.Fatal("test bug: producer substring not found")
	}
	path := writeFixtureCRL(t, tampered)
	list, _ := Load(path)
	pub, _ := crypto.LoadPublicKey([]byte(fixturePEM))
	if list.VerifySignature(pub) {
		t.Error("VerifySignature accepted a CRL with tampered producer field")
	}
}

func TestLookupReturnsRevokedEntry(t *testing.T) {
	list, _ := Load(writeFixtureCRL(t, fixtureCRLJSON))
	revokedAt, reason, ok := list.Lookup(fixtureRevokedKey)
	if !ok {
		t.Fatal("Lookup returned ok=false for a revoked key")
	}
	if reason != "leaked" {
		t.Errorf("reason = %q, want leaked", reason)
	}
	if revokedAt.IsZero() {
		t.Error("revokedAt is zero")
	}
	// The fixture's revoked_at is 2026-01-15T12:00:00 UTC.
	if revokedAt.UTC().Year() != 2026 || revokedAt.UTC().Month() != 1 || revokedAt.UTC().Day() != 15 {
		t.Errorf("revokedAt = %v, want 2026-01-15", revokedAt)
	}
}

func TestLookupReturnsZeroForUnknownKey(t *testing.T) {
	list, _ := Load(writeFixtureCRL(t, fixtureCRLJSON))
	_, _, ok := list.Lookup("ed25519:notrevoked")
	if ok {
		t.Error("Lookup returned ok=true for an unknown key")
	}
}

func TestLoadAcceptsEmptyRevocationsList(t *testing.T) {
	// Sign an empty-revocations CRL inline so the canonical bytes
	// stay accurate. We don't ship this fixture pinned because the
	// signature would only be useful for verifying empty-CRL behavior;
	// for parse/decode this single test is enough.
	body := `{"producer":"Lemma","issued_at":"2026-01-16T00:00:00+00:00","revocations":[],"issuer_key_id":"ed25519:56475aa75463474c","signature":"00"}`
	list, err := Load(writeFixtureCRL(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(list.Revocations) != 0 {
		t.Errorf("expected 0 revocations, got %d", len(list.Revocations))
	}
}

func TestLoadAcceptsZSuffixTimestamps(t *testing.T) {
	// Some bundles produced from external sources may use Z instead
	// of +00:00. Both must parse.
	body := strings.ReplaceAll(fixtureCRLJSON, "+00:00", "Z")
	list, err := Load(writeFixtureCRL(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if list.IssuedAt.IsZero() {
		t.Error("IssuedAt with Z suffix did not parse")
	}
}
