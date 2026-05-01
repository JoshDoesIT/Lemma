package verifier

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoshDoesIT/Lemma/agent/internal/crl"
)

// CRLs revoking the verifier-fixture key (ed25519:56475aa75463474c) at
// three timestamps relative to the envelope's signed_at (2026-01-01T00:00:00+00:00).
// All four are signed by the same private key the verifier-fixture envelopes
// use; signatures pinned from a one-shot Python generation pass.
const (
	crlRevokedBefore = `{"producer":"TestProducer","issued_at":"2026-01-02T00:00:00+00:00","revocations":[{"key_id":"ed25519:56475aa75463474c","revoked_at":"2025-12-01T00:00:00+00:00","reason":"leaked"}],"issuer_key_id":"ed25519:56475aa75463474c","signature":"5e54a867dfdaa6e02d8843441ce6dcb8385295164abf8280dab0d0cead81b870c04864d82b9afaea068d58510cb2d24b5befa3bfc8edfd4c25ae030d4a1f2c08"}`
	crlRevokedAfter  = `{"producer":"TestProducer","issued_at":"2026-01-02T00:00:00+00:00","revocations":[{"key_id":"ed25519:56475aa75463474c","revoked_at":"2026-06-01T00:00:00+00:00","reason":"rotation"}],"issuer_key_id":"ed25519:56475aa75463474c","signature":"09c3e48e345260b661a5f324b834e9582614690089d018c9d267114065cf941553092709a6fc1db82feeef23f94141ebb22ecd17dcccf29e6799413df804840a"}`
	crlRevokedEqual  = `{"producer":"TestProducer","issued_at":"2026-01-02T00:00:00+00:00","revocations":[{"key_id":"ed25519:56475aa75463474c","revoked_at":"2026-01-01T00:00:00+00:00","reason":"exactly at signed_at"}],"issuer_key_id":"ed25519:56475aa75463474c","signature":"7e9aa658ce1eda239d8c5189b7701d71be1f8bed506d0319dbfb41fffa18be07755d89d30412527f480e45ec2f74f3176a2358854ace3b67c06d65b7a1ec8d06"}`
	crlOtherProducer = `{"producer":"Okta","issued_at":"2026-01-02T00:00:00+00:00","revocations":[{"key_id":"ed25519:56475aa75463474c","revoked_at":"2025-12-01T00:00:00+00:00","reason":"should be ignored"}],"issuer_key_id":"ed25519:56475aa75463474c","signature":"4cc63eea63d447ee73600f361e770accc99877e0cc2733468d770e32538c78e8687abc70f0b34944d7d6cad69e69d7bc9847bfa9890f2d67e1d8e20b91ab9205"}`
)

// loadCRL parses a JSON literal into a *crl.List for test wiring. The
// CRL signatures are valid (verified separately by the crl package
// tests); the verifier package treats the CRL as already-trusted.
func loadCRL(t *testing.T, body string) *crl.List {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "crl.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := crl.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// Two-entry signed log produced by Python with a deterministic Ed25519
// keypair (seed = bytes(range(32))). The keys are pinned because the
// agent's verifier has to round-trip every byte the Python signer
// emitted. Regenerating these by hand is in agent/internal/verifier/README
// (not shipped) — see plan.
const (
	fixturePEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
-----END PUBLIC KEY-----
`
	fixtureProducer = "TestProducer"
	fixtureKeyID    = "ed25519:56475aa75463474c"

	fixtureLine0 = `{"event":{"class_uid":2003,"activity_id":1,"time":1700000000,"metadata":{"uid":"fixture-0","product":{"name":"TestProducer"}}},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","entry_hash":"f732ee4807b6c2b9f13acd72f406daf2f46a3b968215c34ccc89993a3ec577bf","signature":"a74c2115e069ddb6ab7a6335e910ff2dbd702befc34d1767c5674f0ba250ca66fb1d65350570e81f8304f35775dfde50494f9364a426bdff27b7428968c03100","signer_key_id":"ed25519:56475aa75463474c","signed_at":"2026-01-01T00:00:00+00:00","provenance":[{"stage":"storage","actor":"lemma.test","timestamp":"2026-01-01T00:00:00+00:00","content_hash":"f732ee4807b6c2b9f13acd72f406daf2f46a3b968215c34ccc89993a3ec577bf"}]}`
	fixtureLine1 = `{"event":{"class_uid":2003,"activity_id":1,"time":1700000000,"metadata":{"uid":"fixture-1","product":{"name":"TestProducer"}}},"prev_hash":"f732ee4807b6c2b9f13acd72f406daf2f46a3b968215c34ccc89993a3ec577bf","entry_hash":"1b5ae30b1ee45b12488cf437a88145ea03c8fe8dd35c90bcf50e3c50e77bb4a9","signature":"ebc40c9bd54a666c0abec1febd97d4cd4a709bec4ecf8c6c854716146b0adff0024641de0383f65ef38dc6ec104666df2952bb70c72543d64930f1a8640f9d08","signer_key_id":"ed25519:56475aa75463474c","signed_at":"2026-01-01T00:00:00+00:00","provenance":[{"stage":"storage","actor":"lemma.test","timestamp":"2026-01-01T00:00:00+00:00","content_hash":"1b5ae30b1ee45b12488cf437a88145ea03c8fe8dd35c90bcf50e3c50e77bb4a9"}]}`
)

// writeFixture lays out a tempdir like the Python project does:
//
//	<tmp>/log.jsonl
//	<tmp>/keys/<safe_producer>/<key_id>.public.pem
//
// and returns the log path and the keys directory.
func writeFixture(t *testing.T, lines []string) (logPath, keysDir string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "log.jsonl")
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	keysDir = filepath.Join(dir, "keys")
	keyDir := filepath.Join(keysDir, fixtureProducer)
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}
	keyPath := filepath.Join(keyDir, fixtureKeyID+".public.pem")
	if err := os.WriteFile(keyPath, []byte(fixturePEM), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return logPath, keysDir
}

func TestVerifyAcceptsPristineMultiEntryLog(t *testing.T) {
	logPath, keysDir := writeFixture(t, []string{fixtureLine0, fixtureLine1})
	results, err := Verify(logPath, keysDir, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Status != "PROVEN" {
			t.Errorf("entry %d: status %q (reason: %s) — want PROVEN", i, r.Status, r.Reason)
		}
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	// Flip one hex char in line 1's signature.
	tampered := strings.Replace(fixtureLine1,
		`"signature":"ebc40c`,
		`"signature":"fbc40c`,
		1)
	if tampered == fixtureLine1 {
		t.Fatal("test bug: signature substring not found")
	}
	logPath, keysDir := writeFixture(t, []string{fixtureLine0, tampered})
	results, err := Verify(logPath, keysDir, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "PROVEN" {
		t.Errorf("entry 0 should still be PROVEN")
	}
	if results[1].Status != "VIOLATED" {
		t.Errorf("entry 1 status %q, want VIOLATED", results[1].Status)
	}
	if !strings.Contains(strings.ToLower(results[1].Reason), "signature") {
		t.Errorf("entry 1 reason should mention signature, got %q", results[1].Reason)
	}
}

func TestVerifyRejectsBrokenChain(t *testing.T) {
	// Replace line 1's prev_hash with the wrong value (zero hash instead
	// of line 0's entry hash).
	bad := strings.Replace(fixtureLine1,
		`"prev_hash":"f732ee4807b6c2b9f13acd72f406daf2f46a3b968215c34ccc89993a3ec577bf"`,
		`"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"`,
		1)
	if bad == fixtureLine1 {
		t.Fatal("test bug: prev_hash substring not found")
	}
	logPath, keysDir := writeFixture(t, []string{fixtureLine0, bad})
	results, err := Verify(logPath, keysDir, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[1].Status != "VIOLATED" {
		t.Errorf("entry 1 status %q, want VIOLATED", results[1].Status)
	}
	if !strings.Contains(strings.ToLower(results[1].Reason), "chain") &&
		!strings.Contains(strings.ToLower(results[1].Reason), "prev") {
		t.Errorf("reason should mention chain or prev, got %q", results[1].Reason)
	}
}

func TestVerifyRejectsTamperedEvent(t *testing.T) {
	// Change the event's uid; entry_hash still claims the original
	// value, so ComputeEntryHash will not match.
	bad := strings.Replace(fixtureLine0, `"fixture-0"`, `"FIXTURE-0"`, 1)
	if bad == fixtureLine0 {
		t.Fatal("test bug: event uid not found")
	}
	logPath, keysDir := writeFixture(t, []string{bad})
	results, err := Verify(logPath, keysDir, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "VIOLATED" {
		t.Errorf("status %q, want VIOLATED", results[0].Status)
	}
	if !strings.Contains(strings.ToLower(results[0].Reason), "hash") {
		t.Errorf("reason should mention hash mismatch, got %q", results[0].Reason)
	}
}

func TestVerifyEmptyFileReturnsEmptyResults(t *testing.T) {
	logPath, keysDir := writeFixture(t, nil)
	results, err := Verify(logPath, keysDir, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty file, got %d", len(results))
	}
}

func TestVerifyMissingKeyFileMarksEntryViolated(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log.jsonl")
	if err := os.WriteFile(logPath, []byte(fixtureLine0+"\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	emptyKeysDir := filepath.Join(dir, "no-keys")
	if err := os.MkdirAll(emptyKeysDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	results, err := Verify(logPath, emptyKeysDir, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "VIOLATED" {
		t.Errorf("status %q, want VIOLATED", results[0].Status)
	}
	if !strings.Contains(strings.ToLower(results[0].Reason), "key") {
		t.Errorf("reason should mention missing key, got %q", results[0].Reason)
	}
}

func TestVerifyReturnsErrorForMalformedJSONL(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log.jsonl")
	if err := os.WriteFile(logPath, []byte("not json\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	keysDir := filepath.Join(dir, "keys")
	_ = os.MkdirAll(keysDir, 0o755)
	if _, err := Verify(logPath, keysDir, Options{}); err == nil {
		t.Error("expected parse error on malformed JSONL, got nil")
	}
}

func TestVerifyMissingFileReturnsError(t *testing.T) {
	if _, err := Verify("/nonexistent/path.jsonl", "/tmp", Options{}); err == nil {
		t.Error("expected error on missing log file, got nil")
	}
}

// CRL test cycles --------------------------------------------------------

func TestVerifyCRLBeforeSignedAtFlipsToViolated(t *testing.T) {
	logPath, keysDir := writeFixture(t, []string{fixtureLine0})
	results, err := Verify(logPath, keysDir, Options{
		CRLs: []*crl.List{loadCRL(t, crlRevokedBefore)},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "VIOLATED" {
		t.Fatalf("status %q, want VIOLATED (reason: %s)", results[0].Status, results[0].Reason)
	}
	if !strings.Contains(results[0].Reason, "CRL") {
		t.Errorf("reason should mention CRL, got %q", results[0].Reason)
	}
	if !strings.Contains(strings.ToLower(results[0].Reason), "revoked") {
		t.Errorf("reason should mention revocation, got %q", results[0].Reason)
	}
}

func TestVerifyCRLAfterSignedAtKeepsProven(t *testing.T) {
	logPath, keysDir := writeFixture(t, []string{fixtureLine0})
	results, err := Verify(logPath, keysDir, Options{
		CRLs: []*crl.List{loadCRL(t, crlRevokedAfter)},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "PROVEN" {
		t.Errorf("status %q, want PROVEN — entry was signed before revocation",
			results[0].Status)
	}
}

func TestVerifyCRLEqualSignedAtFlipsToViolated(t *testing.T) {
	// Python uses signed_at >= revoked_at (>= comparison), so an entry
	// signed at exactly the revocation instant is VIOLATED.
	logPath, keysDir := writeFixture(t, []string{fixtureLine0})
	results, err := Verify(logPath, keysDir, Options{
		CRLs: []*crl.List{loadCRL(t, crlRevokedEqual)},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "VIOLATED" {
		t.Errorf("status %q, want VIOLATED — entry was signed AT revocation instant",
			results[0].Status)
	}
}

func TestVerifyCRLOtherProducerIsIgnored(t *testing.T) {
	// CRL.producer != envelope.producer → CRL ignored.
	logPath, keysDir := writeFixture(t, []string{fixtureLine0})
	results, err := Verify(logPath, keysDir, Options{
		CRLs: []*crl.List{loadCRL(t, crlOtherProducer)},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "PROVEN" {
		t.Errorf("status %q, want PROVEN — cross-producer CRL must be ignored",
			results[0].Status)
	}
}

func TestVerifyMultipleCRLsOnlyMatchingProducerApplies(t *testing.T) {
	// Pass both an Okta CRL (ignored) and a TestProducer CRL (applies).
	// Verdict is VIOLATED.
	logPath, keysDir := writeFixture(t, []string{fixtureLine0})
	results, err := Verify(logPath, keysDir, Options{
		CRLs: []*crl.List{
			loadCRL(t, crlOtherProducer),
			loadCRL(t, crlRevokedBefore),
		},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "VIOLATED" {
		t.Errorf("status %q, want VIOLATED", results[0].Status)
	}
}

func TestVerifyNoCRLsBehavesLikePreSliceG(t *testing.T) {
	// Regression guard: empty Options.CRLs preserves the Slice F
	// behavior for callers that don't care about revocations.
	logPath, keysDir := writeFixture(t, []string{fixtureLine0, fixtureLine1})
	results, err := Verify(logPath, keysDir, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for i, r := range results {
		if r.Status != "PROVEN" {
			t.Errorf("entry %d: status %q (reason %q) want PROVEN",
				i, r.Status, r.Reason)
		}
	}
}

// Local lifecycle test cycles ------------------------------------------

// writeMetaJSON drops a meta.json into <keysDir>/<producer>/ alongside
// the public PEM that writeFixture already laid down. Returns nothing —
// the caller still uses the same keysDir for verifier.Verify.
func writeMetaJSON(t *testing.T, keysDir, producer, body string) {
	t.Helper()
	path := filepath.Join(keysDir, producer, "meta.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const lifecycleRevokedBefore = `{
  "keys": [
    {
      "key_id": "ed25519:56475aa75463474c",
      "status": "REVOKED",
      "activated_at": "2025-12-01T00:00:00+00:00",
      "retired_at": null,
      "revoked_at": "2025-12-15T00:00:00+00:00",
      "revoked_reason": "compromised",
      "successor_key_id": ""
    }
  ]
}`

const lifecycleRevokedAfter = `{
  "keys": [
    {
      "key_id": "ed25519:56475aa75463474c",
      "status": "REVOKED",
      "activated_at": "2025-12-01T00:00:00+00:00",
      "retired_at": null,
      "revoked_at": "2026-06-01T00:00:00+00:00",
      "revoked_reason": "rotation",
      "successor_key_id": ""
    }
  ]
}`

const lifecycleRevokedEqual = `{
  "keys": [
    {
      "key_id": "ed25519:56475aa75463474c",
      "status": "REVOKED",
      "activated_at": "2025-12-01T00:00:00+00:00",
      "retired_at": null,
      "revoked_at": "2026-01-01T00:00:00+00:00",
      "revoked_reason": "exact-instant",
      "successor_key_id": ""
    }
  ]
}`

const lifecycleRetired = `{
  "keys": [
    {
      "key_id": "ed25519:56475aa75463474c",
      "status": "RETIRED",
      "activated_at": "2025-12-01T00:00:00+00:00",
      "retired_at": "2025-12-15T00:00:00+00:00",
      "revoked_at": null,
      "revoked_reason": "",
      "successor_key_id": ""
    }
  ]
}`

func TestVerifyLocalLifecycleRevokedBeforeFlipsToViolated(t *testing.T) {
	logPath, keysDir := writeFixture(t, []string{fixtureLine0})
	writeMetaJSON(t, keysDir, fixtureProducer, lifecycleRevokedBefore)
	results, err := Verify(logPath, keysDir, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "VIOLATED" {
		t.Fatalf("status %q, want VIOLATED (reason %q)", results[0].Status, results[0].Reason)
	}
	if !strings.Contains(results[0].Reason, "source: local lifecycle") {
		t.Errorf("reason should name the local source; got %q", results[0].Reason)
	}
}

func TestVerifyLocalLifecycleRevokedAfterKeepsProven(t *testing.T) {
	logPath, keysDir := writeFixture(t, []string{fixtureLine0})
	writeMetaJSON(t, keysDir, fixtureProducer, lifecycleRevokedAfter)
	results, err := Verify(logPath, keysDir, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "PROVEN" {
		t.Errorf("status %q, want PROVEN — entry signed before revocation",
			results[0].Status)
	}
}

func TestVerifyLocalLifecycleRevokedEqualSignedAtFlipsToViolated(t *testing.T) {
	// Python uses signed_at >= revoked_at — at-the-instant is VIOLATED.
	logPath, keysDir := writeFixture(t, []string{fixtureLine0})
	writeMetaJSON(t, keysDir, fixtureProducer, lifecycleRevokedEqual)
	results, err := Verify(logPath, keysDir, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "VIOLATED" {
		t.Errorf("status %q, want VIOLATED — entry signed AT revocation instant",
			results[0].Status)
	}
}

func TestVerifyLocalLifecycleRetiredKeepsProven(t *testing.T) {
	// Only REVOKED flips. RETIRED is documented but doesn't violate.
	logPath, keysDir := writeFixture(t, []string{fixtureLine0})
	writeMetaJSON(t, keysDir, fixtureProducer, lifecycleRetired)
	results, err := Verify(logPath, keysDir, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "PROVEN" {
		t.Errorf("status %q, want PROVEN — RETIRED status must not flip",
			results[0].Status)
	}
}

func TestVerifyMissingMetaJSONIsPassThrough(t *testing.T) {
	// No meta.json written — same behaviour as Slice F/G; regression guard.
	logPath, keysDir := writeFixture(t, []string{fixtureLine0})
	results, err := Verify(logPath, keysDir, Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "PROVEN" {
		t.Errorf("status %q, want PROVEN with no meta.json", results[0].Status)
	}
}

const lifecycleEarlierThanCRL = `{
  "keys": [
    {
      "key_id": "ed25519:56475aa75463474c",
      "status": "REVOKED",
      "activated_at": "2025-10-01T00:00:00+00:00",
      "retired_at": null,
      "revoked_at": "2025-11-01T00:00:00+00:00",
      "revoked_reason": "local-earlier",
      "successor_key_id": ""
    }
  ]
}`

func TestVerifyLocalAndCRLLocalEarlierWins(t *testing.T) {
	// Local: 2025-11-01. CRL (crlRevokedBefore): 2025-12-01. Local wins.
	logPath, keysDir := writeFixture(t, []string{fixtureLine0})
	writeMetaJSON(t, keysDir, fixtureProducer, lifecycleEarlierThanCRL)
	results, err := Verify(logPath, keysDir, Options{
		CRLs: []*crl.List{loadCRL(t, crlRevokedBefore)},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "VIOLATED" {
		t.Fatalf("status %q, want VIOLATED", results[0].Status)
	}
	if !strings.Contains(results[0].Reason, "source: local lifecycle") {
		t.Errorf("reason should name local lifecycle (it's earlier); got %q",
			results[0].Reason)
	}
	if !strings.Contains(results[0].Reason, "local-earlier") {
		t.Errorf("reason should carry local-source's reason text; got %q",
			results[0].Reason)
	}
}

func TestVerifyLocalAndCRLCRLEarlierWins(t *testing.T) {
	// Local: 2026-01-15 (lifecycleRevokedBefore is 2025-12-15... actually
	// that's earlier than the CRL's 2025-12-01? No, 2025-12-15 is AFTER
	// 2025-12-01). Let me use lifecycleRevokedAfter which sits at
	// 2026-06-01 — well after the CRL's 2025-12-01, so CRL wins.
	// But lifecycleRevokedAfter is AFTER signed_at (2026-01-01) too, so
	// the CRL is the only effective revocation here. Need a lifecycle that
	// is BEFORE signed_at but AFTER the CRL date.
	const lifecycleLaterThanCRL = `{
  "keys": [
    {
      "key_id": "ed25519:56475aa75463474c",
      "status": "REVOKED",
      "activated_at": "2025-10-01T00:00:00+00:00",
      "retired_at": null,
      "revoked_at": "2025-12-20T00:00:00+00:00",
      "revoked_reason": "local-later",
      "successor_key_id": ""
    }
  ]
}`
	logPath, keysDir := writeFixture(t, []string{fixtureLine0})
	writeMetaJSON(t, keysDir, fixtureProducer, lifecycleLaterThanCRL)
	results, err := Verify(logPath, keysDir, Options{
		CRLs: []*crl.List{loadCRL(t, crlRevokedBefore)}, // 2025-12-01
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if results[0].Status != "VIOLATED" {
		t.Fatalf("status %q, want VIOLATED", results[0].Status)
	}
	if !strings.Contains(results[0].Reason, "source: CRL") {
		t.Errorf("reason should name CRL (it's earlier); got %q", results[0].Reason)
	}
}
