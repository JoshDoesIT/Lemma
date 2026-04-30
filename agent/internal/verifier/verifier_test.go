package verifier

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

	fixtureLine0 = `{"event":{"class_uid":2003,"activity_id":1,"time":1700000000,"metadata":{"uid":"fixture-0"}},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","entry_hash":"ad45fdb920ab0ac996b793afa2785983d0fab8a5bf53ca12ed506baf5505249c","signature":"4a4570e276691556d546902f00c76d0d30e504a75d6f3221b7508e5492f49787bd0132553b8f8d5d41d4156014812a76c6713fd448310d7bcf9859c67e373a05","signer_key_id":"ed25519:56475aa75463474c","signed_at":"2026-01-01T00:00:00Z","provenance":[{"stage":"storage","actor":"TestProducer","timestamp":"2026-01-01T00:00:00Z","content_hash":"ad45fdb920ab0ac996b793afa2785983d0fab8a5bf53ca12ed506baf5505249c"}]}`
	fixtureLine1 = `{"event":{"class_uid":2003,"activity_id":1,"time":1700000000,"metadata":{"uid":"fixture-1"}},"prev_hash":"ad45fdb920ab0ac996b793afa2785983d0fab8a5bf53ca12ed506baf5505249c","entry_hash":"838e6b8a4933dd0c0dea6e88998c4b49ef4028ceccd1196478e6d3acfd22a951","signature":"858adef611efcd2ed392d6f3a92f82c746e2c0b8c6392c2afcd3643c9297d62e1db13296161b87936f3caf89ebf303ca92d39b00c9ff9e7be4d9491da870f600","signer_key_id":"ed25519:56475aa75463474c","signed_at":"2026-01-01T00:00:00Z","provenance":[{"stage":"storage","actor":"TestProducer","timestamp":"2026-01-01T00:00:00Z","content_hash":"838e6b8a4933dd0c0dea6e88998c4b49ef4028ceccd1196478e6d3acfd22a951"}]}`
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
	results, err := Verify(logPath, keysDir)
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
		`"signature":"858adef`,
		`"signature":"958adef`,
		1)
	if tampered == fixtureLine1 {
		t.Fatal("test bug: signature substring not found")
	}
	logPath, keysDir := writeFixture(t, []string{fixtureLine0, tampered})
	results, err := Verify(logPath, keysDir)
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
		`"prev_hash":"ad45fdb920ab0ac996b793afa2785983d0fab8a5bf53ca12ed506baf5505249c"`,
		`"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"`,
		1)
	if bad == fixtureLine1 {
		t.Fatal("test bug: prev_hash substring not found")
	}
	logPath, keysDir := writeFixture(t, []string{fixtureLine0, bad})
	results, err := Verify(logPath, keysDir)
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
	results, err := Verify(logPath, keysDir)
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
	results, err := Verify(logPath, keysDir)
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
	results, err := Verify(logPath, emptyKeysDir)
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
	if _, err := Verify(logPath, keysDir); err == nil {
		t.Error("expected parse error on malformed JSONL, got nil")
	}
}

func TestVerifyMissingFileReturnsError(t *testing.T) {
	if _, err := Verify("/nonexistent/path.jsonl", "/tmp"); err == nil {
		t.Error("expected error on missing log file, got nil")
	}
}
