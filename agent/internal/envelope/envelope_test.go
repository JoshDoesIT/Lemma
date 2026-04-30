package envelope

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fixture computed by Lemma's _canonical_signed_bytes path against the
// inputs below; if Go's ComputeEntryHash does not produce this value
// byte-for-byte, the canonical JSON or chain hash logic has drifted.
//
// Generation:
//
//	event = {"class_uid":2003,"activity_id":1,"time":1700000000,
//	         "metadata":{"uid":"test-1"}}
//	provenance = [ProvenanceRecord(stage="ingest", actor="lemma.test",
//	                               timestamp="2026-01-01T00:00:00Z",
//	                               content_hash="abc"),
//	              ProvenanceRecord(stage="storage", ...)]
//	prev_hash = "0"*64
//	-> entry_hash = 1c225b5b051601789f0e6525f7ad31b08382646ed1a6069046f303f1c0009561
const expectedEntryHash = "1c225b5b051601789f0e6525f7ad31b08382646ed1a6069046f303f1c0009561"

const fixtureLine = `{"event":{"class_uid":2003,"activity_id":1,"time":1700000000,"metadata":{"uid":"test-1"}},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","entry_hash":"1c225b5b051601789f0e6525f7ad31b08382646ed1a6069046f303f1c0009561","signature":"unused-for-this-test","signer_key_id":"ed25519:0000000000000000","signed_at":"2026-04-30T00:00:00Z","provenance":[{"stage":"ingest","actor":"lemma.test","timestamp":"2026-01-01T00:00:00Z","content_hash":"abc"},{"stage":"storage","actor":"lemma.test","timestamp":"2026-01-01T00:00:00Z","content_hash":"def"}]}`

func TestParseAcceptsAValidEnvelope(t *testing.T) {
	env, err := Parse([]byte(fixtureLine))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if env.PrevHash != strings.Repeat("0", 64) {
		t.Errorf("PrevHash = %q, want all-zero", env.PrevHash)
	}
	if env.EntryHash != expectedEntryHash {
		t.Errorf("EntryHash = %q, want %q", env.EntryHash, expectedEntryHash)
	}
	if env.SignerKeyID != "ed25519:0000000000000000" {
		t.Errorf("SignerKeyID = %q", env.SignerKeyID)
	}
	if len(env.Provenance) != 2 {
		t.Errorf("expected 2 provenance records, got %d", len(env.Provenance))
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	if _, err := Parse([]byte(`{not json`)); err == nil {
		t.Fatal("expected error on malformed JSON, got nil")
	}
}

func TestComputeEntryHashMatchesPythonOracle(t *testing.T) {
	env, err := Parse([]byte(fixtureLine))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := env.ComputeEntryHash()
	if err != nil {
		t.Fatalf("ComputeEntryHash: %v", err)
	}
	if got != expectedEntryHash {
		t.Errorf("ComputeEntryHash = %q\nwant                %q", got, expectedEntryHash)
	}
}

func TestComputeEntryHashFiltersStorageProvenance(t *testing.T) {
	// If Go forgot to drop the storage-stage record, the canonical
	// bytes would carry an extra entry and the hash would not match.
	// This test guards the filter explicitly: build a second envelope
	// where the storage record is absent and confirm both produce
	// the same hash. (They share the same "ingest" record + event.)
	withStorage := fixtureLine
	withoutStorage := strings.Replace(
		fixtureLine,
		`,{"stage":"storage","actor":"lemma.test","timestamp":"2026-01-01T00:00:00Z","content_hash":"def"}`,
		``,
		1,
	)
	if withStorage == withoutStorage {
		t.Fatal("test bug: substring not found in fixtureLine")
	}

	envA, _ := Parse([]byte(withStorage))
	envB, _ := Parse([]byte(withoutStorage))

	hashA, err := envA.ComputeEntryHash()
	if err != nil {
		t.Fatalf("ComputeEntryHash A: %v", err)
	}
	hashB, err := envB.ComputeEntryHash()
	if err != nil {
		t.Fatalf("ComputeEntryHash B: %v", err)
	}
	if hashA != hashB {
		t.Errorf("storage filter not applied:\n  with    storage: %s\n  without storage: %s", hashA, hashB)
	}
}

func TestComputeEntryHashChangesWhenEventChanges(t *testing.T) {
	envA, err := Parse([]byte(fixtureLine))
	if err != nil {
		t.Fatalf("Parse A: %v", err)
	}
	tampered := strings.Replace(fixtureLine, `"test-1"`, `"test-2"`, 1)
	envB, err := Parse([]byte(tampered))
	if err != nil {
		t.Fatalf("Parse B: %v", err)
	}
	hashA, _ := envA.ComputeEntryHash()
	hashB, _ := envB.ComputeEntryHash()
	if hashA == hashB {
		t.Error("event change should produce a different entry hash")
	}
}

func TestProducerExtractsEventMetadataProductName(t *testing.T) {
	// CRL matching keys off event.metadata.product.name — same field
	// Python's evidence_log._producer_of reads.
	const line = `{"event":{"class_uid":2003,"metadata":{"product":{"name":"Lemma"},"uid":"e1"}},"prev_hash":"00","entry_hash":"00","signature":"00","signer_key_id":"ed25519:0","signed_at":"2026-01-01T00:00:00+00:00","provenance":[]}`
	env, err := Parse([]byte(line))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := env.Producer()
	if err != nil {
		t.Fatalf("Producer: %v", err)
	}
	if got != "Lemma" {
		t.Errorf("Producer = %q, want %q", got, "Lemma")
	}
}

func TestProducerFallsBackToUnknownWhenFieldMissing(t *testing.T) {
	// Mirrors Python evidence_log._producer_of's "unknown" fallback at line 67.
	cases := []struct {
		name string
		line string
	}{
		{"no_metadata", `{"event":{"class_uid":2003},"prev_hash":"00","entry_hash":"00","signature":"00","signer_key_id":"ed25519:0","signed_at":"2026-01-01T00:00:00+00:00","provenance":[]}`},
		{"metadata_not_object", `{"event":{"metadata":"oops"},"prev_hash":"00","entry_hash":"00","signature":"00","signer_key_id":"ed25519:0","signed_at":"2026-01-01T00:00:00+00:00","provenance":[]}`},
		{"no_product", `{"event":{"metadata":{"uid":"e1"}},"prev_hash":"00","entry_hash":"00","signature":"00","signer_key_id":"ed25519:0","signed_at":"2026-01-01T00:00:00+00:00","provenance":[]}`},
		{"product_not_object", `{"event":{"metadata":{"product":"Lemma"}},"prev_hash":"00","entry_hash":"00","signature":"00","signer_key_id":"ed25519:0","signed_at":"2026-01-01T00:00:00+00:00","provenance":[]}`},
		{"empty_name", `{"event":{"metadata":{"product":{"name":""}}},"prev_hash":"00","entry_hash":"00","signature":"00","signer_key_id":"ed25519:0","signed_at":"2026-01-01T00:00:00+00:00","provenance":[]}`},
		{"name_not_string", `{"event":{"metadata":{"product":{"name":42}}},"prev_hash":"00","entry_hash":"00","signature":"00","signer_key_id":"ed25519:0","signed_at":"2026-01-01T00:00:00+00:00","provenance":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := Parse([]byte(tc.line))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got, err := env.Producer()
			if err != nil {
				t.Fatalf("Producer: %v", err)
			}
			if got != "unknown" {
				t.Errorf("Producer = %q, want %q", got, "unknown")
			}
		})
	}
}

func TestSignedAtTimeAcceptsBothTimezoneSuffixes(t *testing.T) {
	cases := []struct {
		name, signedAt string
	}{
		{"plus_00_00", "2026-04-30T12:34:56.123456+00:00"},
		{"Z_suffix", "2026-04-30T12:34:56.123456Z"},
		{"no_microseconds_Z", "2026-04-30T12:34:56Z"},
		{"no_microseconds_offset", "2026-04-30T12:34:56+00:00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &Envelope{SignedAt: tc.signedAt}
			ts, err := env.SignedAtTime()
			if err != nil {
				t.Fatalf("SignedAtTime: %v", err)
			}
			// All four cases should land on 2026-04-30, not e.g. 2025-12-31 due to
			// timezone misinterpretation.
			if ts.UTC().Year() != 2026 || ts.UTC().Month() != 4 || ts.UTC().Day() != 30 {
				t.Errorf("parsed wrong date: %v from %q", ts, tc.signedAt)
			}
		})
	}
}

func TestSignedAtTimeRejectsUnparseableInput(t *testing.T) {
	env := &Envelope{SignedAt: "not a timestamp"}
	if _, err := env.SignedAtTime(); err == nil {
		t.Error("expected error on unparseable signed_at, got nil")
	}
}

// Sanity check: round-tripping via Parse + json.Marshal preserves the
// envelope's identifying fields. (Doesn't have to be byte-identical.)
func TestParsePopulatesAllPublicFields(t *testing.T) {
	env, _ := Parse([]byte(fixtureLine))
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{
		`"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"`,
		`"entry_hash":"` + expectedEntryHash + `"`,
		`"signer_key_id":"ed25519:0000000000000000"`,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("re-marshal missing %q in:\n%s", want, out)
		}
	}
}
