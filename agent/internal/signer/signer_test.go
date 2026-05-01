package signer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	agentcrypto "github.com/JoshDoesIT/Lemma/agent/internal/crypto"
	"github.com/JoshDoesIT/Lemma/agent/internal/envelope"
	"github.com/JoshDoesIT/Lemma/agent/internal/verifier"
)

// Same deterministic Ed25519 keypair the rest of the agent's tests use
// (seed = bytes(range(32))).
const (
	fixturePrivPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f
-----END PRIVATE KEY-----
`
	fixturePubPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
-----END PUBLIC KEY-----
`
	fixtureKeyID = "ed25519:56475aa75463474c"
)

// Parity oracle pinned from a one-shot Python computation that mirrors
// EvidenceLog.append's hash-and-sign flow against the inputs below.
const (
	pinnedEvent       = `{"class_uid":2003,"activity_id":1,"time":1700000000,"metadata":{"product":{"name":"Lemma"},"uid":"go-sign-1"}}`
	pinnedSourceLabel = "test.json"
	pinnedSourceHash  = "abc1234567890def"
	pinnedSourceTS    = "2026-04-30T00:00:00Z"
	pinnedEntryHash   = "ebcc8e27c6ff6fd0831c80b4e7b4bf6bb059fe133fed9f5398067d5242c33068"
)

func loadFixturePriv(t *testing.T) []byte {
	t.Helper()
	priv, err := agentcrypto.LoadPrivateKey([]byte(fixturePrivPEM))
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	return priv
}

func TestBuildEntryHashMatchesPythonOracle(t *testing.T) {
	priv := loadFixturePriv(t)
	in := Inputs{
		EventJSON:         json.RawMessage(pinnedEvent),
		PrevHash:          "", // -> genesis
		Producer:          "Lemma",
		KeyID:             fixtureKeyID,
		PrivateKey:        priv,
		SourceLabel:       pinnedSourceLabel,
		SourceContentHash: pinnedSourceHash,
		SourceTimestamp:   mustTime(t, pinnedSourceTS),
		StorageTimestamp:  mustTime(t, pinnedSourceTS), // doesn't affect entry_hash
		SignedAt:          mustTime(t, pinnedSourceTS),
	}
	line, err := Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	env, err := envelope.Parse(line)
	if err != nil {
		t.Fatalf("Parse output: %v\n%s", err, line)
	}
	if env.EntryHash != pinnedEntryHash {
		t.Errorf("entry_hash = %s\nwant         %s", env.EntryHash, pinnedEntryHash)
	}
	// Recompute against the canonical bytes — should match the claimed value.
	recomputed, err := env.ComputeEntryHash()
	if err != nil {
		t.Fatalf("ComputeEntryHash: %v", err)
	}
	if recomputed != env.EntryHash {
		t.Errorf("self-recompute mismatch: %s vs %s", recomputed, env.EntryHash)
	}
}

func TestBuildSignatureVerifiesUnderMatchingPublicKey(t *testing.T) {
	priv := loadFixturePriv(t)
	pub, _ := agentcrypto.LoadPublicKey([]byte(fixturePubPEM))
	in := defaultInputs(t, priv)
	line, err := Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	env, _ := envelope.Parse(line)
	if !agentcrypto.VerifyEntryHash(pub, env.EntryHash, env.Signature) {
		t.Error("signature does not verify under the matching public key")
	}
}

func TestBuildDefaultsToGenesisPrevHash(t *testing.T) {
	in := defaultInputs(t, loadFixturePriv(t))
	in.PrevHash = ""
	line, _ := Build(in)
	env, _ := envelope.Parse(line)
	if env.PrevHash != strings.Repeat("0", 64) {
		t.Errorf("PrevHash = %q, want all-zero", env.PrevHash)
	}
}

func TestBuildPreservesExplicitPrevHash(t *testing.T) {
	in := defaultInputs(t, loadFixturePriv(t))
	in.PrevHash = "deadbeef" + strings.Repeat("0", 56)
	line, _ := Build(in)
	env, _ := envelope.Parse(line)
	if env.PrevHash != in.PrevHash {
		t.Errorf("PrevHash not preserved: got %q want %q", env.PrevHash, in.PrevHash)
	}
}

func TestBuildIncludesStorageProvenanceWithEntryHashContent(t *testing.T) {
	in := defaultInputs(t, loadFixturePriv(t))
	line, _ := Build(in)
	env, _ := envelope.Parse(line)
	if len(env.Provenance) != 2 {
		t.Fatalf("expected 2 provenance records (source + storage), got %d",
			len(env.Provenance))
	}
	// The second record must be the storage record, with content_hash equal
	// to the entry_hash. Decode it and check.
	var storage struct {
		Stage       string `json:"stage"`
		ContentHash string `json:"content_hash"`
	}
	if err := json.Unmarshal(env.Provenance[1], &storage); err != nil {
		t.Fatal(err)
	}
	if storage.Stage != "storage" {
		t.Errorf("provenance[1].stage = %q, want storage", storage.Stage)
	}
	if storage.ContentHash != env.EntryHash {
		t.Errorf("storage content_hash %s does not equal entry_hash %s",
			storage.ContentHash, env.EntryHash)
	}
}

func TestBuildOutputVerifiesEndToEndViaVerifierPackage(t *testing.T) {
	// The signed output must verify PROVEN through the production verifier
	// package — round-trip parity at the package level.
	priv := loadFixturePriv(t)
	in := defaultInputs(t, priv)
	line, err := Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	logPath, keysDir := writeProverFixture(t, line)
	results, err := verifier.Verify(logPath, keysDir, verifier.Options{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(results) != 1 || results[0].Status != "PROVEN" {
		t.Errorf("expected PROVEN, got %#v", results)
	}
}

func TestBuildRejectsEmptyEvent(t *testing.T) {
	in := defaultInputs(t, loadFixturePriv(t))
	in.EventJSON = nil
	if _, err := Build(in); err == nil {
		t.Error("expected error on empty event, got nil")
	}
}

func TestBuildRejectsMalformedEvent(t *testing.T) {
	in := defaultInputs(t, loadFixturePriv(t))
	in.EventJSON = json.RawMessage("{not json")
	if _, err := Build(in); err == nil {
		t.Error("expected error on malformed event, got nil")
	}
}

func TestBuildSignedAtUsesZSuffixForUTC(t *testing.T) {
	// Pydantic emits Z suffix for UTC timestamps; the agent's wire form
	// matches so the on-disk bytes are indistinguishable from Python's.
	in := defaultInputs(t, loadFixturePriv(t))
	in.SignedAt = time.Date(2026, 4, 30, 12, 34, 56, 789_000_000, time.UTC)
	line, _ := Build(in)
	env, _ := envelope.Parse(line)
	if !strings.HasSuffix(env.SignedAt, "Z") {
		t.Errorf("signed_at = %q, want Z suffix for UTC", env.SignedAt)
	}
}

// --- helpers ---

func mustTime(t *testing.T, iso string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		ts, err = time.Parse(time.RFC3339, iso)
	}
	if err != nil {
		t.Fatalf("parse %q: %v", iso, err)
	}
	return ts
}

func defaultInputs(t *testing.T, priv []byte) Inputs {
	t.Helper()
	return Inputs{
		EventJSON:         json.RawMessage(pinnedEvent),
		PrevHash:          "",
		Producer:          "Lemma",
		KeyID:             fixtureKeyID,
		PrivateKey:        priv,
		SourceLabel:       pinnedSourceLabel,
		SourceContentHash: pinnedSourceHash,
		SourceTimestamp:   mustTime(t, pinnedSourceTS),
		StorageTimestamp:  mustTime(t, pinnedSourceTS),
		SignedAt:          mustTime(t, pinnedSourceTS),
	}
}

func writeProverFixture(t *testing.T, line []byte) (logPath, keysDir string) {
	t.Helper()
	dir := t.TempDir()
	logPath = dir + "/log.jsonl"
	if err := writeFile(logPath, append(line, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	keysDir = dir + "/keys"
	if err := mkdirAll(keysDir+"/Lemma", 0o755); err != nil {
		t.Fatal(err)
	}
	keyPath := keysDir + "/Lemma/" + fixtureKeyID + ".public.pem"
	if err := writeFile(keyPath, []byte(fixturePubPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	return logPath, keysDir
}
