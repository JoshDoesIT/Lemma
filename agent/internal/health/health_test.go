package health

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSnapshotZeroStateIsEmptyButValid(t *testing.T) {
	dir := t.TempDir()
	keysDir := t.TempDir()
	snap, err := Snapshot(SnapshotInput{
		Version:     "0.7.0",
		EvidenceDir: dir,
		KeysDir:     keysDir,
		StartedAt:   time.Now().Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Snapshot on empty dirs: %v", err)
	}
	if snap.Version != "0.7.0" {
		t.Errorf("Version=%q, want 0.7.0", snap.Version)
	}
	if snap.EvidenceCount != 0 {
		t.Errorf("EvidenceCount=%d, want 0 on empty dir", snap.EvidenceCount)
	}
	if snap.ProducerCount != 0 {
		t.Errorf("ProducerCount=%d, want 0 on empty keys-dir", snap.ProducerCount)
	}
	if snap.LastSignedAt != "" {
		t.Errorf("LastSignedAt=%q, want empty on no envelopes", snap.LastSignedAt)
	}
	if snap.UptimeSeconds < 3500 {
		t.Errorf("UptimeSeconds=%d, want ≥ 3500 (started 1h ago)", snap.UptimeSeconds)
	}
}

func TestSnapshotCountsEnvelopesAcrossDayFiles(t *testing.T) {
	dir := t.TempDir()
	keysDir := t.TempDir()
	day1 := filepath.Join(dir, "2026-05-01.jsonl")
	day2 := filepath.Join(dir, "2026-05-02.jsonl")
	if err := os.WriteFile(day1,
		[]byte(`{"signed_at":"2026-05-01T12:00:00Z"}`+"\n"+
			`{"signed_at":"2026-05-01T13:00:00Z"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(day2,
		[]byte(`{"signed_at":"2026-05-02T08:00:00Z"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	snap, err := Snapshot(SnapshotInput{
		Version:     "0.7.0",
		EvidenceDir: dir,
		KeysDir:     keysDir,
		StartedAt:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.EvidenceCount != 3 {
		t.Errorf("EvidenceCount=%d, want 3", snap.EvidenceCount)
	}
	// Latest signed_at is the most recent across all day files.
	if snap.LastSignedAt != "2026-05-02T08:00:00Z" {
		t.Errorf("LastSignedAt=%q, want 2026-05-02T08:00:00Z", snap.LastSignedAt)
	}
}

func TestSnapshotIgnoresBlankLines(t *testing.T) {
	dir := t.TempDir()
	keysDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "2026-05-02.jsonl"),
		[]byte(`{"signed_at":"2026-05-02T12:00:00Z"}`+"\n\n   \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := Snapshot(SnapshotInput{
		EvidenceDir: dir,
		KeysDir:     keysDir,
		StartedAt:   time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if snap.EvidenceCount != 1 {
		t.Errorf("EvidenceCount=%d, want 1 (blank lines must not count)", snap.EvidenceCount)
	}
}

func TestSnapshotCountsProducerSubdirsInKeysDir(t *testing.T) {
	dir := t.TempDir()
	keysDir := t.TempDir()
	for _, p := range []string{"Lemma", "Okta", "AWS"} {
		if err := os.MkdirAll(filepath.Join(keysDir, p), 0o755); err != nil {
			t.Fatal(err)
		}
		// Each producer dir needs at least a meta.json file to count as a producer.
		if err := os.WriteFile(filepath.Join(keysDir, p, "meta.json"),
			[]byte(`{"keys":[]}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A bare file at the keys-dir root is not a producer.
	if err := os.WriteFile(filepath.Join(keysDir, "stray.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	snap, err := Snapshot(SnapshotInput{
		EvidenceDir: dir,
		KeysDir:     keysDir,
		StartedAt:   time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if snap.ProducerCount != 3 {
		t.Errorf("ProducerCount=%d, want 3", snap.ProducerCount)
	}
}

func TestSnapshotMissingDirsAreEmptyNotErrors(t *testing.T) {
	snap, err := Snapshot(SnapshotInput{
		Version:     "0.7.0",
		EvidenceDir: "/nonexistent/evidence",
		KeysDir:     "/nonexistent/keys",
		StartedAt:   time.Now(),
	})
	if err != nil {
		t.Errorf("missing dirs should not error; got %v", err)
	}
	if snap.EvidenceCount != 0 || snap.ProducerCount != 0 {
		t.Errorf("missing dirs should yield zero counts; got %+v", snap)
	}
}

func TestSnapshotMarshalsAsExpectedJSONShape(t *testing.T) {
	dir := t.TempDir()
	keysDir := t.TempDir()
	snap, err := Snapshot(SnapshotInput{
		Version:     "0.7.0",
		EvidenceDir: dir,
		KeysDir:     keysDir,
		StartedAt:   time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	str := string(data)
	for _, want := range []string{
		`"version":"0.7.0"`,
		`"evidence_count":0`,
		`"producer_count":0`,
		`"last_signed_at":""`,
		`"uptime_seconds":`,
		`"started_at":`,
	} {
		if !strings.Contains(str, want) {
			t.Errorf("snapshot JSON missing %q\nfull:\n%s", want, str)
		}
	}
}
