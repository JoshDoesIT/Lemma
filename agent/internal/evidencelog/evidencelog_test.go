package evidencelog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeEnvelope builds a minimal envelope JSONL line for fixture purposes.
// Only entry_hash + event matter for the disk-state tests; everything
// else stays placeholder.
func makeEnvelope(t *testing.T, entryHash, uid string) string {
	t.Helper()
	env := map[string]any{
		"event": map[string]any{
			"class_uid": 2003,
			"metadata":  map[string]any{"uid": uid},
		},
		"prev_hash":     "0000000000000000000000000000000000000000000000000000000000000000",
		"entry_hash":    entryHash,
		"signature":     "00",
		"signer_key_id": "ed25519:00",
		"signed_at":     "2026-05-01T00:00:00Z",
		"provenance":    []any{},
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLatestEntryHashReturnsGenesisForEmptyDir(t *testing.T) {
	dir := t.TempDir()
	log := Log{Dir: dir}
	got, err := log.LatestEntryHash()
	if err != nil {
		t.Fatalf("LatestEntryHash: %v", err)
	}
	if got != GenesisHash {
		t.Errorf("got %q, want genesis", got)
	}
}

func TestLatestEntryHashReturnsGenesisForEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "2026-05-01.jsonl"), "")
	writeFile(t, filepath.Join(dir, "2026-05-02.jsonl"), "\n\n")
	log := Log{Dir: dir}
	got, err := log.LatestEntryHash()
	if err != nil {
		t.Fatalf("LatestEntryHash: %v", err)
	}
	if got != GenesisHash {
		t.Errorf("got %q, want genesis", got)
	}
}

func TestLatestEntryHashReturnsLastEntryFromSingleFile(t *testing.T) {
	dir := t.TempDir()
	body := makeEnvelope(t, "aaaaaa", "e1") + "\n" + makeEnvelope(t, "bbbbbb", "e2") + "\n"
	writeFile(t, filepath.Join(dir, "2026-05-01.jsonl"), body)
	log := Log{Dir: dir}
	got, err := log.LatestEntryHash()
	if err != nil {
		t.Fatalf("LatestEntryHash: %v", err)
	}
	if got != "bbbbbb" {
		t.Errorf("got %q, want %q", got, "bbbbbb")
	}
}

func TestLatestEntryHashWalksReverseLexically(t *testing.T) {
	// Two files: older 2026-01-01 has "old"; newer 2026-05-02 has "new".
	// Reverse-lexical walk picks 2026-05-02 first → returns "new".
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "2026-01-01.jsonl"), makeEnvelope(t, "old", "old")+"\n")
	writeFile(t, filepath.Join(dir, "2026-05-02.jsonl"), makeEnvelope(t, "new", "new")+"\n")
	log := Log{Dir: dir}
	got, err := log.LatestEntryHash()
	if err != nil {
		t.Fatalf("LatestEntryHash: %v", err)
	}
	if got != "new" {
		t.Errorf("got %q, want %q (reverse-lexical walk)", got, "new")
	}
}

func TestLatestEntryHashSkipsEmptyFilesToOlderPopulated(t *testing.T) {
	// Empty newer file → walk back to older populated one.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "2026-01-01.jsonl"), makeEnvelope(t, "old", "old")+"\n")
	writeFile(t, filepath.Join(dir, "2026-05-02.jsonl"), "")
	log := Log{Dir: dir}
	got, err := log.LatestEntryHash()
	if err != nil {
		t.Fatalf("LatestEntryHash: %v", err)
	}
	if got != "old" {
		t.Errorf("got %q, want %q", got, "old")
	}
}

func TestFilePathForTimeFormatsAsYYYYMMDD(t *testing.T) {
	dir := "/tmp/evi"
	log := Log{Dir: dir}
	ts := time.Date(2026, 5, 2, 13, 45, 0, 0, time.UTC)
	got := log.FilePathForTime(ts)
	want := "/tmp/evi/2026-05-02.jsonl"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFilePathForTimeUsesUTCNotLocal(t *testing.T) {
	// Even if the time is in a non-UTC location, the file name should
	// reflect the UTC date.
	dir := "/tmp/evi"
	log := Log{Dir: dir}
	loc, _ := time.LoadLocation("America/Los_Angeles")
	// 2026-05-02T01:00:00-07:00 = 2026-05-02T08:00:00Z (still May 2 UTC).
	ts := time.Date(2026, 5, 2, 1, 0, 0, 0, loc)
	got := log.FilePathForTime(ts)
	if !strings.HasSuffix(got, "2026-05-02.jsonl") {
		t.Errorf("got %q, want UTC-formatted date", got)
	}
}

func TestDedupKeysForFilesReturnsPopulatedSet(t *testing.T) {
	dir := t.TempDir()
	body := makeEnvelope(t, "h1", "uid-A") + "\n" + makeEnvelope(t, "h2", "uid-B") + "\n"
	path := filepath.Join(dir, "2026-05-01.jsonl")
	writeFile(t, path, body)
	log := Log{Dir: dir}
	keys, err := log.DedupKeysForFiles([]string{path})
	if err != nil {
		t.Fatalf("DedupKeysForFiles: %v", err)
	}
	if _, ok := keys["uid:uid-A"]; !ok {
		t.Errorf("expected uid:uid-A in keys; got %v", keys)
	}
	if _, ok := keys["uid:uid-B"]; !ok {
		t.Errorf("expected uid:uid-B in keys; got %v", keys)
	}
}

func TestDedupKeysForFilesSilentlySkipsMissingFile(t *testing.T) {
	dir := t.TempDir()
	log := Log{Dir: dir}
	keys, err := log.DedupKeysForFiles([]string{filepath.Join(dir, "nonexistent.jsonl")})
	if err != nil {
		t.Errorf("expected no error for missing file, got %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected empty key set for missing file, got %d keys", len(keys))
	}
}

func TestDedupKeyForEventWithUid(t *testing.T) {
	event := json.RawMessage(`{"class_uid":2003,"metadata":{"uid":"my-uid","product":{"name":"X"}}}`)
	got, err := DedupKey(event)
	if err != nil {
		t.Fatalf("DedupKey: %v", err)
	}
	if got != "uid:my-uid" {
		t.Errorf("got %q, want %q", got, "uid:my-uid")
	}
}

func TestDedupKeyForEventWithoutUidFallsBackToHash(t *testing.T) {
	event := json.RawMessage(`{"class_uid":2003,"metadata":{}}`)
	got, err := DedupKey(event)
	if err != nil {
		t.Fatalf("DedupKey: %v", err)
	}
	if !strings.HasPrefix(got, "hash:") {
		t.Errorf("got %q, want prefix hash:", got)
	}
	if len(got) != len("hash:")+64 {
		t.Errorf("hash key should be sha256 hex (64 chars), got %d-char value: %s",
			len(got)-len("hash:"), got)
	}
}

func TestDedupKeyForEventWithEmptyUidFallsBackToHash(t *testing.T) {
	event := json.RawMessage(`{"class_uid":2003,"metadata":{"uid":""}}`)
	got, err := DedupKey(event)
	if err != nil {
		t.Fatalf("DedupKey: %v", err)
	}
	if !strings.HasPrefix(got, "hash:") {
		t.Errorf("empty uid should fall through to hash, got %q", got)
	}
}

func TestDedupKeyDifferentEventsProduceDifferentHashKeys(t *testing.T) {
	a, _ := DedupKey(json.RawMessage(`{"class_uid":2003,"metadata":{}}`))
	b, _ := DedupKey(json.RawMessage(`{"class_uid":2004,"metadata":{}}`))
	if a == b {
		t.Errorf("different events produced same hash key: %q", a)
	}
}

func TestAppendCreatesFileIfMissing(t *testing.T) {
	dir := t.TempDir()
	log := Log{Dir: dir}
	path := filepath.Join(dir, "2026-05-02.jsonl")
	if err := log.Append(path, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":1}` + "\n"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestAppendDoesNotTruncateExistingFile(t *testing.T) {
	dir := t.TempDir()
	log := Log{Dir: dir}
	path := filepath.Join(dir, "2026-05-02.jsonl")
	if err := log.Append(path, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := log.Append(path, []byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":1}\n{\"a\":2}\n"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
