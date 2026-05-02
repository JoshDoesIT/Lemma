// Package evidencelog implements the disk-state primitives the agent's
// ingest path needs: per-day file naming, reverse-lexical chain-head
// resolution, dedup-key extraction, and plain append. Mirrors Python's
// EvidenceLog file layout (`<dir>/YYYY-MM-DD.jsonl`) byte-for-byte so a
// log written by Go is interchangeable with one written by Python.
//
// No fsync, no locking. Python doesn't either; mirroring keeps semantics
// identical and the agent stdlib-only.
package evidencelog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// GenesisHash is the prev_hash of the first envelope in a chain.
// Matches Python `_GENESIS_HASH = "0" * 64`.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Log is a directory of YYYY-MM-DD.jsonl files. Pure file-IO; no
// signing, no validation.
type Log struct {
	Dir string
}

// LatestEntryHash returns the entry_hash of the chain head across every
// JSONL file in Log.Dir. Walks files in reverse-lexical order
// (matching Python `evidence_log._latest_entry_hash`); returns
// GenesisHash if no file contains an entry.
func (l Log) LatestEntryHash() (string, error) {
	matches, err := filepath.Glob(filepath.Join(l.Dir, "*.jsonl"))
	if err != nil {
		return "", fmt.Errorf("evidencelog: glob %s: %w", l.Dir, err)
	}
	if len(matches) == 0 {
		return GenesisHash, nil
	}
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	for _, path := range matches {
		hash, err := lastEntryHashIn(path)
		if err != nil {
			return "", err
		}
		if hash != "" {
			return hash, nil
		}
	}
	return GenesisHash, nil
}

// lastEntryHashIn returns the last non-empty line's entry_hash from the
// given file, or "" when the file has no entries.
func lastEntryHashIn(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("evidencelog: open %s: %w", path, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var lastHash string
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var env struct {
			EntryHash string `json:"entry_hash"`
		}
		if err := json.Unmarshal(line, &env); err != nil {
			return "", fmt.Errorf("evidencelog: parse %s: %w", path, err)
		}
		if env.EntryHash != "" {
			lastHash = env.EntryHash
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("evidencelog: scan %s: %w", path, err)
	}
	return lastHash, nil
}

// FilePathForTime returns <Dir>/YYYY-MM-DD.jsonl for the given time,
// computed in UTC. Mirrors Python `evidence_log._log_file()`.
func (l Log) FilePathForTime(t time.Time) string {
	day := t.UTC().Format("2006-01-02")
	return filepath.Join(l.Dir, day+".jsonl")
}

// DedupKeysForFiles loads dedup keys from each given path. Missing files
// are silently skipped. Returns a set keyed on the result of DedupKey
// applied to each envelope's event.
func (l Log) DedupKeysForFiles(paths []string) (map[string]struct{}, error) {
	out := make(map[string]struct{})
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("evidencelog: open %s: %w", path, err)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(strings.TrimSpace(string(line))) == 0 {
				continue
			}
			var env struct {
				Event json.RawMessage `json:"event"`
			}
			if err := json.Unmarshal(line, &env); err != nil {
				f.Close()
				return nil, fmt.Errorf("evidencelog: parse %s: %w", path, err)
			}
			key, err := DedupKey(env.Event)
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("evidencelog: dedup key for %s: %w", path, err)
			}
			out[key] = struct{}{}
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			return nil, fmt.Errorf("evidencelog: scan %s: %w", path, err)
		}
		f.Close()
	}
	return out, nil
}

// Append opens path in append+create mode and writes line + "\n".
// No fsync, no locking — matches Python's EvidenceLog.append.
func (l Log) Append(path string, line []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("evidencelog: mkdir %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("evidencelog: open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("evidencelog: write %s: %w", path, err)
	}
	if _, err := f.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("evidencelog: write newline %s: %w", path, err)
	}
	return nil
}

// DedupKey computes the per-event dedup key. Mirrors Python
// `_dedupe_key(event)`:
//
//   - "uid:<uid>"  when event.metadata.uid is a non-empty string;
//   - "hash:<sha256(event_json)>" otherwise.
//
// The hash form is local to the Go side: Python's variant hashes bytes
// from Pydantic's model_dump_json() (field-declaration order); Go hashes
// the wire JSON as-received. Cross-tool dedup parity for hash-fallback
// entries is not a goal — operators who want it should set
// metadata.uid (the "uid:" path is byte-stable across tools).
func DedupKey(eventJSON json.RawMessage) (string, error) {
	if len(eventJSON) == 0 {
		return "", fmt.Errorf("evidencelog: empty event")
	}
	var probe struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(eventJSON, &probe); err != nil {
		return "", fmt.Errorf("evidencelog: parse event: %w", err)
	}
	if probe.Metadata.UID != "" {
		return "uid:" + probe.Metadata.UID, nil
	}
	h := sha256.Sum256(eventJSON)
	return "hash:" + hex.EncodeToString(h[:]), nil
}
