// Package health computes a point-in-time snapshot of the agent's
// observable state from disk: how many envelopes have been signed,
// when the most recent envelope was signed, how many producers the
// agent has keys for, and how long the process has been running.
//
// The snapshot is what `lemma-agent serve`'s /health endpoint returns
// and what `lemma agent status` parses on the operator side. It is
// derived purely from disk + an injected start time — no in-memory
// counters survive restarts, which keeps the agent stateless.
package health

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Snapshot is the JSON payload of GET /health.
type SnapshotResult struct {
	Version       string `json:"version"`
	EvidenceCount int    `json:"evidence_count"`
	LastSignedAt  string `json:"last_signed_at"`
	ProducerCount int    `json:"producer_count"`
	StartedAt     string `json:"started_at"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// SnapshotInput collects the inputs needed to compute a snapshot:
// agent version, where evidence lives, where producer keys live, and
// when the agent process started.
type SnapshotInput struct {
	Version     string
	EvidenceDir string
	KeysDir     string
	StartedAt   time.Time
}

// Snapshot walks EvidenceDir for *.jsonl files, counts non-blank lines
// across all of them, picks the most recent signed_at across all
// envelopes, and counts producer subdirectories under KeysDir. Missing
// directories are treated as empty (no error) so a freshly-deployed
// agent serves a meaningful /health response.
func Snapshot(in SnapshotInput) (SnapshotResult, error) {
	out := SnapshotResult{
		Version:       in.Version,
		StartedAt:     in.StartedAt.UTC().Format(time.RFC3339),
		UptimeSeconds: int64(time.Since(in.StartedAt).Seconds()),
	}

	count, latest, err := walkEvidence(in.EvidenceDir)
	if err != nil {
		return out, err
	}
	out.EvidenceCount = count
	out.LastSignedAt = latest

	producers, err := countProducers(in.KeysDir)
	if err != nil {
		return out, err
	}
	out.ProducerCount = producers

	return out, nil
}

func walkEvidence(dir string) (count int, latest string, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, "", nil
		}
		return 0, "", err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		c, l, err := scanFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return 0, "", err
		}
		count += c
		if l != "" && l > latest {
			latest = l
		}
	}
	return count, latest, nil
}

func scanFile(path string) (count int, latestSignedAt string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		count++
		var env struct {
			SignedAt string `json:"signed_at"`
		}
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			// A malformed line still counts as an envelope from the
			// agent's perspective — the verifier will catch it. We
			// just can't extract a signed_at from it.
			continue
		}
		if env.SignedAt != "" && env.SignedAt > latestSignedAt {
			latestSignedAt = env.SignedAt
		}
	}
	return count, latestSignedAt, scanner.Err()
}

func countProducers(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// A producer dir must carry a meta.json — bare directories
		// (e.g. left over from rm -rf) don't count as producers.
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "meta.json")); err == nil {
			n++
		}
	}
	return n, nil
}
