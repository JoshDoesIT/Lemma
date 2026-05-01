// Package envelope parses Lemma signed-evidence envelopes (one per JSONL
// line in `.lemma/evidence/*.jsonl`) and recomputes their chained entry
// hashes byte-identically to the Python `_canonical_signed_bytes` path.
package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/JoshDoesIT/Lemma/agent/internal/canonjson"
)

// Envelope mirrors src/lemma/models/signed_evidence.py::SignedEvidence on
// the wire. Event and provenance entries are kept as raw JSON so the
// canonical re-serialisation is deterministic regardless of how the
// underlying OCSF event nests.
type Envelope struct {
	Event       json.RawMessage   `json:"event"`
	PrevHash    string            `json:"prev_hash"`
	EntryHash   string            `json:"entry_hash"`
	Signature   string            `json:"signature"`
	SignerKeyID string            `json:"signer_key_id"`
	SignedAt    string            `json:"signed_at"`
	Provenance  []json.RawMessage `json:"provenance"`
}

// Parse reads one JSONL line into an Envelope.
func Parse(line []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return nil, fmt.Errorf("envelope: parse: %w", err)
	}
	return &env, nil
}

// ComputeEntryHash returns the SHA-256 hex digest of
//
//	prev_hash_ascii_bytes || canonjson({event, provenance_excluding_storage})
//
// matching `_canonical_signed_bytes` + the chain hash from Python's
// EvidenceLog. Storage-stage provenance is filtered out before
// canonicalisation; this is the same filter EvidenceLog applies before
// signing (storage records are appended after the signature, never
// covered by it).
func (e *Envelope) ComputeEntryHash() (string, error) {
	filtered, err := filterStorageProvenance(e.Provenance)
	if err != nil {
		return "", err
	}
	// Build the canonical {event, provenance} payload by re-decoding each
	// raw piece, walking the structure, sorting keys, and emitting compact
	// bytes. Going through canonjson on the assembled map (rather than
	// concatenating per-field canonical bytes by hand) keeps the
	// "{event:..,provenance:..}" key ordering deterministic too — Python
	// emits them sorted, so canonjson does the same.
	payload := map[string]any{
		"event":      mustDecodeAny(e.Event),
		"provenance": mustDecodeAnySlice(filtered),
	}
	canon, err := canonjson.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("envelope: canonicalise payload: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write(canon)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Producer returns event.metadata.product.name. Matches Python
// evidence_log._producer_of: when any hop is missing or the wrong type
// the function returns "unknown" — the same fallback Python uses, so a
// CRL whose producer is "unknown" can't accidentally match malformed
// envelopes. The error return is reserved for future use; today the
// method always returns nil.
func (e *Envelope) Producer() (string, error) {
	var event map[string]any
	dec := json.NewDecoder(bytes.NewReader(e.Event))
	dec.UseNumber()
	if err := dec.Decode(&event); err != nil {
		return "unknown", nil
	}
	metadata, ok := event["metadata"].(map[string]any)
	if !ok {
		return "unknown", nil
	}
	product, ok := metadata["product"].(map[string]any)
	if !ok {
		return "unknown", nil
	}
	name, ok := product["name"].(string)
	if !ok || name == "" {
		return "unknown", nil
	}
	return name, nil
}

// SignedAtTime parses the SignedAt wire string into a time.Time. Accepts
// both `Z` and `+HH:MM` suffixes — Python emits `+00:00` for timezone-
// aware datetimes, but bundles produced from external sources may use
// the shorter `Z` form.
func (e *Envelope) SignedAtTime() (time.Time, error) {
	return parseISO8601(e.SignedAt)
}

// parseISO8601 accepts the formats Lemma writes plus a couple of common
// variants. Returns a time.Time in UTC (no information loss for the
// suffixes we accept; Python writes UTC-only timestamps).
func parseISO8601(s string) (time.Time, error) {
	for _, layout := range []string{
		"2006-01-02T15:04:05.000000Z07:00",
		"2006-01-02T15:04:05.999999Z07:00",
		"2006-01-02T15:04:05Z07:00",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("envelope: cannot parse timestamp %q", s)
}

// filterStorageProvenance returns the subset of provenance records whose
// stage is not "storage". Anything that doesn't decode is an error.
func filterStorageProvenance(prov []json.RawMessage) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(prov))
	for _, raw := range prov {
		var probe struct {
			Stage string `json:"stage"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, fmt.Errorf("envelope: parse provenance: %w", err)
		}
		if probe.Stage != "storage" {
			out = append(out, raw)
		}
	}
	return out, nil
}

// mustDecodeAny converts raw JSON to any via UseNumber. It returns nil
// for empty input. Errors are silenced because the envelope-level Parse
// already validated the bytes are JSON; if a sub-tree is malformed the
// canonjson encode will surface that.
func mustDecodeAny(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	return v
}

// mustDecodeAnySlice walks a []json.RawMessage and returns []any.
func mustDecodeAnySlice(raws []json.RawMessage) []any {
	out := make([]any, 0, len(raws))
	for _, r := range raws {
		out = append(out, mustDecodeAny(r))
	}
	return out
}
