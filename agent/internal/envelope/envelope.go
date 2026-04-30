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
