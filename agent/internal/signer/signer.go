// Package signer produces signed envelope JSONL lines byte-compatible
// with Python's EvidenceLog.append. Mirrors the hash-and-sign flow at
// src/lemma/services/evidence_log.py:146-196.
package signer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/JoshDoesIT/Lemma/agent/internal/canonjson"
	agentcrypto "github.com/JoshDoesIT/Lemma/agent/internal/crypto"
)

const genesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Inputs gathers everything Build needs.
type Inputs struct {
	EventJSON         json.RawMessage   // the OCSF event payload
	PrevHash          string            // hex; defaults to "0"*64 when empty
	Producer          string            // for the signer_key_id namespace
	KeyID             string            // resolved upstream via keystore.LoadActive
	PrivateKey        ed25519.PrivateKey
	SourceLabel       string // operator-supplied (e.g. file path or "-")
	SourceContentHash string // hex sha256 of the raw input bytes
	SourceTimestamp   time.Time
	StorageTimestamp  time.Time
	SignedAt          time.Time
}

// Build returns one envelope serialized as a single JSONL line (no
// trailing newline). The caller writes it to stdout or appends it to a
// log file.
//
// Flow:
//  1. Validate inputs.
//  2. Build the source-stage provenance record.
//  3. Compute canonical signed bytes = canonjson({event, provenance: [source]}).
//  4. entry_hash = sha256(prev_hash_ascii || canonical).
//  5. signature = ed25519.Sign(priv, entry_hash_raw_bytes).
//  6. Append the storage-stage record (excluded from signed bytes).
//  7. Marshal the envelope in Pydantic's field-declaration order.
func Build(in Inputs) ([]byte, error) {
	if len(in.EventJSON) == 0 {
		return nil, errors.New("signer: empty event")
	}
	if in.KeyID == "" {
		return nil, errors.New("signer: KeyID required")
	}
	if len(in.PrivateKey) == 0 {
		return nil, errors.New("signer: PrivateKey required")
	}
	if !json.Valid(in.EventJSON) {
		return nil, errors.New("signer: event is not valid JSON")
	}

	prevHash := in.PrevHash
	if prevHash == "" {
		prevHash = genesisPrevHash
	}

	source := provRecord{
		Stage:       "source",
		Actor:       "lemma-agent-sign:" + in.SourceLabel,
		Timestamp:   isoZ(in.SourceTimestamp),
		ContentHash: in.SourceContentHash,
	}

	// Canonical signed bytes — must match _canonical_signed_bytes byte-for-byte.
	eventDecoded, err := decodeWithNumber(in.EventJSON)
	if err != nil {
		return nil, fmt.Errorf("signer: decode event: %w", err)
	}
	signedPayload := map[string]any{
		"event":      eventDecoded,
		"provenance": []any{source.toMap()},
	}
	canon, err := canonjson.Marshal(signedPayload)
	if err != nil {
		return nil, fmt.Errorf("signer: canonicalise: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(canon)
	entryHash := hex.EncodeToString(h.Sum(nil))

	sigHex := agentcrypto.SignEntryHash(in.PrivateKey, entryHash)
	if sigHex == "" {
		return nil, errors.New("signer: SignEntryHash failed")
	}

	storage := provRecord{
		Stage:       "storage",
		Actor:       "lemma-agent",
		Timestamp:   isoZ(in.StorageTimestamp),
		ContentHash: entryHash,
	}

	// Marshal in Pydantic's SignedEvidence field-declaration order so the
	// on-disk wire form is indistinguishable from Python's append output.
	out := wireEnvelope{
		Event:       in.EventJSON,
		PrevHash:    prevHash,
		EntryHash:   entryHash,
		Signature:   sigHex,
		SignerKeyID: in.KeyID,
		SignedAt:    isoZ(in.SignedAt),
		Provenance:  []provRecord{source, storage},
	}
	return json.Marshal(out)
}

// wireEnvelope mirrors models/signed_evidence.py::SignedEvidence's field
// declaration order so json.Marshal emits keys in the same sequence
// Pydantic does.
type wireEnvelope struct {
	Event       json.RawMessage `json:"event"`
	PrevHash    string          `json:"prev_hash"`
	EntryHash   string          `json:"entry_hash"`
	Signature   string          `json:"signature"`
	SignerKeyID string          `json:"signer_key_id"`
	SignedAt    string          `json:"signed_at"`
	Provenance  []provRecord    `json:"provenance"`
}

// provRecord mirrors models/signed_evidence.py::ProvenanceRecord.
type provRecord struct {
	Stage       string `json:"stage"`
	Actor       string `json:"actor"`
	Timestamp   string `json:"timestamp"`
	ContentHash string `json:"content_hash"`
}

func (p provRecord) toMap() map[string]any {
	return map[string]any{
		"stage":        p.Stage,
		"actor":        p.Actor,
		"timestamp":    p.Timestamp,
		"content_hash": p.ContentHash,
	}
}

// isoZ formats a UTC timestamp as Pydantic does in model_dump_json:
//
//	2026-04-30T12:34:56.789012Z
//
// Trailing zeros are dropped (Python uses up to microsecond precision;
// trailing zeros suppressed). Non-UTC inputs are converted to UTC first.
func isoZ(t time.Time) string {
	t = t.UTC()
	// Match Pydantic's microsecond-precision format with `Z` suffix.
	s := t.Format("2006-01-02T15:04:05.000000")
	// Pydantic suppresses trailing-zero microseconds: 12:34:56.000000 -> 12:34:56
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	return s + "Z"
}

func decodeWithNumber(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
