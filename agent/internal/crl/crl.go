// Package crl parses and verifies Lemma RevocationList documents.
// Mirrors src/lemma/services/crypto.py::_crl_canonical_bytes byte-for-byte
// so a CRL signed by Python verifies in Go and vice versa.
package crl

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/JoshDoesIT/Lemma/agent/internal/canonjson"
)

// Entry is one revoked-key record in a CRL.
type Entry struct {
	KeyID     string
	RevokedAt time.Time
	Reason    string

	// revokedAtRaw preserves the exact wire string fed into the
	// canonical-bytes computation. Go's time.Time.MarshalJSON would
	// otherwise emit a slightly different format than Python's
	// datetime.isoformat(), breaking signature verification.
	revokedAtRaw string
}

// List is the parsed RevocationList document.
type List struct {
	Producer    string
	IssuedAt    time.Time
	Revocations []Entry
	IssuerKeyID string
	Signature   string

	issuedAtRaw string
}

// Load reads a CRL JSON file from disk.
func Load(path string) (*List, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crl: read %s: %w", path, err)
	}
	return parse(data)
}

// VerifySignature reconstructs the same canonical bytes Python's
// crypto._crl_canonical_bytes emits and runs Ed25519 verify against pub.
// Returns false on any decode failure or signature mismatch.
func (l *List) VerifySignature(pub ed25519.PublicKey) bool {
	canon, err := l.canonicalBytes()
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(l.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, canon, sig)
}

// Lookup returns (revokedAt, reason, true) when keyID is revoked in
// this CRL; otherwise (zero, "", false).
func (l *List) Lookup(keyID string) (time.Time, string, bool) {
	for _, e := range l.Revocations {
		if e.KeyID == keyID {
			return e.RevokedAt, e.Reason, true
		}
	}
	return time.Time{}, "", false
}

// canonicalBytes mirrors Python's _crl_canonical_bytes: a sorted-key,
// compact-separator JSON of {producer, issued_at, issuer_key_id,
// revocations} where each revocation is {key_id, reason, revoked_at}.
// The signature field is excluded.
//
// Critical timezone-suffix rule: Python signs the canonical form
// produced by datetime.isoformat(), which emits `+00:00` for UTC —
// never `Z`. Pydantic's model_dump_json on the wire uses `Z`, so the
// raw on-wire string and the signed-canonical string differ. We
// normalize by replacing a trailing `Z` with `+00:00` here.
func (l *List) canonicalBytes() ([]byte, error) {
	revs := make([]any, 0, len(l.Revocations))
	for _, e := range l.Revocations {
		revs = append(revs, map[string]any{
			"key_id":     e.KeyID,
			"reason":     e.Reason,
			"revoked_at": canonicalizeTimestamp(e.revokedAtRaw),
		})
	}
	payload := map[string]any{
		"producer":      l.Producer,
		"issued_at":     canonicalizeTimestamp(l.issuedAtRaw),
		"issuer_key_id": l.IssuerKeyID,
		"revocations":   revs,
	}
	return canonjson.Marshal(payload)
}

// canonicalizeTimestamp normalizes a UTC ISO 8601 timestamp to the form
// Python's datetime.isoformat() produces. The only transformation today
// is `Z` -> `+00:00`; non-UTC offsets pass through unchanged.
func canonicalizeTimestamp(ts string) string {
	if len(ts) > 0 && ts[len(ts)-1] == 'Z' {
		return ts[:len(ts)-1] + "+00:00"
	}
	return ts
}

// parse decodes the CRL JSON, capturing both the parsed time.Time values
// (used for verdict comparisons) and the raw timestamp strings (used for
// signature reconstruction).
func parse(data []byte) (*List, error) {
	var raw struct {
		Producer    string `json:"producer"`
		IssuedAt    string `json:"issued_at"`
		Revocations []struct {
			KeyID     string `json:"key_id"`
			RevokedAt string `json:"revoked_at"`
			Reason    string `json:"reason"`
		} `json:"revocations"`
		IssuerKeyID string `json:"issuer_key_id"`
		Signature   string `json:"signature"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("crl: parse: %w", err)
	}

	issuedAt, err := parseISO8601(raw.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("crl: parse issued_at: %w", err)
	}
	revs := make([]Entry, 0, len(raw.Revocations))
	for i, r := range raw.Revocations {
		revokedAt, err := parseISO8601(r.RevokedAt)
		if err != nil {
			return nil, fmt.Errorf("crl: parse revocations[%d].revoked_at: %w", i, err)
		}
		revs = append(revs, Entry{
			KeyID:        r.KeyID,
			RevokedAt:    revokedAt,
			Reason:       r.Reason,
			revokedAtRaw: r.RevokedAt,
		})
	}
	return &List{
		Producer:    raw.Producer,
		IssuedAt:    issuedAt,
		Revocations: revs,
		IssuerKeyID: raw.IssuerKeyID,
		Signature:   raw.Signature,
		issuedAtRaw: raw.IssuedAt,
	}, nil
}

// parseISO8601 accepts both Python's `+00:00` form and the shorter `Z`
// suffix bundles from external sources may use.
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
	return time.Time{}, fmt.Errorf("cannot parse %q", s)
}
