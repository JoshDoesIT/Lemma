// Package verifier walks a Lemma signed-evidence JSONL file end-to-end
// and reports per-entry PROVEN / VIOLATED status. Mirrors the envelope
// layer of Python's EvidenceLog.verify_entry — the chain hash, recomputed
// entry hash, Ed25519 signature, and any revocations from local lifecycle
// (`<keys-dir>/<producer>/meta.json`) and supplied CRLs all combine to
// produce the verdict. Local + CRL sources merge with "earlier wins" per
// Python evidence_log.py:340-356.
package verifier

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/JoshDoesIT/Lemma/agent/internal/crl"
	"github.com/JoshDoesIT/Lemma/agent/internal/crypto"
	"github.com/JoshDoesIT/Lemma/agent/internal/envelope"
	"github.com/JoshDoesIT/Lemma/agent/internal/keystore"
)

// Options threads optional inputs into Verify. Today only CRLs.
type Options struct {
	// CRLs is the set of already-trusted RevocationList documents to
	// apply per-envelope. The verifier does NOT re-verify CRL signatures;
	// the caller (typically agent main) does that once before this call.
	CRLs []*crl.List
}

const genesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Result is the per-envelope outcome.
type Result struct {
	EntryHash string // claimed hash from the envelope
	Status    string // "PROVEN" or "VIOLATED"
	Reason    string // empty when PROVEN; one-line diagnostic otherwise
}

// Verify reads jsonlPath line-by-line. For each envelope:
//
//  1. prev_hash matches the prior entry's entry_hash (genesis = 64×"0")
//  2. computed entry hash equals the claimed entry_hash
//  3. the Ed25519 signature decoded from the envelope verifies against
//     the producer's public key under <keysDir>/<safe_producer>/<key_id>.public.pem
//  4. revocation check from two sources, earlier wins:
//     - local lifecycle at <keysDir>/<producer>/meta.json (the same
//       file Python's crypto.read_lifecycle reads), where status=REVOKED
//       and revoked_at is set;
//     - any CRL in opts.CRLs whose Producer matches the envelope's
//       event.metadata.product.name.
//     If the effective revoked_at is at or before the envelope's
//     signed_at, the verdict flips to VIOLATED with the source named.
//
// Returns one Result per envelope in order. The function returns an error
// only when the file can't be read or a line can't be parsed at all;
// individual signature/chain failures surface as VIOLATED Results.
func Verify(jsonlPath, keysDir string, opts Options) ([]Result, error) {
	f, err := os.Open(jsonlPath)
	if err != nil {
		return nil, fmt.Errorf("verifier: open %s: %w", jsonlPath, err)
	}
	defer f.Close()

	var results []Result
	prevEntryHash := genesisPrevHash

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // OCSF events can be large
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		env, err := envelope.Parse(line)
		if err != nil {
			return nil, fmt.Errorf("verifier: parse line: %w", err)
		}

		r := verifyOne(env, prevEntryHash, keysDir, opts.CRLs)
		results = append(results, r)
		prevEntryHash = env.EntryHash
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("verifier: scan: %w", err)
	}
	return results, nil
}

// verifyOne runs the four checks against a single envelope. Returns
// VIOLATED on the first failed check; never returns an error.
func verifyOne(env *envelope.Envelope, expectedPrev string, keysDir string, crls []*crl.List) Result {
	r := Result{EntryHash: env.EntryHash}

	// 1. chain
	if env.PrevHash != expectedPrev {
		r.Status = "VIOLATED"
		r.Reason = fmt.Sprintf("chain prev_hash mismatch: got %s, want %s",
			short(env.PrevHash), short(expectedPrev))
		return r
	}

	// 2. recompute entry hash
	computed, err := env.ComputeEntryHash()
	if err != nil {
		r.Status = "VIOLATED"
		r.Reason = fmt.Sprintf("compute entry hash: %v", err)
		return r
	}
	if computed != env.EntryHash {
		r.Status = "VIOLATED"
		r.Reason = fmt.Sprintf("entry hash mismatch: computed %s, claimed %s",
			short(computed), short(env.EntryHash))
		return r
	}

	// 3. signature
	pemBytes, err := crypto.LoadPublicKeyByID(keysDir, env.SignerKeyID)
	if err != nil {
		r.Status = "VIOLATED"
		r.Reason = err.Error()
		return r
	}
	pub, err := crypto.LoadPublicKey(pemBytes)
	if err != nil {
		r.Status = "VIOLATED"
		r.Reason = fmt.Sprintf("load public key: %v", err)
		return r
	}
	if !crypto.VerifyEntryHash(pub, env.EntryHash, env.Signature) {
		r.Status = "VIOLATED"
		r.Reason = "signature does not verify"
		return r
	}

	// 4. Revocation check — local lifecycle + CRL, earlier wins.
	producer, _ := env.Producer()
	signedAt, parseErr := env.SignedAtTime()
	if parseErr != nil {
		r.Status = "VIOLATED"
		r.Reason = fmt.Sprintf("parse signed_at: %v", parseErr)
		return r
	}

	localTS, localReason, hasLocal := lookupLocalRevocation(keysDir, producer, env.SignerKeyID)
	crlTS, crlReason, hasCRL := lookupCRLRevocation(crls, producer, env.SignerKeyID)

	effective, reason, source := mergeRevocations(
		localTS, localReason, hasLocal,
		crlTS, crlReason, hasCRL,
	)
	if source != "" && !signedAt.Before(effective) {
		if reason == "" {
			reason = "no reason given"
		}
		r.Status = "VIOLATED"
		r.Reason = fmt.Sprintf(
			"signer key %s was revoked at %s (%s; source: %s); this entry was signed at or after revocation",
			env.SignerKeyID, effective.Format("2006-01-02T15:04:05Z07:00"), reason, source,
		)
		return r
	}

	r.Status = "PROVEN"
	return r
}

// lookupLocalRevocation reads the producer's local lifecycle and reports
// whether keyID is REVOKED there.
func lookupLocalRevocation(keysDir, producer, keyID string) (time.Time, string, bool) {
	lc, ok, err := keystore.LoadLifecycle(keysDir, producer)
	if err != nil || !ok {
		return time.Time{}, "", false
	}
	return lc.RevokedAt(keyID)
}

// lookupCRLRevocation finds the first CRL whose producer matches and
// whose revocation list names keyID. Returns the timestamp + reason if
// found.
func lookupCRLRevocation(crls []*crl.List, producer, keyID string) (time.Time, string, bool) {
	for _, list := range crls {
		if list.Producer != producer {
			continue
		}
		if t, r, ok := list.Lookup(keyID); ok {
			return t, r, true
		}
	}
	return time.Time{}, "", false
}

// mergeRevocations applies the "earlier wins" rule from Python
// evidence_log.py:340-356. Returns zero time + empty source when neither
// source flagged the key.
func mergeRevocations(
	localTS time.Time, localReason string, hasLocal bool,
	crlTS time.Time, crlReason string, hasCRL bool,
) (time.Time, string, string) {
	switch {
	case hasLocal && hasCRL:
		// Earlier wins; on a tie the local lifecycle wins (defensive,
		// matches Python's `if local_revoked_at <= crl_revoked_at`).
		if !localTS.After(crlTS) {
			return localTS, localReason, "local lifecycle"
		}
		return crlTS, crlReason, "CRL"
	case hasLocal:
		return localTS, localReason, "local lifecycle"
	case hasCRL:
		return crlTS, crlReason, "CRL"
	default:
		return time.Time{}, "", ""
	}
}

// short truncates a 64-char hash for diagnostic output.
func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
