// Package verifier walks a Lemma signed-evidence JSONL file end-to-end
// and reports per-entry PROVEN / VIOLATED status. Mirrors the envelope
// layer of Python's EvidenceLog.verify_entry — the chain hash, recomputed
// entry hash, Ed25519 signature, and any CRL revocations all combine to
// produce the verdict. Local-lifecycle revocation (the keys/<producer>/
// meta.json source on the Python side) is out of scope; the agent's
// keys-dir is a flat trust store of pinned public keys.
package verifier

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/JoshDoesIT/Lemma/agent/internal/crl"
	"github.com/JoshDoesIT/Lemma/agent/internal/crypto"
	"github.com/JoshDoesIT/Lemma/agent/internal/envelope"
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
//  4. for each CRL in opts.CRLs whose Producer matches the envelope's
//     event.metadata.product.name, if the signer key is revoked at or
//     before the envelope's signed_at, the verdict flips to VIOLATED.
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

	// 4. CRL revocation check
	if len(crls) > 0 {
		producer, _ := env.Producer()
		signedAt, err := env.SignedAtTime()
		if err != nil {
			r.Status = "VIOLATED"
			r.Reason = fmt.Sprintf("parse signed_at: %v", err)
			return r
		}
		for _, list := range crls {
			if list.Producer != producer {
				continue
			}
			revokedAt, reason, ok := list.Lookup(env.SignerKeyID)
			if !ok {
				continue
			}
			// Python uses signed_at >= revoked_at: an entry signed at the
			// revocation instant is VIOLATED. !signedAt.Before(revokedAt)
			// is the same comparison expressed for time.Time.
			if !signedAt.Before(revokedAt) {
				r.Status = "VIOLATED"
				if reason == "" {
					reason = "no reason given"
				}
				r.Reason = fmt.Sprintf(
					"signer key %s was revoked at %s (%s; source: CRL); this entry was signed at or after revocation",
					env.SignerKeyID, revokedAt.Format("2006-01-02T15:04:05Z07:00"), reason,
				)
				return r
			}
		}
	}

	r.Status = "PROVEN"
	return r
}

// short truncates a 64-char hash for diagnostic output.
func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
