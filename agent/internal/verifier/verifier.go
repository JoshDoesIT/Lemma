// Package verifier walks a Lemma signed-evidence JSONL file end-to-end
// and reports per-entry PROVEN / VIOLATED status. Mirrors the envelope
// layer of Python's EvidenceLog.verify_entry — the chain hash, recomputed
// entry hash, and Ed25519 signature must all check out for a PROVEN
// result. CRL / lifecycle revocation is out of scope (deferred to a
// later #25 slice).
package verifier

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/JoshDoesIT/Lemma/agent/internal/crypto"
	"github.com/JoshDoesIT/Lemma/agent/internal/envelope"
)

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
//
// Returns one Result per envelope in order. The function returns an error
// only when the file can't be read or a line can't be parsed at all;
// individual signature/chain failures surface as VIOLATED Results.
func Verify(jsonlPath, keysDir string) ([]Result, error) {
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

		r := verifyOne(env, prevEntryHash, keysDir)
		results = append(results, r)
		prevEntryHash = env.EntryHash
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("verifier: scan: %w", err)
	}
	return results, nil
}

// verifyOne runs the three checks against a single envelope. Returns
// VIOLATED on the first failed check; never returns an error.
func verifyOne(env *envelope.Envelope, expectedPrev string, keysDir string) Result {
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
	pemBytes, err := loadPublicKeyByID(keysDir, env.SignerKeyID)
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

	r.Status = "PROVEN"
	return r
}

// loadPublicKeyByID looks up a producer's public PEM by key ID. Lemma
// stores keys under <keysDir>/<producer>/<key_id>.public.pem; the
// envelope itself does not name the producer (the storage record's
// actor is the writer module, e.g. "lemma.services.evidence_log",
// not the producer-key namespace, e.g. "Lemma"). The verifier walks
// the immediate subdirectories of keysDir looking for a file matching
// the envelope's signer_key_id. signer_key_id is a SHA-256 prefix of
// the public-key bytes, so collisions across producers are not a
// concern in practice.
func loadPublicKeyByID(keysDir, signerKeyID string) ([]byte, error) {
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, fmt.Errorf("read keys-dir %s: %w", keysDir, err)
	}
	candidate := signerKeyID + ".public.pem"
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(keysDir, e.Name(), candidate)
		data, err := os.ReadFile(path)
		if err == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("public key not found for key_id %s under %s", signerKeyID, keysDir)
}

// short truncates a 64-char hash for diagnostic output.
func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
