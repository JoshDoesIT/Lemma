# Lemma Agent

The Lemma Agent is the binary that will run inside target environments
(Kubernetes sidecar, systemd unit, or bare-metal process), forward signed
evidence envelopes to a Control Plane, and pull configuration. It is the
runtime counterpart to the `lemma agent` CLI in the main Python package.

## Status

**Signs and verifies signed evidence logs offline today, including
CRL-driven revocation.** The agent does not yet talk to a Control Plane,
manage evidence on disk, or implement any of the `install` / `status` /
`sync` behaviour described by the CLI surface in
`src/lemma/commands/agent.py`. What it can do, byte-for-byte against the
Python signer:

1. **Verify** a Lemma signed-evidence JSONL — each entry's `prev_hash`
   matches the prior entry's `entry_hash`; recomputing the entry hash
   from the canonical `{event, provenance_excluding_storage}` payload
   yields the claimed value; the Ed25519 signature over the 32-byte
   entry hash verifies under the producer's public key; and for each
   `--crl <path>` whose `producer` matches the envelope's
   `event.metadata.product.name`, the signing key is **not** revoked at
   or before the envelope's `signed_at` (Python's
   `signed_at >= revoked_at` rule). CRL signatures are themselves
   verified against the issuer's public key before any per-envelope
   check runs; a bad CRL aborts the run with exit 1 rather than silently
   being ignored.
2. **Sign** an OCSF event into a complete envelope — given an ACTIVE
   producer key under `--keys-dir`, the agent computes the canonical
   payload, hashes the chain, signs the hash, and emits a single JSONL
   line indistinguishable from what Python's `EvidenceLog.append`
   produces.

The agent is **stateless** for both subcommands. `verify` reads a JSONL
file and exits; `sign` reads one event and emits one envelope.
Operators handle log-file management, chain bookkeeping (passing
`--prev-hash` from the prior entry), and dedup themselves — those are a
later slice.

**Caveat for sign**: the input event must already be in the form
Python's OCSF Pydantic models would emit (default fields like
`severity_id`, `status_id`, `message` set explicitly). Pre-normalize
through `lemma.services.ocsf_normalizer.normalize` if you're starting
from a partial OCSF event; otherwise the resulting envelope won't
verify on the Python side because Pydantic adds defaults during
verification.

That bridges Python and Go through the envelope format and gives every
later slice (forwarding, mTLS sync, agent-side evidence load) something
concrete to build on.

## Build

Requires Go 1.23 or newer.

```bash
cd agent
go build -o lemma-agent .
```

## Usage

### Verify

```bash
./lemma-agent verify <evidence.jsonl> --keys-dir <dir> [--crl <path>]...
```

`<dir>` is the directory containing producer subdirectories with
`<key_id>.public.pem` files — the same layout Lemma writes under
`.lemma/keys/`. The agent walks every subdirectory looking for the
matching key, so a flat trust-store with multiple producers works too.

`--crl <path>` is repeatable (one per producer in a multi-producer
bundle). When omitted, the agent prints
`Note: No CRL supplied; revocations issued elsewhere are not visible.`
to stdout — exit code unchanged. A CRL whose producer doesn't match an
envelope's `event.metadata.product.name` is ignored for that envelope.

Exit codes:

- `0` — every entry PROVEN
- `1` — at least one entry VIOLATED (chain mismatch, hash mismatch,
  signature failure, or CRL revocation), **or** a supplied CRL failed
  its own signature check (no per-envelope output in the latter case)
- `2` — usage error (missing flag, malformed JSONL)

### Sign

```bash
./lemma-agent sign --keys-dir <dir> --producer <name> [--prev-hash <hex>] [--event <path>] [--source-label <s>]
```

Reads one OCSF event from `--event <path>` or stdin, looks up the
producer's currently-ACTIVE key under
`<dir>/<producer>/<key_id>.private.pem`, builds a signed envelope, and
prints one JSONL line to stdout. Defaults to genesis (`"0"*64`) when
`--prev-hash` is absent — operators chain envelopes by piping
`--prev-hash $(tail -1 log.jsonl | jq -r .entry_hash)` into the next
call.

Exit codes:

- `0` — envelope written
- `1` — signing failed (missing ACTIVE key, malformed PEM, IO error)
- `2` — usage error (missing flag, empty event)

Run `./lemma-agent` (no arguments) for a one-line summary of the version
and available subcommands.

## Test

```bash
cd agent
go vet ./...
go test ./...
```

The Python integration test at `tests/integration/test_agent_verify.py`
is the parity oracle: it asks Python's `EvidenceLog` to write a signed
log, then runs this binary against it and asserts a PROVEN verdict. Any
canonical-JSON drift between the two implementations surfaces there as a
VIOLATED entry-hash mismatch.

## Roadmap

The full agent design — federation protocol, evidence forwarding, control
plane wiring, deployment shapes, signing — is tracked under
[#25 Federated Agent Architecture](https://github.com/JoshDoesIT/Lemma/issues/25).
Subsequent slices on that issue layer on top of the verify primitive
shipped here.
