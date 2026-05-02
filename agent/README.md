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
   entry hash verifies under the producer's public key; the signing
   key is **not** revoked at or before the envelope's `signed_at`
   from either revocation source — the local lifecycle file at
   `<keys-dir>/<producer>/meta.json` (`status: REVOKED` records) and
   any `--crl <path>` whose `producer` matches the envelope's
   `event.metadata.product.name`. When BOTH sources flag the same key,
   the earlier `revoked_at` wins. CRL signatures are themselves
   verified against the issuer's public key before any per-envelope
   check runs; a bad CRL aborts the run with exit 1 rather than
   silently being ignored. Missing or unreadable `meta.json` is treated
   as no local revocation (pass-through).
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

### Keygen

```bash
./lemma-agent keygen --keys-dir <dir> --producer <name>
```

Mints an Ed25519 keypair for `<name>` and writes the same on-disk
layout Python's `lemma init` / `crypto.generate_keypair` produces:

- `<dir>/<safe_producer>/<key_id>.private.pem` (PKCS#8 PEM, mode 0o600)
- `<dir>/<safe_producer>/<key_id>.public.pem` (SubjectPublicKeyInfo PEM, mode 0o644)
- `<dir>/<safe_producer>/meta.json` with one `ACTIVE` record

`<safe_producer>` replaces `/` and ` ` with `_` so the producer name
can't escape the keys directory. The `key_id` is
`"ed25519:" + sha256(raw_public).hex()[:16]` — same algorithm Python
uses, so the same key minted on either side produces the same key_id.

**Idempotent**: a second call against a producer that already has an
ACTIVE key returns its key_id without modifying any files. Output:

- New: `Generated ed25519:<id> for producer <name>.`
- Existing: `Producer <name> already has ACTIVE key ed25519:<id>.`

Pair `keygen` with `ingest` and `verify` to deploy a fully self-
sufficient Go-only agent — no Python required for the runtime path.
**Rotation and revocation are not in this binary yet** (use Python's
`crypto.rotate_key` / `crypto.revoke_key` for those). They'll land in
later slices.

Exit codes:

- `0` — fresh keypair minted, OR existing ACTIVE key returned
- `1` — filesystem error (mkdir, write, chmod)
- `2` — usage error (missing flag)

### Ingest

```bash
./lemma-agent ingest <input> --keys-dir <dir> --evidence-dir <dir> --producer <name> [--source-label <s>]
```

Reads OCSF events from `<input>` (a `.json` file with a single object,
a `.jsonl` file with one object per line, or `-` for stdin in JSONL
form), signs each under the producer's ACTIVE key, and appends the
resulting envelopes to `<evidence-dir>/<YYYY-MM-DD>.jsonl` files. The
date is derived from each event's `time` field, so events spanning
multiple days land in multiple files. The chain hash flows across the
batch and across calls — second invocations pick up `prev_hash` from
the latest entry already on disk.

Dedup is **per-day** and matches Python's `lemma evidence ingest`: an
event whose `metadata.uid` (or, fallback, content hash) is already
present in the day's file is skipped. Re-ingesting the same input
produces `0 ingested, N skipped (duplicate).`

Source-stage provenance is built once per call: `actor =
"lemma-agent-ingest:<label>"`, `content_hash = sha256(raw input
bytes)`. The `--source-label` overrides the default (input file path,
or `-` for stdin).

Exit codes:

- `0` — all events processed (including the all-deduped case)
- `1` — read failure, parse error, missing ACTIVE key, or signing
  failure
- `2` — usage error (missing flag, unsupported file extension)

**Same OCSF pre-normalization caveat as `sign`**: the input event
must already be in the form Pydantic's OCSF models would emit, or
the resulting envelope won't verify on the Python side.

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
