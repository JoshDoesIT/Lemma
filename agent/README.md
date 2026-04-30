# Lemma Agent

The Lemma Agent is the binary that will run inside target environments
(Kubernetes sidecar, systemd unit, or bare-metal process), forward signed
evidence envelopes to a Control Plane, and pull configuration. It is the
runtime counterpart to the `lemma agent` CLI in the main Python package.

## Status

**Verifies signed evidence logs offline today.** The agent does not yet
talk to a Control Plane, manage evidence, or implement any of the
`install` / `status` / `sync` behaviour described by the CLI surface in
`src/lemma/commands/agent.py`. What it can do is read a Lemma signed
evidence JSONL and check, byte-for-byte against the Python signer:

1. each entry's `prev_hash` matches the prior entry's `entry_hash`;
2. recomputing the entry hash from the canonical
   `{event, provenance_excluding_storage}` payload yields the claimed value;
3. the Ed25519 signature over the 32-byte entry hash verifies under the
   producer's public key.

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

```bash
./lemma-agent verify <evidence.jsonl> --keys-dir <dir>
```

`<dir>` is the directory containing producer subdirectories with
`<key_id>.public.pem` files — the same layout Lemma writes under
`.lemma/keys/`. The agent walks every subdirectory looking for the
matching key, so a flat trust-store with multiple producers works too.

Exit codes:

- `0` — every entry PROVEN
- `1` — at least one entry VIOLATED (chain mismatch, hash mismatch, or
  signature failure)
- `2` — usage error (missing flag, malformed JSONL)

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
