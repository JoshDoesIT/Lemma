# Lemma Agent

The Lemma Agent is the binary that will run inside target environments
(Kubernetes sidecar, systemd unit, or bare-metal process), forward signed
evidence envelopes to a Control Plane, and pull configuration. It is the
runtime counterpart to the `lemma agent` CLI in the main Python package.

## Status

**Scaffold only.** This module compiles, runs, and prints its version. It does
not yet talk to a Control Plane, manage evidence, or implement any of the
`install` / `status` / `sync` behaviour described by the CLI surface in
`src/lemma/commands/agent.py`.

The current binary exists so that:

1. There is a real artefact for future install / status / sync work to land in.
2. CI exercises a Go build (`go vet`, `go test`, `go build`) so the module
   cannot rot while the slices that fill it in are landing.
3. The Python `lemma agent install` command has somewhere concrete to point
   operators at instead of a phantom binary path.

## Build

Requires Go 1.23 or newer.

```bash
cd agent
go build -o lemma-agent .
```

## Run

```bash
./lemma-agent
```

Expected output:

```
lemma-agent v0.1.0
not yet implemented; tracked under #25
```

## Test

```bash
cd agent
go vet ./...
go test ./...
```

## Roadmap

The full agent design — federation protocol, evidence forwarding, control plane
wiring, deployment shapes — is tracked under
[#25 Federated Agent Architecture](https://github.com/JoshDoesIT/Lemma/issues/25).
Subsequent slices on that issue will replace the placeholder `run` body with
real install / status / sync implementations.
