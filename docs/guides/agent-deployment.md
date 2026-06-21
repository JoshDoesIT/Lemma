# Deploying the Lemma Agent

The Lemma Agent is a small, stateless Go binary that runs inside a target
environment, signs/verifies/ingests evidence, exposes a `/health` endpoint,
and forwards signed evidence envelopes to a [Control
Plane](../security/evidence-and-transport.md#3-transport-security-mtls-for-federation).
This guide covers the supported deployment shapes.

`lemma agent install` renders a ready-to-apply deployment artifact for each
shape; you don't hand-write the manifests.

```bash
lemma agent install --shape <k8s|systemd|launcher> --output ./deploy [options]
```

| Option | Default | Applies to | Description |
|--------|---------|------------|-------------|
| `--shape` | (required) | all | `k8s`, `systemd`, or `launcher`. |
| `--output` | (required) | all | Directory the rendered artifact is written to. |
| `--image` | the published agent image | k8s | Container image to run. |
| `--binary-path` | `/usr/local/bin/lemma-agent` | systemd / launcher | Path to the binary on the host. |
| `--evidence-dir` | host evidence dir | all | Directory the agent serves signed evidence from. |
| `--keys-dir` | host keys dir | all | Producer keys (private PEMs at mode `0600`). |
| `--health-port` | agent default | all | Port the `/health` endpoint binds. |
| `--force` | `false` | all | Overwrite an existing rendered artifact. |

## Kubernetes (sidecar)

Render and apply a Deployment that runs the agent alongside the workload whose
evidence you want forwarded:

```bash
lemma agent install --shape k8s --output ./deploy \
  --image ghcr.io/joshdoesit/lemma-agent:latest \
  --evidence-dir /var/lib/lemma-agent/evidence \
  --keys-dir /var/lib/lemma-agent/keys
kubectl apply -f ./deploy/lemma-agent.yaml
```

Provide the `evidence` and `keys` paths as Pod volume mounts. The container
image is **distroless static, non-root** (no shell, no package manager) — a
minimal attack surface. Mount the keys volume read-only and keep private PEMs
at `0600`.

## systemd (bare-metal / VM)

For a host running the binary directly under systemd:

```bash
lemma agent install --shape systemd --output ./deploy \
  --binary-path /usr/local/bin/lemma-agent
sudo cp ./deploy/lemma-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lemma-agent
```

The unit restarts the agent on failure and starts it on boot. Place the binary
at `--binary-path` and the keys/evidence under the configured directories.

## Bare-metal launcher script

When systemd isn't available (containers without an init system, ad-hoc
hosts), render an executable launcher:

```bash
lemma agent install --shape launcher --output ./deploy
./deploy/launcher.sh
```

The script is written executable (`0755`) and starts the agent with the
configured evidence/keys directories and health port.

## Docker

The agent ships a multi-stage `Dockerfile` (build → distroless static):

```bash
docker build -t lemma-agent:dev -f agent/Dockerfile agent/
docker run --rm \
  -v "$PWD/evidence:/var/lib/lemma-agent/evidence" \
  -v "$PWD/keys:/var/lib/lemma-agent/keys:ro" \
  -p 8080:8080 \
  lemma-agent:dev
```

The default entrypoint runs `serve` on port 8080 against
`/var/lib/lemma-agent/{evidence,keys}`.

## Forwarding evidence to a Control Plane

The Go agent's `lemma-agent forward` pushes signed envelopes to a Control
Plane receiver (`POST /v1/evidence`). The receiver verifies each envelope's
Ed25519 signature and persists it. Two transport options:

- **Plain HTTP / HTTPS** — the envelope signature is the integrity guarantee;
  TLS adds confidentiality.
- **HTTPS + mTLS** — the receiver, started with `--client-ca`, requires the
  agent to present a client certificate. See the [security
  model](../security/evidence-and-transport.md#3-transport-security-mtls-for-federation)
  for the `lemma control-plane serve` flags.

Because the agent is **stateless**, scaling out is just running more replicas;
there is no shared agent state to coordinate. Evidence integrity comes from the
signature + hash chain, not from the agent's runtime.

## Air-gapped environments

The agent needs no outbound internet — only a route to the Control Plane (or
none at all, if you ship evidence out via removable media):

1. **Pre-stage the binary/image** during your normal supply-chain import
   (the distroless image and the static binary have no runtime package
   fetches).
2. **Run `verify` locally** — `lemma-agent verify <evidence.jsonl> --keys-dir
   <dir> [--crl <path>]` checks the chain, content hashes, signatures, and
   revocations entirely offline, with only the public keys and any CRLs.
3. **Carry revocations on media** — offline signed `RevocationList` (CRL)
   files merge into verification with `--crl`, so a key revoked on the
   connected side is honored air-gapped (see the [security
   model](../security/evidence-and-transport.md#offline-revocation-lists-crls)).

## Checking agent health

```bash
lemma agent status --endpoint http://<agent-host>:<health-port>
```

`lemma agent status` queries the agent's `/health` endpoint and reports
uptime, last sync time, and evidence counts — the same probe shape the Control
Plane exposes, so one observability convention covers both sides of the
federation.
