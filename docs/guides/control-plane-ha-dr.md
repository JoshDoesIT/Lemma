# Control Plane: High Availability & Disaster Recovery

The [Control Plane](../security/evidence-and-transport.md#3-transport-security-mtls-for-federation)
receiver is **stateless compute over durable, tamper-evident state**. That
split is what makes its HA/DR story simple: you recreate the process from a
rendered deployment artifact, and you protect (and *verify*) the state it
persists.

Because every evidence envelope is Ed25519-signed and hash-chained, recovery is
**cryptographically verifiable end-to-end** — after a restore you can *prove* the
evidence is intact, not merely present. A tampered or truncated restore surfaces
as `VIOLATED` / `DEGRADED`, never as a silent success.

## What state to protect

| State | Where | Why it matters |
|-------|-------|----------------|
| **Evidence store** | `--evidence-dir` (`<producer>/<YYYY-MM-DD>.jsonl`) | The signed, hash-chained record of received evidence — the thing you cannot regenerate. |
| **Producer public keys** | `--keys-dir` (`<producer>/<key_id>.public.pem`) | Required to verify envelope signatures on restore. |
| **Revocation lists (CRLs)** | wherever you distribute them | Needed so a restored verifier still honors revocations. |

The receiver *process* is disposable — recreate it from
[`lemma control-plane install`](../reference/index.md#lemma-control-plane-install)
(`systemd`, `docker-compose`, `helm`, or `terraform`). No configuration lives
only in the running process.

## Backup

Back up the evidence and keys directories. The evidence log is **append-only**,
so incremental backups are cheap and never rewrite history:

```bash
# Point-in-time archive of the receiver's durable state.
tar czf lemma-cp-$(date -u +%Y%m%dT%H%M%SZ).tgz \
  -C /var/lib/lemma-control-plane evidence keys
```

- **Prefer immutable targets.** Push backups to write-once / object-lock storage
  (e.g. S3 Object Lock) so a compromised host can't rewrite prior evidence. This
  complements — it does not replace — the log's own tamper-evidence.
- **Cadence sets your RPO.** With continuous volume replication your RPO
  approaches zero; with periodic archives your RPO is the archive interval.
- **Keys change rarely.** Snapshot `keys/` on every producer rotation, not just
  on the evidence schedule.

## Restore

1. **Recreate compute** from the deployment artifact and start
   [`lemma control-plane serve`](../reference/index.md#lemma-control-plane-serve).
2. **Restore state** into the same `--evidence-dir` / `--keys-dir`:

    ```bash
    tar xzf lemma-cp-<timestamp>.tgz -C /var/lib/lemma-control-plane
    ```

3. **Verify before trusting the restore.** Do not assume "files present" means
   "evidence intact":

    ```bash
    # Rollup across all producers — confirms the store reads and chains.
    lemma control-plane aggregate --evidence-dir /var/lib/lemma-control-plane/evidence

    # Per-entry cryptographic check (hash-chain + signature). VIOLATED/DEGRADED
    # on any entry means the restore is compromised — do not put it into service.
    lemma evidence verify <entry_hash>
    ```

   For an off-box drill, verify a self-contained
   [audit bundle](../reference/index.md#lemma-evidence-bundle) on a fresh machine
   with `lemma evidence verify --bundle <dir>` — it needs no `.lemma/` and proves
   the chain end to end.

## High availability / failover

The receiver holds no in-process state, so HA is a compute + storage story:

- **Scale out.** Run N replicas behind a load balancer; the `helm` chart's
  `replicaCount` and an ASG behind an ALB (adapt the `terraform` module) both
  work. Health checks hit `/health`; the LB drains unhealthy instances.
- **Share the durable state.** Put `evidence/` and `keys/` on shared durable
  storage (EFS/NFS, or an object-store-backed volume) so any replica serves the
  same log, or run active/standby with replicated block storage.
- **One writer per producer.** The hash-chain is *per producer* — concurrent
  writers appending to the same producer's day-file can fork the chain. Front the
  receiver with a single active writer per producer (or partition producers
  across writers / queue ingest) so appends stay linear. Read/verify/aggregate
  paths scale freely.
- **Transport stays hardened in failover.** Keep mTLS (`--cert` / `--key` /
  `--client-ca`) terminated at, or passed through to, every replica — see the
  [security model](../security/evidence-and-transport.md).

## RTO / RPO targets

Concrete targets depend on your storage tier; use these as a starting point:

| Tier | RPO (data loss window) | RTO (time to serve) | How |
|------|------------------------|---------------------|-----|
| **Baseline** | ≤ 24h | ≤ 4h | Nightly archive to object storage; restore + `aggregate`/`verify` drill. |
| **Standard** | ≤ 1h | ≤ 30m | Hourly incremental sync; warm standby from the artifact. |
| **Continuous** | ≈ 0 | ≤ 5m | Shared/replicated durable volume + N receiver replicas behind an LB. |

**RTO includes verification.** Budget the `aggregate` + `verify` step into your
recovery time — a restore isn't "done" until the chain verifies, and that check
is what lets you attest the recovered evidence is trustworthy.

## Why recovery is provable, not hopeful

Traditional DR asks "did the files come back?" Lemma's evidence is signed and
hash-chained, so DR asks a stronger question — "does the chain still verify under
the producers' keys?" — and answers it deterministically. That means a recovered
Control Plane can be *attested* as intact, which is exactly what an auditor needs
after an incident.
