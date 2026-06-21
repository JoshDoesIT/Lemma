# Security Model: Evidence Integrity, Keys, and Transport

Lemma's trust story has three layers: every evidence entry is **signed** and
**hash-chained**, signing keys have an explicit **lifecycle** with offline
revocation, and federation traffic can be secured with **mTLS**. This page is
the consolidated model; the per-command mechanics live in the
[CLI reference](../reference/index.md#lemma-evidence).

## 1. Evidence integrity: signing + hash chaining

Each event appended to the evidence log is wrapped in a `SignedEvidence`
envelope:

- **Ed25519 signature.** The entry is signed by the producer's private key.
  The signature covers the entry hash, so any tampering with the event or its
  provenance breaks verification.
- **Hash chain.** Every envelope carries `prev_hash` (the prior entry's hash)
  and `entry_hash` (a hash over `prev_hash` + the event + provenance). The
  chain makes the log **append-only**: you cannot alter or remove a historical
  entry without invalidating every entry after it.
- **Provenance records.** Transformations (source, normalization, storage) are
  folded into the signed hash, so the chain attests not just to the event but
  to how it was produced.

`lemma evidence verify <ENTRY_HASH>` walks the chain to the target entry and
renders a verdict:

| Verdict | Meaning |
|---------|---------|
| **PROVEN** | Chain + content hash intact **and** signature verifies against a trusted, non-revoked key. |
| **DEGRADED** | Chain + content hash intact, but the signature can't be verified (e.g. the verifier doesn't have the producer's public key). |
| **VIOLATED** | A content/chain hash is wrong — the log was tampered with. |

Verification works **offline, on a fresh install, with only the public key** —
no service, no database.

## 2. Key lifecycle, rotation, and revocation

Keys live under `.lemma/keys/<producer>/`, with a `meta.json` recording every
key the producer has ever held and its state:

| State | Meaning |
|-------|---------|
| **ACTIVE** | Current signing key; new entries are signed with it. |
| **RETIRED** | Superseded by rotation; historical signatures still verify. |
| **REVOKED** | Compromised/withdrawn; signatures made after the revocation time are **not** trusted. |

- **Rotate** (`lemma evidence rotate-key`) promotes a new ACTIVE key and marks
  the previous one RETIRED. Past evidence keeps verifying — verification
  consults `meta.json` to decide whether a historical signature was made while
  its key was valid.
- **Revoke** (`lemma evidence revoke-key`) marks a key REVOKED as of a
  timestamp. Entries signed after that time stop being PROVEN.

### Offline revocation lists (CRLs)

Revocation has to work across air-gapped boundaries, so revocations travel as
**signed `RevocationList` (CRL)** documents:

- `lemma evidence export-crl` emits a CRL signed by the producer.
- `lemma evidence verify --crl <path>` merges that CRL into the verdict. The
  CRL's own signature is checked against the producer's known public key — an
  **unverifiable CRL aborts** rather than being silently ignored (silently
  dropping it would let an attacker suppress revocations).
- A CRL can only *add* revocations, never remove them; when local and CRL both
  flag a key, the **earlier** revocation time wins (defense in depth).
- Verifying without `--crl` prints an advisory that revocations issued
  elsewhere aren't visible — the verifier's picture may be incomplete.

> **Connector credentials** are a separate concern from signing keys — they're
> covered in [Connector Credentials](connector-secrets.md). Signing keys prove
> *who produced the evidence*; connector tokens authenticate Lemma *to upstream
> systems* and never enter the evidence log.

## 3. Transport security: mTLS for federation

The federated agent forwards signed envelopes to the Control Plane receiver
(`POST /v1/evidence`). That hop is secured at two independent layers:

1. **Envelope signatures (always on).** Even over plain HTTP, every envelope
   is Ed25519-signed; the receiver verifies it and records the verdict. An
   attacker who intercepts or replays traffic cannot forge a PROVEN entry
   without the producer's private key.
2. **TLS / mTLS (transport).** `lemma control-plane serve` wires TLS through a
   `ssl.SSLContext`:

   ```bash
   # Server-authenticated TLS (HTTPS):
   lemma control-plane serve --port 8443 \
     --evidence-dir ./cp-evidence --keys-dir ./cp-keys \
     --cert server.pem --key server.key

   # Mutual TLS — receiver requires a client cert signed by the given CA:
   lemma control-plane serve --port 8443 \
     --evidence-dir ./cp-evidence --keys-dir ./cp-keys \
     --cert server.pem --key server.key --client-ca clients-ca.pem
   ```

| Flag | Effect |
|------|--------|
| `--cert` / `--key` | Enables HTTPS (server certificate). Must be set together. |
| `--client-ca` | Requires mTLS: clients must present a certificate signed by this CA (`ssl.CERT_REQUIRED`). Requires `--cert`/`--key`. |
| `--bind` | Defaults to `127.0.0.1`; use `0.0.0.0` to expose on all interfaces (do this only behind TLS). |

**Certificate management** is delegated to your existing PKI — Lemma consumes
PEM files (`--cert`, `--key`, `--client-ca`) rather than issuing certificates,
so it slots behind cert-manager, an internal CA, or files you rotate out of
band. Rotating a server or client cert is a restart with new PEM paths; the
signature layer is unaffected, so in-flight trust doesn't depend on the cert.

### Defense in depth

The two layers are deliberately independent. TLS protects confidentiality and
authenticates the *connection*; the Ed25519 signature authenticates the
*evidence* and survives TLS termination at a load balancer or sidecar. A
compromise of one layer does not compromise the other.

## See also

- [`lemma evidence verify` and key commands](../reference/index.md#lemma-evidence)
- [`lemma control-plane`](../reference/index.md#lemma-control-plane)
- [Connector Credentials](connector-secrets.md)
