# @lemma/connector-sdk (TypeScript)

The TypeScript counterpart of Lemma's Python connector SDK (Refs
[#108](https://github.com/JoshDoesIT/Lemma/issues/108)). Build evidence
connectors in TypeScript that emit OCSF events byte-compatible with what
`lemma evidence collect` ingests.

This is the **v0 authoring slice**: OCSF types, a `Connector` base, and a
runnable reference connector. It is dependency-free and runs under Node's
built-in TypeScript support — no build step, no `tsc`, no `node_modules`.

## Requirements

- Node.js ≥ 22.6 (uses `--experimental-strip-types`).

## Build your first connector

```ts
import { Connector, complianceFinding, type ConnectorManifest, type OcsfEvent } from "@lemma/connector-sdk";

export class AcmeConnector extends Connector {
  readonly manifest: ConnectorManifest = {
    name: "acme",
    version: "0.1.0",
    producer: "Acme",
    description: "Acme posture.",
  };

  *collect(): Iterable<OcsfEvent> {
    const utcDate = new Date().toISOString().slice(0, 10);
    yield complianceFinding({
      message: "MFA enabled for all admins.",
      statusId: 1,
      uid: `acme:mfa:${utcDate}`, // stable per (target, signal, UTC date) so re-runs dedupe
      producer: "Acme",
    });
  }
}
```

## Test

```bash
cd clients/typescript
npm test          # node --test --experimental-strip-types test/
```

## Signing

Ed25519 signing is available via `node:crypto` (no external dependency):

```ts
import { complianceFinding, generateKeyPair, signEvent, verifyEvent } from "@lemma/connector-sdk";

const keys = generateKeyPair();
const ev = complianceFinding({ message: "ok", statusId: 1, uid: "acme:x:2026-06-20", producer: "Acme" });
const sig = signEvent(ev, keys.privateKeyPem);   // hex signature over canonical JSON
verifyEvent(ev, sig, keys.publicKeyPem);          // true; tampering or a wrong key → false
```

Events are canonicalized (recursively key-sorted JSON) before signing so the
bytes are deterministic.

## Hash-chained evidence log

`EvidenceLog` binds each event into a signed, append-only chain — the TS
counterpart of the Python log:

```ts
import { EvidenceLog, complianceFinding, generateKeyPair } from "@lemma/connector-sdk";

const keys = generateKeyPair();
const log = new EvidenceLog(keys.privateKeyPem, keys.publicKeyPem, "acme-key");
log.append(complianceFinding({ message: "ok", statusId: 1, uid: "acme:x:2026-06-20", producer: "Acme" }));
log.verify(); // [{ index: 0, verdict: "PROVEN", reason: "" }, ...]
```

`entryHash = sha256(prevHash || canonical(event))` and the entry hash is
Ed25519-signed; tampering with an event, a signature, or the chain link
surfaces as `VIOLATED` / `DEGRADED` on `verify()`.

## What's here vs deferred

- **Here**: OCSF event types (`complianceFinding`), the `Connector` base
  (`collect()` / `run()`), a `ReferenceConnector`, Ed25519 signing
  (`generateKeyPair`, `signEvent`, `verifyEvent`, `canonicalize`), and a
  hash-chained `EvidenceLog` (`append`, `entries`, `verify`).
- **Cross-language parity (verified)**: both the chain-hash primitive
  (`chainHash`, `canonicalize`) **and** the `complianceFinding` event
  serialization are **byte-identical to Python's**. A shared fixture generated
  from a real Python `ComplianceFinding` via `EvidenceLog._compute_entry_hash`
  is checked from both sides (`test/interop.test.ts` +
  `tests/sdk/test_ts_interop.py`): the TS factory's output equals the Python
  event byte-for-byte, and a TS-built event hashes — through the production
  Python hash — to the same entry hash. A TS-produced event therefore verifies
  on the Python side.
- **Deferred** (tracked on #108): `npm` publishing and richer OCSF classes as
  connector work demands them.
