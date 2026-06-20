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

## What's here vs deferred

- **Here**: OCSF event types (`complianceFinding` factory), the `Connector`
  base with `collect()` / `run()`, a `ReferenceConnector`, and Ed25519
  signing / verification (`generateKeyPair`, `signEvent`, `verifyEvent`,
  `canonicalize`).
- **Deferred** (tracked on #108): the full hash-chained evidence log in
  TypeScript with `prev_hash` chaining matching the Python entry-hash layout
  (today the Python CLI persists), `npm` publishing, and richer OCSF classes
  as connector work demands them.
