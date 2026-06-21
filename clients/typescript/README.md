# @lemma/connector-sdk (TypeScript)

The TypeScript counterpart of Lemma's Python connector SDK (Refs
[#108](https://github.com/JoshDoesIT/Lemma/issues/108)). Build evidence
connectors in TypeScript that emit OCSF events byte-compatible with what
`lemma evidence collect` ingests.

OCSF types, a `Connector` base, a runnable reference connector, Ed25519
signing, and a hash-chained evidence log. The runtime is **dependency-free**
and develops with **no build step** — source runs directly under Node's
built-in TypeScript support. Publishing compiles `.js` + `.d.ts` into `dist/`
so npm consumers get full type annotations.

## Requirements

- Node.js ≥ 22.6 (uses `--experimental-strip-types`).

## Install

```bash
npm install @lemma/connector-sdk
```

The package ships type declarations (`dist/*.d.ts`) and resolves under
`moduleResolution: nodenext`/`bundler`, so imports are fully typed with no
`@types` package needed.

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
npm run build     # emit dist/*.js + dist/*.d.ts (what gets published)
```

## Validating output against Lemma's OCSF schema

A connector authored here emits OCSF events; `lemma connector test` (the Python
CLI) validates an emitted fixture against the **same** OCSF schema Python
connectors are held to — the cross-language acceptance check:

```bash
# Dump your connector's events to a file, one JSON object per line…
node --experimental-strip-types your-connector.ts > events.jsonl
# …then validate them against the production OCSF schema.
lemma connector test events.jsonl
```

`test/fixtures/ts-connector-events.jsonl` is a committed example: the TS test
asserts the SDK reproduces it, and `tests/sdk/test_ts_interop.py` runs
`lemma connector test` over it, so the two languages stay in lockstep.

## Publishing

Publishing is automated. Push a `connector-sdk-v<version>` tag (matching
`package.json`'s `version`) and the `Connector SDK` workflow builds and runs
`npm publish` using the `NPM_TOKEN` repository secret. `prepublishOnly`
recompiles `dist/` first, so a release always carries fresh `.js` + `.d.ts`.

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
- **Published to npm** (#228): `@lemma/connector-sdk` ships with compiled
  `.d.ts` types, and `lemma connector test <fixture>` validates a TS
  connector's emitted OCSF output against the production schema.
- **Richer OCSF classes** are added as the lexicon expands — tracked in
  [#89](https://github.com/JoshDoesIT/Lemma/issues/89).
