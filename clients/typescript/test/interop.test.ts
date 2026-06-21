/** Cross-language entry-hash + event-serialization parity (Refs #108).
 *
 * The fixture (`fixtures/entry-hash.json`) was generated from a *real* Python
 * `ComplianceFinding` via `EvidenceLog._compute_entry_hash`. These tests prove:
 *
 *   1. the TS chain-hash primitive matches the Python entry hash, and
 *   2. the TS `complianceFinding` factory produces an event byte-identical to
 *      Python's serialization (so a TS-built event hashes to the Python value).
 *
 * The matching Python test (tests/sdk/test_ts_interop.py) checks the same
 * fixture from the other side.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { chainHash } from "../src/evidence.ts";
import { canonicalize } from "../src/signing.ts";
import { complianceFinding } from "../src/ocsf.ts";

const fixturePath = fileURLToPath(new URL("./fixtures/entry-hash.json", import.meta.url));
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

test("TS chainHash matches the Python-generated entry hash", () => {
  assert.equal(chainHash(fixture.prevHash, fixture.payload), fixture.expectedEntryHash);
});

test("TS complianceFinding serializes byte-identically to Python", () => {
  const tsEvent = complianceFinding(fixture.factoryInput);
  // Same canonical bytes as the real Python ComplianceFinding in the fixture.
  assert.equal(canonicalize(tsEvent), canonicalize(fixture.payload.event));
});

test("a TS-built event hashes to the Python entry hash end to end", () => {
  const tsEvent = complianceFinding(fixture.factoryInput);
  const hash = chainHash(fixture.prevHash, { event: tsEvent, provenance: [] });
  assert.equal(hash, fixture.expectedEntryHash);
});
