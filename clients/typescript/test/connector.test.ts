/** Tests for the Lemma TypeScript Connector SDK (Refs #108).
 *
 * Runs with zero dependencies via Node's built-in test runner + type
 * stripping:  node --test --experimental-strip-types test/*.test.ts
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import { complianceFinding } from "../src/ocsf.ts";
import { ReferenceConnector } from "../src/reference.ts";

test("complianceFinding produces a well-formed OCSF event", () => {
  const ev = complianceFinding({
    message: "m",
    statusId: 1,
    uid: "acme:sig:2026-06-20",
    producer: "Acme",
  });
  assert.equal(ev.class_uid, 2003);
  assert.equal(ev.class_name, "Compliance Finding");
  assert.equal(ev.category_uid, 2000);
  assert.equal(ev.type_uid, 200301);
  assert.equal(ev.status_id, 1);
  assert.equal(ev.metadata.uid, "acme:sig:2026-06-20");
  assert.equal(ev.metadata.product.name, "Acme");
  // Round-trips through JSON (the wire format the evidence log ingests).
  assert.deepEqual(JSON.parse(JSON.stringify(ev)).class_uid, 2003);
});

test("reference connector collect() yields one valid finding", () => {
  const events = [...new ReferenceConnector().collect()];
  assert.equal(events.length, 1);
  assert.equal(events[0].class_uid, 2003);
  assert.ok(events[0].metadata.uid.startsWith("reference:self-check:"));
});

test("run() drains collect() and counts unique uids", async () => {
  const result = await new ReferenceConnector().run();
  assert.equal(result.events.length, 1);
  assert.equal(result.uniqueUids, 1);
});

test("dedupe uid is stable across two runs the same day", () => {
  const a = [...new ReferenceConnector().collect()][0].metadata.uid;
  const b = [...new ReferenceConnector().collect()][0].metadata.uid;
  assert.equal(a, b);
});
