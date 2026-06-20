/** Tests for the hash-chained TS evidence log (Refs #108). */

import assert from "node:assert/strict";
import { test } from "node:test";

import { EvidenceLog, GENESIS_HASH } from "../src/evidence.ts";
import { complianceFinding } from "../src/ocsf.ts";
import { generateKeyPair } from "../src/signing.ts";

function finding(uid: string) {
  return complianceFinding({
    message: "m",
    statusId: 1,
    uid,
    producer: "Acme",
    time: "2026-06-20T12:00:00.000Z",
  });
}

function newLog() {
  const keys = generateKeyPair();
  return { log: new EvidenceLog(keys.privateKeyPem, keys.publicKeyPem, "acme-key"), keys };
}

test("first entry chains from genesis", () => {
  const { log } = newLog();
  const env = log.append(finding("a"));
  assert.equal(env.prevHash, GENESIS_HASH);
  assert.equal(env.signerKeyId, "acme-key");
});

test("entries chain prev_hash to the prior entry_hash", () => {
  const { log } = newLog();
  const e1 = log.append(finding("a"));
  const e2 = log.append(finding("b"));
  assert.equal(e2.prevHash, e1.entryHash);
});

test("a clean chain verifies PROVEN end to end", () => {
  const { log } = newLog();
  log.append(finding("a"));
  log.append(finding("b"));
  log.append(finding("c"));
  const verdicts = log.verify().map((r) => r.verdict);
  assert.deepEqual(verdicts, ["PROVEN", "PROVEN", "PROVEN"]);
});

test("tampering an event content is detected as VIOLATED", () => {
  const { log } = newLog();
  log.append(finding("a"));
  log.append(finding("b"));
  // Mutate a stored event in place (simulating tampering on disk).
  (log.entries()[0].event as { message: string }).message = "altered";
  const results = log.verify();
  assert.equal(results[0].verdict, "VIOLATED");
});

test("tampering a signature is detected as DEGRADED", () => {
  const { log } = newLog();
  log.append(finding("a"));
  (log.entries()[0] as { signature: string }).signature = "00".repeat(64);
  assert.equal(log.verify()[0].verdict, "DEGRADED");
});

test("breaking the chain link is detected as VIOLATED", () => {
  const { log } = newLog();
  log.append(finding("a"));
  log.append(finding("b"));
  (log.entries()[1] as { prevHash: string }).prevHash = GENESIS_HASH;
  assert.equal(log.verify()[1].verdict, "VIOLATED");
});
