/** Tests for Ed25519 signing in the Lemma TypeScript SDK (Refs #108). */

import assert from "node:assert/strict";
import { test } from "node:test";

import { complianceFinding } from "../src/ocsf.ts";
import { canonicalize, generateKeyPair, signEvent, verifyEvent } from "../src/signing.ts";

function event() {
  return complianceFinding({
    message: "m",
    statusId: 1,
    uid: "acme:sig:2026-06-20",
    producer: "Acme",
    time: "2026-06-20T12:00:00.000Z",
  });
}

test("generateKeyPair returns PEM keys", () => {
  const { publicKeyPem, privateKeyPem } = generateKeyPair();
  assert.match(publicKeyPem, /BEGIN PUBLIC KEY/);
  assert.match(privateKeyPem, /BEGIN PRIVATE KEY/);
});

test("sign then verify round-trips", () => {
  const keys = generateKeyPair();
  const ev = event();
  const sig = signEvent(ev, keys.privateKeyPem);
  assert.ok(verifyEvent(ev, sig, keys.publicKeyPem));
});

test("tampering with the event breaks verification", () => {
  const keys = generateKeyPair();
  const ev = event();
  const sig = signEvent(ev, keys.privateKeyPem);
  const tampered = { ...ev, message: "altered" };
  assert.equal(verifyEvent(tampered, sig, keys.publicKeyPem), false);
});

test("a different key cannot verify the signature", () => {
  const a = generateKeyPair();
  const b = generateKeyPair();
  const ev = event();
  const sig = signEvent(ev, a.privateKeyPem);
  assert.equal(verifyEvent(ev, sig, b.publicKeyPem), false);
});

test("canonicalization is order-independent", () => {
  const a = canonicalize({ b: 1, a: { d: 2, c: 3 } });
  const b = canonicalize({ a: { c: 3, d: 2 }, b: 1 });
  assert.equal(a, b);
});
