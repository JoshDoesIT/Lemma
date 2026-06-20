/**
 * Ed25519 signing for the Lemma TypeScript SDK (Refs #108).
 *
 * Uses Node's built-in `node:crypto` (no external dependency) to sign OCSF
 * events with Ed25519 — the same scheme the Python evidence log uses. Events
 * are canonicalized (recursively key-sorted JSON) before signing so the bytes
 * are deterministic regardless of property insertion order.
 *
 * This is the signing primitive; wiring it into a full hash-chained TS
 * evidence log (with `prev_hash` chaining and the exact Python entry-hash
 * layout) is the next slice on #108. Today the Python CLI owns persistence.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";

import type { OcsfEvent } from "./ocsf.ts";

export interface Ed25519KeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

/** Generate an Ed25519 keypair as PEM strings (matching the Python key store). */
export function generateKeyPair(): Ed25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

/** Deterministic JSON: object keys sorted recursively, arrays in order. */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortDeep);
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortDeep((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

function toPrivateKey(pem: string): KeyObject {
  return createPrivateKey(pem);
}

function toPublicKey(pem: string): KeyObject {
  return createPublicKey(pem);
}

/** Sign an OCSF event's canonical bytes; returns a hex signature. */
export function signEvent(event: OcsfEvent, privateKeyPem: string): string {
  const message = Buffer.from(canonicalize(event), "utf8");
  // Ed25519 takes a null digest algorithm in Node's sign/verify API.
  const signature = nodeSign(null, message, toPrivateKey(privateKeyPem));
  return signature.toString("hex");
}

/** Verify a hex signature over an OCSF event's canonical bytes. */
export function verifyEvent(
  event: OcsfEvent,
  signatureHex: string,
  publicKeyPem: string,
): boolean {
  try {
    const message = Buffer.from(canonicalize(event), "utf8");
    return nodeVerify(null, message, toPublicKey(publicKeyPem), Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}
