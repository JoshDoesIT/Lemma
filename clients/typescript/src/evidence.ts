/**
 * Hash-chained, signed evidence log for the Lemma TypeScript SDK (Refs #108).
 *
 * The TS counterpart of the Python `EvidenceLog`: each appended event is bound
 * into an append-only chain — `entryHash = sha256(prevHash || canonical(event))`
 * — and the entry hash is Ed25519-signed. Tampering with any event or breaking
 * the chain invalidates every entry from that point on, exactly like the Python
 * log.
 *
 * This is self-consistent and verifiable within TypeScript. Byte-for-byte
 * parity with the Python entry-hash layout (so a TS-produced envelope verifies
 * on the Python side) is the next slice on #108; the chaining/verification
 * semantics here already match.
 */

import { createHash } from "node:crypto";

import type { OcsfEvent } from "./ocsf.ts";
import { canonicalize, signMessage, verifyMessage } from "./signing.ts";

export const GENESIS_HASH = "0".repeat(64);

export interface SignedEvidence {
  event: OcsfEvent;
  prevHash: string;
  entryHash: string;
  signature: string;
  signerKeyId: string;
}

export type Verdict = "PROVEN" | "VIOLATED" | "DEGRADED";

export interface VerifyResult {
  index: number;
  verdict: Verdict;
  reason: string;
}

function computeEntryHash(prevHash: string, event: OcsfEvent): string {
  return createHash("sha256").update(prevHash + canonicalize(event), "utf8").digest("hex");
}

export class EvidenceLog {
  private readonly envelopes: SignedEvidence[] = [];
  private readonly privateKeyPem: string;
  private readonly publicKeyPem: string;
  private readonly signerKeyId: string;

  constructor(privateKeyPem: string, publicKeyPem: string, signerKeyId = "ts-key") {
    this.privateKeyPem = privateKeyPem;
    this.publicKeyPem = publicKeyPem;
    this.signerKeyId = signerKeyId;
  }

  /** Sign, chain, and append an event. Returns the new envelope. */
  append(event: OcsfEvent): SignedEvidence {
    const prevHash = this.envelopes.length
      ? this.envelopes[this.envelopes.length - 1].entryHash
      : GENESIS_HASH;
    const entryHash = computeEntryHash(prevHash, event);
    const signature = signMessage(entryHash, this.privateKeyPem);
    const envelope: SignedEvidence = {
      event,
      prevHash,
      entryHash,
      signature,
      signerKeyId: this.signerKeyId,
    };
    this.envelopes.push(envelope);
    return envelope;
  }

  entries(): readonly SignedEvidence[] {
    return this.envelopes;
  }

  /** Walk the chain and return a per-entry verdict. */
  verify(): VerifyResult[] {
    const results: VerifyResult[] = [];
    let expectedPrev = GENESIS_HASH;
    for (let i = 0; i < this.envelopes.length; i++) {
      const env = this.envelopes[i];
      const recomputed = computeEntryHash(env.prevHash, env.event);
      if (env.prevHash !== expectedPrev) {
        results.push({ index: i, verdict: "VIOLATED", reason: "chain link broken" });
      } else if (recomputed !== env.entryHash) {
        results.push({ index: i, verdict: "VIOLATED", reason: "content hash mismatch" });
      } else if (!verifyMessage(env.entryHash, env.signature, this.publicKeyPem)) {
        results.push({ index: i, verdict: "DEGRADED", reason: "signature unverifiable" });
      } else {
        results.push({ index: i, verdict: "PROVEN", reason: "" });
      }
      expectedPrev = env.entryHash;
    }
    return results;
  }
}
