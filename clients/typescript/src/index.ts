/** Public surface of the Lemma TypeScript Connector SDK (Refs #108). */

export { complianceFinding } from "./ocsf.ts";
export type {
  ComplianceFinding,
  ComplianceFindingInput,
  OcsfEvent,
  OcsfMetadata,
  StatusId,
} from "./ocsf.ts";
export { Connector } from "./connector.ts";
export type { CollectResult, ConnectorManifest } from "./connector.ts";
export { ReferenceConnector } from "./reference.ts";
export {
  canonicalize,
  generateKeyPair,
  signEvent,
  signMessage,
  verifyEvent,
  verifyMessage,
} from "./signing.ts";
export type { Ed25519KeyPair } from "./signing.ts";
export { chainHash, EvidenceLog, GENESIS_HASH } from "./evidence.ts";
export type { SignedEvidence, Verdict, VerifyResult } from "./evidence.ts";
