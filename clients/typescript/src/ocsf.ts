/**
 * Minimal OCSF event types for the Lemma TypeScript Connector SDK (Refs #108).
 *
 * Mirrors the Python SDK's `lemma.models.ocsf` shape so events emitted from a
 * TypeScript connector are byte-compatible with what `lemma evidence collect`
 * ingests. Kept dependency-free and type-only so it runs under Node's
 * type-stripping (`node --experimental-strip-types`).
 */

/** OCSF review/finding status. 1 = Pass, 2 = Fail, 0 = Unknown/No-data. */
export type StatusId = 0 | 1 | 2;

export interface OcsfMetadata {
  version: string;
  product: { name: string; vendor_name?: string; uid?: string };
  /** Stable dedupe key — `EvidenceLog` collapses same-`uid` events per UTC day. */
  uid: string;
  [key: string]: unknown;
}

export interface OcsfEvent {
  class_uid: number;
  class_name: string;
  category_uid: number;
  category_name: string;
  type_uid: number;
  activity_id: number;
  /** RFC 3339 / ISO-8601 timestamp. */
  time: string;
  metadata: OcsfMetadata;
  message?: string;
  status_id?: StatusId;
}

export interface ComplianceFinding extends OcsfEvent {
  class_uid: 2003;
  status_id: StatusId;
}

export interface ComplianceFindingInput {
  message: string;
  statusId: StatusId;
  uid: string;
  producer: string;
  time?: string;
  vendorName?: string;
}

/**
 * Construct a well-formed OCSF Compliance Finding (class_uid 2003), filling the
 * fixed taxonomy fields so connector authors only supply the signal.
 */
export function complianceFinding(input: ComplianceFindingInput): ComplianceFinding {
  return {
    class_uid: 2003,
    class_name: "Compliance Finding",
    category_uid: 2000,
    category_name: "Findings",
    type_uid: 200301,
    activity_id: 1,
    time: input.time ?? new Date().toISOString(),
    message: input.message,
    status_id: input.statusId,
    metadata: {
      version: "1.3.0",
      product: { name: input.producer, vendor_name: input.vendorName, uid: input.uid },
      uid: input.uid,
    },
  };
}
