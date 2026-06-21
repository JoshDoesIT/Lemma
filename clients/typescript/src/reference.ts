/**
 * Reference connector for the Lemma TypeScript SDK (Refs #108).
 *
 * The TS counterpart of the Python reference JSONL connector: a minimal,
 * runnable connector that emits one Compliance Finding, so a scaffolded
 * project works end-to-end before a real integration is wired in.
 */

import { Connector, type ConnectorManifest } from "./connector.ts";
import { complianceFinding, type OcsfEvent } from "./ocsf.ts";

export class ReferenceConnector extends Connector {
  readonly manifest: ConnectorManifest = {
    name: "reference",
    version: "0.1.0",
    producer: "Lemma",
    description: "Reference connector emitting a single Compliance Finding.",
    capabilities: ["reference"],
  };

  private readonly utcDate = new Date().toISOString().slice(0, 10);

  *collect(): Iterable<OcsfEvent> {
    yield complianceFinding({
      message: "Reference connector self-check passed.",
      statusId: 1,
      // Stable per (producer, signal, UTC date) so same-day re-runs dedupe.
      uid: `reference:self-check:${this.utcDate}`,
      producer: this.manifest.producer,
    });
  }
}
