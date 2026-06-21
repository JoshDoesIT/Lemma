/**
 * Connector base for the Lemma TypeScript SDK (Refs #108).
 *
 * Mirrors the Python `lemma.sdk.connector.Connector`: a connector declares a
 * manifest (the `producer` is the signing identity) and implements `collect()`
 * to yield OCSF events. `run()` drains the stream and reports a tally — the
 * TypeScript counterpart of `Connector.run(evidence_log)`. Persisting the
 * events to the signed, hash-chained evidence log is done by the Python CLI
 * (or a forthcoming TS evidence client); this slice covers authoring + OCSF
 * output.
 */

import type { OcsfEvent } from "./ocsf.ts";

export interface ConnectorManifest {
  name: string;
  version: string;
  /** Signing identity for events this connector emits. */
  producer: string;
  description: string;
  capabilities?: string[];
}

export interface CollectResult {
  events: OcsfEvent[];
  /** Count of distinct `metadata.uid`s — what the evidence log would ingest. */
  uniqueUids: number;
}

export abstract class Connector {
  abstract readonly manifest: ConnectorManifest;

  /** Yield OCSF events representing evidence collected from the source. */
  abstract collect(): Iterable<OcsfEvent> | AsyncIterable<OcsfEvent>;

  /** Drain `collect()` into a list and report how many unique events it holds. */
  async run(): Promise<CollectResult> {
    const events: OcsfEvent[] = [];
    for await (const event of this.collect() as AsyncIterable<OcsfEvent>) {
      events.push(event);
    }
    const uids = new Set(events.map((e) => e.metadata.uid));
    return { events, uniqueUids: uids.size };
  }
}
