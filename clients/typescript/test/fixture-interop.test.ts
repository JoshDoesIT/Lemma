/**
 * Cross-language fixture parity for `lemma connector test` (Refs #228).
 *
 * `test/fixtures/ts-connector-events.jsonl` is the committed output of the TS
 * SDK's `complianceFinding()` for a fixed set of inputs. This test asserts the
 * SDK still reproduces that fixture byte-for-byte (TS is the source of truth);
 * the Python side (`tests/sdk/test_ts_interop.py`) runs `lemma connector test`
 * over the same file and asserts every event validates against the production
 * OCSF schema. Together they prove a TS-authored connector's emitted events are
 * accepted by Lemma's validator.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { complianceFinding, type ComplianceFindingInput } from "../src/ocsf.ts";

const FIXTURE = fileURLToPath(
  new URL("./fixtures/ts-connector-events.jsonl", import.meta.url),
);

// The exact inputs used to generate the committed fixture, in order.
const INPUTS: ComplianceFindingInput[] = [
  {
    message: "Branch protection is enabled on the default branch.",
    statusId: 1,
    uid: "github:branch-protection:2026-01-01",
    producer: "GitHub",
    vendorName: "GitHub",
    time: "2026-01-01T00:00:00Z",
  },
  {
    message: "Root account MFA is not enabled.",
    statusId: 2,
    uid: "aws:root-mfa:2026-01-01",
    producer: "AWS",
    vendorName: "Amazon Web Services",
    severityId: 4,
    time: "2026-01-01T00:00:00Z",
  },
];

test("SDK reproduces the committed cross-language fixture", () => {
  const lines = readFileSync(FIXTURE, "utf8").trim().split("\n");
  assert.equal(lines.length, INPUTS.length);
  INPUTS.forEach((input, i) => {
    assert.deepEqual(complianceFinding(input), JSON.parse(lines[i]));
  });
});
