# CLI Reference

Complete reference for every Lemma CLI command, subcommand, flag, and option.

## Global

```
lemma [COMMAND] [OPTIONS]
```

Lemma is a compliance-as-code CLI that maps organizational policies to regulatory framework controls using local AI inference.

---

## `lemma init`

Scaffold a new compliance-as-code project.

```bash
lemma init
```

Creates a `.lemma/` directory in the current working directory with the local index and configuration structure. Fails if `.lemma/` already exists.

**Example:**

```bash
mkdir my-project && cd my-project
lemma init
# ✓ Initialized Lemma project in /path/to/my-project
```

---

## `lemma status`

Show compliance posture summary for the current project.

```bash
lemma status
```

Displays indexed frameworks, policy file count, and overall mapping state.

---

## `lemma validate`

Validate an OSCAL JSON file against the OSCAL schema.

```bash
lemma validate <FILE>
```

| Argument | Required | Description |
|----------|----------|-------------|
| `FILE` | Yes | Path to the OSCAL JSON file to validate |

**Example:**

```bash
lemma validate catalog.json
# ✓ Valid OSCAL catalog — 1,196 controls
```

---

## `lemma framework`

Manage compliance frameworks. Has three subcommands.

### `lemma framework add`

Index a bundled compliance framework by name.

```bash
lemma framework add <NAME>
```

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Framework short name (e.g., `nist-800-53`, `nist-csf-2.0`, `nist-800-171`) |

**Bundled Frameworks:**

| Name | Description | Controls |
|------|-------------|----------|
| `nist-800-53` | NIST SP 800-53 Rev 5 | 1,196 |
| `nist-csf-2.0` | NIST Cybersecurity Framework 2.0 | 219 |
| `nist-800-171` | NIST SP 800-171 Rev 3 | 130 |

**Example:**

```bash
lemma framework add nist-800-53
# ✓ Indexed nist-800-53 — 1,196 controls indexed.
```

### `lemma framework list`

List all indexed frameworks with control counts.

```bash
lemma framework list
```

**Example output:**

```
┌──────────────────┬──────────┐
│ Framework        │ Controls │
├──────────────────┼──────────┤
│ nist-800-53      │    1,196 │
│ nist-csf-2.0     │      219 │
└──────────────────┴──────────┘
```

### `lemma framework import`

Import a user-provided framework file and index it.

```bash
lemma framework import <FILE>
```

| Argument | Required | Description |
|----------|----------|-------------|
| `FILE` | Yes | Path to framework file (`.json`, `.pdf`, `.xlsx`, `.csv`) |

Supported formats:

- **`.json`** — OSCAL catalog JSON (parsed directly)
- **`.pdf`** — PDF document (parsed via Docling; requires `[ingest]` extras)
- **`.xlsx`** / **`.csv`** — Spreadsheet (parsed via openpyxl; requires `[ingest]` extras)

**Example:**

```bash
lemma framework import my-framework.json
# ✓ Imported my-framework — 42 controls indexed.
```

---

## `lemma map`

Map policies to framework controls using AI-powered semantic matching.

```bash
lemma map [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--framework` | *(required)* | Framework name to map against |
| `--output` | `json` | Output format: `json`, `oscal`, `html`, `csv` |
| `--threshold` | `0.3` | Confidence threshold (0.0–1.0) for including matches |

**Examples:**

```bash
# JSON output (default)
lemma map --framework nist-800-53

# HTML report for stakeholders
lemma map --framework nist-csf-2.0 --output html > report.html

# CSV for spreadsheet import
lemma map --framework nist-800-53 --output csv > mapping.csv

# Only high-confidence matches
lemma map --framework nist-800-53 --threshold 0.5
```

### Confidence-gated automation

`lemma map` honors per-operation auto-accept thresholds defined in `lemma.config.yaml`. When an AI output's confidence is at or above the configured threshold, its trace entry is automatically promoted from `PROPOSED` to `ACCEPTED` with `auto_accepted: true`. Outputs below the threshold remain `PROPOSED` for human review.

```yaml
# lemma.config.yaml
ai:
  automation:
    thresholds:
      map: 0.85
```

Thresholds must be in the range `0.0`–`1.0`. Operations without a configured threshold are never auto-accepted. Review-status transitions (including auto-accepts) are visible via `lemma ai audit --status ACCEPTED`.

#### Policy event audit trail

Every time `lemma map` loads the automation config, it diffs the current thresholds against the last recorded state and appends any changes as policy events to `.lemma/policy-events/YYYY-MM-DD.jsonl`. Events carry one of three types — `threshold_set`, `threshold_changed`, or `threshold_removed` — plus the previous and new values, the operation affected, and the config file path that triggered the change. The log is append-only so the history of governance changes is independently auditable from AI decision traces.

---

## `lemma query`

Ask the compliance graph a question in plain English. An LLM translates the question into a bounded structured plan (`QueryPlan`), the executor walks the graph using existing traversals, and every call lands in the AI trace log with `operation="query"` (or `"evidence_query"` when the plan filters Evidence by attribute) and `operation_kind="read"`.

```bash
lemma query "<QUESTION>" [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--verbose` | `false` | Print the resolved query plan before the results |
| `--format` | `table` | Output format: `table` or `json` |

**Examples:**

```bash
lemma query "Which controls does NIST AC-2 harmonize with?"
lemma query --verbose "Which policies satisfy ac-2?"
lemma query --format json "How many controls does nist-csf-2.0 have?"
lemma query "What evidence supports de.cm-01?"
lemma query "Who owns ac-2?"
lemma query "What risks threaten the audit-log bucket?"
lemma query "Which resources impact au-2?"
```

**Queryable edge types:**

| Edge | From → To | Typical question |
|------|-----------|------------------|
| `SATISFIES` | Policy → Control | "Which policies satisfy AC-2?" |
| `HARMONIZED_WITH` | Control ↔ Control | "What controls are harmonized with AC-2?" |
| `CONTAINS` | Framework → Control | "List controls in NIST 800-53" |
| `EVIDENCES` | Evidence → Control | "What evidence supports CC6.1?" |
| `SCOPED_TO` | Resource → Scope | "What resources are in the prod scope?" |
| `OWNS` | Person → Control / Resource | "Who owns AC-2?" |
| `IMPACTS` | Resource → Control | "Which resources impact AU-2?" |
| `THREATENS` | Risk → Resource | "What risks threaten the audit bucket?" |
| `MITIGATED_BY` | Risk → Control | "What risks does CP-9 mitigate?" |
| `APPLIES_TO` | Scope → Framework | "What scopes apply to NIST CSF?" |

**Evidence-attribute filters:**

When a question narrows Evidence by attribute, the translator emits a plan with one or more of these fields. The executor applies them only to Evidence-typed nodes — non-Evidence nodes reached by the same plan walk through unchanged.

| Filter | Type | Example | Question shape |
|---|---|---|---|
| `time_range` | `[start, end)` ISO-8601 strings (half-open) | `["2026-04-26T00:00:00Z", "2026-04-27T00:00:00Z"]` | "What evidence landed in the last 24 hours?" |
| `severity` | any-of OCSF severity *names* | `["HIGH", "CRITICAL"]` | "Show me critical-severity findings." |
| `producer` | any-of producer names | `["GitHub", "AWS"]` | "Authentication events from the GitHub connector." |
| `class_uid` | any-of OCSF class_uid ints | `[3002]` | "Auth events" (3002 = Authentication) |

When any of these fields is set, the trace's `operation` is `"evidence_query"` instead of `"query"`, so auditors can distinguish attribute-filtered evidence questions via `lemma ai audit --operation evidence_query`.

**Multi-hop chains:**

Some compliance questions naturally span more than one edge. The plan can carry an optional `follow` chain — each entry adds one more hop from the prior hop's results, capped at 3 hops total (entry + up to 2 follow hops). Per-hop `node_filter` narrows the prior hop's results before walking the current edge ("from prior-hop nodes matching X, walk edge Y").

```bash
# Framework → Controls → harmonized peers (2 hops)
lemma query "What harmonized controls cover framework nist-csf-2.0?"

# Framework → IA-family controls → policies (2 hops with node_filter)
lemma query "Which policies satisfy controls in the IA family?"
```

Translator output for the second example resolves to `entry_node="framework:nist-800-53"`, `edge_filter=["CONTAINS"]`, `direction="out"`, with `follow=[{node_filter: {family: "IA"}, edge_filter: ["SATISFIES"], direction: "in"}]`. Plans exceeding the 3-hop cap fail with a clear error before any walk runs; v1 single-hop plans (no `follow` field) keep their existing semantics byte-identical.

**What it can and can't do:**

- Supports single-hop and chained multi-hop traversals (NEIGHBORS / IMPACT / framework control counts) with edge-type, direction, per-hop attribute, and Evidence-attribute filters. Total traversal depth capped at 3 hops.
- Results render a per-row **Attributes** column: Evidence shows `producer · time_iso`, Risk shows `title [SEVERITY]`, Person shows email, Resource shows its type.
- Short entry-node names (`"ac-2"`) are resolved against the real graph. Ambiguous short names (same control ID in multiple frameworks) fail with a message listing all candidates so you can rephrase with a framework qualifier.

---

## `lemma harmonize`

Harmonize controls across all indexed frameworks into a Common Control Framework (CCF).

```bash
lemma harmonize [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--threshold` | `0.85` | Cosine similarity threshold for clustering |
| `--output` | `json` | Output format: `json` |

**Example:**

```bash
lemma harmonize --threshold 0.9
```

**Side effects:**

- Writes an OSCAL Profile to `.lemma/harmonization.oscal.json` describing the cross-framework clusters. The profile imports each source catalog and encodes each cluster as a back-matter resource with `lemma:harmonized-cluster` properties.
- **Persists `HARMONIZED_WITH` edges into the compliance graph** for every pair within each cluster. The pair-wise edge similarity is `min(member.similarity)` (conservative — equivalent only as much as the weakest member is to the cluster head). These edges power Cross-Scope Evidence Reuse (`lemma scope reuse`, `lemma evidence rebuild-reuse`).
- Recomputes `IMPLICITLY_EVIDENCES` edges across the whole graph after writing the harmonization edges. The reuse threshold defaults to `ai.automation.thresholds.evidence-reuse` (or 0.7 if unset).
- Appends one `AITrace` per equivalence decision to `.lemma/traces/YYYY-MM-DD.jsonl` with `operation="harmonize"`. Audit these with `lemma ai audit --operation harmonize`.
- Honors `ai.automation.thresholds.harmonize` in `lemma.config.yaml` to auto-accept equivalences at or above the configured threshold.

---

## `lemma coverage`

Show per-framework coverage percentages based on current mappings.

```bash
lemma coverage [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--threshold` | `0.85` | Cosine similarity threshold |

---

## `lemma gaps`

Identify unmapped controls for a specific framework.

```bash
lemma gaps [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--framework` | *(required)* | Framework name to analyze |
| `--threshold` | `0.85` | Cosine similarity threshold |

**Example:**

```bash
lemma gaps --framework nist-csf-2.0
```

---

## `lemma diff`

Compare controls between two frameworks to identify overlaps and differences.

```bash
lemma diff [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--from` | *(required)* | Source framework name |
| `--to` | *(required)* | Target framework name |

**Example:**

```bash
lemma diff --from nist-800-53 --to nist-csf-2.0
```

---

## `lemma graph`

Query and visualize the compliance knowledge graph. The graph is automatically populated when you run `lemma framework add` and `lemma map`.

### `lemma graph export`

Export the full compliance graph as JSON for visualization with D3.js, Cytoscape, or other graph tools.

```bash
lemma graph export
```

Outputs the complete node-link graph to stdout in JSON format. Pipe to a file for use with visualization tools:

```bash
lemma graph export > graph.json
```

### `lemma graph impact`

Trace all controls and frameworks affected by a specific node.

```bash
lemma graph impact <NODE_ID>
```

| Argument | Required | Description |
|----------|----------|-------------|
| `NODE_ID` | Yes | Node identifier (e.g., `policy:access-control.md`, `control:nist-800-53:ac-7`) |

Displays a Rich table showing every control and framework reachable from the specified node via graph traversal.

**Example:**

```bash
lemma graph impact policy:access-control.md
# Shows all controls and frameworks connected to this policy
```

---

## `lemma connector`

Build, scaffold, and test Lemma evidence connectors. Every connector declares a `ConnectorManifest` (the `producer` is the signing identity) and implements a `collect()` method that yields OCSF events. `Connector.run(evidence_log)` pipes the stream into the signed, hash-chained evidence log from [`lemma evidence`](#lemma-evidence).

### `lemma connector init`

Scaffold a new connector project.

```bash
lemma connector init <NAME> [--producer <ID>]
```

| Option | Required | Description |
|--------|----------|-------------|
| `NAME` | Yes | Connector project name (path-safe); creates `./<NAME>/` |
| `--producer` | No | Signing identity for emitted events. Defaults to the project name. |

The scaffolded project is runnable out of the box — it subclasses the reference JSONL connector and reads from `fixtures/events.jsonl`. Drop a few OCSF events into that file and run `lemma connector test ./<NAME>` to verify.

### `lemma connector test`

Validate a connector project by importing it, running `collect()`, and checking every event against the OCSF schema.

```bash
lemma connector test <PATH>
```

Exits `0` with an event-count summary on success, `1` on malformed output, import failure, missing fixture, or schema violation.

**Status — v0 slice (#26):** Python SDK, reference JSONL connector, `init`/`test` CLIs. Deferred to follow-ups:
- TypeScript SDK → [#108](https://github.com/JoshDoesIT/Lemma/issues/108)
- `lemma connector publish` → [#109](https://github.com/JoshDoesIT/Lemma/issues/109)
- Certification workflow → [#110](https://github.com/JoshDoesIT/Lemma/issues/110)
- Push/pull execution models → [#111](https://github.com/JoshDoesIT/Lemma/issues/111)

---

## `lemma evidence`

Inspect and verify the append-only, signed, hash-chained evidence log.

### `lemma evidence verify`

Verify the integrity of a single evidence entry by its `entry_hash`.

```bash
lemma evidence verify <ENTRY_HASH>
```

| Argument | Required | Description |
|----------|----------|-------------|
| `ENTRY_HASH` | Yes | Hex-encoded SHA-256 entry hash of the evidence to verify |

The verdict is one of:

- **PROVEN** — hash consistent, chain link to the prior entry intact, signature verifies under the producer's key.
- **DEGRADED** — hash and chain are intact, but the signer's public key is unavailable (key rotated, revoked, or never imported).
- **VIOLATED** — content has been modified or the chain has been broken somewhere at or before this entry.

Exit code is `0` only on PROVEN; anything else exits `1` so scripts can fail-fast.

**Provenance chain.** When the state is PROVEN or DEGRADED, verify prints the full transformation chain attached to the envelope — one indented line per stage, with timestamp, actor, and truncated content hash. A typical ingested record's chain:

```
PROVEN  a1b2c3d4e5f60718…
  Hash, chain, and signature all valid for producer 'Lemma'.
  Provenance chain:
    source (2026-04-23T12:00:00Z) actor: ingest-cli:batch.jsonl  hash: 9a1e4c5b2f01…
    normalization (2026-04-23T12:00:00Z) actor: lemma.ocsf_normalizer/1  hash: e78d12ab4c5f…
    storage (2026-04-23T12:00:00Z) actor: lemma.services.evidence_log  hash: a1b2c3d4e5f6…
```

The source and normalization records are part of the signed hash — tampering with any of them breaks verification the same way tampering with the event body does. The storage record carries the entry hash as its `content_hash` and is appended last so the chain always terminates at this log.

### `lemma evidence log`

Show every entry in the evidence log with its per-entry integrity state.

```bash
lemma evidence log
```

Output is a Rich table with columns for time, OCSF class name, producer, truncated entry hash, a **Graph** indicator (`✓` / `✗` — whether the entry has been loaded into the compliance graph via `lemma evidence load`), and the integrity verdict.

### `lemma evidence load`

Walk every envelope in the signed log and upsert a corresponding `Evidence` node into the compliance graph, with `EVIDENCES` edges pointing at each control named in the event's `metadata.control_refs` list.

```bash
lemma evidence load
```

This is the operator-triggered equivalent of `lemma scope load` — reads are side-effect-free, graph mutations happen only when you run this command. Re-running is safe: `add_evidence` is idempotent and stale edges are rebuilt when `control_refs` narrows.

**Fails loud on unresolved control refs.** An envelope whose `control_refs` names a control that isn't indexed in the graph (framework not yet `lemma framework add`-ed, or typo'd control id) aborts the whole batch with an error naming the unresolved refs. No silent partial loads — fix the metadata or index the framework, then re-run.

**The `metadata.control_refs` convention.** Operators and connectors signal control linkage by setting this list on OCSF metadata:

```json
{
  "class_uid": 2003,
  "class_name": "Compliance Finding",
  "metadata": {
    "version": "1.3.0",
    "product": {"name": "Manual"},
    "uid": "smoke-1",
    "control_refs": ["nist-csf-2.0:gv.oc-1", "nist-800-53:ac-2"]
  }
}
```

Each entry has the shape `<framework-short-name>:<control-id>`. The field is optional — an evidence entry without `control_refs` still lands as an `Evidence` node, it just has no `EVIDENCES` edges (the audit story "we have this evidence" still holds even when the "which control does it support" link isn't recorded yet).

Once loaded, evidence is reachable from every existing graph surface: `lemma graph impact control:nist-800-53:ac-2` surfaces every piece of linked evidence, and `lemma query` traversals see `Evidence` nodes alongside frameworks and controls.

**Auto-rebuilds Cross-Scope Evidence Reuse.** After the direct `EVIDENCES` walk, `evidence load` recomputes `IMPLICITLY_EVIDENCES` edges across the whole graph: for each Evidence with a direct edge to Control C, every harmonized peer C' with `HARMONIZED_WITH` similarity at or above `ai.automation.thresholds.evidence-reuse` (default 0.7) gets an implicit edge from the same Evidence, carrying `via_control=C` and the harmonization `similarity` for explainability. Implicit edges are skipped when the target peer already has a direct EVIDENCES from the same Evidence (direct wins). The success message reports the implicit-edge count when nonzero.

### `lemma evidence rebuild-reuse`

Recompute `IMPLICITLY_EVIDENCES` edges on demand without re-running discover or load. Useful when you've changed the harmonization-similarity threshold, edited the OSCAL profile by hand, or want to see how reuse coverage shifts at a different floor.

```bash
lemma evidence rebuild-reuse [--min-similarity 0.7]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--min-similarity` | `ai.automation.thresholds.evidence-reuse` (or 0.7 if unset) | Per-run override for the harmonization-similarity floor. Edges below the floor are dropped on rebuild. |

The command drops every existing `IMPLICITLY_EVIDENCES` edge before rewriting, so tightening the threshold cleanly invalidates stale reuse. Idempotent.

### `lemma evidence infer`

AI-propose `EVIDENCES` edges for orphaned `Evidence` nodes — those that have no outgoing `EVIDENCES` edges because their underlying OCSF event arrived without a `metadata.control_refs` list.

```bash
lemma evidence infer [--top-k 3] [--accept-all]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--top-k` | `3` | Candidate controls retrieved per indexed framework per evidence (cost: ~`top-k × frameworks` LLM calls per orphan). |
| `--accept-all` | `false` | Write every parseable proposal as an edge and auto-accept the trace at threshold `0.0`, bypassing configured gating. Useful for first-time backfills when you trust the model. |

For each orphaned `Evidence` node, `infer` looks up the original OCSF event in the signed log, retrieves top-k candidate controls from each indexed framework via the same vector index `lemma map` uses, and prompts the LLM to score each `(evidence, candidate)` pair on a 0.0–1.0 confidence scale. Every prompt produces one entry in the AI trace log under `operation="evidence-mapping"` — auditable via `lemma ai audit --operation evidence-mapping`.

**Confidence-gated edge writes.** Configure an auto-accept threshold in `lemma.config.yaml`:

```yaml
ai:
  automation:
    thresholds:
      evidence-mapping: 0.80
```

A proposal at or above the threshold writes an `EVIDENCES` edge with the `confidence` recorded as an edge attribute and promotes the trace to `ACCEPTED`. A proposal below the threshold leaves the trace as `PROPOSED` for human review — no edge is written. With no threshold configured (or `automation` block missing), `infer` never auto-accepts; every proposal stays `PROPOSED`.

**Skip rules.** `infer` skips any Evidence node that already has at least one outgoing `EVIDENCES` edge — whether from `lemma evidence load` (operator-asserted via `metadata.control_refs`) or from a previous `infer` run that auto-accepted. This makes re-runs safe: only genuinely orphaned evidences trigger LLM calls.

**Re-running and PROPOSED traces.** An evidence node with only `PROPOSED` traces (no edges) re-triggers inference on the next run. With non-deterministic models (Ollama temperature > 0) this can produce slightly different proposals each time, growing the trace log. Reviewers can filter on the latest pass via `lemma ai audit`. The behavior is intentional: re-running is the operator asking the model again.

### `lemma evidence rotate-key`

Retire the producer's active signing key and generate a new one. Pre-rotation entries keep verifying PROVEN under the retired key; new entries are signed with the successor.

```bash
lemma evidence rotate-key --producer <NAME>
```

| Option | Required | Description |
|--------|----------|-------------|
| `--producer` | Yes | Producer name (e.g. `Lemma`, `Okta`, `AWS`) |

### `lemma evidence revoke-key`

Mark a specific signing key as revoked with a required reason. Signatures made at or after `revoked_at` under a revoked key verify as `VIOLATED`; signatures made before revocation remain `PROVEN`.

```bash
lemma evidence revoke-key --producer <NAME> --key-id <ID> --reason <TEXT>
```

| Option | Required | Description |
|--------|----------|-------------|
| `--producer` | Yes | Producer name whose key is being revoked |
| `--key-id` | Yes | Exact key identifier (e.g. `ed25519:abcd1234`) to revoke |
| `--reason` | Yes | Why this key is being revoked (operator note) |

### `lemma evidence keys`

List every signing key on file with its lifecycle state, activation timestamp, retirement/revocation timestamp, and revocation reason.

```bash
lemma evidence keys
```

### `lemma evidence ingest`

Read OCSF events from a file (or stdin) and append them to the signed evidence log. Intended for sandbox testing and one-off operator loads when no connector is in place.

```bash
lemma evidence ingest <FILE> [--dry-run]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `FILE` | Yes | Path to a `.json` (single OCSF payload) or `.jsonl` (newline-delimited OCSF payloads). Use `-` to read JSONL from stdin. |

| Option | Default | Description |
|--------|---------|-------------|
| `--dry-run` | off | Validate every record without writing to the evidence log. |

**Format detection.** The extension decides: `.json` is a single payload, `.jsonl` is newline-delimited. Stdin (`-`) is always JSONL. Any other extension is rejected with an error naming the accepted ones — no content sniffing.

**Atomicity.** The run is all-or-nothing. Every record is validated against the OCSF normalizer before the first `append()`, so a malformed record anywhere in a JSONL file means nothing is written. The error message names the file, and for JSONL the line number, so the fix is obvious. Re-run once the file is clean; dedupe guarantees already-ingested records won't duplicate.

**Summary output.** On success, a single line: `N ingested, M skipped (duplicate).` — the skip count comes from the evidence log's existing `metadata.uid`-keyed dedupe guard. `--dry-run` instead prints `N valid (dry run — nothing written).`

**Example:**

```bash
lemma init sandbox && cd sandbox
echo '{"class_uid":2003,"class_name":"Compliance Finding","category_uid":2000,"category_name":"Findings","type_uid":200301,"activity_id":1,"time":"2026-04-23T12:00:00+00:00","metadata":{"version":"1.3.0","product":{"name":"Manual"},"uid":"smoke-1"}}' > smoke.jsonl
lemma evidence ingest smoke.jsonl
# 1 ingested, 0 skipped (duplicate).
lemma evidence ingest smoke.jsonl
# 0 ingested, 1 skipped (duplicate).
```

### `lemma evidence collect`

Run a first-party connector and append its OCSF output to the signed evidence log. Each event is normalized, deduped on `metadata.uid`, and wrapped in a `SignedEvidence` envelope hash-chained to the prior entry.

```bash
lemma evidence collect <CONNECTOR> [OPTIONS]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `CONNECTOR` | Yes | First-party connector name. Currently: `github`, `okta`, `aws`. |

| Option | Required | Description |
|--------|----------|-------------|
| `--repo` | For `github` | Repository in `owner/name` form |
| `--domain` | For `okta` | Okta domain, e.g. `your-org.okta.com` |
| `--region` | For `aws` | AWS region (defaults to `us-east-1`) |

**First-party connectors**

- `github` — collects branch protection on `main`, CODEOWNERS presence, and open Dependabot alert counts bucketed by severity. Auth via the `LEMMA_GITHUB_TOKEN` environment variable (optional for public repos within GitHub's 60-req/hr unauthenticated cap; required for private repos and to lift the rate limit to 5000/hr). Rate-limited responses raise a clean error naming the endpoint.
- `okta` — collects MFA enrollment policy state and the SSO application inventory (active vs. total counts). Auth via the `LEMMA_OKTA_TOKEN` environment variable (required — Okta has no unauthenticated API). The token is passed as an `SSWS <token>` authorization header. Rate-limited responses (HTTP 429) raise a clean error naming the endpoint. Stable `metadata.uid` per `(event_type, domain, UTC date)` so same-day re-runs dedupe against themselves.
- `aws` — collects account-level posture aligned with the CIS AWS Foundations Benchmark: IAM root-account MFA enabled (CIS 1.5), IAM password policy presence + minimum length ≥ 14 (CIS 1.8), and at least one multi-region CloudTrail (CIS 3.1). Auth via the AWS default credential chain (env vars, AWS profile, IMDS) — no Lemma-specific env var. Missing credentials raise a clean error at construction time rather than mid-collect. Stable `metadata.uid` per `(event_type, account_id, UTC date)` so same-day re-runs dedupe against themselves.

Output reports how many events were ingested and how many were skipped as duplicates (same `metadata.uid` already in the log — stable per `event_type`, the producer's target identifier, and UTC date).

---

## `lemma check`

Run the CI/CD compliance gate over the knowledge graph. Exits non-zero if any control in the selected framework has zero satisfying policies, so pipelines can fail builds on compliance regressions.

```bash
lemma check [--framework <ID>] [--format text|json|sarif] [--min-confidence FLOAT]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--framework` | all frameworks in the graph | Restrict the check to a single framework (e.g. `nist-800-53`) |
| `--format` | `text` | Output format: `text` (human-readable Rich table), `json` (machine-parseable), or `sarif` (SARIF 2.1.0 for GitHub Code Scanning / GitLab CI ingestion) |
| `--min-confidence` | `0.0` | Only count `SATISFIES` edges whose `confidence` attribute is at or above this floor. Default `0.0` accepts every edge (preserves v0 behavior). Operators raise this in CI to demand a higher bar than the auto-accept threshold. |

**Pass criterion.** A control is `PASSED` if at least one policy has a `SATISFIES` edge pointing at it whose `confidence` ≥ `--min-confidence`; `FAILED` otherwise. Edges with no recorded confidence are treated as fully trusted (default `1.0`) so legacy / external-tool-written edges keep working.

**`--min-confidence` vs `ai.automation.thresholds.map`.** They're orthogonal: `ai.automation.thresholds.map` (default 0.85) governs whether `lemma map` *auto-accepts* a new mapping into the graph as a SATISFIES edge. `--min-confidence` filters which already-accepted edges *count toward `lemma check`'s pass/fail*. A mapping accepted at 0.85 can still be filtered out by `lemma check --min-confidence 0.95` for stricter CI gating.

**Exit codes.** `0` only when every control in scope passes; `1` on any failure, on unknown `--framework`, on unknown `--format`, or outside a Lemma project.

**JSON output shape** (stable for CI/CD integrations; `min_confidence_applied` was added alongside the `--min-confidence` flag):

```json
{
  "framework": "nist-800-53",
  "outcomes": [
    {
      "control_id": "control:nist-800-53:ac-2",
      "framework": "nist-800-53",
      "short_id": "ac-2",
      "title": "Account Management",
      "status": "FAILED",
      "satisfying_policies": []
    }
  ],
  "total": 1,
  "passed": 0,
  "failed": 1,
  "min_confidence_applied": 0.0
}
```

**SARIF output.** `--format sarif` emits SARIF 2.1.0 JSON for ingestion into GitHub Code Scanning (`github/codeql-action/upload-sarif@v3`) or GitLab's SAST report ingestion. Only `FAILED` controls become SARIF results — passing controls are not findings, so they don't clutter the Security tab. Each result carries:

| SARIF field | Lemma value |
|---|---|
| `ruleId` | The full prefixed `control_id` (e.g. `control:nist-800-53:ac-2`) so multi-framework projects don't collide |
| `level` | `error` for every failed control |
| `message.text` | The control title with a "not satisfied" suffix |
| `locations[0]` | `.lemma/graph.json` — the artifact establishing the verdict (per-policy file provenance is a future refinement) |
| `properties` | `{framework, short_id, satisfying_policies, min_confidence_applied}` for audit context |

**Example workflow:**

```bash
lemma init
lemma framework add nist-csf-2.0
lemma map                                                # creates SATISFIES edges
lemma check                                              # human-readable gate
lemma check --format json | jq '.failed'                 # machine-readable for CI
lemma check --format sarif --min-confidence 0.9          # strict CI gate, GitHub Code Scanning
```

See `docs/guides/ci-cd-integration.md` for end-to-end GitHub Actions and GitLab CI snippets including the SARIF upload step.

**Follow-ups tracked separately** — GitHub Action wrapper ([#120](https://github.com/JoshDoesIT/Lemma/issues/120)) and OPA/Rego policy-as-code ([#121](https://github.com/JoshDoesIT/Lemma/issues/121)). Drift detection and compliance-debt metrics stay inside the parent [#28](https://github.com/JoshDoesIT/Lemma/issues/28) task list.

---

## `lemma scope`

Scope-as-code — declare which compliance frameworks apply to which slice of your infrastructure, and validate the declaration with a strict schema before it ever reaches an auditor.

This is the v0 slice of the [Living Scope Engine](https://github.com/JoshDoesIT/Lemma/issues/24). Auto-discovery (AWS, Azure, GCP, K8s, Terraform, vSphere, Ansible, CMDB), the scope ring model, cross-scope evidence reuse, `lemma scope impact --plan`, and `lemma scope visualize` remain open tasks inside that issue.

### `lemma scope init`

Scaffold a starter scope-as-code file at `scopes/<name>.<ext>`. Refuses to overwrite an existing file — operators delete it manually if they want to regenerate.

```bash
lemma scope init [--name <NAME>] [--format yaml|hcl]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--name` | `default` | Writes `scopes/<NAME>.<ext>`. |
| `--format` | `yaml` | Output format. `yaml` writes `scopes/<NAME>.yaml`; `hcl` writes `scopes/<NAME>.hcl` using Terraform-style block syntax (`match_rule { ... }` blocks, attribute = value pairs). Both formats are interchangeable in `scopes/`. |

### `lemma scope status`

Parse every `scopes/*.yaml`, `scopes/*.yml`, and `scopes/*.hcl` file, validate it against the schema, and render a table of declared scopes. Exit code is `0` on success or empty state; `1` if any file has a parse or schema error.

```bash
lemma scope status
```

The table includes an **In Graph** column showing ✓ when the scope has been loaded into the compliance graph via `lemma scope load`, and ✗ when it's declared in YAML but not yet loaded. This makes it obvious at a glance which scopes an auditor can traverse through `lemma graph impact` and which are still YAML-only.

Error output is line-aware: a YAML syntax mistake or a schema violation is reported as `<file>:<line>:<col>: <reason>` so the operator can jump straight to the offending record. When multiple files have errors, all errors are reported in one pass.

### `lemma scope load`

Load every declared scope into the compliance graph as a `Scope` node with `APPLIES_TO` edges pointing at each bound framework. Operator-run, same model as `lemma map` and `lemma harmonize` — nothing touches the graph until you invoke it.

```bash
lemma scope load
```

Re-running is safe: `add_scope` is idempotent — same scope name updates the node's `justification` and `rule_count` in place, and existing `APPLIES_TO` edges are rebuilt so a scope that drops a framework from its YAML drops the corresponding edge.

**Fails loud on unknown frameworks.** If a scope references a framework that isn't indexed in the graph (`lemma framework add <name>` has never been run for it), `load` exits `1` with an error naming the missing framework(s). No silent partial loads.

Once loaded, a scope is queryable through every existing graph surface:

- `lemma graph impact scope:<name>` traverses from the scope outward — the frameworks it applies to, the controls those frameworks contain.
- `lemma query "..."` over the graph sees `Scope` nodes alongside frameworks and controls.

### `lemma scope matches`

Evaluate a declared resource's attributes against every scope's `match_rules` and print which scopes would contain it. Read-only — doesn't touch the graph. Useful as a sanity check before committing scope YAML or as a local preview of what a Terraform plan would trigger.

```bash
lemma scope matches <RESOURCE-ID>
```

| Argument | Required | Description |
|----------|----------|-------------|
| `RESOURCE-ID` | Yes | The `id` field from a declared `resources/*.yaml` file |

**Match semantics.** A scope contains a resource when **every** one of its `match_rules` evaluates to true against the resource's `attributes`. A scope with zero rules is a catch-all and matches everything (operators use this deliberately for org-wide scopes). Rule `source` paths use dotted traversal — `aws.tags.Environment` walks `{aws: {tags: {Environment: ...}}}`. A missing path does not match (does not raise); heterogeneous resource attributes are expected.

**Operators** (already documented in the scope-as-code schema): `equals`, `contains`, `in` (requires a list `value`), `matches` (regex).

**Example**

```bash
$ lemma scope matches prod-us-east-rds
prod-us-east-rds matches 2 scope(s):
  prod-us-east  →  nist-800-53, nist-csf-2.0
  pci-cardholder  →  pci-dss-4.0
```

Exit code is `0` whether any scopes match or none — "no match" is a legitimate answer. A missing resource id or a malformed scope/resource YAML exits `1`.

### `lemma scope explain`

Show **why** a Resource node currently in the compliance graph belongs to each of its scopes. Reads the per-edge `matched_rules` attribution that `lemma scope discover` records on every `SCOPED_TO` edge; renders it as a per-scope explanation. Distinct from `lemma scope matches` (which evaluates rules dry against a YAML-declared resource) — `explain` reads what's already in the graph from past discover runs.

```bash
lemma scope explain <RESOURCE-ID>
```

`<RESOURCE-ID>` accepts either the bare id (`payments-db`) or the prefixed node id (`resource:payments-db`); both resolve.

```text
$ lemma scope explain resource:payments-db
Resource: payments-db (aws.rds.instance)
In 2 scope(s):
  prod-us-east  ← aws.tags.Environment, equals, 'prod'
  pci-dss       ← aws.region, equals, 'us-east-1'
                ← aws.tags.DataClassification, in, ['cardholder', 'pci']
```

When a scope's rules attribute multiple rules (all of them must have fired for the scope to match), each rule renders on its own line under the scope name.

**Manual declarations** (`lemma resource load` from `resources/*.yaml`) carry no rule context; `explain` labels those edges as `(no rule attribution — manual declaration or catch-all scope)`. Catch-all scopes (zero `match_rules`) render the same way — operators can disambiguate via `lemma scope status` (catch-all scopes show `Rules = 0`).

Exit code is `1` for an unknown resource id or outside a Lemma project; `0` otherwise.

### `lemma scope impact --plan`

Evaluate a Terraform plan against every declared scope and report which planned changes move a resource across scope boundaries. Designed for CI/CD: exit code is `1` whenever any change enters or exits a scope so a pipeline can fail the merge and pull a human into the review. Emits `0` when the plan is entirely scope-neutral.

```bash
terraform show -json plan.tfplan > plan.json
lemma scope impact --plan plan.json
```

| Option | Required | Description |
|--------|----------|-------------|
| `--plan` | Yes | Path to a Terraform plan JSON file (from `terraform show -json`) |

**What it computes.** For each `resource_changes[]` entry in the plan, `scope impact` runs the resource's `change.before` and `change.after` attributes through every declared scope's `match_rules`. The delta is split three ways:

- **Entered** — scope(s) the resource will newly belong to after the plan applies. This is the signal an auditor cares about most: "you're bringing new infrastructure into prod scope."
- **Exited** — scope(s) the resource was in but will no longer be. Also flagged — removing a resource from a compliance scope may mean you're losing evidence coverage for a control.
- **Unchanged** — scope membership that's stable across the change. Not printed (it's the no-news case).

**No-op rows are filtered.** Terraform plans include `actions: ["no-op"]` entries for unchanged resources; `scope impact` drops them since they can't move scope membership by definition.

**Example CI invocation (GitHub Actions excerpt):**

```yaml
- run: terraform show -json plan.tfplan > plan.json
- run: lemma scope impact --plan plan.json
  # exits non-zero on any scope boundary change → pipeline fails, reviewer pulled in
```

### `lemma scope posture`

Per-framework compliance posture for declared scopes. For each scope bound to one or more frameworks, this walks the graph (`Scope → APPLIES_TO → Framework → CONTAINS → Control`) and reports per framework:

- **Controls** — total number of controls in the framework.
- **Mapped** — number with at least one inbound `SATISFIES` edge from a policy.
- **Evidenced** — number with at least one inbound `EVIDENCES` *or* `IMPLICITLY_EVIDENCES` edge. Direct attestation and Cross-Scope Evidence Reuse both count toward total coverage.
- **Reused** — number that are evidenced *only* via implicit (harmonization-driven) edges. Subset of `Evidenced`. Engineers read this column to spot which controls lean on harmonization rather than direct attestation; auditors typically ignore it and read `Evidenced` for total coverage.
- **Covered** — number with both `Mapped` and `Evidenced`. This is the number an auditor usually asks for — "how many controls are both asserted by a policy and supported by real evidence?"

```bash
lemma scope posture [<SCOPE>]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `SCOPE` | No | When provided, renders a per-framework drill-down for that one scope. Omit to summarize every scope in the graph. |

**Prerequisite.** The scope needs to be in the graph — run `lemma scope load` first. Likewise, controls come from `lemma framework add`, SATISFIES edges come from `lemma map`, and EVIDENCES edges come from `lemma evidence load`. `IMPLICITLY_EVIDENCES` edges (the source of `Reused`) come from `lemma harmonize` + `lemma evidence load` (or a manual `lemma evidence rebuild-reuse`). An empty graph prints a friendly hint pointing at those commands.

**Exit codes.** `0` on success (including empty results), `1` on an unknown scope name or outside a Lemma project. `posture` is a read-only report, not a gate — pipelines that want to fail on bad posture use `lemma check`.

### `lemma scope reuse`

Show which controls in a declared scope are covered by **Cross-Scope Evidence Reuse** — evidence attached to a control in a different framework that, via a `HARMONIZED_WITH` equivalence above the configured similarity threshold, also satisfies a control in *this* scope's frameworks.

```bash
lemma scope reuse <SCOPE>
```

Each line in the output traces one implicit-evidence chain: the in-scope control, the source evidence (truncated entry hash), the via-control (the harmonized peer in the other framework that owns the direct EVIDENCES), and the harmonization similarity score that gated the reuse.

```text
$ lemma scope reuse pci
Scope: pci → pci-dss-4.0
Implicitly evidenced controls (3):
  pci-dss-4.0:1.2.4  ← evidence:abc123def456…  (via nist-800-53:ac-2, similarity 0.91)
  pci-dss-4.0:8.2.1  ← evidence:def456abc123…  (via nist-800-53:ia-5, similarity 0.84)
  pci-dss-4.0:12.1   ← evidence:cafebabe1234…  (via nist-csf-2.0:gv.oc-1, similarity 0.85)
```

**Distinct from `lemma scope explain`.** `scope explain <resource-id>` explains why a Resource lands in each of its scopes (which `match_rule` fired); `scope reuse <scope>` explains which Controls in a scope are evidenced by harmonization rather than direct attestation. Different question, different graph walk.

**Exit codes.** `0` on success (including the no-reuse case, which prints a hint), `1` on an unknown scope name or outside a Lemma project.

### `lemma scope drift`

Compare a provider's current discover output against the graph and report the SCOPED_TO delta — what entered scopes, what exited, what attributes changed but stayed in the same scope, what got created upstream, what was deleted upstream. Read-only by default; `--apply` mutates (and prunes Resource nodes whose underlying infrastructure no longer exists).

```bash
lemma scope drift <PROVIDER> [PROVIDER-FLAGS] [--apply]
```

The `<PROVIDER>` argument and per-provider flags are identical to `lemma scope discover` (see the discover sections below). `drift` runs the same provider auth + discover invocation; the only difference is what it does with the candidates.

**Output table** — one row per resource with non-`unchanged` status:

| Column | Meaning |
|---|---|
| Resource | The resource id |
| Status | `created` / `deleted` / `scope_change` / `attribute_drift` |
| Entered | Scopes the resource newly belongs to |
| Exited | Scopes the resource no longer belongs to |
| Attribute changes | Per-field `before→after` diffs |

**Exit codes.** `0` when there's no drift (or `--apply` succeeded); `1` when drift is detected and `--apply` was not passed (CI-friendly — pipelines can gate on drift the same way they gate on `lemma scope impact --plan`).

**Cron pattern for scheduled drift detection:**

```cron
# Every 15 minutes, check AWS account for drift; mail-on-failure via cron's MAILTO.
*/15 * * * * cd /path/to/project && /usr/local/bin/lemma scope drift aws --region us-east-1 || echo "drift detected"
```

The `--apply` flag is what makes drift the active half of Continuous Scope Validation: re-evaluates scope memberships for resources whose attributes changed, creates Resource nodes for newly-discovered assets, and **prunes Resource nodes whose live infrastructure has been deleted upstream** (closes a long-standing pruning gap).

### `lemma scope watch`

Foreground daemon (built on `watchdog` / inotify on Linux, FSEvents on macOS) that watches `scopes/` and `resources/` for changes and re-loads them on edit. Critically, when a scope file changes the daemon **re-evaluates every existing Resource against the new rules** — using stored attributes, no provider invocation needed — so YAML/HCL edits propagate to scope memberships instantly. The other half of Continuous Scope Validation: `drift` handles infrastructure changes; `watch` handles authoring changes.

```bash
lemma scope watch [--debounce-ms 300]
```

| Option | Default | Description |
|---|---|---|
| `--debounce-ms` | `300` | Coalesce file events fired within this window. Multi-file edits (sed across N files, an editor's atomic save sequence) don't trigger N reloads. |

**One-line status per coalesced reload batch:**

```text
Watching scopes/ and resources/ — Ctrl+C to stop.
14:32:17 reloaded 3 scope(s), 4 resource(s); propagated 2, pruned 1.
14:35:02 reloaded 3 scope(s), 4 resource(s); propagated 0, pruned 0.
```

`propagated` counts existing Resources whose scope membership changed because the YAML rules changed; `pruned` counts Resources that no longer match any scope after the rule change (auto-cleaned).

**Foreground only** — operators run under `tmux` / `screen` / `systemctl --user` / `docker run` for persistence. Lemma stays a CLI, not a service framework. Daemonization (background, log-to-file, PID-file management) is intentionally out of scope.

**Signal handling.** `SIGINT` / `SIGTERM` shuts down the observer cleanly (no thread leak, no orphaned watch handles).

### `lemma scope visualize`

Render the scope-centered slice of the compliance graph as Graphviz DOT on stdout. Includes Scope, Framework, Control, and Resource nodes with `APPLIES_TO`, `CONTAINS`, and `SCOPED_TO` edges. Pipe the output through any Graphviz renderer (`dot`, `neato`, etc.) to turn it into an image.

```bash
lemma scope visualize [<SCOPE>] | dot -Tpng -o graph.png
```

| Argument | Required | Description |
|----------|----------|-------------|
| `SCOPE` | No | Restrict the rendering to one scope and its reachable frameworks / controls / resources. Omit to render every declared scope. |

**Why DOT, not PNG directly.** Emitting DOT keeps Lemma free of a heavy Graphviz Python binding and lets operators pick their preferred renderer (`dot` for hierarchical, `neato` for force-directed, `fdp` for cluster layouts). A typical workflow:

```bash
lemma scope visualize prod > prod.dot
dot -Tpng prod.dot -o prod.png       # render
dot -Tsvg prod.dot -o prod.svg       # vector for documentation sites
```

**Exit codes.** `0` on success, including an empty graph (you'll get a valid but empty digraph). `1` on an unknown scope name or when invoked outside a Lemma project.

### `lemma scope discover aws`

Auto-discover cloud resources directly from an AWS account. For every discovered asset, run its attributes through the declared scope `match_rules` and write a `Resource` node + `SCOPED_TO` edge for each match. Eliminates hand-curating `resources/*.yaml` for production cloud accounts.

```bash
lemma scope discover aws [--region <r>] [--service ec2,s3,iam] [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--region` | `us-east-1` | AWS region for region-scoped APIs (EC2). S3 and IAM are global; the flag is ignored for them. |
| `--service` | `ec2,s3,iam` | Comma-separated list of services to enumerate. |
| `--dry-run` | `false` | Print the matched resources as YAML to stdout; do not touch the graph. Useful as a preview before the first real run. |

**Auth.** boto3's default credential chain (env vars / AWS profile / IMDS). No Lemma-specific env var. Missing credentials raise a clean `ValueError` at construction time via STS `GetCallerIdentity` so operators aren't surprised mid-discover.

**What gets discovered (v0).**

| Service | API | Resource id | Resource type | Notable attributes |
|---------|-----|-------------|---------------|--------------------|
| EC2 instances | `ec2:DescribeInstances` (paginated) | `aws-ec2-<instance-id>` | `aws.ec2.instance` | `aws.region`, `aws.state`, `aws.instance_type`, `aws.availability_zone`, `aws.tags.<Key>` |
| S3 buckets | `s3:ListBuckets` + `s3:GetBucketLocation` | `aws-s3-<bucket-name>` | `aws.s3.bucket` | `aws.region`, `aws.name` |
| IAM users | `iam:ListUsers` (paginated) | `aws-iam-user-<user-name>` | `aws.iam.user` | `aws.user_name`, `aws.path`, `aws.create_date` |

EC2 tags are normalized from boto3's `[{Key, Value}, ...]` to `{Key: Value, ...}` so existing scope rules using dotted paths like `aws.tags.Environment` work unchanged.

**Multi-scope match handling.** When a discovered resource matches more than one declared scope, the command takes the alphabetically-first match and prints a yellow warning naming all matches. The current `Resource → Scope` edge is single-valued; true multi-scope membership is the Scope Ring Model on [#24](https://github.com/JoshDoesIT/Lemma/issues/24).

**Per-service error tolerance.** If one AWS service raises (AccessDenied, throttling, etc.) the discover continues with the others. The summary line counts resources from successful services; failed services are logged.

**No pruning.** If an asset is deleted in AWS, its corresponding Resource node persists in the graph until manually removed or until [#144](https://github.com/JoshDoesIT/Lemma/issues/144) ships a prune surface. Re-running discover refreshes attributes on still-existing assets via `add_resource`'s idempotent rebuild.

**Exit codes.** `0` on success. `1` outside a Lemma project, when no scopes are declared, when the provider is anything other than `aws` / `terraform`, or when AWS credentials cannot be resolved.

### `lemma scope discover terraform`

Discover resources from a Terraform state file (`terraform.tfstate`) instead of a live cloud API. Useful when Lemma's host has read access to the state file but not directly to the AWS / GCP / Azure account, when the operator wants to discover resources from multiple cloud providers in a single pass, or when the state file is the team's source of truth for what's deployed.

```bash
lemma scope discover terraform --path <path-to-tfstate> [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--path` | (required) | Path to a `terraform.tfstate` JSON file. |
| `--dry-run` | `false` | Print matched resources as YAML; do not touch the graph. |

The `--region` and `--service` flags are accepted but ignored for the `terraform` provider.

**This is different from `lemma scope impact --plan`.** That command parses Terraform *plan* output (`terraform show -json plan.tfplan`) to gate CI on scope-boundary crossings. `lemma scope discover terraform` parses the *state* file to populate `Resource` nodes for the live, deployed infrastructure. State and plan share JSON shapes but encode different things; passing a plan file to `discover` exits with an error pointing at `--plan`.

**Resource shape.**

- `id`: `tf-<tf-type>.<name>` for un-indexed resources, with a `[<index>]` suffix for `count`-indexed (int) or `for_each`-indexed (string) resources. Example: `tf-aws_instance.web[0]`, `tf-aws_instance.web[us-east-1a]`.
- `type`: three TF types are normalized to match AWS-API discovery so existing scope rules port across sources — `aws_instance` → `aws.ec2.instance`, `aws_s3_bucket` → `aws.s3.bucket`, `aws_iam_user` → `aws.iam.user`. Every other Terraform type is kept verbatim (`google_compute_instance`, `azurerm_virtual_machine`, `datadog_monitor`, etc.).
- `attributes`: for the three mapped types, attributes nest under `aws.*` to match AWS-API discovery's shape (so `aws.tags.Environment` rules port). For everything else, attributes nest under `tf.*` so operators write source-specific rules deliberately rather than relying on silent coercion.

**Sensitive-attribute redaction.** Lemma's graph commits to disk at `.lemma/graph.json`, so leaking secrets there is a real risk. Both Terraform sensitivity encodings are walked:

- `instances[].sensitive_attributes` — top-level string keys and `[{type: get_attr, value: …}, ...]` step paths get the value at that path replaced with the literal string `<redacted>`.
- `instances[].sensitive_values` — a parallel structure with `true` markers; matching nodes in `attributes` are replaced with `<redacted>`.

Targeted, not whole-block: an RDS instance with a sensitive `password` keeps `engine`, `instance_class`, `tags`, etc., so scope rules on `aws.tags.Environment` still match. Sensitive paths that don't resolve (stale state vs current schema) are silently skipped.

**Mode filter.** `mode: "data"` resources (Terraform data sources) are skipped — they're read-only references, not deployed assets.

**Exit codes.** `0` on success. `1` if `--path` is missing, if the file doesn't look like a Terraform state file (the error names `--plan` if the file is a plan), if the file is missing, or if no scopes are declared.

### `lemma scope discover k8s`

Discover Kubernetes resources from the configured cluster context. Walks the kube-apiserver, runs each discovered resource's attributes through the declared scope `match_rules`, and writes a `Resource` node + `SCOPED_TO` edge for each match. Useful for containerized environments where workloads are the audit unit rather than cloud assets.

```bash
lemma scope discover k8s [--context <ctx>] [--namespace <ns,...>] [--kind <kinds>] [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--context` | (current kubeconfig context) | kubeconfig context to use. Pass when you maintain multiple clusters in one kubeconfig. |
| `--namespace` | (all namespaces) | Comma-separated list of namespaces to restrict to. |
| `--kind` | `namespace,deployment,service` | Comma-separated kinds to enumerate. |
| `--dry-run` | `false` | Print matched resources as YAML to stdout; do not touch the graph. |

**Auth.** kubeconfig only (env `KUBECONFIG` or `~/.kube/config`). No in-cluster ServiceAccount fallback in v0 — running discovery from inside a pod will be added behind an explicit flag if/when an operator needs it. Missing kubeconfig raises a clean `ValueError` at construction time.

**Cluster reachability.** Validated via `version_api.get_code()` before any listing — cheaper than listing namespaces and requires no RBAC. A `ConnectionRefused` / unreachable cluster surfaces as a clean error rather than a confusing per-kind ApiException.

**What gets discovered (v0).**

| K8s kind | API call | Resource id | Resource type | Notable attributes |
|---|---|---|---|---|
| Namespace | `core_v1.list_namespace` | `k8s-<context>-namespace-<name>` | `k8s.namespace` | `k8s.labels.<key>`, `k8s.annotations.<key>` |
| Deployment | `apps_v1.list_deployment_for_all_namespaces` | `k8s-<context>-deployment-<ns>-<name>` | `k8s.deployment` | `k8s.labels.<key>`, `k8s.replicas`, `k8s.image` |
| Service | `core_v1.list_service_for_all_namespaces` | `k8s-<context>-service-<ns>-<name>` | `k8s.service` | `k8s.service_type`, `k8s.labels.<key>` |

**Pods deliberately excluded.** Pods are ephemeral (HPA churn, OOMKills, rollouts) — discovering them produces a graph that lies within minutes. Deployments are the declarative truth. Add `--kind pod` if you need it; it's not in the v0 set.

**Cluster context in the ID.** Multi-cluster shops running prod and staging with the same namespace + deployment names would corrupt each other on the second `discover` run if IDs didn't carry cluster identity. AWS gets free disambiguation via account+region in ARNs; K8s names don't, so the context is baked in. When `--context` is unset, the literal string `current` is used.

**Annotation strip.** `kubectl.kubernetes.io/*` annotations are dropped before storing — `kubectl.kubernetes.io/last-applied-configuration` alone can be multi-KB and re-embeds spec data already on the resource. User-set annotations (`team.example.com/owner`, etc.) are preserved.

**Per-kind error tolerance.** If listing one kind raises (e.g. RBAC denial on `Deployments`) the others still produce results; the failed kind is logged.

**Secret references not enumerated.** Deployment Secret references (`volumes[].secret`, `envFrom[].secretRef`) are not captured to avoid scope creep — names aren't sensitive but enumeration multiplies the surface (projected volumes, CSI, image pull secrets). Ship `replicas` + `image` only.

**Exit codes.** `0` on success. `1` outside a Lemma project, when no scopes are declared, when the provider is unsupported, when kubeconfig can't be loaded, when a requested kind is unknown, or when the cluster is unreachable.

### `lemma scope discover gcp`

Auto-discover GCP resources via **Cloud Asset Inventory** (`cloudasset.googleapis.com`) — Google's canonical "what resources exist" API. One client + one `list_assets()` call covers Compute, Storage, IAM, and dozens of other services.

```bash
lemma scope discover gcp --project <id> [--asset-type <types,...>] [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--project` | (required) | GCP project id. Required for the `gcp` provider. |
| `--asset-type` | `compute.googleapis.com/Instance,storage.googleapis.com/Bucket,iam.googleapis.com/ServiceAccount` | Comma-separated CAI asset types to enumerate. |
| `--dry-run` | `false` | Print matched resources as YAML; do not touch the graph. |

**Auth.** Application Default Credentials. Set `GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json` for non-interactive runs, or run `gcloud auth application-default login` once for a developer machine. Missing credentials raise a clean `ValueError` at construction time.

**Enable the Cloud Asset API first.** This is the most common first-run failure. Run:

```bash
gcloud services enable cloudasset.googleapis.com
```

**Reachability check.** The CLI probes the project up front by listing one asset of the first requested type. If the API is disabled or the credentials lack `cloudasset.assets.listAssets` IAM permission, the probe surfaces a clean error rather than a confusing per-type GoogleAPIError mid-discover.

**What gets discovered (v0).**

| CAI asset type | Lemma id | Lemma type | Notable attributes |
|---|---|---|---|
| `compute.googleapis.com/Instance` | `gcp-<project>-instance-<name>` | `gcp.compute.instance` | `gcp.labels.<key>`, `gcp.machine_type`, `gcp.status`, `gcp.location` |
| `storage.googleapis.com/Bucket` | `gcp-<project>-bucket-<name>` | `gcp.storage.bucket` | `gcp.labels.<key>`, `gcp.storage_class`, `gcp.location` |
| `iam.googleapis.com/ServiceAccount` | `gcp-<project>-sa-<basename-before-@>` | `gcp.iam.service_account` | `gcp.email`, `gcp.display_name` |

**Project in the ID.** GCP names alone don't carry project identity — running discover against `prod-project` and then `staging-project` would otherwise corrupt each other's Resource nodes if any names overlap. Project is baked into every ID, just like cluster context for k8s.

**Service Account ID uses `--project`, not the email's project.** Google-managed SAs (`service-12345@compute-system.iam.gserviceaccount.com`) embed a Google service project in their email — using that for the Lemma id would collide across discoveries. The id always uses `--project`; the full email is preserved under `attributes.gcp.email` so scope rules can target either.

**Snake_case field names.** GCP's protobuf Struct converts to a dict via `MessageToDict(..., preserving_proto_field_name=True)` so attribute keys are `machine_type`, `storage_class`, `display_name`, etc. Matches AWS's `instance_type` / k8s's `service_type` convention so dotted-path scope rules read uniformly.

**Per-asset-type error tolerance.** A `PermissionDenied` on Compute doesn't block Storage + IAM enumeration; the failed type is logged and the others still produce results.

**`labels` as the natural scope-rule target.** GCP labels are the analog of AWS tags / k8s labels. A scope rule `source: gcp.labels.environment, operator: equals, value: prod` works through the existing dotted-path matcher unchanged.

**Out of scope for v0.** No `--folder` / `--organization` (broader IAM required); no IAM policy / org policy enumeration via CAI's `IAM_POLICY` content type; only the three "audit pillar" asset types. The full CAI catalog is one append away on the `--asset-type` flag.

**Exit codes.** `0` on success. `1` outside a Lemma project, when no scopes are declared, when the provider is unsupported, when `--project` is missing, when credentials can't be resolved, when the project is unreachable, when an unknown asset type is requested, or when `--asset-type` is empty.

### `lemma scope discover azure`

Auto-discover Azure resources via **Resource Graph** (`Microsoft.ResourceGraph`) — Azure's canonical "what resources exist" API, equivalent to GCP's Cloud Asset Inventory. One client + one KQL query covers Compute, Storage, IAM, and dozens of other resource types.

```bash
lemma scope discover azure --subscription <id> [--resource-type <types,...>] [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--subscription` | (required) | Azure subscription id (typically a GUID like `12345678-1234-1234-1234-123456789abc`). Required for the `azure` provider. Whitespace-only values are rejected. |
| `--resource-type` | `microsoft.compute/virtualmachines,microsoft.storage/storageaccounts,microsoft.managedidentity/userassignedidentities` | Comma-separated Azure resource types to enumerate. |
| `--dry-run` | `false` | Print matched resources as YAML; do not touch the graph. |

**Auth.** `DefaultAzureCredential` chain. Set the `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET` env vars for non-interactive runs, or run `az login` once for a developer machine. Missing credentials raise a clean `ValueError` at construction time.

**Register the Resource Graph provider first.** This is the most common first-run failure. Run:

```bash
az provider register --namespace Microsoft.ResourceGraph
```

**Reachability check.** The CLI probes the subscription up front by querying the first user-supplied resource type at `take 1`. If the provider isn't registered or credentials lack `Microsoft.ResourceGraph/resources/read`, the probe surfaces a clean error rather than a confusing per-type `HttpResponseError` mid-discover. Resource-type allow-list validation runs **before** the probe, so a typo'd `--resource-type` surfaces as a clean validation error too.

**What gets discovered (v0).**

| Azure resource type | Lemma id | Lemma type | Notable attributes |
|---|---|---|---|
| `microsoft.compute/virtualmachines` | `azure-<subscription>-vm-<name>` | `azure.compute.vm` | `azure.tags.<key>`, `azure.vm_size`, `azure.location`, `azure.resource_group` |
| `microsoft.storage/storageaccounts` | `azure-<subscription>-storage-<name>` | `azure.storage.account` | `azure.tags.<key>`, `azure.sku`, `azure.storage_kind`, `azure.location` |
| `microsoft.managedidentity/userassignedidentities` | `azure-<subscription>-mi-<name>` | `azure.identity.user_assigned` | `azure.principal_id`, `azure.location` |

**Identity choice — Managed Identities, not Azure AD principals.** Azure AD (Microsoft Entra) users / groups / service principals live in the separate Microsoft Graph API (separate SDK, separate auth domain — Graph token vs ARM token). Managed Identities live in Resource Graph and are the *workload identities* — what compute resources authenticate as. Maps cleanly to AWS-IAM-user / GCP-service-account in audit framing. AAD-principal enumeration is tracked as a follow-up.

**Subscription in the ID.** Azure subscriptions are typically GUIDs and don't carry friendly identity. Subscription is baked into every Resource ID so multi-subscription tenants don't collide on the second discover run. GUIDs in IDs are ugly but stable — same call as k8s `--context` for opaque user-supplied identifiers.

**Per-type field projection.** Resource Graph returns wildly different shapes per type — `location` is a top-level column, `vm_size` is nested under `properties.hardwareProfile`, `sku` is a top-level column on Storage Accounts (not under properties). The service projects per-type explicitly to avoid bloating `graph.json` with the hundreds of `properties.*` fields Resource Graph returns by default.

**`tags=None` handling.** Resource Graph returns `tags=None` for resources with no tags set; the service normalizes to `{}` so `azure.tags.environment` rules don't crash on untagged resources.

**Pagination.** Transparent. Resource Graph caps responses at 1000 rows; the service walks `skip_token` until exhaustion.

**Per-resource-type error tolerance.** A `403` on Compute (e.g. provider not registered) doesn't block Storage + Managed Identity enumeration; the failed type is logged and the others still produce results.

**Out of scope for v0.** No `--management-group` scope (broader IAM required); no Azure AD principal enumeration (separate SDK); only the three "audit pillar" resource types. The full Resource Graph catalog is one append away on `--resource-type`.

**Exit codes.** `0` on success. `1` outside a Lemma project, when no scopes are declared, when the provider is unsupported, when `--subscription` is missing or whitespace-only, when credentials can't be resolved, when the subscription is unreachable, when an unknown resource type is requested, or when `--resource-type` is empty.

### `lemma scope discover file`

Bulk import resources from a CSV, JSON, or JSON Lines file. The on-prem analog of the cloud discovery sources, useful in air-gapped environments without outbound internet, when the source of truth is a CMDB / spreadsheet / Ansible inventory export, or as a universal escape hatch for any system that can produce a list of resources.

```bash
lemma scope discover file --path <path> [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--path` | (required) | Path to a `.csv` / `.json` / `.jsonl` file. Reuses the `--path` option already used by `terraform`. |
| `--dry-run` | `false` | Print matched resources as YAML; do not touch the graph. |

**Format detection by extension.** `.csv` → CSV with header row; `.json` → top-level JSON array; `.jsonl` → one JSON record per line. Anything else exits `1` with the unrecognized extension named.

**JSON / JSONL schema.** Each record is an object with:

```json
{
  "id": "vm-prod-1",
  "type": "vmware.vm",
  "attributes": {
    "vsphere": {
      "host": "esxi-1",
      "tags": {"environment": "prod"}
    }
  },
  "impacts": []
}
```

- `id` (string, required, non-empty) — verbatim into the graph.
- `type` (string, required, non-empty) — verbatim into the graph.
- `attributes` (object, optional, defaults to `{}`) — verbatim into the Resource node, no auto-wrapping.
- `impacts` (list of strings, optional) — control refs of the form `control:<framework>:<id>`.

**CSV schema.** Header row required. Two reserved columns:

- `id` (required)
- `type` (required)

Every other column becomes an attribute via **dotted-path expansion**: a column named `vsphere.tags.environment` becomes `attributes["vsphere"]["tags"]["environment"]`. This lets you write CSV that produces matcher-compatible nested attributes without hand-constructing JSON.

```csv
id,type,vsphere.host,vsphere.tags.environment
vm-prod-1,vmware.vm,esxi-1,prod
vm-prod-2,vmware.vm,esxi-1,prod
vm-staging-1,vmware.vm,esxi-2,staging
```

CSV doesn't natively support lists, so `impacts` is **not expressible in CSV**. Use JSON for resources that need impacts.

Empty cells become empty strings — explicit, not omitted.

**Operator-controlled schema.** Unlike the cloud providers (which auto-wrap attributes under `aws.*` / `gcp.*` / `azure.*` / `k8s.*`), file import does **not** auto-wrap. Operators are free to use whatever attribute shape works for their CMDB. To share scope rules with cloud-discovered resources, mirror the cloud convention manually (e.g. write CSV columns like `aws.tags.Environment`).

**Operator-controlled IDs.** The `id` field is used verbatim — no `aws-` / `gcp-` / `tf-` prefixing. Use whatever naming scheme already exists in the source CMDB.

**Validation, fail-loud.** Records missing `id` or `type` abort with the offending record index. Duplicate ids within a file abort with every duplicate listed. Malformed JSON / JSONL aborts with the file/line number.

**Empty file.** Returns 0 results, exits 0. Not an error.

**Exit codes.** `0` on success. `1` outside a Lemma project, when no scopes are declared, when the provider is unsupported, when `--path` is missing, when the file is missing, when the extension is unrecognized, when a record is missing required fields, or when duplicate ids are present.

### `lemma scope discover ansible`

Discover hosts from an Ansible inventory by reading the JSON output of `ansible-inventory --list`. Useful for any Ansible-managed environment — the JSON shape is universal across static INI / static YAML / dynamic plugin inventories (AWS EC2 plugin, Terraform inventory, etc.), so one path covers them all.

```bash
lemma scope discover ansible --inventory <path-to-json> [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--inventory` | (required) | Path to a JSON file produced by `ansible-inventory --list`. |
| `--dry-run` | `false` | Print matched resources as YAML; do not touch the graph. |

**Generate the input file first.** Lemma does not invoke Ansible itself, so no Ansible install is required on Lemma's host. The operator runs:

```bash
ansible-inventory --list -i /etc/ansible/hosts > inventory.json
# or with a dynamic inventory plugin:
ansible-inventory --list -i ec2.aws.yml > inventory.json
```

This shifts the inventory-format details to the operator's existing Ansible toolchain and keeps the Lemma surface uniform regardless of inventory source.

**What gets discovered.** One `ansible.host` resource per host in `_meta.hostvars`:

| Lemma field | Value |
|---|---|
| `id` | `ansible-<hostname>` |
| `type` | `ansible.host` |

Attributes nest under `ansible.*`:

```yaml
ansible:
  hostname: web-1
  ansible_host: 10.0.1.10        # convenience extract from host_vars
  host_vars:                     # full host_vars dict, verbatim
    env: prod
    owner: platform
  groups:                        # boolean projection per group
    webservers: true
    production: true
```

**Group membership as boolean projection.** Each group a host belongs to becomes `attributes.ansible.groups.<group>: true`. Scope rules target group membership via the existing `equals` operator:

```yaml
match_rules:
  - source: ansible.groups.production
    operator: equals
    value: true
```

This works because the existing matcher's `CONTAINS` is string-substring-only and `IN` is "actual in rule.value list" — neither cleanly supports list-membership-of-groups. The boolean projection sidesteps that limitation without forcing matcher changes.

**Group hierarchy resolved transitively.** A host in `webservers` is also in `production` if `production` is a parent group (lists `webservers` as a `child`). This matches Ansible's own resolution semantics so scope rules behave the way operators expect.

**Convenience extract: `ansible_host`.** Lifted out of `host_vars` to the top of the namespace because it's the most common scope-rule target after groups.

**`host_vars` preserved verbatim.** Operators can write rules against arbitrary host variables (`ansible.host_vars.env`, `ansible.host_vars.datacenter`, etc.).

**Implicit groups dropped.** Ansible's `all` and `ungrouped` pseudo-groups are not projected — operators almost never want to write rules against those, and including them would clutter the attribute dict.

**Exit codes.** `0` on success. `1` outside a Lemma project, when no scopes are declared, when the provider is unsupported, when `--inventory` is missing, when the file is missing, or when the file isn't valid JSON.

### `lemma scope discover servicenow`

Discover Configuration Items (CIs) from a ServiceNow CMDB via the Table API. Common in enterprise environments where ServiceNow is the authoritative asset inventory; reading the `cmdb_ci` table directly turns Lemma's scope matcher into something useful for any ITSM-managed org.

```bash
lemma scope discover servicenow --instance <name> [--ci-class <table>] [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--instance` | (required) | ServiceNow instance name — the `<name>` part of `https://<name>.service-now.com`. Whitespace-only values are rejected. |
| `--ci-class` | `cmdb_ci` | CI table to query. The default returns every CI across all subclasses; pass `cmdb_ci_server` etc. to restrict. |
| `--dry-run` | `false` | Print matched resources as YAML; do not touch the graph. |

**Auth via env vars.** HTTP Basic auth using:

- `LEMMA_SNOW_USER` — ServiceNow user (or app credential username)
- `LEMMA_SNOW_PASSWORD` — corresponding password

Mirrors the GitHub / Okta connector pattern. OAuth2 is a follow-up if a real deployment needs it; Basic auth covers most enterprise integrations.

**Reachability check.** The CLI probes the instance up front with a 1-row Table API query before discovery starts. 401 / 404 / network errors surface as a clean `ValueError` with the instance named, rather than failing mid-pagination.

**What gets discovered.** Per row in the `cmdb_ci` query result (or whatever table is named via `--ci-class`):

| Lemma field | Value |
|---|---|
| `id` | `snow-<instance>-<sys_id>` |
| `type` | `snow.<sys_class_name>` (e.g. `snow.cmdb_ci_server`, `snow.cmdb_ci_database`) |

Type is **derived from each row's `sys_class_name`** rather than a Lemma-side mapping table. Operators get fine-grained types automatically — including for tenant-custom classes (`u_acme_compute_node` → `snow.u_acme_compute_node`) — without maintaining a mapping that drifts.

**Attributes preserved verbatim under `snow.*`.** ServiceNow rows are flat dicts of strings, so there's no protobuf / nested-properties bloat to filter. Every column comes through, including:

- Standard fields: `name`, `operational_status`, `category`, `manufacturer`, etc.
- **Custom `u_*` columns**: `u_environment`, `u_owner`, `u_data_center`, etc.

Custom columns are exactly what operators want for scope rules; preserving them verbatim means tenant-specific schemas work without configuration:

```yaml
match_rules:
  - source: snow.u_environment
    operator: equals
    value: prod
```

**Instance baked into the id.** Multi-environment ITSM deployments (prod-snow + staging-snow instances of the same vendor) would otherwise collide on the second discover run. Same logic as GCP project-in-id and Azure subscription-in-id.

**Pagination is transparent.** ServiceNow caps responses at 1000 rows per page; the service walks `sysparm_offset` until exhaustion. Operators don't need to think about it.

**Exit codes.** `0` on success. `1` outside a Lemma project, when no scopes are declared, when the provider is unsupported, when `--instance` is missing or whitespace-only, when `LEMMA_SNOW_USER` / `LEMMA_SNOW_PASSWORD` env vars are missing, or when the instance is unreachable / returns auth errors.

### `lemma scope discover device42`

Discover devices from a Device42 IPAM/CMDB/DCIM deployment via the v1.0 Devices API. Pairs with `lemma scope discover servicenow` to fully cover the CMDB-integration story for #24's on-prem section.

```bash
lemma scope discover device42 --url <deployment-url> [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--url` | (required) | Device42 deployment URL — must include scheme (`https://d42.example.com`). Whitespace-only values are rejected. |
| `--dry-run` | `false` | Print matched resources as YAML; do not touch the graph. |

**Auth via env vars.** HTTP Basic auth using:

- `LEMMA_DEVICE42_USER`
- `LEMMA_DEVICE42_PASSWORD`

Mirrors the ServiceNow / GitHub / Okta pattern. API token auth (`X-Auth-Token` header in newer Device42 versions) is a follow-up if anyone needs it.

**URL must include scheme.** Pass `https://d42.example.com` or `http://...` (some on-prem deployments are HTTP-only inside a private network). Bare hostnames are rejected to avoid ambiguous misconfiguration.

**Reachability check.** The CLI probes the deployment up front with a 1-row Devices query before discovery starts. 401 / 404 / network errors surface as a clean `ValueError` with the URL named, rather than failing mid-pagination.

**What gets discovered.** Per row in the `/api/1.0/devices/` response:

| Lemma field | Value |
|---|---|
| `id` | `device42-<host>-<device_id>` (host extracted from the URL — no scheme, no port, no path) |
| `type` | `device42.<type>` (e.g. `device42.physical`, `device42.virtual`, `device42.cluster`) — derived per row from the device's `type` field |

Type is **derived per row**, not from a Lemma-side mapping table. Operators get fine-grained types automatically including for tenant-custom values without configuration drift — same call as ServiceNow's `sys_class_name` derivation.

**Attributes preserved verbatim under `device42.*`.** Device42 device records are flat dicts (no protobuf / nested-properties bloat to filter), so every column comes through. Two normalizations:

1. **`custom_fields` array → flat dict.** Device42 returns custom fields as `[{key, value}, ...]` which isn't matcher-friendly. The service expands this to `device42.custom_fields.<key>: <value>` so operators write rules like:
   ```yaml
   match_rules:
     - source: device42.custom_fields.environment
       operator: equals
       value: prod
   ```
2. **`tags` preserved verbatim.** Device42 returns tags differently across versions (string in older deployments, list in newer ones). The service preserves whatever shape the API returns; operators write source-version-aware rules.

**Host in the id.** Multi-deployment shops (prod-d42 + staging-d42) would otherwise collide on the second discover run. Same logic as GCP project-in-id, Azure subscription-in-id, ServiceNow instance-in-id.

**Pagination is transparent.** Device42 returns `total_count` in every response; the service walks `offset` until exhaustion. The `total_count`-driven termination is cleaner than ServiceNow's "partial page = stop" inference.

**Exit codes.** `0` on success. `1` outside a Lemma project, when no scopes are declared, when the provider is unsupported, when `--url` is missing / whitespace-only / lacks a scheme, when `LEMMA_DEVICE42_USER` / `LEMMA_DEVICE42_PASSWORD` env vars are missing, or when the deployment is unreachable / returns auth errors.

### `lemma scope discover vsphere`

Discover virtual machines, ESXi hosts, and datastores from a VMware vCenter via the vSphere Web Services SDK (pyVmomi). vCenter is the dominant on-prem virtualization platform; reading its inventory directly turns the matcher into something useful for any VMware shop without round-tripping through a CMDB.

```bash
lemma scope discover vsphere --host <vcenter-hostname> [--port 443] [--insecure] \
    [--datacenter <name>] [--vsphere-kind vm,host,datastore] [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | (required) | vCenter hostname (e.g. `vcenter.example.com`). Whitespace-only values are rejected. |
| `--port` | `443` | vCenter port. |
| `--insecure` | `false` | Skip SSL verification. Lab/dev vCenters with self-signed certs only — production deployments should configure proper certs and leave this off. |
| `--datacenter` | (all) | Datacenter name filter. v0 reserves the flag; the service walks every datacenter rooted at `content.rootFolder` regardless. Per-datacenter filtering at the `CreateContainerView` level is tracked in [#154](https://github.com/JoshDoesIT/Lemma/issues/154). |
| `--vsphere-kind` | `vm,host,datastore` | Comma-separated kinds to enumerate. Unknown kind exits `1`. |
| `--dry-run` | `false` | Print matched resources as YAML; do not touch the graph. |

**Auth via env vars.** Username + password (the vSphere SDK's session-based auth):

- `LEMMA_VSPHERE_USER` (e.g. `administrator@vsphere.local`)
- `LEMMA_VSPHERE_PASSWORD`

**SSL handling.** Default verifies the vCenter cert chain. `--insecure` skips verification — use only for lab vCenters with self-signed certs. Process-exit cleans up the SDK session; explicit `Disconnect()` is tracked in [#155](https://github.com/JoshDoesIT/Lemma/issues/155).

**What gets discovered.** Three v0 kinds, mirroring the AWS / GCP / Azure three-pillar shape:

| Kind | vSphere type | Lemma id | Lemma type |
|---|---|---|---|
| `vm` | `vim.VirtualMachine` | `vsphere-<vc-host>-vm-<moid>` | `vsphere.vm` |
| `host` | `vim.HostSystem` | `vsphere-<vc-host>-host-<moid>` | `vsphere.host` |
| `datastore` | `vim.Datastore` | `vsphere-<vc-host>-datastore-<moid>` | `vsphere.datastore` |

vCenter's `_moId` (managed object id, e.g. `vm-1234`) is unique within a vCenter; combining it with `--host` lets multi-vCenter shops discover into one graph without collisions. Same convention as GCP project-in-id, Azure subscription-in-id, ServiceNow instance-in-id.

**Attributes nest under `vsphere.*`.** Per-kind, an explicit projection (no `**spread` — pyVmomi managed objects have hundreds of fields, many recursive) populates:

- VM — `kind`, `vc_host`, `moid`, `name`, `guest_os`, `power_state`, `cpu_count`, `memory_mb`, `tags`.
- Host — `kind`, `vc_host`, `moid`, `name`, `version`, `connection_state`, `cpu_count`, `memory_mb` (normalized from bytes), `vendor`, `model`, `tags`.
- Datastore — `kind`, `vc_host`, `moid`, `name`, `type` (`VMFS` / `NFS` / `vsan` / etc.), `capacity_bytes`, `free_bytes`, `tags`.

**Custom Attributes (legacy) → `vsphere.tags.<name>`.** vCenter's legacy Custom Attributes (`obj.customValue` keyed by integer that resolves via `content.customFieldsManager.field`) project into a flat `tags` dict so operators write rules like:

```yaml
match_rules:
  - source: vsphere.tags.environment
    operator: equals
    value: prod
```

vSphere 6.0+ Tags (the vAPI / `cis.tagging` REST endpoints) are a separate auth domain and are tracked in [#156](https://github.com/JoshDoesIT/Lemma/issues/156). Any tag scheme already migrated to Custom Attributes works in v0.

**Per-kind RBAC tolerance.** A `vim.fault.NoPermission` or `vim.fault.NotAuthenticated` on one kind logs a warning and continues to the next; a service-account that can read VMs but not Hosts still produces useful output.

**Exit codes.** `0` on success. `1` outside a Lemma project, when no scopes are declared, when the provider is unsupported, when `--host` is missing / whitespace-only, when `LEMMA_VSPHERE_USER` / `LEMMA_VSPHERE_PASSWORD` env vars are missing, when vCenter rejects credentials, or when the vCenter is unreachable.

### `lemma scope discover network`

Discover live hosts on operator-supplied CIDR range(s) by shelling out to the [nmap](https://nmap.org) binary. The discovery-of-last-resort: every other on-prem source assumes the operator already has an inventory (Ansible, CMDB, vCenter); network scanning finds hosts that no inventory system knows about. Critical for shadow-IT discovery and air-gapped environments where IPAM lives in someone's spreadsheet. Closes the on-prem auto-discovery section of [#24](https://github.com/JoshDoesIT/Lemma/issues/24).

```bash
lemma scope discover network --cidr <cidr>[,<cidr>...] \
    [--network-port 22,80,443,3389,445,3306,5432,8080] \
    [--label <name>] [--privileged] [--detect-versions] [--ipv6] [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--cidr` | (required) | Comma-separated CIDR(s) to scan (e.g. `10.0.0.0/24,10.0.1.0/24`). Each is validated via `ipaddress.ip_network` before any scan runs. v6 CIDRs require `--ipv6`. |
| `--network-port` | `22,80,443,3389,445,3306,5432,8080` | Comma-separated TCP ports to probe per host. Empty (`--network-port ""`) falls back to host-discovery only. |
| `--label` | (none) | Optional label baked into discovered resource ids (`network-<label>-<ip>`) for multi-network shops or overlapping RFC1918 ranges. |
| `--privileged` | `false` | Switch nmap to SYN scan + OS fingerprinting (`-sS -O`). Requires root / `CAP_NET_RAW`; the CLI errors loud at construction if missing. Surfaces `attributes.network.os` + `mac` + an OS-derived type (`network.host.linux` / `.windows` / `.bsd` / etc.). |
| `--detect-versions` | `false` | Append nmap service-version detection (`-sV`). Adds `attributes.network.services.<port>: {name, product, version}`. Slow; significantly more network noise. |
| `--ipv6` | `false` | Pass `-6` to nmap and accept IPv6 CIDRs only. v6 host ids are bracket-wrapped (`network-[2001:db8::1]`). |
| `--dry-run` | `false` | Print matched resources as YAML; do not touch the graph. |

**nmap binary prerequisite.** Install via `brew install nmap` (macOS) or `apt install nmap` (Debian/Ubuntu). The CLI errors loud at construction if `nmap` is not on PATH.

**Authorization warning.** Network scanning a range you do not own may violate law or policy — typing this command is your authorization. Lemma does not interactively confirm; the operator is responsible for ensuring every CIDR passed is one they're permitted to scan.

**`--privileged` IDS / IPS noise.** SYN scan + OS fingerprinting trip intrusion-detection signatures in many shops. Coordinate with the security team before running `--privileged` against any subnet that's monitored, or expect to explain a scanner alert.

**`--detect-versions` time impact.** `-sV` probes service banners on every open port and waits for responses; a `/24` scan that runs in seconds without `-sV` can take minutes with it. Useful for vuln-correlation but not a smart default for routine inventory passes.

**`--ipv6` routing gotcha.** `nmap -6` requires a v6-routable path from the scanner to the target. Many internal networks are v6-disabled at the router even when the host stacks support it; if scans return zero hosts on a known-live v6 range, check `ip -6 route` on the scanner before assuming the target is down.

**Default scan profile.** Unprivileged TCP-connect (`nmap -sT -Pn -R -oX -`) — runs on a dev laptop without root. The default port list `{22, 80, 443, 3389, 445, 3306, 5432, 8080}` covers the SSH / web / RDP / SMB / DB pillars audit operators care about; nmap's full top-1000 takes minutes per `/24`, the eight-port list takes seconds.

**What gets discovered.**

| Field | Value |
|---|---|
| `id` | `network-<ip>` (or `network-<label>-<ip>` with `--label`; v6 wraps the address: `network-[2001:db8::1]`) |
| `type` | `network.host` (or `network.host.<family>` with `--privileged` when nmap returns an OS match) |
| `attributes.network.ip` | The bare IP (no brackets) |
| `attributes.network.hostname` | Reverse DNS or `null` |
| `attributes.network.open_ports` | List of ints, sorted ascending |
| `attributes.network.scan_label` | Present only with `--label` |
| `attributes.network.os` | Present only with `--privileged` and a confident match: `{name, family, accuracy}` |
| `attributes.network.mac` | Present only with `--privileged` and when the host is on the local subnet |
| `attributes.network.services` | Present only with `--detect-versions`: `{"<port>": {name, product, version}}` |

**Worked example — find RDP-exposed hosts.** Declare a scope rule and run a default scan:

```yaml
match_rules:
  - source: network.open_ports
    operator: contains
    value: 3389
```

```bash
lemma scope discover network --cidr 10.0.0.0/24 --label prod-vlan
```

Hosts with port 3389 open land in the scope; everything else is skipped. With `--detect-versions` you can target specific service versions: `network.services.443.product, equals, nginx`.

**Exit codes.** `0` on success. `1` outside a Lemma project, when no scopes are declared, when the provider is unsupported, when `--cidr` is missing / whitespace-only, when `--network-port` contains non-integer entries, when nmap is not on PATH, when `--privileged` is set without root / `CAP_NET_RAW`, when a CIDR's address family conflicts with `--ipv6`, or when nmap exits non-zero.

### Scope-as-code schema

Both YAML and HCL are accepted side-by-side in `scopes/`. The Pydantic model is format-agnostic; pick whichever syntax fits your team's existing toolchain.

**YAML form:**

```yaml
name: prod-us-east                      # required; unique scope identifier
frameworks:                             # required; non-empty list of framework IDs
  - nist-800-53
  - nist-csf-2.0
justification: >-                       # optional; free-text audit rationale
  Customer-facing production environment subject to contractual
  obligations with our enterprise customers.
match_rules:                            # optional; rules selecting in-scope resources
  - source: aws.tags.Environment
    operator: equals                    # equals | contains | in | matches
    value: prod
  - source: aws.region
    operator: in
    value:
      - us-east-1
      - us-east-2
```

**HCL form** (Terraform-style block syntax):

```hcl
name          = "prod-us-east"
frameworks    = ["nist-800-53", "nist-csf-2.0"]
justification = <<-EOT
  Customer-facing production environment subject to contractual
  obligations with our enterprise customers.
EOT

match_rule {
  source   = "aws.tags.Environment"
  operator = "equals"
  value    = "prod"
}

match_rule {
  source   = "aws.region"
  operator = "in"
  value    = ["us-east-1", "us-east-2"]
}
```

The one structural difference: HCL uses repeated `match_rule { ... }` blocks where YAML uses a `match_rules:` list. The HCL parser collects every `match_rule` block into the same `match_rules` field internally; both forms produce identical `ScopeDefinition` objects. Unknown top-level fields are rejected in both formats — a typo such as `match_rul` fails with a line-numbered error rather than being silently dropped.

---

## `lemma resource`

Manage declared infrastructure resources. A **Resource** is one infrastructure asset (an RDS instance, an S3 bucket, a Kubernetes deployment) that belongs to one or more declared compliance Scopes. Declaring resources gives the compliance graph a population to reason about: once loaded, `lemma graph impact resource:<id>` surfaces the scope → framework → control chain(s) that a single resource answers to.

The Scope Ring Model (shipped alongside `lemma scope explain`) lets one Resource sit in N overlapping scopes simultaneously — a payments database can be in both `prod-us-east` and `pci-dss` as a single graph node with two `SCOPED_TO` edges, not two duplicate Resources.

### `lemma resource load`

Parse every `resources/*.yaml`, `resources/*.yml`, and `resources/*.hcl` file, validate each against the schema, and upsert a `Resource` node into the compliance graph with one `SCOPED_TO` edge per declared scope.

```bash
lemma resource load
```

Re-running is safe: `add_resource` is idempotent — same `id` updates `attributes` in place, and the full `SCOPED_TO` edge set is rebuilt, so a resource that rotates from `scopes: [prod, dev]` to `scopes: [prod, staging]` cleanly drops the `dev` edge and adds `staging`.

**Fails loud on unresolved scopes.** If any name in `scopes:` doesn't resolve to a Scope node (`lemma scope load` has never run for it, or the scope YAML was deleted), `load` exits `1` listing every missing scope. No silent partial loads — the entire batch aborts.

### `lemma resource list`

Parse every resource YAML and render a Rich table with the id, type, comma-joined declared scopes, a ✓/✗ indicating whether **every** declared scope is in the graph, and the attribute count.

```bash
lemma resource list
```

### Resource-as-code schema

Both YAML and HCL are accepted side-by-side in `resources/`. Resource HCL has no block-style fields (everything is `attribute = value`), so the two formats map almost 1:1.

**YAML form:**

```yaml
id: payments-db                # required; unique within the project
type: aws.rds.instance         # required; free-form string naming the resource kind
scopes:                        # required; non-empty list of declared Scope names
  - prod-us-east
  - pci-dss
attributes:                    # optional; arbitrary key/value pairs copied to the node
  region: us-east-1
  engine: postgres
  multi_az: true
impacts:                       # optional; control refs the resource directly contributes to
  - control:nist-800-53:au-2
  - control:nist-csf-2.0:de.cm-01
```

**HCL form:**

```hcl
id     = "payments-db"
type   = "aws.rds.instance"
scopes = ["prod-us-east", "pci-dss"]

attributes = {
  region   = "us-east-1"
  engine   = "postgres"
  multi_az = true
}

impacts = [
  "control:nist-800-53:au-2",
  "control:nist-csf-2.0:de.cm-01",
]
```

**Field rules.**

- `id` is caller-supplied and is the dedup key on re-runs.
- `type` is free-form. Conventions like `aws.rds.instance`, `aws.s3.bucket`, `k8s.deployment` are suggested but not enforced.
- `scopes` is a **non-empty list** of scope names already loaded into the graph via `lemma scope load`. Single-scope resources still use the list shape (`scopes: [prod-us-east]`) — the singular `scope:` key was removed in the Scope Ring Model rewrite and now fails the schema check with an "extra inputs are not permitted" error.
- `attributes` is loose (`dict[str, Any]`) — resource types vary enormously, and a rigid per-type schema would block operators from declaring anything we haven't anticipated.
- `impacts` is optional. Each entry is a `control:<framework>:<control-id>` ref naming a control this resource directly contributes to (e.g., the audit-log bucket impacts `control:nist-800-53:au-2`). Generates `IMPACTS` edges in the graph. Distinct from `SCOPED_TO` — `SCOPED_TO` is scope membership; `IMPACTS` is direct contribution. Unresolved control refs abort `lemma resource load` with the missing refs named.
- Unknown top-level fields fail loud with a line-numbered error. Typoing `resource_type:` for `type:` doesn't silently drop, and the deprecated singular `scope:` key surfaces the same error so operators get a one-line fix.

**Worked example — multi-scope payments DB.**

```yaml
# resources/payments-db.yaml
id: payments-db
type: aws.rds.instance
scopes:
  - prod-us-east     # production region scope (NIST CSF)
  - pci-dss          # PCI-DSS scope (PCI-DSS 4.0)
attributes:
  engine: postgres
  multi_az: true
```

After `lemma resource load`, `lemma graph impact resource:payments-db` walks **both** SCOPED_TO edges from one starting node, surfacing the union of NIST CSF and PCI-DSS controls the resource answers to. Compare with `lemma scope explain resource:payments-db` to see which scope rule(s) (or "manual declaration" for hand-authored YAML) caused each scope membership.

---

## `lemma person`

Manage declared people (or shared aliases) who are accountable for controls and/or resources. A **Person** is the audit answer to "who owns this control?" — the universal ownership question. Persons are loaded as `Person` nodes in the compliance graph with `OWNS` edges pointing at controls and/or resources they're responsible for.

Like resource-as-code, this is manual declaration only. Operators author `people/*.yaml` files and load them with `lemma person load`. LDAP / OIDC / HR-system auto-population is a future concern (tracked in #76).

### `lemma person load`

Parse every `people/*.yaml` and `people/*.yml` file, validate each against the schema, and upsert a `Person` node into the graph with one `OWNS` edge per entry in the `owns` list.

```bash
lemma person load
```

Re-running is safe: `add_person` is idempotent — same `id` updates `name`, `email`, `role`, and the full set of `OWNS` edges in place. Dropping an entry from `owns` drops the corresponding edge cleanly.

**Fails loud on unresolved targets.** If any `owns` entry names a node that isn't in the graph (typo'd control id, resource that wasn't loaded), `load` exits `1` with an error listing every unresolved ref and pointing at the right fix command (`lemma framework add` for controls, `lemma resource load` for resources). No silent partial loads.

### `lemma person list`

Parse every person YAML and render a Rich table: id, name, role, owns-count, and a ✓/✗ column showing whether every `owns` ref currently resolves in the graph. Quick sanity check before running `load`, or for catching drift when someone deleted a resource without updating its owner's YAML.

```bash
lemma person list
```

### Person-as-code schema

```yaml
id: alice                             # required; unique within the project
name: Alice Chen                      # required; full display name
email: alice@example.com              # optional; contact address or team alias
role: Security Lead                   # optional; free-form title / responsibility
owns:                                 # optional; controls and/or resources this person owns
  - control:nist-800-53:ac-2
  - control:nist-csf-2.0:gv.oc-1
  - resource:prod-us-east-rds
```

**The `owns` ref convention.** Each entry is a prefixed node id — the same id used everywhere else in the graph:

- `control:<framework>:<control-id>` — e.g. `control:nist-800-53:ac-2`
- `resource:<resource-id>` — e.g. `resource:prod-us-east-rds`

A single `owns` list can mix both target types. Operators see the same ids here they'd see in `lemma graph impact` output; no separate field for controls vs. resources. Unknown top-level fields fail loud with a line-numbered error (`manager:` for example will be rejected).

---

## `lemma risk`

Manage declared risks — bad outcomes the organization wants to avoid. A **Risk** is the audit answer to "what happens if this control fails?" or "what threatens this resource?" Risks land as `Risk` nodes in the compliance graph with `THREATENS` edges to Resources and `MITIGATED_BY` edges to Controls.

### `lemma risk load`

Parse every `risks/*.yaml` file, validate against the schema, and upsert a `Risk` node with `THREATENS` and `MITIGATED_BY` edges.

```bash
lemma risk load
```

Re-running is safe: `add_risk` is idempotent — same `id` updates `title`, `description`, `severity`, and the full set of `THREATENS`/`MITIGATED_BY` edges in place. Dropping an entry from `threatens` or `mitigated_by` drops the corresponding edge cleanly.

**Fails loud on unresolved targets.** A `threatens` entry must resolve to a `resource:<id>` in the graph; a `mitigated_by` entry must resolve to a `control:<framework>:<id>`. Unresolved refs abort the whole batch with every missing ref named — no silent partial loads.

### `lemma risk list`

Render a Rich table of declared risks ordered by severity (CRITICAL first, LOW last). Each row shows id, title, severity (color-coded), `threatens` count, and `mitigated_by` count.

```bash
lemma risk list
```

### Risk-as-code schema

```yaml
id: audit-log-loss                    # required; unique within the project
title: Loss of audit logs             # required; short summary
description: >-                       # optional; longer narrative
  Audit log bucket compromised or accidentally deleted, leaving
  no forensic record of activity in the production environment.
severity: high                        # required; one of low | medium | high | critical
threatens:                            # optional; resource:<id> refs
  - resource:audit-logs-bucket
mitigated_by:                         # optional; control:<framework>:<id> refs
  - control:nist-800-53:au-2
  - control:nist-csf-2.0:de.cm-01
```

**Field rules.**

- `severity` is a closed enum (`low`, `medium`, `high`, `critical`). Free-form severity strings would make scoring impossible; the four-level ladder matches NIST/ISO conventions.
- `threatens` and `mitigated_by` are separate fields rather than a single mixed list because the relationships are semantically different — "threatens this resource" vs. "is mitigated by this control" — and operators benefit from unambiguous intent.
- Unknown top-level fields fail loud with a line-numbered error.

`Risk` nodes are queryable via every existing graph surface — `lemma graph impact risk:<id>` walks both edge types, and `lemma scope visualize` will include risks when a future visualizer slice surfaces them.

---

## `lemma ai`

AI transparency and governance commands.

### `lemma ai system-card`

Display the AI System Card — a versioned transparency document describing every AI model used in Lemma.

```bash
lemma ai system-card [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `markdown` | Output format: `markdown` or `json` |

The system card documents model capabilities, known limitations, training data provenance, and risk mitigations.

**Examples:**

```bash
# Human-readable markdown (default)
lemma ai system-card

# Machine-readable JSON
lemma ai system-card --format json
```

### `lemma ai bom`

Export the AI Bill of Materials (AIBOM) as a CycloneDX 1.6 JSON document.

```bash
lemma ai bom
```

The AIBOM enumerates every AI model registered in the system card and provides a machine-readable inventory suitable for supply-chain review and AI governance (EU AI Act, NIST AI RMF). Each component includes the model name, version, publisher, purpose, training data provenance, and — when available — a cryptographic hash. Output is validated against a bundled CycloneDX 1.6 structural schema before being emitted; invalid BOMs raise an error rather than writing broken JSON.

**Examples:**

```bash
# Emit AIBOM to stdout
lemma ai bom

# Pipe to a file for attestation
lemma ai bom > aibom.cdx.json
```

### `lemma ai audit`

Query and filter the AI decision trace log.

```bash
lemma ai audit [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--model` | *(all)* | Filter by model ID (e.g., `ollama/llama3.2`) |
| `--status` | *(all)* | Filter by review status: `PROPOSED`, `ACCEPTED`, `REJECTED` |
| `--operation` | *(all)* | Filter by operation type (e.g., `map`, `harmonize`, `query`, `evidence_query`) |
| `--kind` | *(all)* | Filter by operation kind: `decision` (map/harmonize/...) or `read` (query/evidence_query) |
| `--format` | `table` | Output format: `table` or `json` |
| `--summary` | `false` | Show aggregate statistics instead of individual traces |

The audit log captures every AI decision: input, prompt, model, raw output, confidence score, and human review status.

`--operation` and `--kind` are complementary. `--kind decision` returns every trace that *changed* the compliance record (map, harmonize, evidence-mapping); `--kind read` returns every read-only operation (query, evidence_query). Use `--operation` when you want a specific kind of decision or read; use `--kind` when you want to separate "what AI told us" from "what someone asked."

**Examples:**

```bash
# All traces as a Rich table
lemma ai audit

# Filter by model
lemma ai audit --model ollama/llama3.2

# Only accepted mappings
lemma ai audit --status ACCEPTED

# Only harmonization traces
lemma ai audit --operation harmonize

# Only attribute-filtered evidence queries
lemma ai audit --operation evidence_query

# Every read-only operation (query + evidence_query)
lemma ai audit --kind read

# Every decision (map / harmonize / evidence-mapping)
lemma ai audit --kind decision

# JSON for CI/scripting
lemma ai audit --format json

# Aggregate statistics
lemma ai audit --summary
```

