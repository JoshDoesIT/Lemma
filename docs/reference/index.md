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

Ask the compliance graph a question in plain English. An LLM translates the question into a bounded structured plan (`QueryPlan`), the executor walks the graph using existing traversals, and every call lands in the AI trace log with `operation="query"`.

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
```

**What it can and can't do:**

- Supports single-hop traversals (NEIGHBORS / IMPACT / framework control counts) with edge-type and direction filters. Multi-hop questions ("framework → its controls → harmonized controls") land in a future release — see [#105](https://github.com/JoshDoesIT/Lemma/issues/105).
- Evidence-node queries ("what evidence supports SOC 2 CC6.1?") require evidence nodes in the graph, which ship with connector work — tracked in [#97](https://github.com/JoshDoesIT/Lemma/issues/97).
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
| `CONNECTOR` | Yes | First-party connector name. Currently: `github`, `okta`. |

| Option | Required | Description |
|--------|----------|-------------|
| `--repo` | For `github` | Repository in `owner/name` form |
| `--domain` | For `okta` | Okta domain, e.g. `your-org.okta.com` |

**First-party connectors**

- `github` — collects branch protection on `main`, CODEOWNERS presence, and open Dependabot alert counts bucketed by severity. Auth via the `LEMMA_GITHUB_TOKEN` environment variable (optional for public repos within GitHub's 60-req/hr unauthenticated cap; required for private repos and to lift the rate limit to 5000/hr). Rate-limited responses raise a clean error naming the endpoint.
- `okta` — collects MFA enrollment policy state and the SSO application inventory (active vs. total counts). Auth via the `LEMMA_OKTA_TOKEN` environment variable (required — Okta has no unauthenticated API). The token is passed as an `SSWS <token>` authorization header. Rate-limited responses (HTTP 429) raise a clean error naming the endpoint. Stable `metadata.uid` per `(event_type, domain, UTC date)` so same-day re-runs dedupe against themselves.

Output reports how many events were ingested and how many were skipped as duplicates (same `metadata.uid` already in the log — stable per `event_type`, producer-specific target, and UTC date).

---

## `lemma check`

Run the CI/CD compliance gate over the knowledge graph. Exits non-zero if any control in the selected framework has zero satisfying policies, so pipelines can fail builds on compliance regressions.

```bash
lemma check [--framework <ID>] [--format text|json]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--framework` | all frameworks in the graph | Restrict the check to a single framework (e.g. `nist-800-53`) |
| `--format` | `text` | Output format: `text` (human-readable Rich table) or `json` (machine-parseable) |

**Pass criterion (v0).** A control is `PASSED` if at least one policy has a `SATISFIES` edge pointing at it in the compliance graph, and `FAILED` otherwise. The check does not currently weight edges by confidence score — any recorded mapping counts — and does not consider evidence-node integrity. These refinements are tracked as follow-ups (see below).

**Exit codes.** `0` only when every control in scope passes; `1` on any failure, on unknown `--framework`, or outside a Lemma project.

**JSON output shape** (stable for CI/CD integrations):

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
  "failed": 1
}
```

**Example workflow:**

```bash
lemma init
lemma framework add nist-csf-2.0
lemma map                                     # creates SATISFIES edges
lemma check                                   # human-readable gate
lemma check --format json | jq '.failed'      # machine-readable for CI
```

**Follow-ups tracked separately** — SARIF output ([#119](https://github.com/JoshDoesIT/Lemma/issues/119)), GitHub Action wrapper ([#120](https://github.com/JoshDoesIT/Lemma/issues/120)), OPA/Rego policy-as-code ([#121](https://github.com/JoshDoesIT/Lemma/issues/121)), and `--min-confidence` flag ([#122](https://github.com/JoshDoesIT/Lemma/issues/122)). Drift detection and compliance-debt metrics stay inside the parent [#28](https://github.com/JoshDoesIT/Lemma/issues/28) task list.

---

## `lemma scope`

Scope-as-code — declare which compliance frameworks apply to which slice of your infrastructure, and validate the declaration with a strict schema before it ever reaches an auditor.

This is the v0 slice of the [Living Scope Engine](https://github.com/JoshDoesIT/Lemma/issues/24). Auto-discovery (AWS, Azure, GCP, K8s, Terraform, vSphere, Ansible, CMDB), the scope ring model, cross-scope evidence reuse, `lemma scope impact --plan`, and `lemma scope visualize` remain open tasks inside that issue.

### `lemma scope init`

Scaffold a starter scope-as-code YAML file at `scopes/<name>.yaml`. Refuses to overwrite an existing file — operators delete it manually if they want to regenerate.

```bash
lemma scope init [--name <NAME>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--name` | `default` | Writes `scopes/<NAME>.yaml` |

### `lemma scope status`

Parse every `scopes/*.yaml` and `scopes/*.yml` file, validate it against the schema, and render a table of declared scopes. Exit code is `0` on success or empty state; `1` if any file has a parse or schema error.

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

### Scope-as-code schema

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

Unknown top-level fields are rejected — a typo such as `match_rule` (singular) fails with a line-numbered error rather than being silently dropped.

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
| `--operation` | *(all)* | Filter by operation type (e.g., `map`, `harmonize`) |
| `--format` | `table` | Output format: `table` or `json` |
| `--summary` | `false` | Show aggregate statistics instead of individual traces |

The audit log captures every AI decision: input, prompt, model, raw output, confidence score, and human review status.

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

# JSON for CI/scripting
lemma ai audit --format json

# Aggregate statistics
lemma ai audit --summary
```

