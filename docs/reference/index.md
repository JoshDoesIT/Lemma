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

### `lemma evidence log`

Show every entry in the evidence log with its per-entry integrity state.

```bash
lemma evidence log
```

Output is a Rich table with columns for time, OCSF class name, producer, truncated entry hash, and the integrity verdict.

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

