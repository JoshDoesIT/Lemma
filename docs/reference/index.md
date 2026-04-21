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
