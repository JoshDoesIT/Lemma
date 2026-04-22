# Architecture

Understand the design decisions and data flow behind Lemma's core engine.

## Pipeline Overview

Lemma's Phase 1 core engine follows a four-stage pipeline. Every stage operates locally — no data leaves your machine.

```mermaid
flowchart LR
    A["📄 Source Files<br/>(PDF, XLSX, CSV, OSCAL JSON)"] --> B["**Parse**<br/>Docling / openpyxl / OSCAL"]
    B --> C["**Index**<br/>sentence-transformers → ChromaDB"]
    C --> D["**Map**<br/>Semantic search + LLM reasoning"]
    D --> E["**Harmonize**<br/>Cross-framework CCF clustering"]

    style A fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style B fill:#1e293b,stroke:#8b5cf6,color:#e2e8f0
    style C fill:#1e293b,stroke:#06b6d4,color:#e2e8f0
    style D fill:#1e293b,stroke:#f59e0b,color:#e2e8f0
    style E fill:#1e293b,stroke:#10b981,color:#e2e8f0
```

## Data Flow

```mermaid
flowchart TD
    subgraph Parse["Parse Phase"]
        PDF["PDF"] --> Docling["Docling<br/>Layout-aware extraction"]
        XLSX["XLSX/CSV"] --> OpenPyXL["openpyxl / csv<br/>Column detection"]
        OSCAL["OSCAL JSON"] --> Catalog["Catalog Parser<br/>Group → Control → Prose"]
        Docling --> Controls["Control Records<br/>{id, title, prose, family}"]
        OpenPyXL --> Controls
        Catalog --> Controls
    end

    subgraph Index["Index Phase"]
        Controls --> Embed["sentence-transformers<br/>all-MiniLM-L6-v2"]
        Embed --> ChromaDB["ChromaDB<br/>Vector Store"]
    end

    subgraph Map["Map Phase"]
        Policies["Policy Markdown Files"] --> Query["Semantic Query"]
        ChromaDB --> Query
        Query --> Candidates["Top-K Control Candidates"]
        Candidates --> LLM["LLM Reasoning<br/>(Ollama / OpenAI)"]
        LLM --> Report["MappingReport<br/>{policy, control, confidence, rationale}"]
    end

    subgraph Harmonize["Harmonize Phase"]
        ChromaDB --> Cluster["Embedding-Based Clustering"]
        Cluster --> CCF["Common Control Framework<br/>UnionFind Groups"]
        CCF --> Coverage["Coverage & Gap Analysis"]
    end

    style Parse fill:#0f172a,stroke:#8b5cf6,color:#e2e8f0
    style Index fill:#0f172a,stroke:#06b6d4,color:#e2e8f0
    style Map fill:#0f172a,stroke:#f59e0b,color:#e2e8f0
    style Harmonize fill:#0f172a,stroke:#10b981,color:#e2e8f0
```

## Stage Details

### 1. Parse — Document Intelligence

The parse stage converts diverse framework formats into a uniform control record:

```python
{"id": "ac-1", "title": "Access Control Policy", "prose": "...", "family": "Access Control"}
```

| Format | Parser | Dependency |
|--------|--------|------------|
| OSCAL JSON | `parsers.oscal.parse_catalog()` | stdlib |
| PDF | `parsers.pdf.parse_pdf()` | `docling` (optional `[ingest]`) |
| XLSX | `parsers.excel.parse_excel()` | `openpyxl` |
| CSV | `parsers.excel.parse_excel()` | stdlib |

**Design decision:** Docling is ~500MB and lazily imported behind `_get_converter()`. This keeps the core CLI lightweight for users who only use OSCAL catalogs.

### 2. Index — Vector Embeddings

Control prose is embedded using `all-MiniLM-L6-v2` (384-dimensional vectors) and stored in a local ChromaDB instance at `.lemma/index/`. Collections are namespaced per framework.

**Upsert semantics:** Re-indexing the same framework updates existing records without duplication.

### 3. Map — AI-Powered Matching

The mapper reads Markdown policy files and for each policy:

1. **Retrieves** the top-K most similar controls via vector cosine similarity
2. **Reasons** about the match using an LLM (Ollama by default, OpenAI optional)
3. **Scores** each match with a confidence value and plain-language rationale

The output conforms to the `MappingReport` Pydantic model.

### 4. Harmonize — Cross-Framework Correlation

The harmonizer identifies semantically equivalent controls across different frameworks using embedding-based clustering (UnionFind). This produces a Common Control Framework (CCF) — map a control once, satisfy it across every overlapping framework.

## OSCAL-Native Data Model

All internal models map to [NIST OSCAL](https://pages.nist.gov/OSCAL/) structures:

```mermaid
classDiagram
    class Catalog {
        +UUID uuid
        +Metadata metadata
        +List~Group~ groups
    }
    class Group {
        +str id
        +str title
        +List~Control~ controls
    }
    class Control {
        +str id
        +str title
        +List~Part~ parts
        +List~Control~ controls
    }
    class Part {
        +str id
        +str name
        +str prose
    }

    Catalog --> Group : contains
    Group --> Control : contains
    Control --> Part : has
    Control --> Control : sub-controls
```

## OCSF Evidence Models

Lemma's Phase 3 connectors will collect compliance evidence from disparate sources — SIEM, CSPM, ITSM, identity providers. To avoid inventing a proprietary schema, Lemma adopts [**OCSF** (Open Cybersecurity Schema Framework)](https://schema.ocsf.io/) as the wire format for normalized evidence.

OCSF provides a vendor-agnostic taxonomy of security telemetry maintained by a broad industry consortium and licensed Apache-2.0. Each event carries:

- A numeric `class_uid` identifying the specific event class (e.g., `2003` = Compliance Finding).
- A numeric `category_uid` identifying the high-level category (e.g., `2000` = Findings, `3000` = IAM).
- Standardized fields for `time`, `severity_id`, `status_id`, `activity_id`, `metadata`, and a free-form `message`.

### Classes modeled today

This release ships the minimum lexicon needed to prove the schema and unblock connector work. All three classes live in `src/lemma/models/ocsf.py`.

| Class | `class_uid` | Category | Why it's here |
|---|---|---|---|
| `ComplianceFinding` | 2003 | Findings (2000) | Direct representation of an evaluated compliance control outcome — the most natural OCSF class for GRC evidence. |
| `DetectionFinding` | 2004 | Findings (2000) | The modern replacement for the deprecated Security Finding (2001) class in OCSF 1.1+. Used when a connector emits a generic detection result that still maps to a control. |
| `AuthenticationEvent` | 3002 | IAM (3000) | Evidence of identity and access activity (MFA use, SSO logins, privilege escalations) — a common compliance signal. Also proves the base-class design generalizes across categories. |

### Design notes

- **Enums are `IntEnum`, not `StrEnum`.** OCSF serializes identifiers as integers on the wire; `StrEnum` would force lossy coercion. This is a deliberate divergence from the `StrEnum` pattern used by `TraceStatus` and `PolicyEventType`.
- **Category consistency is enforced.** Each concrete class pins its `class_uid` via `Literal[...]` and validates that `category_uid` matches the expected category — so a misconfigured connector fails loudly on ingestion instead of silently polluting the graph.
- **Nested OCSF objects (`Actor`, `Device`, full `Metadata`) are typed as `dict[str, Any]` for now.** Strongly-typed sub-schemas will arrive driven by connector demand rather than speculatively modeled.

### What's deferred

The following are intentionally out of scope for this release and will arrive with connector work:

- An event normalization / ingestion service.
- Connector adapters that emit these events.
- OCSF-to-control mapping logic (belongs in the harmonization/mapping layer).
- Additional OCSF event classes beyond the three above.
- Per-class `activity_id` enums.

## Project Layout

```
.lemma/                     # Local project data (git-ignored)
├── index/                  # ChromaDB vector store
└── config.json             # Project configuration

src/lemma/
├── cli.py                  # Typer CLI entry point
├── commands/               # Command implementations
│   ├── framework.py        # framework add/list/import
│   ├── harmonize.py        # harmonize/coverage/gaps/diff
│   ├── init.py             # init
│   ├── map.py              # map
│   ├── status.py           # status
│   └── validate.py         # validate
├── data/frameworks/        # Bundled OSCAL catalogs
├── models/                 # Pydantic models (OSCAL, mapping, harmonization)
└── services/               # Business logic
    ├── framework.py         # Registry, add/list/import orchestration
    ├── indexer.py           # ChromaDB embedding and query
    ├── mapper.py            # Policy → control mapping engine
    ├── harmonizer.py        # Cross-framework CCF clustering
    └── parsers/             # Format-specific document parsers
        ├── oscal.py         # OSCAL JSON catalog parser
        ├── pdf.py           # PDF parser (Docling)
        └── excel.py         # XLSX/CSV parser (openpyxl)
```
