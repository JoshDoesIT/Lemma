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
