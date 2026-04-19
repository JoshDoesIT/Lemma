# Architecture

> **Note:** This is a living document and will be updated as Lemma progresses through its roadmap phases.

Lemma follows a federated, Git-native, and AI-enabled architecture designed to prioritize provability and local execution.

## High-Level System Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                        Lemma CLI                            │
├──────────┬──────────┬──────────┬──────────┬────────────────┤
│  Parse   │  Index   │   Map    │Harmonize │   Scope        │
│ (Docling)│(ChromaDB)│ (AI+Vec) │  (CCF)   │ (as-Code)      │
├──────────┴──────────┴──────────┴──────────┴────────────────┤
│              OSCAL-Native Data Model                        │
├─────────────────────────────────────────────────────────────┤
│           Compliance Knowledge Graph                        │
├──────────┬──────────┬──────────┬──────────────────────────┤
│  Agents  │Connectors│  Proofs  │     Dashboard (UI)        │
│ (Mesh)   │  (SDK)   │ (Merkle) │     (Next.js)             │
└──────────┴──────────┴──────────┴──────────────────────────┘
```

## Core Components

### 1. Lemma CLI & Git-Native Pipeline
At the forefront is the **Lemma CLI**, which interacts directly with the developer workflow. Compliance states are tracked via Git, aligning seamlessly with modern CI/CD operations. Running `lemma check` evaluates the repository's configuration against its mapped policies.

### 2. Ingestion & Transformation Engine (Parse & Index)
Frameworks exist in varied, messy formats. Lemma utilizes layout-aware document ingestion to translate PDFs, Excel sheets, and raw text into normalized structures. These are immediately serialized and embedded into a local vector database for semantic search and correlation.

### 3. OSCAL-Native Data Model
All underlying data structures map directly to the **NIST OSCAL** (Open Security Controls Assessment Language) standard. Lemma operates natively using these JSON/XML definitions, eliminating proprietary lock-in.

### 4. AI-Powered Control Mapping & Harmonization
When assessing an environment, Lemma employs an AI router (defaulting to local Ollama inference) accompanied by RAG retrieval against the vector index.
- **Mapping:** Matches implemented technical controls against necessary framework policies.
- **Harmonization:** Cross-correlates semantic equivalents across different frameworks to establish a "Test Once, Comply Many" reality via a Common Control Framework (CCF).

### 5. Compliance Knowledge Graph
Beyond linear arrays of JSON data, Lemma constructs a powerful graph structure to link infrastructure Resources, evidence Events, policies, and frameworks. This supports profound querying capabilities to determine blast radius or control coverage visually.

### 6. Infrastructure Mesh & Agents
Instead of demanding full access to inbound ports for scanning, Lemma deploys lightweight, stateless **Agents** that reside inside your specific topologies—be it a Kubernetes cluster, a private VPC, or an air-gapped location. Agents collect localized state and push verified results asynchronously to the control plane.

### 7. Connectors & Merkle Proofs
The system uses modular plugins (**Connectors**) via a typed SDK to pull metadata from external systems (GitHub, AWS, Identity Providers). As evidence flows back into Lemma, it is subjected to continuous hashing processes built on a Merkle Tree, guaranteeing verifiable, tamper-evident **Proof Chains**. 

### 8. Web Dashboard
The presentation layer provides comprehensive views covering active scopes, raw agent telemetry, detailed AI traces (ensuring decisions are explainable), and the eventual state rendering necessary for auditor assessments.
