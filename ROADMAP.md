# Lemma: Product Roadmap

> **Mission:** Build the open-source, AI-native GRC platform that makes compliance provable, portable, and engineer-first.

---

## Phase 0 — Foundation & Repository Governance
**Theme:** "Before you write a line of product code, the house must be in order."

- **Repository Initialization**: MIT/Apache 2.0 licensing, robust ignore rules.
- **Governance**: Code of Conduct, Contributing guides, Security policy, Architecture overview, and Governance model.
- **Workflow**: Automated CI/CD scaffolding (Lint, Test, Secure) and standardized issue/PR templates to strictly govern incoming code.
- **Identity**: Brand definitions and baseline architectural documentation.

## Phase 1 — Core Engine
**Theme:** "The mathematical foundation. Parse, index, map, prove."

- **OSCAL-Native Data Model**: Strong underlying schemas mapped directly to the NIST OSCAL definitions to prevent vendor lock-in.
- **Git-Native Repository**: The `lemma init` and `lemma status` commands to track compliance states alongside infrastructure code.
- **Framework Ingestion**: Converting human-readable frameworks (PDFs, spreadsheets) into normalized embeddings via Docling and local vector stores.
- **Control Mapping & Harmonization**: Core AI mapping logic to correlate implemented controls against necessary framework requirements, minimizing duplicative compliance work.

## Phase 2 — Intelligence Layer
**Theme:** "AI that shows its work. A graph that reveals what spreadsheets hide."

- **Compliance Knowledge Graph**: Modeling relationships between Frameworks, Controls, Evidence, Resources, and Scopes to allow for complex querying and impact analysis.
- **Transparent AI System**: An append-only trace log for all AI decisions, detailing the model inputs, prompts, outputs, and confidence scores. 
- **Human-in-the-Loop Workflow**: Ensuring 'confidence-gated automation', requiring human verification for AI decisions that fall below configurable thresholds.

## Phase 3 — Infrastructure Mesh & Integration Layer
**Theme:** "Run anywhere. Connect to everything. Scope precisely."

- **Living Scope Engine**: Defining compliance boundaries via Code (e.g., scoping AWS resources dynamically).
- **Federated Agent Architecture**: A lightweight, stateless agent capable of operating securely in air-gapped, local, or cloud environments, pushing signed evidence to the control plane.
- **Connector SDK**: Tools to rapidly ingest security and compliance logs from cloud configurations, GitHub repositories, Identity Providers, and ticketing systems.
- **Continuous Proof Chains**: Merkle-Tree-backed evidence logs ensuring non-repudiation and tamper protection on compliance data over time.

## Phase 4 — Platform & Community
**Theme:** "Make the invisible visible. Give the community the tools to own their compliance."

- **Web Dashboard**: An engineer-first UI (Void Black, Terminal Green accents) showcasing posture dashboards, AI trace viewers, and interactive graphs.
- **Community Framework Library**: Curated, public-domain OSCAL framework definitions (NIST 800-53, HIPAA, FedRAMP).
- **Connector Registry**: Fostering community-supported integrations into disparate operational tools.
- **Full Documentation**: API references, setup sequences, and architecture decision records.

## Phase 5 — Enterprise Readiness
**Theme:** "Scale from one engineer to an entire program. Every environment, every team, one truth."

- **Multi-Tenancy & Access Control**: RBAC support spanning owners, engineers, and read-only auditors.
- **Auditor Portal**: Secure evidence packaging and timeline review tailored specifically to external compliance assessors.
- **Reporting & Analytics**: Tracking "Compliance Debt" alongside technical debt metrics, offering timeline-based posture views.
- **Advanced Integrations**: Synchronization with external SIEM, ITSM, and CSPM systems.

---

*This roadmap is public and subject to regular updates as the project evolves through community feedback and contributions.*
