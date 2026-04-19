# ⊢ lemma

**Provable Compliance. No Black Boxes.**

<!-- Badges -->
[![CI](https://github.com/JoshDoesIT/Lemma/actions/workflows/ci.yml/badge.svg)](https://github.com/JoshDoesIT/Lemma/actions/workflows/ci.yml)
[![Security](https://github.com/JoshDoesIT/Lemma/actions/workflows/security.yml/badge.svg)](https://github.com/JoshDoesIT/Lemma/actions/workflows/security.yml)
[![License](https://img.shields.io/github/license/JoshDoesIT/Lemma)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-00FF41.svg)](CONTRIBUTING.md)
[![GitHub Discussions](https://img.shields.io/github/discussions/JoshDoesIT/Lemma)](https://github.com/JoshDoesIT/Lemma/discussions)

---

Lemma is an **open-source, AI-native GRC platform** built by engineers, for engineers. It treats compliance as a rigorous, provable engineering discipline — not an art of deception.

Born in the aftermath of high-profile compliance fraud, Lemma exists because the industry proved it cannot police itself. We don't rubber-stamp; we prove.

## Why Lemma?

| Traditional GRC | Lemma |
|:----------------|:------|
| Compliance lives in spreadsheets and PDFs | Compliance lives in Git — version-controlled, diffable, auditable |
| AI is a black box that rubber-stamps results | AI shows its work — every decision logged, explainable, challengeable |
| Evidence is a screenshot taken once a year | Evidence is a cryptographically signed, continuously evaluated proof chain |
| One scope fits all (or nothing) | Living scopes adapt to your infrastructure in real time |
| Vendor lock-in with proprietary formats | OSCAL-native — your data is portable, always |
| Cloud-only, SaaS-dependent | Run anywhere — cloud, on-prem, air-gapped, hybrid multi-cloud |

## Core Principles

### ∴ Compliance is Code
Open source means our algorithms and AI agents are auditable. If you don't trust a mapping, inspect the prompt. No more black boxes.

### ∴ Engineers First, Auditors Second
The platform speaks Git, JSON, integrations, and CI/CD before it speaks SOC 2 or ISO 27001. We automate the engineering burden so the audit takes care of itself.

### ∴ Absolute Flexibility
No two infrastructure environments are identical. Lemma integrates anywhere — from managed cloud to on-premise data centers, air-gapped systems, and hybrid multi-cloud environments.

### ∴ End the Theater
Built as a direct response to industry fraud. We don't generate fake evidence. We don't rubber-stamp. We prove.

## Features

- **Git-Native Compliance** — `lemma init` scaffolds a compliance-as-code repository. Audit readiness via `git diff`.
- **OSCAL-Native Data Model** — All compliance artifacts stored in the NIST OSCAL standard. No vendor lock-in.
- **Framework Ingestion** — Parse PDFs, spreadsheets, and OSCAL catalogs. Bring any framework.
- **AI-Powered Mapping** — Vector similarity + LLM-assisted control-to-evidence mapping with confidence scores.
- **Test Once, Comply Many** — Harmonization engine unifies semantically equivalent controls across frameworks.
- **Compliance Knowledge Graph** — Queryable graph of frameworks, controls, evidence, and infrastructure.
- **Transparent AI** — Every AI decision includes a full trace: input, prompt, model, output, confidence. Challengeable.
- **Living Scope** — Declarative, infrastructure-aware scoping that auto-discovers boundaries and shares evidence across overlapping frameworks.
- **Compliance Mesh** — Federated agents run inside each environment. On-prem, air-gapped, multi-cloud — unified.
- **Connector SDK** — Build and share custom integrations via a typed SDK and community registry.
- **CI/CD Gates** — `lemma check` as a build gate. Compliance debt tracked like tech debt.
- **Continuous Proof Chains** — Cryptographically signed, Merkle-tree evidence logs. Tamper-proof by design.

## Quick Start

```bash
# Install Lemma (coming soon)
# npm install -g @lemma-ai/cli

# Scaffold a compliance-as-code repository
lemma init

# Add a framework
lemma framework add nist-800-53

# Map your policies to controls
lemma map

# Generate common control mappings across frameworks
lemma harmonize

# Check your compliance posture
lemma status
```

## Architecture

```
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

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full phased product roadmap.

| Phase | Theme | Timeline |
|:------|:------|:---------|
| **0** | Foundation & Governance | Days 1–3 |
| **1** | Core Engine | Week 1–2 |
| **2** | Intelligence Layer | Week 2–4 |
| **3** | Infrastructure Mesh | Week 4–6 |
| **4** | Platform & Community | Week 6–7 |
| **5** | Enterprise Readiness | Week 7–8 |

## Contributing

We welcome contributions from GRC engineers, security practitioners, and developers. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the PR process.

**First time?** Look for issues labeled [`good-first-issue`](https://github.com/JoshDoesIT/Lemma/labels/status%3A%20good-first-issue).

## Security

To report a vulnerability, please use [GitHub Security Advisories](https://github.com/JoshDoesIT/Lemma/security/advisories/new). Do **not** open a public issue for security reports. See [SECURITY.md](SECURITY.md) for details.

## License

Lemma is licensed under the [Apache License 2.0](LICENSE).

---

<sub>*In mathematics, a lemma is a proven proposition used as a stepping stone to a larger theorem. You cannot achieve compliance without proving the individual controls first.* **Q.E.D.**</sub>
