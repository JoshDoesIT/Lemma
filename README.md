# ⊢ lemma

**Provable compliance. No black boxes.**

[![CI](https://github.com/JoshDoesIT/Lemma/actions/workflows/ci.yml/badge.svg)](https://github.com/JoshDoesIT/Lemma/actions/workflows/ci.yml)
[![Security](https://github.com/JoshDoesIT/Lemma/actions/workflows/security.yml/badge.svg)](https://github.com/JoshDoesIT/Lemma/actions/workflows/security.yml)
[![Coverage](https://codecov.io/gh/JoshDoesIT/Lemma/branch/main/graph/badge.svg)](https://codecov.io/gh/JoshDoesIT/Lemma)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/JoshDoesIT/Lemma/badge)](https://securityscorecards.dev/viewer/?uri=github.com/JoshDoesIT/Lemma)
[![License](https://img.shields.io/github/license/JoshDoesIT/Lemma)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-00FF41.svg)](CONTRIBUTING.md)
[![GitHub Discussions](https://img.shields.io/github/discussions/JoshDoesIT/Lemma)](https://github.com/JoshDoesIT/Lemma/discussions)

---

Lemma is an open-source, AI-native GRC platform for engineers who want compliance to behave like the rest of their stack: version-controlled, testable, auditable, reproducible.

It treats every compliance artifact — frameworks, controls, policies, evidence, scopes, AI decisions — as a first-class object you can diff, query, sign, and prove. The AI shows its work. The evidence is signed. The graph is queryable in plain English. Nothing is rubber-stamped.

## What's different

| Most GRC tools | Lemma |
|:---|:---|
| Compliance lives in spreadsheets and PDFs | Compliance lives in Git — diffable, reviewable, replayable |
| AI is a black box that produces "the answer" | Every AI decision is logged with prompt, model, output, confidence, and reviewer |
| Evidence is a screenshot taken once a year | Evidence is a Merkle-chained, Ed25519-signed log with offline revocation lists |
| One scope fits all (or nothing) | Living scopes auto-discover infrastructure and share evidence across overlapping frameworks |
| Vendor-locked formats | OSCAL-native; your data is portable, always |
| SaaS-only | Runs anywhere — laptop, on-prem, air-gapped, hybrid multi-cloud |

## How it works

Lemma is a CLI plus a small set of services. The mental model:

1. **Index frameworks.** `lemma framework add nist-800-53` parses the catalog, embeds every control, and writes a typed graph.
2. **Map policies.** `lemma map ./policies` runs vector retrieval + an LLM scoring pass; every decision lands in an append-only trace log with a confidence score and a `PROPOSED` status until a human (or a configured threshold) accepts it.
3. **Harmonize.** `lemma harmonize` finds semantically equivalent controls across frameworks via cosine similarity + Union-Find, so one policy can satisfy NIST 800-53, CSF 2.0, and 800-171 at once.
4. **Discover scope.** `lemma scope discover <provider>` walks AWS / Azure / GCP / Kubernetes / vSphere / Ansible / ServiceNow / Device42 / network / static files and writes Resource nodes scoped to declarative scope definitions.
5. **Collect evidence.** First-party connectors (and the SDK) sign every event with Ed25519, hash-chain it into `.lemma/evidence/`, and link it back to the controls it proves.
6. **Query in English.** `lemma query "What harmonized controls cover framework nist-csf-2.0?"` translates the question into a bounded graph plan and walks it. No prompt injection surface — the LLM can only emit plans the executor recognizes.
7. **Verify.** `lemma evidence verify <hash> --crl audit-pack/crl-Lemma.json` renders PROVEN / VIOLATED / DEGRADED. Works offline, on a fresh install, with only the public key.
8. **Gate CI.** `lemma check --format sarif --min-confidence 0.85` produces SARIF that lands in GitHub Code Scanning. Compliance debt tracked like tech debt.

Every AI artifact is reproducible. Every evidence chain is signed. Every release ships an AI System Card and AIBOM alongside the SBOM.

## Quick start

Lemma is a Python package distributed as `lemma-grc`. With [uv](https://docs.astral.sh/uv/):

```bash
uv tool install lemma-grc

lemma init my-program
cd my-program

lemma framework add nist-800-53
lemma framework add nist-csf-2.0
lemma map ./policies
lemma harmonize
lemma status
```

Or with pip:

```bash
pip install lemma-grc
```

The CLI is fully local by default — Ollama for LLM calls, ChromaDB for vector index, no cloud required. Switch to OpenAI or another backend in `lemma.config.yaml` when you want.

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                         lemma CLI                          │
├────────────┬────────────┬──────────┬──────────┬────────────┤
│   parse    │   index    │   map    │harmonize │   query    │
│  (Docling) │ (ChromaDB) │ (AI+Vec) │  (CCF)   │ (NL→Plan)  │
├────────────┴────────────┴──────────┴──────────┴────────────┤
│            Compliance Knowledge Graph (NetworkX)           │
├────────────┬─────────────┬─────────────────────────────────┤
│   scope    │  evidence   │         AI trace log            │
│ (as-Code)  │  (signed)   │  (append-only, append-anywhere) │
├────────────┴─────────────┴─────────────────────────────────┤
│              OSCAL-Native Data Model                       │
└────────────────────────────────────────────────────────────┘
```

Connector SDK plugs in at the edges. Federated agents push signed evidence from on-prem and air-gapped environments back to the same graph.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full phased product plan. Current state:

| Phase | Theme | Status |
|:------|:------|:------|
| **0** | Foundation & Governance | ✅ shipped |
| **1** | Core Engine | ✅ shipped |
| **2** | Intelligence Layer | ✅ shipped |
| **3** | Infrastructure Mesh & Integration | 🟡 in flight |
| **4** | Platform & Community | ⏳ planned |
| **5** | Enterprise Readiness | ⏳ planned |

Phase 3 is the current focus: connector SDK + first-party connectors, federated agent, signed-evidence hardening, and the bundle/audit-pack distribution surface.

## Contributing

Issues labeled [`good-first-issue`](https://github.com/JoshDoesIT/Lemma/labels/status%3A%20good-first-issue) are the easiest place to start. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the PR process.

Lemma uses TDD throughout. Every feature ships with red-then-green test cycles, and every PR closes its source issue with file/test pointers per Acceptance Criterion.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/JoshDoesIT/Lemma/security/advisories/new) — please don't open public issues. See [SECURITY.md](SECURITY.md) for the disclosure process and supported versions.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

<sub>*In mathematics, a lemma is a small proof you reach for on the way to a larger theorem. The compliance argument is no different — you can't prove the program until you've proved the controls.*</sub>
