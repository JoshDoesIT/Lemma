# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `lemma query "<question>"` answers natural-language questions about the compliance knowledge graph. An LLM translates the question to a structured `QueryPlan` (bounded to traversals the executor supports — NEIGHBORS, IMPACT, FRAMEWORK_CONTROL_COUNT — with edge-type and direction filters), the executor walks the graph, and every invocation is recorded in the AI trace log with `operation="query"`. `--verbose` prints the resolved plan before the results so "AI that shows its work" extends to read queries too.
- Short entry-node names (e.g., `"ac-2"`) are resolved against the graph at translate time; ambiguous matches fail loud with all candidate node IDs listed. The translator retries once with validation feedback on malformed LLM output, then raises a clean `ValueError` — no silent fallback.
- New AI operation type `query` alongside the existing `map` and `harmonize` — filter with `lemma ai audit --operation query`. Query traces use `confidence=0.0` and `determination="QUERY_EXECUTED"` as conventions for the read-only operation kind.
- Key lifecycle for evidence signing. Per-producer keys now live under `.lemma/keys/<producer>/<key_id>.*.pem` with a sibling `meta.json` tracking every key the producer has held. Status is one of `ACTIVE`, `RETIRED`, or `REVOKED`. Flat pre-lifecycle layouts are auto-migrated to the versioned layout on first access.
- `lemma evidence rotate-key --producer <name>` retires the producer's active signing key and generates a fresh one. Pre-rotation entries keep verifying PROVEN under the retired key; new entries use the successor.
- `lemma evidence revoke-key --producer <name> --key-id <id> --reason <str>` marks a key REVOKED. Verification now returns VIOLATED for entries signed at or after `revoked_at` under a revoked key, and stays PROVEN for signatures made before the revocation.
- `lemma evidence keys` lists every signing key with its lifecycle state, activation timestamp, retirement/revocation timestamp, and revocation reason.
- `SignedEvidence` gains a `signed_at` field so key-lifecycle checks can compare the signing timestamp (not `event.time`) against `revoked_at`.
- Continuous proof chains on the evidence log. Every entry appended to `.lemma/evidence/YYYY-MM-DD.jsonl` is now wrapped in a `SignedEvidence` envelope with an SHA-256 hash chain (`prev_hash` → `entry_hash`) and an Ed25519 signature produced by the signing key for `metadata.product.name`. Per-producer keypairs live under `.lemma/keys/` with `0600` private-key permissions.
- `lemma evidence verify <entry_hash>` — integrity check returning PROVEN (hash + chain + signature all valid), DEGRADED (hash + chain valid but signer's key unavailable), or VIOLATED (hash or chain broken). Non-zero exit on anything other than PROVEN.
- `lemma evidence log` — Rich-table timeline showing time, class, producer, entry hash prefix, and per-row integrity state.
- `EvidenceIntegrityState` enum, `SignedEvidence` envelope model, and `ProvenanceRecord` model. The storage-stage provenance record is populated today; earlier stages populate as connectors (#26/#27) arrive.
- `lemma harmonize` now records every cross-framework equivalence decision as an `AITrace` with `operation="harmonize"`, honors `ai.automation.thresholds.harmonize` for confidence-gated auto-accept, and persists the result as an OSCAL Profile at `.lemma/harmonization.oscal.json`. The Profile imports each source catalog and encodes clusters as back-matter resources with `lemma:harmonized-cluster` properties and `rlinks` to member controls.
- `related_control_id` and `related_framework` fields on `AITrace` to carry pair-event endpoints. Map traces (single-control) default them to empty strings; harmonize traces populate both sides with a deterministic primary/secondary ordering so each equivalence is one trace.
- `lemma ai audit --operation <op>` filter for querying traces by operation type (e.g., `harmonize`, `map`).
- Auditor-facing documentation: "How Lemma's AI Works" (`docs/concepts/ai.md`) walking through framework indexing, mapping, harmonization, the PROPOSED→ACCEPTED/REJECTED lifecycle, and confidence-gated automation; a Graph Query Cookbook with 10 worked examples (`docs/guides/graph-queries.md`); a static AI System Card page (`docs/reference/ai-system-card.md`) surfacing the model registry in the published docs.
- End-to-end integration tests covering the full Phase 2 CLI pipeline: cross-artifact consistency between the compliance graph, the AI trace log, and the audit CLI; graph integrity (no orphaned policies, no phantom edges); auto-accept behavior wired through config; policy-event emission on threshold changes between `lemma map` runs.
- Shared `lemma_project` pytest fixture (`tests/conftest.py`) that lands an initialized project with `nist-csf-2.0` indexed, for use by integration tests and future PRs.
- OCSF event ingestion. `normalize()` in `src/lemma/services/ocsf_normalizer.py` dispatches an incoming payload to the right concrete OCSF model via a Pydantic discriminated-union `TypeAdapter`, rejecting payloads with a missing/unknown `class_uid` or naive (tz-less) `time`. `EvidenceLog` in `src/lemma/services/evidence_log.py` persists normalized events to `.lemma/evidence/YYYY-MM-DD.jsonl`, with `append`/`read_all`/`filter_by_class`/`filter_by_time_range` and append-time dedupe keyed on `metadata.uid` (falling back to a content hash). The log is strictly append-only — no update/delete/clear.
- OCSF (Open Cybersecurity Schema Framework) event type models at `src/lemma/models/ocsf.py`. Adds an `OcsfBaseEvent` and three concrete classes — `ComplianceFinding` (2003), `DetectionFinding` (2004), `AuthenticationEvent` (3002) — so future connectors can emit evidence in a vendor-agnostic wire format. Category consistency is enforced per class; enums use `IntEnum` to match OCSF's integer identifiers.
- `lemma ai bom` CLI command exports an AI Bill of Materials in CycloneDX 1.6 JSON format, enumerating every model in the system card with name, version, provider, purpose, training data provenance, and optional SHA hash. Output is validated against a bundled CycloneDX 1.6 structural schema before it leaves the process.
- Optional `model_hash` field on `ModelCard` for supply-chain integrity digests (e.g., `sha256:...`).
- Confidence-gated automation for AI mapping. `ai.automation.thresholds.<operation>` in `lemma.config.yaml` auto-accepts AI outputs at or above the configured threshold; outputs below remain PROPOSED for human review. Auto-accepted trace entries are marked with `auto_accepted: true` and record the applied threshold in the review rationale.
- `auto_accepted` field on `AITrace` distinguishes gate-driven acceptances from human-driven ones.
- Policy event audit log at `.lemma/policy-events/YYYY-MM-DD.jsonl`. Each `lemma map` run diffs `ai.automation.thresholds` against the prior state and appends `threshold_set`, `threshold_changed`, or `threshold_removed` events — so governance-relevant config changes are independently auditable from AI decision traces.
- Initial project scaffolding and repository structure.
- `README.md` containing the project vision, principles, and high-level architecture.
- Core governance documents including `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `GOVERNANCE.md`.
- `ROADMAP.md` defining the Phase 0 through Phase 5 launch strategy.
- `.github` configuration containing issue templates, pull request templates, and CI/CD workflow skeletons.
