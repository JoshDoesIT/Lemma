# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
