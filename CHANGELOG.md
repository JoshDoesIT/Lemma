# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Confidence-gated automation for AI mapping. `ai.automation.thresholds.<operation>` in `lemma.config.yaml` auto-accepts AI outputs at or above the configured threshold; outputs below remain PROPOSED for human review. Auto-accepted trace entries are marked with `auto_accepted: true` and record the applied threshold in the review rationale.
- `auto_accepted` field on `AITrace` distinguishes gate-driven acceptances from human-driven ones.
- Initial project scaffolding and repository structure.
- `README.md` containing the project vision, principles, and high-level architecture.
- Core governance documents including `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `GOVERNANCE.md`.
- `ROADMAP.md` defining the Phase 0 through Phase 5 launch strategy.
- `.github` configuration containing issue templates, pull request templates, and CI/CD workflow skeletons.
