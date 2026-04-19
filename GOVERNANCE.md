# Project Governance

This document describes the governance model for the Lemma open-source project. This model ensures transparent decision-making, predictable development, and maintains the project's core principles of being engineer-first and treating compliance as code.

## Maintainer Responsibilities

Project Maintainers are active contributors who have demonstrated a commitment to the long-term health and success of Lemma. 

Maintainers are responsible for:
- Directing the overall roadmap and architecture.
- Reviewing and merging pull requests, ensuring they adhere strictly to the Test-Driven Development (TDD) conventions and quality standards.
- Ensuring the adherence to the [Code of Conduct](CODE_OF_CONDUCT.md).
- Responding to security reports via established confidential channels.
- Acting as shepherds for community RFCs (Request for Comments).

A list of current maintainers will be maintained in a `CODEOWNERS` document upon the formal release of the codebase (Phase 1).

## Decision Making

Lemma operates on a model of "lazy consensus" for minor changes and a structured RFC process for major architectural shifts.

- **Minor Changes (Bug fixes, documentation, minor features):** Assuming the changes are fully tested, pass CI, and align with the current architecture, maintainers can approve and merge via standard GitHub PR reviews.
- **Major Changes (Architecture, broad APIs, significant user-facing alterations):** These require an RFC proposal before extensive implementation begins.

## Request for Comments (RFC) Process

Before embarking on significant work, contributors and maintainers must submit an RFC to ensure community buy-in and technical validity. The process prevents wasted effort and documents architectural decisions over time.

1. Create a new issue using the **RFC Issue Template** provided in the repository.
2. Outline the Motivation, Detailed Design, Alternatives Considered, and Unresolved Questions.
3. Announce the RFC to the community (e.g., via GitHub Discussions).
4. The RFC must be open for comment for a minimum of 7 days to allow adequate review.
5. A maintainer will eventually summarize the discussion and mark the RFC as **Accepted**, **Rejected**, or **On Hold**.
6. Once **Accepted**, work can begin via standard PRs that reference the original RFC.

## Conflict Resolution

Disagreements surrounding technical design are expected and healthy. Conflicts are to be resolved through the following escalation path:

1. **Constructive Discussion:** Rely on the RFC issue tracker or pull request threads to debate technical merits, grounded in verifiable data and engineering standard practice.
2. **Community Feedback:** Request the input of other contributors in GitHub Discussions.
3. **Maintainer Consensus:** If a technical disagreement remains unresolved, project maintainers will vote on the path forward, documenting the rationale extensively.

For interpersonal conflicts or violations of community standards, refer to the [Code of Conduct](CODE_OF_CONDUCT.md).
