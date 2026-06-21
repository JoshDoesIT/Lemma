# RFC Template

Copy this into a new issue titled `RFC: <short title>` for any
architecturally significant change (new subsystem, breaking schema/API change,
new runtime dependency, security-model change, or anything expensive to
reverse). See the [RFC process](https://github.com/JoshDoesIT/Lemma/blob/main/CONTRIBUTING.md#rfc-process-major-architectural-decisions)
in `CONTRIBUTING.md` for how RFCs are reviewed and decided.

---

## Summary

One paragraph: what is being proposed, in plain terms.

## Motivation

What problem does this solve? Who is affected, and what is the cost of *not*
doing it? Link any issues or user reports.

## Design

The proposed change in detail:

- New/changed components, data models, or CLI surface.
- How it fits the existing architecture (reference `ARCHITECTURE.md`).
- New dependencies, if any, and why they're justified.
- Security and AI-transparency implications (every AI decision must remain
  logged with its trace).

## Alternatives considered

What other approaches were weighed, and why this one wins. "Do nothing" is a
valid alternative to evaluate.

## Risks and drawbacks

What could go wrong, what becomes harder, and what's hard to reverse. Note any
breaking changes — these require a
[migration guide](https://github.com/JoshDoesIT/Lemma/blob/main/docs/contributing/migrations.md).

## Rollout

How this ships: phasing, feature flags, deprecation windows, and the tests
that will prove it works. Reference the implementing PR(s) once opened.

## Decision

_Filled in by a maintainer._ Accepted / Declined / Deferred, with a one-line
rationale and links to the implementing PR(s).
