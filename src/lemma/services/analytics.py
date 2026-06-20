"""Compliance analytics — the Compliance Debt metric (Refs #40).

The roadmap's Reporting & Analytics theme tracks "Compliance Debt" alongside
technical debt: the body of controls that *should* be satisfied but aren't, so
teams can burn it down deliberately rather than discover it at audit time.

This is distinct from harmonization ``coverage`` (which measures cross-framework
control overlap) — debt is computed from the same ``CheckResult`` as
``lemma check``, so "what the CI gate fails on" and "the debt you owe" are the
same number. Per-framework debt is ranked worst-first so the next thing to pay
down is at the top.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lemma.models.check_result import CheckResult, CheckStatus


@dataclass(frozen=True)
class FrameworkDebt:
    """Per-framework compliance debt."""

    framework: str
    total: int
    uncovered: int

    @property
    def debt_ratio(self) -> float:
        return (self.uncovered / self.total) if self.total else 0.0

    @property
    def debt_pct(self) -> float:
        return round(100 * self.debt_ratio, 1)


@dataclass(frozen=True)
class ComplianceDebt:
    """Aggregate compliance-debt snapshot across all frameworks in scope."""

    total_controls: int
    uncovered: int
    frameworks: list[FrameworkDebt] = field(default_factory=list)

    @property
    def covered(self) -> int:
        return self.total_controls - self.uncovered

    @property
    def debt_ratio(self) -> float:
        return (self.uncovered / self.total_controls) if self.total_controls else 0.0

    @property
    def debt_pct(self) -> float:
        return round(100 * self.debt_ratio, 1)


def compute_compliance_debt(result: CheckResult) -> ComplianceDebt:
    """Compute the Compliance Debt snapshot from a ``CheckResult``.

    Debt = controls that are FAILED (no satisfying policy at the applied
    confidence). Per-framework entries are sorted worst-first (highest debt
    ratio), ties broken by larger uncovered count, then framework name.
    """
    totals: dict[str, int] = {}
    uncovered: dict[str, int] = {}
    for outcome in result.outcomes:
        fw = outcome.framework
        totals[fw] = totals.get(fw, 0) + 1
        if outcome.status == CheckStatus.FAILED:
            uncovered[fw] = uncovered.get(fw, 0) + 1

    frameworks = [
        FrameworkDebt(framework=fw, total=totals[fw], uncovered=uncovered.get(fw, 0))
        for fw in totals
    ]
    frameworks.sort(key=lambda f: (-f.debt_ratio, -f.uncovered, f.framework))

    return ComplianceDebt(
        total_controls=sum(totals.values()),
        uncovered=sum(uncovered.values()),
        frameworks=frameworks,
    )
