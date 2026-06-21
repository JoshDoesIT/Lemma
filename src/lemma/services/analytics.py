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

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from lemma.models.check_result import CheckResult, CheckStatus

_HISTORY_FILE = "debt-history.jsonl"


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


def record_debt_snapshot(
    analytics_dir: Path,
    debt: ComplianceDebt,
    *,
    at: datetime | None = None,
) -> Path:
    """Append a debt snapshot to the append-only history log, for trend tracking.

    Returns the history file path. Snapshots are one JSON object per line
    (``timestamp``, ``total_controls``, ``covered``, ``uncovered``,
    ``debt_pct``) so a burn-down can be charted over time.
    """
    analytics_dir = Path(analytics_dir)
    analytics_dir.mkdir(parents=True, exist_ok=True)
    history_path = analytics_dir / _HISTORY_FILE
    snapshot = {
        "timestamp": (at or datetime.now(UTC)).isoformat(),
        "total_controls": debt.total_controls,
        "covered": debt.covered,
        "uncovered": debt.uncovered,
        "debt_pct": debt.debt_pct,
    }
    with history_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(snapshot) + "\n")
    return history_path


def read_debt_history(analytics_dir: Path) -> list[dict]:
    """Read all debt snapshots in chronological (append) order."""
    history_path = Path(analytics_dir) / _HISTORY_FILE
    if not history_path.exists():
        return []
    snapshots: list[dict] = []
    for line in history_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            snapshots.append(json.loads(line))
    return snapshots
