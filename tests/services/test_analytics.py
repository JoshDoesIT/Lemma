"""Tests for the compliance-debt analytics service (Refs #40)."""

from __future__ import annotations


def _result(pairs):
    """Build a CheckResult from (framework, short_id, passed) tuples."""
    from lemma.models.check_result import CheckResult, CheckStatus, ControlCheckOutcome

    outcomes = [
        ControlCheckOutcome(
            control_id=f"control:{fw}:{cid}",
            framework=fw,
            short_id=cid,
            title=cid,
            status=CheckStatus.PASSED if ok else CheckStatus.FAILED,
        )
        for fw, cid, ok in pairs
    ]
    return CheckResult(framework=None, outcomes=outcomes)


class TestComputeComplianceDebt:
    def test_totals_and_ratio(self):
        from lemma.services.analytics import compute_compliance_debt

        result = _result(
            [
                ("nist-800-53", "ac-1", True),
                ("nist-800-53", "ac-2", False),
                ("nist-800-53", "ac-3", False),
                ("hipaa", "164.312(b)", True),
            ]
        )
        debt = compute_compliance_debt(result)
        assert debt.total_controls == 4
        assert debt.covered == 2
        assert debt.uncovered == 2
        assert debt.debt_ratio == 0.5
        assert debt.debt_pct == 50.0

    def test_per_framework_sorted_worst_first(self):
        from lemma.services.analytics import compute_compliance_debt

        result = _result(
            [
                ("a", "1", True),  # framework a: 0% debt
                ("a", "2", True),
                ("b", "1", False),  # framework b: 100% debt
                ("c", "1", False),  # framework c: 50% debt
                ("c", "2", True),
            ]
        )
        debt = compute_compliance_debt(result)
        order = [f.framework for f in debt.frameworks]
        assert order == ["b", "c", "a"]  # worst debt first
        b = debt.frameworks[0]
        assert b.uncovered == 1
        assert b.total == 1
        assert b.debt_ratio == 1.0

    def test_empty_result_is_zero_debt(self):
        from lemma.services.analytics import compute_compliance_debt

        debt = compute_compliance_debt(_result([]))
        assert debt.total_controls == 0
        assert debt.uncovered == 0
        assert debt.debt_ratio == 0.0
        assert debt.frameworks == []

    def test_all_covered_is_zero_debt(self):
        from lemma.services.analytics import compute_compliance_debt

        debt = compute_compliance_debt(_result([("a", "1", True), ("a", "2", True)]))
        assert debt.uncovered == 0
        assert debt.debt_ratio == 0.0


class TestDebtHistory:
    def test_snapshot_then_read_round_trips(self, tmp_path):
        from datetime import UTC, datetime

        from lemma.services.analytics import (
            compute_compliance_debt,
            read_debt_history,
            record_debt_snapshot,
        )

        debt = compute_compliance_debt(_result([("a", "1", True), ("a", "2", False)]))
        adir = tmp_path / "analytics"
        record_debt_snapshot(adir, debt, at=datetime(2026, 6, 20, tzinfo=UTC))

        history = read_debt_history(adir)
        assert len(history) == 1
        assert history[0]["uncovered"] == 1
        assert history[0]["total_controls"] == 2
        assert history[0]["debt_pct"] == 50.0
        assert history[0]["timestamp"].startswith("2026-06-20")

    def test_snapshots_append_in_order(self, tmp_path):
        from datetime import UTC, datetime

        from lemma.services.analytics import (
            compute_compliance_debt,
            read_debt_history,
            record_debt_snapshot,
        )

        adir = tmp_path / "analytics"
        record_debt_snapshot(
            adir,
            compute_compliance_debt(_result([("a", "1", False), ("a", "2", False)])),
            at=datetime(2026, 6, 19, tzinfo=UTC),
        )
        record_debt_snapshot(
            adir,
            compute_compliance_debt(_result([("a", "1", True), ("a", "2", False)])),
            at=datetime(2026, 6, 20, tzinfo=UTC),
        )
        history = read_debt_history(adir)
        assert [h["debt_pct"] for h in history] == [100.0, 50.0]  # burning down

    def test_read_missing_history_is_empty(self, tmp_path):
        from lemma.services.analytics import read_debt_history

        assert read_debt_history(tmp_path / "nope") == []
