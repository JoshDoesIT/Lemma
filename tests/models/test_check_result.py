"""Tests for the `CheckResult` model used by `lemma check`."""

from __future__ import annotations

import pytest


class TestCheckResultConstruction:
    def test_empty_result_has_zero_counts(self):
        from lemma.models.check_result import CheckResult

        result = CheckResult(framework=None, outcomes=[])

        assert result.total == 0
        assert result.passed == 0
        assert result.failed == 0

    def test_counts_derive_from_outcomes(self):
        from lemma.models.check_result import (
            CheckResult,
            CheckStatus,
            ControlCheckOutcome,
        )

        outcomes = [
            ControlCheckOutcome(
                control_id="control:nist-800-53:ac-1",
                framework="nist-800-53",
                short_id="ac-1",
                title="Access Control Policy and Procedures",
                status=CheckStatus.PASSED,
                satisfying_policies=["policy:ac.md"],
            ),
            ControlCheckOutcome(
                control_id="control:nist-800-53:ac-2",
                framework="nist-800-53",
                short_id="ac-2",
                title="Account Management",
                status=CheckStatus.FAILED,
                satisfying_policies=[],
            ),
        ]
        result = CheckResult(framework="nist-800-53", outcomes=outcomes)

        assert result.total == 2
        assert result.passed == 1
        assert result.failed == 1


class TestCheckStatusEnum:
    def test_enum_has_passed_and_failed(self):
        from lemma.models.check_result import CheckStatus

        assert CheckStatus.PASSED.value == "PASSED"
        assert CheckStatus.FAILED.value == "FAILED"

    def test_unknown_status_rejected(self):
        from lemma.models.check_result import ControlCheckOutcome

        with pytest.raises(ValueError):
            ControlCheckOutcome(
                control_id="control:x:y",
                framework="x",
                short_id="y",
                title="t",
                status="MAYBE",  # type: ignore[arg-type]
                satisfying_policies=[],
            )
