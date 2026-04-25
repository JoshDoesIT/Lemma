"""Tests for the Risk Pydantic model."""

from __future__ import annotations

import pytest


class TestRiskDefinition:
    def test_accepts_valid_dict(self):
        from lemma.models.risk import RiskDefinition, RiskSeverity

        r = RiskDefinition(
            id="audit-log-loss",
            title="Loss of audit logs",
            description="Audit log bucket compromised or accidentally deleted.",
            severity="high",
            threatens=["resource:prod-rds"],
            mitigated_by=["control:nist-800-53:au-2"],
        )
        assert r.id == "audit-log-loss"
        assert r.severity == RiskSeverity.HIGH
        assert r.threatens == ["resource:prod-rds"]
        assert r.mitigated_by == ["control:nist-800-53:au-2"]

    def test_optional_fields_default_to_empty(self):
        from lemma.models.risk import RiskDefinition

        r = RiskDefinition(id="r1", title="t", severity="low")
        assert r.description == ""
        assert r.threatens == []
        assert r.mitigated_by == []

    def test_rejects_unknown_top_level_field(self):
        """A typo like `severities` (plural) must fail loud."""
        from lemma.models.risk import RiskDefinition

        with pytest.raises(ValueError, match=r"(?i)severities"):
            RiskDefinition(
                id="r1",
                title="t",
                severities="high",  # type: ignore[call-arg]
            )

    def test_rejects_unknown_severity_value(self):
        from lemma.models.risk import RiskDefinition

        with pytest.raises(ValueError, match=r"(?i)severity|critical|low"):
            RiskDefinition(
                id="r1",
                title="t",
                severity="catastrophic",  # type: ignore[arg-type]
            )

    def test_severity_enum_values(self):
        from lemma.models.risk import RiskSeverity

        assert RiskSeverity.LOW.value == "low"
        assert RiskSeverity.MEDIUM.value == "medium"
        assert RiskSeverity.HIGH.value == "high"
        assert RiskSeverity.CRITICAL.value == "critical"
