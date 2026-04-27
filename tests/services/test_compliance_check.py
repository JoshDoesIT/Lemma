"""Tests for the compliance-check service powering `lemma check`."""

from __future__ import annotations

import pytest


def _graph_with_controls():
    """Build a graph with two frameworks, some controls, one SATISFIES edge."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53", title="NIST 800-53")
    g.add_control(
        framework="nist-800-53",
        control_id="ac-1",
        title="Access Control Policy and Procedures",
        family="AC",
    )
    g.add_control(
        framework="nist-800-53",
        control_id="ac-2",
        title="Account Management",
        family="AC",
    )
    g.add_framework("nist-csf-2.0", title="NIST CSF 2.0")
    g.add_control(
        framework="nist-csf-2.0",
        control_id="pr.aa-1",
        title="Identities and credentials",
        family="PR.AA",
    )

    g.add_policy("access-control.md", title="Access Control Policy")
    g.add_mapping(
        policy="access-control.md",
        framework="nist-800-53",
        control_id="ac-1",
        confidence=0.9,
    )
    return g


class TestCheckOnEmptyGraph:
    def test_empty_graph_returns_zero_counts(self):
        from lemma.services.compliance_check import check
        from lemma.services.knowledge_graph import ComplianceGraph

        result = check(ComplianceGraph())
        assert result.total == 0
        assert result.passed == 0
        assert result.failed == 0
        assert result.outcomes == []


class TestPassedControls:
    def test_control_with_satisfies_edge_is_passed(self):
        from lemma.models.check_result import CheckStatus
        from lemma.services.compliance_check import check

        result = check(_graph_with_controls(), framework="nist-800-53")
        ac1 = next(o for o in result.outcomes if o.short_id == "ac-1")

        assert ac1.status == CheckStatus.PASSED
        assert ac1.satisfying_policies == ["policy:access-control.md"]


class TestFailedControls:
    def test_control_without_satisfies_is_failed(self):
        from lemma.models.check_result import CheckStatus
        from lemma.services.compliance_check import check

        result = check(_graph_with_controls(), framework="nist-800-53")
        ac2 = next(o for o in result.outcomes if o.short_id == "ac-2")

        assert ac2.status == CheckStatus.FAILED
        assert ac2.satisfying_policies == []


class TestFrameworkFilter:
    def test_filter_excludes_controls_outside_framework(self):
        from lemma.services.compliance_check import check

        result = check(_graph_with_controls(), framework="nist-800-53")

        frameworks = {o.framework for o in result.outcomes}
        assert frameworks == {"nist-800-53"}
        assert all(not o.short_id.startswith("pr.aa") for o in result.outcomes)

    def test_no_filter_includes_all_frameworks(self):
        from lemma.services.compliance_check import check

        result = check(_graph_with_controls())

        frameworks = {o.framework for o in result.outcomes}
        assert frameworks == {"nist-800-53", "nist-csf-2.0"}


class TestUnknownFramework:
    def test_unknown_framework_raises_with_candidate_list(self):
        from lemma.services.compliance_check import check

        pattern = r"(?i)nist-800-53.*nist-csf-2\.0|nist-csf-2\.0.*nist-800-53"
        with pytest.raises(ValueError, match=pattern):
            check(_graph_with_controls(), framework="iso-27001")


def _graph_with_confidence_edges():
    """Two SATISFIES edges to ac-1 with different confidence levels."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53")
    g.add_control(framework="nist-800-53", control_id="ac-1", title="AC-1", family="AC")
    g.add_policy("low.md", title="Low-confidence policy")
    g.add_policy("high.md", title="High-confidence policy")
    g.add_mapping(policy="low.md", framework="nist-800-53", control_id="ac-1", confidence=0.5)
    g.add_mapping(policy="high.md", framework="nist-800-53", control_id="ac-1", confidence=0.95)
    return g


class TestMinConfidenceFilter:
    def test_default_zero_accepts_every_satisfies_edge(self):
        from lemma.models.check_result import CheckStatus
        from lemma.services.compliance_check import check

        result = check(_graph_with_confidence_edges())
        outcome = next(o for o in result.outcomes if o.short_id == "ac-1")

        assert outcome.status == CheckStatus.PASSED
        assert outcome.satisfying_policies == ["policy:high.md", "policy:low.md"]
        assert result.min_confidence_applied == 0.0

    def test_high_threshold_excludes_low_confidence_edges(self):
        from lemma.models.check_result import CheckStatus
        from lemma.services.compliance_check import check

        result = check(_graph_with_confidence_edges(), min_confidence=0.9)
        outcome = next(o for o in result.outcomes if o.short_id == "ac-1")

        assert outcome.status == CheckStatus.PASSED
        assert outcome.satisfying_policies == ["policy:high.md"]
        assert result.min_confidence_applied == 0.9

    def test_threshold_above_all_edges_flips_to_failed(self):
        from lemma.models.check_result import CheckStatus
        from lemma.services.compliance_check import check

        result = check(_graph_with_confidence_edges(), min_confidence=0.99)
        outcome = next(o for o in result.outcomes if o.short_id == "ac-1")

        assert outcome.status == CheckStatus.FAILED
        assert outcome.satisfying_policies == []


class TestToSarif:
    def test_emits_one_result_per_failed_control(self):
        from lemma.services.compliance_check import check, to_sarif

        result = check(_graph_with_controls(), framework="nist-800-53")
        sarif = to_sarif(result)

        assert sarif.version == "2.1.0"
        assert len(sarif.runs) == 1

        # ac-1 PASSED → not emitted; ac-2 FAILED → one result.
        result_ids = [r.rule_id for r in sarif.runs[0].results]
        assert "control:nist-800-53:ac-2" in result_ids
        assert "control:nist-800-53:ac-1" not in result_ids

    def test_failed_results_carry_error_level_and_audit_properties(self):
        from lemma.services.compliance_check import check, to_sarif

        result = check(_graph_with_controls(), framework="nist-800-53", min_confidence=0.0)
        sarif = to_sarif(result)
        ac2 = next(r for r in sarif.runs[0].results if r.rule_id == "control:nist-800-53:ac-2")

        assert ac2.level == "error"
        assert "Account Management" in ac2.message.text
        assert ac2.properties["framework"] == "nist-800-53"
        assert ac2.properties["short_id"] == "ac-2"
        assert ac2.properties["min_confidence_applied"] == 0.0
        assert ac2.properties["satisfying_policies"] == []

    def test_sarif_log_round_trips_through_pydantic(self):
        from lemma.models.sarif import SarifLog
        from lemma.services.compliance_check import check, to_sarif

        result = check(_graph_with_controls(), framework="nist-800-53")
        sarif = to_sarif(result)

        wire = sarif.model_dump(by_alias=True)
        # `$schema` must be the wire-form key (not the Python attribute name).
        assert "$schema" in wire
        assert wire["$schema"].startswith("https://json.schemastore.org/sarif")

        # Round-trip back through Pydantic.
        rebuilt = SarifLog.model_validate(wire)
        assert rebuilt.version == sarif.version
        assert len(rebuilt.runs) == len(sarif.runs)
        assert len(rebuilt.runs[0].results) == len(sarif.runs[0].results)
