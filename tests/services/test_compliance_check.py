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
