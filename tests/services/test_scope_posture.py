"""Tests for per-scope posture computation."""

from __future__ import annotations

import pytest


def _graph_with_full_picture():
    """Build scope→framework→controls, with policy mappings and evidence links."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53")
    g.add_control(
        framework="nist-800-53", control_id="ac-2", title="Account Management", family="AC"
    )
    g.add_control(
        framework="nist-800-53", control_id="ac-3", title="Access Enforcement", family="AC"
    )
    g.add_control(framework="nist-800-53", control_id="au-2", title="Event Logging", family="AU")

    g.add_policy("access-policy.md", title="Access Policy")
    g.add_mapping(
        policy="access-policy.md", framework="nist-800-53", control_id="ac-2", confidence=0.9
    )
    # ac-3 is mapped but not evidenced; au-2 is evidenced but not mapped.
    g.add_mapping(
        policy="access-policy.md", framework="nist-800-53", control_id="ac-3", confidence=0.8
    )

    # Evidence linked to ac-2 and au-2.
    g.add_evidence(
        entry_hash="a" * 64,
        producer="Lemma",
        class_name="Compliance Finding",
        time_iso="2026-04-24T12:00:00+00:00",
        control_refs=["nist-800-53:ac-2"],
    )
    g.add_evidence(
        entry_hash="b" * 64,
        producer="Lemma",
        class_name="Compliance Finding",
        time_iso="2026-04-24T12:00:00+00:00",
        control_refs=["nist-800-53:au-2"],
    )

    g.add_scope(
        name="prod",
        frameworks=["nist-800-53"],
        justification="Prod.",
        rule_count=0,
    )
    return g


class TestComputePosture:
    def test_counts_controls_mapped_evidenced_covered(self):
        from lemma.services.scope_posture import compute_posture

        posture = compute_posture("prod", _graph_with_full_picture())

        assert posture.scope == "prod"
        # One framework bound to the scope.
        assert len(posture.frameworks) == 1
        fw = posture.frameworks[0]
        assert fw.name == "nist-800-53"
        assert fw.total == 3
        assert fw.mapped == 2  # ac-2, ac-3 have SATISFIES edges
        assert fw.evidenced == 2  # ac-2, au-2 have EVIDENCES edges
        assert fw.covered == 1  # only ac-2 has both

    def test_scope_with_multiple_frameworks_reports_each_separately(self):
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.scope_posture import compute_posture

        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.add_control(framework="nist-800-53", control_id="ac-1", title="AC-1", family="AC")
        g.add_framework("nist-csf-2.0")
        g.add_control(
            framework="nist-csf-2.0", control_id="gv.oc-1", title="GV-OC-1", family="GV.OC"
        )

        g.add_scope(
            name="multi",
            frameworks=["nist-800-53", "nist-csf-2.0"],
            justification="two",
            rule_count=0,
        )
        posture = compute_posture("multi", g)

        assert {fw.name for fw in posture.frameworks} == {"nist-800-53", "nist-csf-2.0"}
        for fw in posture.frameworks:
            assert fw.total == 1
            assert fw.mapped == 0
            assert fw.evidenced == 0
            assert fw.covered == 0

    def test_unknown_scope_raises(self):
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.scope_posture import compute_posture

        g = ComplianceGraph()
        g.add_framework("nist-800-53")

        with pytest.raises(ValueError, match=r"(?i)missing|does not|unknown"):
            compute_posture("missing", g)

    def test_framework_with_no_controls_reports_zeros(self):
        """A framework loaded but empty: every count is zero."""
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.scope_posture import compute_posture

        g = ComplianceGraph()
        g.add_framework("empty-fw")
        g.add_scope(
            name="s",
            frameworks=["empty-fw"],
            justification="",
            rule_count=0,
        )

        posture = compute_posture("s", g)
        fw = posture.frameworks[0]
        assert fw.total == 0
        assert fw.mapped == 0
        assert fw.evidenced == 0
        assert fw.covered == 0
        assert fw.reused == 0


class TestComputePostureWithReuse:
    """Cross-Scope Evidence Reuse extension: a control counts as `evidenced`
    if it has ≥1 inbound EVIDENCES *or* IMPLICITLY_EVIDENCES edge. The
    `reused` field counts controls that are evidenced ONLY via implicit edges
    (no direct EVIDENCES) — useful for spotting which controls lean on
    harmonization-driven reuse vs direct attestation.
    """

    def _graph_with_cross_scope_reuse(self):
        from lemma.services.knowledge_graph import ComplianceGraph

        g = ComplianceGraph()
        g.add_framework("nist-csf-2.0")
        g.add_framework("pci-dss-4.0")
        g.add_control(
            framework="nist-csf-2.0",
            control_id="gv.oc-1",
            title="Org Context 1",
            family="GV.OC",
        )
        g.add_control(
            framework="pci-dss-4.0",
            control_id="12.1",
            title="Information Security Policy",
            family="12",
        )
        g.add_control(
            framework="pci-dss-4.0",
            control_id="12.2",
            title="Risk Assessment",
            family="12",
        )
        g.add_harmonization(
            framework_a="nist-csf-2.0",
            control_a="gv.oc-1",
            framework_b="pci-dss-4.0",
            control_b="12.1",
            similarity=0.85,
        )
        # Direct EVIDENCES on the NIST control — reuse propagates to PCI 12.1.
        g.add_evidence(
            entry_hash="a" * 64,
            producer="Lemma",
            class_name="Compliance Finding",
            time_iso="2026-04-26T12:00:00+00:00",
            control_refs=["nist-csf-2.0:gv.oc-1"],
        )
        g.rebuild_implicit_evidences(min_similarity=0.7)
        g.add_scope(
            name="pci",
            frameworks=["pci-dss-4.0"],
            justification="PCI",
            rule_count=0,
        )
        return g

    def test_evidenced_counts_implicit_edges_too(self):
        """PCI 12.1 has no direct EVIDENCES but has an IMPLICITLY_EVIDENCES; counts."""
        from lemma.services.scope_posture import compute_posture

        posture = compute_posture("pci", self._graph_with_cross_scope_reuse())
        fw = posture.frameworks[0]
        assert fw.total == 2  # 12.1, 12.2
        assert fw.evidenced == 1  # 12.1 via implicit
        assert fw.reused == 1  # 12.1 is implicit-only

    def test_reused_counts_only_implicit_only_controls(self):
        """A control with both direct + implicit edges counts as evidenced, NOT reused."""
        from lemma.services.scope_posture import compute_posture

        g = self._graph_with_cross_scope_reuse()
        # Add a direct EVIDENCES to PCI 12.1 alongside the implicit one.
        g.add_evidence(
            entry_hash="b" * 64,
            producer="Lemma",
            class_name="Compliance Finding",
            time_iso="2026-04-26T12:00:00+00:00",
            control_refs=["pci-dss-4.0:12.1"],
        )

        posture = compute_posture("pci", g)
        fw = posture.frameworks[0]
        assert fw.evidenced == 1  # still 12.1 (direct now)
        assert fw.reused == 0  # 12.1 is no longer implicit-only
