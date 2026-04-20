"""Tests for harmonization domain models.

Follows TDD: tests written BEFORE implementation.
"""

from __future__ import annotations

import pytest


class TestSourceControl:
    """Tests for SourceControl model."""

    def test_source_control_creation(self):
        """SourceControl holds a framework-qualified control reference."""
        from lemma.models.harmonization import SourceControl

        sc = SourceControl(
            framework="nist-800-53",
            control_id="ac-2",
            title="Account Management",
            similarity=0.92,
        )
        assert sc.framework == "nist-800-53"
        assert sc.control_id == "ac-2"
        assert sc.title == "Account Management"
        assert sc.similarity == pytest.approx(0.92)


class TestCommonControl:
    """Tests for CommonControl model."""

    def test_common_control_creation(self):
        """CommonControl clusters equivalent controls from multiple frameworks."""
        from lemma.models.harmonization import CommonControl, SourceControl

        controls = [
            SourceControl(
                framework="nist-800-53",
                control_id="ac-2",
                title="Account Management",
                similarity=1.0,
            ),
            SourceControl(
                framework="hipaa",
                control_id="164.312(a)",
                title="Access Control",
                similarity=0.89,
            ),
        ]

        cc = CommonControl(
            cluster_id="cluster-001",
            controls=controls,
            primary_label="Account Management",
            primary_description="Manage system accounts, including establishing...",
        )
        assert cc.cluster_id == "cluster-001"
        assert len(cc.controls) == 2
        assert cc.primary_label == "Account Management"
        assert cc.primary_description.startswith("Manage system accounts")

    def test_common_control_framework_list(self):
        """CommonControl exposes a list of participating frameworks."""
        from lemma.models.harmonization import CommonControl, SourceControl

        cc = CommonControl(
            cluster_id="c1",
            controls=[
                SourceControl(
                    framework="nist-800-53",
                    control_id="ac-2",
                    title="AM",
                    similarity=1.0,
                ),
                SourceControl(
                    framework="hipaa",
                    control_id="164.312(a)",
                    title="AC",
                    similarity=0.89,
                ),
            ],
            primary_label="Test",
            primary_description="Test",
        )
        assert set(cc.frameworks) == {"nist-800-53", "hipaa"}


class TestHarmonizationReport:
    """Tests for HarmonizationReport model."""

    def test_report_computed_fields(self):
        """Report computes total_controls and cluster_count."""
        from lemma.models.harmonization import (
            CommonControl,
            HarmonizationReport,
            SourceControl,
        )

        report = HarmonizationReport(
            frameworks=["nist-800-53", "hipaa"],
            clusters=[
                CommonControl(
                    cluster_id="c1",
                    controls=[
                        SourceControl(
                            framework="nist-800-53",
                            control_id="ac-2",
                            title="AM",
                            similarity=1.0,
                        ),
                        SourceControl(
                            framework="hipaa",
                            control_id="164.312(a)",
                            title="AC",
                            similarity=0.89,
                        ),
                    ],
                    primary_label="Account Mgmt",
                    primary_description="Test",
                ),
            ],
            threshold=0.85,
        )
        assert report.cluster_count == 1
        assert report.total_controls == 2


class TestCoverageReport:
    """Tests for CoverageReport model."""

    def test_coverage_report_creation(self):
        """CoverageReport holds per-framework coverage percentages."""
        from lemma.models.harmonization import CoverageReport

        report = CoverageReport(
            frameworks={"nist-800-53": 0.34, "hipaa": 0.67},
        )
        assert report.frameworks["nist-800-53"] == pytest.approx(0.34)
        assert report.frameworks["hipaa"] == pytest.approx(0.67)


class TestGapReport:
    """Tests for GapReport model."""

    def test_gap_report_creation(self):
        """GapReport lists controls with no cross-framework match."""
        from lemma.models.harmonization import GapReport

        report = GapReport(
            framework="nist-800-53",
            unmapped_controls=[
                {"control_id": "ac-17", "title": "Remote Access"},
                {"control_id": "si-4", "title": "System Monitoring"},
            ],
            total_controls=100,
        )
        assert report.framework == "nist-800-53"
        assert len(report.unmapped_controls) == 2
        assert report.gap_percentage == pytest.approx(2.0)


class TestDiffResult:
    """Tests for DiffResult model."""

    def test_diff_result_creation(self):
        """DiffResult tracks added/removed/modified controls."""
        from lemma.models.harmonization import DiffResult

        result = DiffResult(
            from_framework="nist-800-53-r4",
            to_framework="nist-800-53-r5",
            added=["ac-22", "ac-23"],
            removed=["ac-18"],
            modified=[
                {
                    "control_id": "ac-2",
                    "change_summary": "Title updated",
                }
            ],
        )
        assert result.from_framework == "nist-800-53-r4"
        assert len(result.added) == 2
        assert len(result.removed) == 1
        assert len(result.modified) == 1
