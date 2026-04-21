"""Tests for coverage and gap analysis services.

Follows TDD: tests written BEFORE implementation.
"""

from __future__ import annotations

import pytest


def _make_report(
    *,
    nist_ids: list[str] | None = None,
    hipaa_ids: list[str] | None = None,
    cross_fw_pairs: list[tuple[str, str]] | None = None,
):
    """Build a test HarmonizationReport with specified clusters.

    Args:
        nist_ids: Singleton NIST control IDs.
        hipaa_ids: Singleton HIPAA control IDs.
        cross_fw_pairs: Pairs of (nist_id, hipaa_id) that cluster together.
    """
    from lemma.models.harmonization import (
        CommonControl,
        HarmonizationReport,
        SourceControl,
    )

    clusters = []
    cluster_idx = 0

    # Cross-framework clusters
    for nist_id, hipaa_id in cross_fw_pairs or []:
        clusters.append(
            CommonControl(
                cluster_id=f"c{cluster_idx}",
                controls=[
                    SourceControl(
                        framework="nist-800-53",
                        control_id=nist_id,
                        title=f"NIST {nist_id}",
                        similarity=1.0,
                    ),
                    SourceControl(
                        framework="hipaa",
                        control_id=hipaa_id,
                        title=f"HIPAA {hipaa_id}",
                        similarity=0.9,
                    ),
                ],
                primary_label=f"Cluster {cluster_idx}",
                primary_description="Test cluster.",
            )
        )
        cluster_idx += 1

    # Singleton NIST controls
    for nist_id in nist_ids or []:
        clusters.append(
            CommonControl(
                cluster_id=f"c{cluster_idx}",
                controls=[
                    SourceControl(
                        framework="nist-800-53",
                        control_id=nist_id,
                        title=f"NIST {nist_id}",
                        similarity=1.0,
                    ),
                ],
                primary_label=f"NIST {nist_id}",
                primary_description="Singleton.",
            )
        )
        cluster_idx += 1

    # Singleton HIPAA controls
    for hipaa_id in hipaa_ids or []:
        clusters.append(
            CommonControl(
                cluster_id=f"c{cluster_idx}",
                controls=[
                    SourceControl(
                        framework="hipaa",
                        control_id=hipaa_id,
                        title=f"HIPAA {hipaa_id}",
                        similarity=1.0,
                    ),
                ],
                primary_label=f"HIPAA {hipaa_id}",
                primary_description="Singleton.",
            )
        )
        cluster_idx += 1

    return HarmonizationReport(
        frameworks=["nist-800-53", "hipaa"],
        clusters=clusters,
        threshold=0.85,
    )


class TestCoverage:
    """Tests for compute_coverage."""

    def test_coverage_full(self):
        """All controls in cross-framework clusters → 100% coverage."""
        from lemma.services.coverage import compute_coverage

        report = _make_report(
            cross_fw_pairs=[("ac-2", "164.312(a)")],
        )
        coverage = compute_coverage(report)
        assert coverage.frameworks["nist-800-53"] == pytest.approx(1.0)
        assert coverage.frameworks["hipaa"] == pytest.approx(1.0)

    def test_coverage_partial(self):
        """Mix of clustered and singleton controls gives partial coverage."""
        from lemma.services.coverage import compute_coverage

        report = _make_report(
            nist_ids=["si-4", "au-3"],
            cross_fw_pairs=[("ac-2", "164.312(a)")],
        )
        coverage = compute_coverage(report)
        # NIST: 1 of 3 controls in cross-fw cluster = 33%
        assert coverage.frameworks["nist-800-53"] == pytest.approx(1 / 3, rel=0.01)
        # HIPAA: 1 of 1 = 100%
        assert coverage.frameworks["hipaa"] == pytest.approx(1.0)


class TestGaps:
    """Tests for compute_gaps."""

    def test_gaps_for_framework(self):
        """Singleton controls with no cross-framework match are gaps."""
        from lemma.services.coverage import compute_gaps

        report = _make_report(
            nist_ids=["si-4", "au-3"],
            cross_fw_pairs=[("ac-2", "164.312(a)")],
        )
        gaps = compute_gaps(report, "nist-800-53")
        unmapped_ids = {c["control_id"] for c in gaps.unmapped_controls}
        assert unmapped_ids == {"si-4", "au-3"}
        assert gaps.total_controls == 3

    def test_gaps_no_gaps(self):
        """All controls in cross-framework clusters → no gaps."""
        from lemma.services.coverage import compute_gaps

        report = _make_report(
            cross_fw_pairs=[("ac-2", "164.312(a)")],
        )
        gaps = compute_gaps(report, "nist-800-53")
        assert len(gaps.unmapped_controls) == 0
