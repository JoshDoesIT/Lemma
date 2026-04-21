"""Tests for the harmonizer service.

Follows TDD: tests written BEFORE implementation.
"""

from __future__ import annotations

import pytest

from lemma.services.indexer import ControlIndexer


class TestHarmonizer:
    """Tests for harmonize_frameworks."""

    def test_harmonize_no_frameworks_errors(self, tmp_path):
        """Harmonizing with no indexed frameworks raises ValueError."""
        from lemma.services.harmonizer import harmonize_frameworks

        indexer = ControlIndexer(index_dir=tmp_path / "index")

        with pytest.raises(ValueError, match=r"[Nn]o.*(framework|indexed)"):
            harmonize_frameworks(indexer=indexer)

    def test_harmonize_single_framework_singleton_clusters(self, tmp_path):
        """Single framework produces only singleton clusters (no cross-fw match)."""
        from lemma.services.harmonizer import harmonize_frameworks

        indexer = ControlIndexer(index_dir=tmp_path / "index")
        indexer.index_controls(
            "nist-800-53",
            [
                {
                    "id": "ac-2",
                    "title": "Account Management",
                    "prose": "Manage system accounts.",
                    "family": "AC",
                },
                {
                    "id": "ac-3",
                    "title": "Access Enforcement",
                    "prose": "Enforce access rules.",
                    "family": "AC",
                },
            ],
        )

        report = harmonize_frameworks(indexer=indexer)
        assert report.cluster_count >= 1
        # Single framework → no cross-framework clusters possible
        for cluster in report.clusters:
            frameworks_in_cluster = {c.framework for c in cluster.controls}
            assert len(frameworks_in_cluster) == 1

    def test_harmonize_cross_framework_clustering(self, tmp_path):
        """Semantically similar controls across frameworks are clustered together."""
        from lemma.services.harmonizer import harmonize_frameworks

        indexer = ControlIndexer(index_dir=tmp_path / "index")
        indexer.index_controls(
            "framework-a",
            [
                {
                    "id": "a-1",
                    "title": "Account Management",
                    "prose": "The organization manages information system accounts.",
                    "family": "AC",
                },
            ],
        )
        indexer.index_controls(
            "framework-b",
            [
                {
                    "id": "b-1",
                    "title": "User Account Administration",
                    "prose": "The organization administers user accounts for information systems.",
                    "family": "AC",
                },
            ],
        )

        report = harmonize_frameworks(indexer=indexer, threshold=0.5)
        # With low threshold and very similar text, should cluster
        cross_fw_clusters = [
            c for c in report.clusters if len({sc.framework for sc in c.controls}) > 1
        ]
        assert len(cross_fw_clusters) >= 1

    def test_harmonize_deterministic_output(self, tmp_path):
        """Running harmonize twice on the same data produces identical output."""
        from lemma.services.harmonizer import harmonize_frameworks

        indexer = ControlIndexer(index_dir=tmp_path / "index")
        indexer.index_controls(
            "fw-a",
            [
                {
                    "id": "a-1",
                    "title": "Access Control",
                    "prose": "Control access.",
                    "family": "AC",
                },
                {"id": "a-2", "title": "Audit Logging", "prose": "Log events.", "family": "AU"},
            ],
        )
        indexer.index_controls(
            "fw-b",
            [
                {
                    "id": "b-1",
                    "title": "Access Management",
                    "prose": "Manage access.",
                    "family": "AC",
                },
            ],
        )

        report_1 = harmonize_frameworks(indexer=indexer, threshold=0.5)
        report_2 = harmonize_frameworks(indexer=indexer, threshold=0.5)

        assert report_1.model_dump() == report_2.model_dump()

    def test_harmonize_respects_threshold(self, tmp_path):
        """Higher threshold produces fewer cross-framework clusters."""
        from lemma.services.harmonizer import harmonize_frameworks

        indexer = ControlIndexer(index_dir=tmp_path / "index")
        indexer.index_controls(
            "fw-a",
            [
                {
                    "id": "a-1",
                    "title": "Access Control",
                    "prose": "Control access to systems.",
                    "family": "AC",
                }
            ],
        )
        indexer.index_controls(
            "fw-b",
            [
                {
                    "id": "b-1",
                    "title": "Access Management",
                    "prose": "Manage access to systems.",
                    "family": "AC",
                }
            ],
        )

        low_report = harmonize_frameworks(indexer=indexer, threshold=0.3)
        high_report = harmonize_frameworks(indexer=indexer, threshold=0.99)

        # High threshold should produce more (or equal) clusters (less merging)
        assert high_report.cluster_count >= low_report.cluster_count

    def test_harmonize_cluster_head_uses_longest_description(self, tmp_path):
        """Cluster head uses the longest prose for primary_description."""
        from lemma.services.harmonizer import harmonize_frameworks

        short_prose = "Manage accounts."
        long_prose = (
            "The organization manages information system accounts, "
            "including establishing, activating, modifying, reviewing, "
            "disabling, and removing accounts."
        )

        indexer = ControlIndexer(index_dir=tmp_path / "index")
        indexer.index_controls(
            "fw-a",
            [{"id": "a-1", "title": "Account Mgmt", "prose": short_prose, "family": "AC"}],
        )
        indexer.index_controls(
            "fw-b",
            [{"id": "b-1", "title": "Account Management", "prose": long_prose, "family": "AC"}],
        )

        report = harmonize_frameworks(indexer=indexer, threshold=0.3)

        # Find the cluster that has both a-1 and b-1
        for cluster in report.clusters:
            ctrl_ids = {c.control_id for c in cluster.controls}
            if "a-1" in ctrl_ids and "b-1" in ctrl_ids:
                assert len(cluster.primary_description) >= len(long_prose)
                break
