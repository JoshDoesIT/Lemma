"""Tests for the harmonizer service.

Follows TDD: tests written BEFORE implementation.
"""

from __future__ import annotations

from pathlib import Path

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


class TestHarmonizerTraceIntegration:
    """Trace emission for cross-framework equivalence decisions."""

    def _setup_cross_framework_indexer(self, tmp_path: Path) -> ControlIndexer:
        indexer = ControlIndexer(index_dir=tmp_path / "index")
        indexer.index_controls(
            "framework-a",
            [
                {
                    "id": "a-1",
                    "title": "Account Management",
                    "prose": "The organization manages information system accounts.",
                    "family": "AC",
                }
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
                }
            ],
        )
        return indexer

    def test_harmonize_emits_one_trace_per_equivalence(self, tmp_path: Path):
        from lemma.services.harmonizer import harmonize_frameworks
        from lemma.services.trace_log import TraceLog

        indexer = self._setup_cross_framework_indexer(tmp_path)
        trace_log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")

        harmonize_frameworks(indexer=indexer, threshold=0.5, trace_log=trace_log)

        traces = trace_log.read_all()
        harmonize_traces = [t for t in traces if t.operation == "harmonize"]
        assert harmonize_traces, "expected at least one harmonize trace"

        t = harmonize_traces[0]
        assert t.confidence > 0.5  # similarity met threshold
        assert t.determination == "HARMONIZED"
        assert t.model_id == "sentence-transformers/all-MiniLM-L6-v2"
        # pair fields populated on both sides
        assert t.control_id and t.framework
        assert t.related_control_id and t.related_framework
        assert (t.framework, t.control_id) != (t.related_framework, t.related_control_id)

    def test_harmonize_trace_pair_is_deterministically_ordered(self, tmp_path: Path):
        """Primary side of the pair is the lexicographically smaller (framework, control)."""
        from lemma.services.harmonizer import harmonize_frameworks
        from lemma.services.trace_log import TraceLog

        indexer = self._setup_cross_framework_indexer(tmp_path)
        trace_log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")

        harmonize_frameworks(indexer=indexer, threshold=0.5, trace_log=trace_log)

        harmonize_traces = [t for t in trace_log.read_all() if t.operation == "harmonize"]
        for t in harmonize_traces:
            primary = (t.framework, t.control_id)
            secondary = (t.related_framework, t.related_control_id)
            assert primary < secondary, (
                f"trace pair not ordered: primary={primary}, secondary={secondary}"
            )

    def test_harmonize_without_trace_log_still_works(self, tmp_path: Path):
        """trace_log is optional — omitting it preserves prior behavior."""
        from lemma.services.harmonizer import harmonize_frameworks

        indexer = self._setup_cross_framework_indexer(tmp_path)

        report = harmonize_frameworks(indexer=indexer, threshold=0.5)
        # Still produces a real report without crashing
        assert report.cluster_count >= 1

    def test_auto_accept_gate_promotes_high_similarity_equivalences(self, tmp_path: Path):
        from lemma.services.config import AutomationConfig
        from lemma.services.harmonizer import harmonize_frameworks
        from lemma.services.trace_log import TraceLog

        indexer = self._setup_cross_framework_indexer(tmp_path)
        trace_log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")

        harmonize_frameworks(
            indexer=indexer,
            threshold=0.5,
            trace_log=trace_log,
            automation=AutomationConfig(thresholds={"harmonize": 0.6}),
        )

        traces = trace_log.read_all()
        accepted = [
            t for t in traces if t.operation == "harmonize" and t.status.value == "ACCEPTED"
        ]
        assert accepted, "expected auto-accepted harmonize trace when similarity >= 0.6"
        for t in accepted:
            assert t.auto_accepted is True
            assert t.parent_trace_id  # links to PROPOSED entry
            assert t.related_control_id  # pair fields preserved on the review entry

    def test_auto_accept_skipped_when_below_operation_threshold(self, tmp_path: Path):
        from lemma.services.config import AutomationConfig
        from lemma.services.harmonizer import harmonize_frameworks
        from lemma.services.trace_log import TraceLog

        indexer = self._setup_cross_framework_indexer(tmp_path)
        trace_log = TraceLog(log_dir=tmp_path / ".lemma" / "traces")

        harmonize_frameworks(
            indexer=indexer,
            threshold=0.5,
            trace_log=trace_log,
            automation=AutomationConfig(thresholds={"harmonize": 0.99}),
        )

        traces = trace_log.read_all()
        accepted = [
            t for t in traces if t.operation == "harmonize" and t.status.value == "ACCEPTED"
        ]
        assert accepted == []
