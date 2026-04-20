"""Tests for framework version differ.

Follows TDD: tests written BEFORE implementation.
"""

from __future__ import annotations

from lemma.services.indexer import ControlIndexer


class TestFrameworkDiffer:
    """Tests for diff_frameworks."""

    def test_diff_identical_frameworks(self, tmp_path):
        """Identical frameworks produce empty diff."""
        from lemma.services.differ import diff_frameworks

        indexer = ControlIndexer(index_dir=tmp_path / "index")
        controls = [
            {"id": "ac-2", "title": "Account Mgmt", "prose": "Manage.", "family": "AC"},
        ]
        indexer.index_controls("fw-v1", controls)
        indexer.index_controls("fw-v2", controls)

        result = diff_frameworks(indexer, "fw-v1", "fw-v2")
        assert len(result.added) == 0
        assert len(result.removed) == 0
        assert len(result.modified) == 0

    def test_diff_added_controls(self, tmp_path):
        """Controls in v2 but not v1 are 'added'."""
        from lemma.services.differ import diff_frameworks

        indexer = ControlIndexer(index_dir=tmp_path / "index")
        indexer.index_controls(
            "fw-v1",
            [{"id": "ac-2", "title": "Account Mgmt", "prose": "Manage.", "family": "AC"}],
        )
        indexer.index_controls(
            "fw-v2",
            [
                {"id": "ac-2", "title": "Account Mgmt", "prose": "Manage.", "family": "AC"},
                {"id": "ac-22", "title": "New Control", "prose": "New.", "family": "AC"},
            ],
        )

        result = diff_frameworks(indexer, "fw-v1", "fw-v2")
        assert "ac-22" in result.added
        assert len(result.removed) == 0

    def test_diff_removed_controls(self, tmp_path):
        """Controls in v1 but not v2 are 'removed'."""
        from lemma.services.differ import diff_frameworks

        indexer = ControlIndexer(index_dir=tmp_path / "index")
        indexer.index_controls(
            "fw-v1",
            [
                {"id": "ac-2", "title": "Account Mgmt", "prose": "Manage.", "family": "AC"},
                {
                    "id": "ac-18",
                    "title": "Remote Access",
                    "prose": "Control remote.",
                    "family": "AC",
                },
            ],
        )
        indexer.index_controls(
            "fw-v2",
            [{"id": "ac-2", "title": "Account Mgmt", "prose": "Manage.", "family": "AC"}],
        )

        result = diff_frameworks(indexer, "fw-v1", "fw-v2")
        assert "ac-18" in result.removed
        assert len(result.added) == 0

    def test_diff_modified_controls(self, tmp_path):
        """Same control ID with different text is 'modified'."""
        from lemma.services.differ import diff_frameworks

        indexer = ControlIndexer(index_dir=tmp_path / "index")
        indexer.index_controls(
            "fw-v1",
            [
                {
                    "id": "ac-2",
                    "title": "Account Management",
                    "prose": "Manage system accounts.",
                    "family": "AC",
                }
            ],
        )
        indexer.index_controls(
            "fw-v2",
            [
                {
                    "id": "ac-2",
                    "title": "Account Management (Enhanced)",
                    "prose": "Manage and monitor all system accounts with enhanced requirements.",
                    "family": "AC",
                }
            ],
        )

        result = diff_frameworks(indexer, "fw-v1", "fw-v2")
        modified_ids = [m["control_id"] for m in result.modified]
        assert "ac-2" in modified_ids
