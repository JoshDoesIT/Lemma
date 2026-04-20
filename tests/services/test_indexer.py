"""Tests for the ChromaDB vector indexer service.

Follows TDD: tests written BEFORE the implementation.
Validates control indexing, retrieval stats, and upsert behavior.
"""


class TestIndexer:
    """Tests for the ChromaDB vector indexer."""

    def test_index_controls(self, tmp_path):
        """Indexer stores controls in a ChromaDB collection."""
        from lemma.services.indexer import ControlIndexer

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        controls = [
            {
                "id": "ac-1",
                "title": "Policy",
                "prose": "Develop access control policy.",
                "family": "AC",
            },
            {
                "id": "ac-2",
                "title": "Account Mgmt",
                "prose": "Manage accounts.",
                "family": "AC",
            },
        ]
        indexer.index_controls("nist-800-53", controls)

        stats = indexer.get_collection_stats("nist-800-53")
        assert stats["count"] == 2

    def test_collection_stats_empty(self, tmp_path):
        """Stats return zero count for non-existent collection."""
        from lemma.services.indexer import ControlIndexer

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        stats = indexer.get_collection_stats("nonexistent")
        assert stats["count"] == 0

    def test_upsert_controls(self, tmp_path):
        """Re-indexing the same framework upserts without duplicating."""
        from lemma.services.indexer import ControlIndexer

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        controls = [
            {
                "id": "ac-1",
                "title": "Policy",
                "prose": "Develop access control policy.",
                "family": "AC",
            },
        ]

        # Index twice
        indexer.index_controls("nist-800-53", controls)
        indexer.index_controls("nist-800-53", controls)

        stats = indexer.get_collection_stats("nist-800-53")
        assert stats["count"] == 1  # No duplicates

    def test_index_creates_directory(self, tmp_path):
        """Indexer creates the index directory if it doesn't exist."""
        from lemma.services.indexer import ControlIndexer

        index_dir = tmp_path / "deep" / "nested" / "index"
        assert not index_dir.exists()

        indexer = ControlIndexer(index_dir=index_dir)
        controls = [
            {"id": "ac-1", "title": "Policy", "prose": "Test.", "family": "AC"},
        ]
        indexer.index_controls("test-fw", controls)

        assert index_dir.exists()

    def test_list_indexed_frameworks(self, tmp_path):
        """Indexer can list all frameworks that have been indexed."""
        from lemma.services.indexer import ControlIndexer

        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        controls = [
            {"id": "ac-1", "title": "Policy", "prose": "Test.", "family": "AC"},
        ]
        indexer.index_controls("fw-alpha", controls)
        indexer.index_controls("fw-beta", controls)

        frameworks = indexer.list_indexed_frameworks()
        assert "fw-alpha" in frameworks
        assert "fw-beta" in frameworks
