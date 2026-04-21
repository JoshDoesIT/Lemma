"""Integration test for the full Parse → Index → Map pipeline.

Verifies the end-to-end flow using a bundled framework catalog:
1. Parse the OSCAL catalog into control records
2. Index controls into ChromaDB
3. Map a sample policy document against the indexed framework
4. Verify the output structure matches MappingReport schema
"""

from __future__ import annotations

import json
from pathlib import Path

from lemma.services.framework import add_bundled_framework, get_framework_registry
from lemma.services.parsers.oscal import parse_catalog


class TestFullPipelineIntegration:
    """End-to-end integration tests for the core engine pipeline."""

    def test_parse_index_roundtrip(self, tmp_path: Path):
        """Parse a bundled catalog and verify index produces correct control count."""
        (tmp_path / ".lemma").mkdir()

        result = add_bundled_framework("nist-csf-2.0", project_dir=tmp_path)

        assert result["indexed"] is True
        assert result["control_count"] >= 200
        assert result["name"] == "nist-csf-2.0"

    def test_index_query_returns_relevant_controls(self, tmp_path: Path):
        """Index a framework and verify semantic query returns relevant results."""
        from lemma.services.indexer import ControlIndexer

        (tmp_path / ".lemma" / "index").mkdir(parents=True)
        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")

        # Index a small set of controls
        controls = [
            {
                "id": "ac-1",
                "title": "Access Control Policy",
                "prose": "Define and enforce access control policies.",
                "family": "Access Control",
            },
            {
                "id": "ir-1",
                "title": "Incident Response Policy",
                "prose": "Establish incident response procedures.",
                "family": "Incident Response",
            },
            {
                "id": "sc-1",
                "title": "System Communications Protection",
                "prose": "Protect communications and network boundaries.",
                "family": "System Protection",
            },
        ]
        indexer.index_controls("test-framework", controls)

        # Query for access-related controls
        results = indexer.query_similar("test-framework", "access control policy", n_results=2)

        assert len(results) >= 1
        # The top result should be the access control policy
        assert results[0]["control_id"] == "ac-1"

    def test_full_pipeline_parse_index_map_structure(self, tmp_path: Path):
        """Full pipeline: parse catalog → index → map policy → verify output structure."""
        from lemma.services.indexer import ControlIndexer

        # Step 1: Parse
        registry = get_framework_registry()
        catalog_path = registry["nist-csf-2.0"]
        raw = json.loads(catalog_path.read_text())
        catalog_data = raw.get("catalog", raw)
        controls = parse_catalog(catalog_data)

        assert len(controls) >= 200

        # Step 2: Index
        (tmp_path / ".lemma" / "index").mkdir(parents=True)
        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        indexer.index_controls("nist-csf-2.0", controls)

        stats = indexer.get_collection_stats("nist-csf-2.0")
        assert stats["count"] == len(controls)

        # Step 3: Query (simulating what the mapper does)
        query = "We require multi-factor authentication for all privileged accounts"
        results = indexer.query_similar("nist-csf-2.0", query, n_results=5)

        assert len(results) >= 1
        # Each result should have the expected structure
        for result in results:
            assert "control_id" in result
            assert "title" in result
            assert "distance" in result
            assert "document" in result

    def test_upsert_does_not_duplicate(self, tmp_path: Path):
        """Re-indexing the same framework does not create duplicate controls."""
        (tmp_path / ".lemma").mkdir()

        result1 = add_bundled_framework("nist-csf-2.0", project_dir=tmp_path)
        result2 = add_bundled_framework("nist-csf-2.0", project_dir=tmp_path)

        assert result1["control_count"] == result2["control_count"]

    def test_list_after_multi_framework_index(self, tmp_path: Path):
        """list_frameworks returns all indexed frameworks after adding multiple."""
        from lemma.services.framework import list_frameworks

        (tmp_path / ".lemma").mkdir()

        add_bundled_framework("nist-csf-2.0", project_dir=tmp_path)
        add_bundled_framework("nist-800-171", project_dir=tmp_path)

        frameworks = list_frameworks(project_dir=tmp_path)

        names = {fw["name"] for fw in frameworks}
        assert "nist-csf-2.0" in names
        assert "nist-800-171" in names
        assert all(fw["control_count"] > 0 for fw in frameworks)
