"""Tests for the framework service.

Follows TDD: tests written BEFORE the implementation.
Validates the orchestration layer between parsers, indexer, and framework registry.
"""

import json

import pytest


class TestFrameworkRegistry:
    """Tests for the bundled framework registry."""

    def test_get_registry_contains_nist_800_53(self):
        """Registry includes the bundled NIST 800-53 catalog."""
        from lemma.services.framework import get_framework_registry

        registry = get_framework_registry()
        assert "nist-800-53" in registry

    def test_get_registry_paths_exist(self):
        """All registered framework paths point to existing files."""
        from lemma.services.framework import get_framework_registry

        registry = get_framework_registry()
        for name, path in registry.items():
            assert path.exists(), f"Framework '{name}' path does not exist: {path}"


class TestFrameworkService:
    """Tests for the high-level framework management service."""

    def test_add_bundled_nist_800_53(self, tmp_path):
        """Adding nist-800-53 parses and indexes the bundled catalog."""
        from lemma.services.framework import add_bundled_framework

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()

        result = add_bundled_framework("nist-800-53", project_dir=tmp_path)

        assert result["name"] == "nist-800-53"
        assert result["control_count"] >= 300
        assert result["indexed"] is True

    def test_add_unknown_framework_errors(self, tmp_path):
        """Adding an unknown bundled framework name raises ValueError."""
        from lemma.services.framework import add_bundled_framework

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()

        with pytest.raises(ValueError, match="Unknown framework"):
            add_bundled_framework("nonexistent-framework", project_dir=tmp_path)

    def test_add_framework_upserts(self, tmp_path):
        """Re-adding a framework upserts without duplicating controls."""
        from lemma.services.framework import add_bundled_framework
        from lemma.services.indexer import ControlIndexer

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()

        result1 = add_bundled_framework("nist-800-53", project_dir=tmp_path)
        result2 = add_bundled_framework("nist-800-53", project_dir=tmp_path)

        assert result1["control_count"] == result2["control_count"]

        # Verify no duplicates in the index
        indexer = ControlIndexer(index_dir=tmp_path / ".lemma" / "index")
        stats = indexer.get_collection_stats("nist-800-53")
        assert stats["count"] == result1["control_count"]

    def test_list_frameworks_empty(self, tmp_path):
        """Listing frameworks returns empty list when nothing indexed."""
        from lemma.services.framework import list_frameworks

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()

        frameworks = list_frameworks(project_dir=tmp_path)
        assert frameworks == []

    def test_list_frameworks_with_indexed(self, tmp_path):
        """Listing frameworks returns metadata for indexed frameworks."""
        from lemma.services.framework import add_bundled_framework, list_frameworks

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()

        add_bundled_framework("nist-800-53", project_dir=tmp_path)
        frameworks = list_frameworks(project_dir=tmp_path)

        assert len(frameworks) >= 1
        fw = frameworks[0]
        assert fw["name"] == "nist-800-53"
        assert fw["control_count"] >= 300

    def test_import_json_framework(self, tmp_path):
        """Importing a JSON file parses it as an OSCAL catalog."""
        from lemma.services.framework import import_framework

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()

        # Create a minimal OSCAL catalog JSON
        catalog = {
            "catalog": {
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "metadata": {
                    "title": "Test Catalog",
                    "last-modified": "2026-01-01T00:00:00Z",
                },
                "groups": [
                    {
                        "id": "ac",
                        "title": "Access Control",
                        "controls": [
                            {
                                "id": "ac-1",
                                "title": "Policy",
                                "parts": [
                                    {
                                        "id": "ac-1_smt",
                                        "name": "statement",
                                        "prose": "Develop access control policy.",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        }

        catalog_file = tmp_path / "test-catalog.json"
        catalog_file.write_text(json.dumps(catalog))

        result = import_framework(catalog_file, project_dir=tmp_path)

        assert result["name"] == "test-catalog"
        assert result["control_count"] == 1
        assert result["indexed"] is True

    def test_import_unsupported_format_errors(self, tmp_path):
        """Importing an unsupported file format raises ValueError."""
        from lemma.services.framework import import_framework

        lemma_dir = tmp_path / ".lemma"
        lemma_dir.mkdir()

        bad_file = tmp_path / "framework.docx"
        bad_file.write_text("not a real docx")

        with pytest.raises(ValueError, match="Unsupported"):
            import_framework(bad_file, project_dir=tmp_path)


class TestHipaaSecurityRuleFramework:
    """The bundled HIPAA Security Rule community framework (Refs #33)."""

    def test_registry_includes_hipaa(self):
        from lemma.services.framework import get_framework_registry

        registry = get_framework_registry()
        assert "hipaa-security-rule" in registry
        assert registry["hipaa-security-rule"].is_file()

    def test_catalog_is_valid_oscal_and_parses(self):
        import json

        from lemma.services.framework import get_framework_registry
        from lemma.services.parsers.oscal import parse_catalog

        path = get_framework_registry()["hipaa-security-rule"]
        catalog = json.loads(path.read_text())["catalog"]
        assert catalog["metadata"]["title"].startswith("HIPAA Security Rule")

        controls = parse_catalog(catalog)
        # Five safeguard families, dozens of standards + implementation specs.
        assert len(controls) > 50
        families = {c["family"] for c in controls}
        assert "Administrative Safeguards" in families
        assert "Physical Safeguards" in families
        assert "Technical Safeguards" in families

    def test_catalog_controls_have_id_title_prose(self):
        import json

        from lemma.services.framework import get_framework_registry
        from lemma.services.parsers.oscal import parse_catalog

        path = get_framework_registry()["hipaa-security-rule"]
        controls = parse_catalog(json.loads(path.read_text())["catalog"])
        for c in controls:
            assert c["id"]
            assert c["title"]
            assert c["prose"]

    def test_catalog_includes_known_technical_safeguard(self):
        import json

        from lemma.services.framework import get_framework_registry
        from lemma.services.parsers.oscal import parse_catalog

        path = get_framework_registry()["hipaa-security-rule"]
        controls = parse_catalog(json.loads(path.read_text())["catalog"])
        by_id = {c["id"]: c for c in controls}
        # §164.312(a)(1) Access Control, with its Encryption/Decryption spec.
        assert "164.312(a)(1)" in by_id
        assert by_id["164.312(a)(1)"]["title"] == "Access Control"
        assert "164.312(a)(2)(iv)" in by_id  # Encryption and Decryption (Addressable)
