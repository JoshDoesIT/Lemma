"""Tests for the OSCAL catalog parser service.

Follows TDD: tests written BEFORE the implementation.
Validates extraction of controls and prose from OSCAL catalog structures.
"""

import json
from pathlib import Path


class TestOscalParser:
    """Tests for parsing OSCAL catalogs into indexable control records."""

    def test_parse_catalog_extracts_controls(self):
        """Parser extracts all top-level controls from a catalog's groups."""
        from lemma.services.parsers.oscal import parse_catalog

        catalog_path = (
            Path(__file__).parent.parent.parent.parent
            / "src"
            / "lemma"
            / "data"
            / "frameworks"
            / "nist-800-53-rev5.json"
        )
        raw = json.loads(catalog_path.read_text())
        controls = parse_catalog(raw["catalog"])

        # NIST 800-53 has 324+ top-level controls across 20 families
        assert len(controls) >= 300
        assert all("id" in c for c in controls)
        assert all("title" in c for c in controls)

    def test_parse_catalog_extracts_prose(self):
        """Parser extracts prose text from control parts for embedding."""
        from lemma.services.parsers.oscal import parse_catalog

        catalog_path = (
            Path(__file__).parent.parent.parent.parent
            / "src"
            / "lemma"
            / "data"
            / "frameworks"
            / "nist-800-53-rev5.json"
        )
        raw = json.loads(catalog_path.read_text())
        controls = parse_catalog(raw["catalog"])

        # At least some controls should have prose content
        controls_with_prose = [c for c in controls if c.get("prose")]
        assert len(controls_with_prose) > 100

    def test_parse_catalog_handles_enhancements(self):
        """Parser flattens nested control enhancements (e.g., AC-2(1))."""
        from lemma.services.parsers.oscal import parse_catalog

        catalog_path = (
            Path(__file__).parent.parent.parent.parent
            / "src"
            / "lemma"
            / "data"
            / "frameworks"
            / "nist-800-53-rev5.json"
        )
        raw = json.loads(catalog_path.read_text())
        controls = parse_catalog(raw["catalog"])

        # Check that enhancements are flattened into the list
        # NIST 800-53 OSCAL uses dot notation (e.g., ac-2.1) for enhancements
        enhancement_ids = [c["id"] for c in controls if "." in c["id"]]
        assert len(enhancement_ids) > 50  # 800-53 has many enhancements

    def test_parse_catalog_includes_family_context(self):
        """Each control record includes its parent group/family title."""
        from lemma.services.parsers.oscal import parse_catalog

        catalog_path = (
            Path(__file__).parent.parent.parent.parent
            / "src"
            / "lemma"
            / "data"
            / "frameworks"
            / "nist-800-53-rev5.json"
        )
        raw = json.loads(catalog_path.read_text())
        controls = parse_catalog(raw["catalog"])

        ac_controls = [c for c in controls if c["id"].startswith("ac-")]
        assert len(ac_controls) > 0
        assert all(c.get("family") == "Access Control" for c in ac_controls)

    def test_parse_minimal_catalog(self):
        """Parser works with a minimal catalog structure."""
        from lemma.services.parsers.oscal import parse_catalog

        minimal = {
            "uuid": "12345678-1234-1234-1234-123456789abc",
            "metadata": {"title": "Test", "last-modified": "2026-01-01T00:00:00Z"},
            "groups": [
                {
                    "id": "ac",
                    "title": "Access Control",
                    "controls": [
                        {
                            "id": "ac-1",
                            "title": "Policy and Procedures",
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
        controls = parse_catalog(minimal)
        assert len(controls) == 1
        assert controls[0]["id"] == "ac-1"
        assert controls[0]["title"] == "Policy and Procedures"
        assert "access control policy" in controls[0]["prose"].lower()
        assert controls[0]["family"] == "Access Control"
