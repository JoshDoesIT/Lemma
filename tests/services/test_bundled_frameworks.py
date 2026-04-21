"""Tests for bundled framework catalog registration and ingestion.

Validates that all registered catalogs exist, parse successfully,
and produce non-trivial control counts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lemma.services.framework import get_framework_registry
from lemma.services.parsers.oscal import parse_catalog


class TestBundledFrameworks:
    """Verify all bundled framework catalogs are valid and registered."""

    def test_registry_contains_expected_frameworks(self):
        """Registry includes all three bundled public domain frameworks."""
        registry = get_framework_registry()
        assert "nist-800-53" in registry
        assert "nist-csf-2.0" in registry
        assert "nist-800-171" in registry

    def test_all_registry_paths_exist(self):
        """Every registered catalog path points to a real file."""
        registry = get_framework_registry()
        for name, path in registry.items():
            assert path.exists(), f"Catalog file missing for '{name}': {path}"

    @pytest.mark.parametrize(
        ("framework_name", "min_controls"),
        [
            ("nist-800-53", 1000),
            ("nist-csf-2.0", 200),
            ("nist-800-171", 100),
        ],
    )
    def test_catalog_parses_with_expected_control_count(
        self, framework_name: str, min_controls: int
    ):
        """Each bundled catalog parses to at least the expected number of controls."""
        registry = get_framework_registry()
        catalog_path = registry[framework_name]

        raw = json.loads(catalog_path.read_text())
        catalog_data = raw.get("catalog", raw)
        controls = parse_catalog(catalog_data)

        assert len(controls) >= min_controls, (
            f"{framework_name} produced {len(controls)} controls, expected >= {min_controls}"
        )

    @pytest.mark.parametrize("framework_name", ["nist-800-53", "nist-csf-2.0", "nist-800-171"])
    def test_catalog_controls_have_required_fields(self, framework_name: str):
        """Each control record has id, title, prose, and family keys."""
        registry = get_framework_registry()
        catalog_path = registry[framework_name]

        raw = json.loads(catalog_path.read_text())
        catalog_data = raw.get("catalog", raw)
        controls = parse_catalog(catalog_data)

        for control in controls[:10]:  # Spot-check first 10
            assert "id" in control, f"Missing 'id' in {framework_name} control"
            assert "title" in control, f"Missing 'title' in {framework_name} control"
            assert "prose" in control, f"Missing 'prose' in {framework_name} control"
            assert "family" in control, f"Missing 'family' in {framework_name} control"

    def test_add_bundled_csf_indexes_successfully(self, tmp_path: Path):
        """lemma framework add nist-csf-2.0 indexes controls."""
        from lemma.services.framework import add_bundled_framework

        (tmp_path / ".lemma").mkdir()
        result = add_bundled_framework("nist-csf-2.0", project_dir=tmp_path)

        assert result["name"] == "nist-csf-2.0"
        assert result["control_count"] >= 200
        assert result["indexed"] is True

    def test_add_bundled_171_indexes_successfully(self, tmp_path: Path):
        """lemma framework add nist-800-171 indexes controls."""
        from lemma.services.framework import add_bundled_framework

        (tmp_path / ".lemma").mkdir()
        result = add_bundled_framework("nist-800-171", project_dir=tmp_path)

        assert result["name"] == "nist-800-171"
        assert result["control_count"] >= 100
        assert result["indexed"] is True
