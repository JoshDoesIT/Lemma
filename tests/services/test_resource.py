"""Tests for the resource-as-code parser service."""

from __future__ import annotations

from pathlib import Path

import pytest


def _valid_yaml(id_: str = "prod-rds") -> str:
    return (
        f"id: {id_}\n"
        "type: aws.rds.instance\n"
        "scopes:\n  - default\n"
        "attributes:\n"
        "  region: us-east-1\n"
        "  engine: postgres\n"
    )


class TestLoadResource:
    def test_loads_valid_yaml_file(self, tmp_path: Path):
        from lemma.services.resource import load_resource

        path = tmp_path / "rds.yaml"
        path.write_text(_valid_yaml())

        r = load_resource(path)

        assert r.id == "prod-rds"
        assert r.type == "aws.rds.instance"
        assert r.scopes == ["default"]
        assert r.attributes["region"] == "us-east-1"

    def test_raises_on_malformed_yaml_with_line_number(self, tmp_path: Path):
        from lemma.services.resource import load_resource

        path = tmp_path / "broken.yaml"
        path.write_text("id: r1\ntype: aws.s3.bucket\nscope: default\nattributes: [unterminated\n")

        with pytest.raises(ValueError) as excinfo:
            load_resource(path)

        message = str(excinfo.value)
        assert "broken.yaml" in message
        assert ":4:" in message or ":5:" in message

    def test_raises_on_schema_violation_naming_the_field(self, tmp_path: Path):
        from lemma.services.resource import load_resource

        path = tmp_path / "typo.yaml"
        path.write_text(
            "id: r1\n"
            "resource_type: aws.s3.bucket\n"  # wrong field name
            "scopes:\n  - default\n"
        )

        with pytest.raises(ValueError) as excinfo:
            load_resource(path)

        assert "typo.yaml" in str(excinfo.value)
        assert "resource_type" in str(excinfo.value)

    def test_loads_multi_scope_yaml(self, tmp_path: Path):
        """Scope Ring Model: a resource declared in multiple scopes parses cleanly."""
        from lemma.services.resource import load_resource

        path = tmp_path / "payments-db.yaml"
        path.write_text(
            "id: payments-db\n"
            "type: aws.rds.instance\n"
            "scopes:\n  - prod-us-east\n  - pci-dss\n"
            "attributes:\n  engine: postgres\n"
        )

        r = load_resource(path)
        assert r.scopes == ["prod-us-east", "pci-dss"]

    def test_rejects_old_singular_scope_key(self, tmp_path: Path):
        """`scope: <name>` was renamed to `scopes: [<name>]`; old shape must error."""
        from lemma.services.resource import load_resource

        path = tmp_path / "old-shape.yaml"
        path.write_text(
            "id: r1\ntype: aws.s3.bucket\nscope: default\n"  # singular — old shape
        )

        with pytest.raises(ValueError) as excinfo:
            load_resource(path)

        msg = str(excinfo.value)
        assert "old-shape.yaml" in msg
        assert "scope" in msg


class TestLoadAllResources:
    def test_returns_empty_when_directory_missing(self, tmp_path: Path):
        from lemma.services.resource import load_all_resources

        assert load_all_resources(tmp_path / "does-not-exist") == []

    def test_loads_every_valid_file_sorted_by_id(self, tmp_path: Path):
        from lemma.services.resource import load_all_resources

        (tmp_path / "z.yaml").write_text(_valid_yaml("zulu-asset"))
        (tmp_path / "a.yaml").write_text(_valid_yaml("alpha-asset"))

        resources = load_all_resources(tmp_path)

        assert [r.id for r in resources] == ["alpha-asset", "zulu-asset"]

    def test_accumulates_errors_across_multiple_bad_files(self, tmp_path: Path):
        from lemma.services.resource import load_all_resources

        (tmp_path / "ok.yaml").write_text(_valid_yaml())
        (tmp_path / "bad1.yaml").write_text("id: r1\nresource_type: foo\nscope: default\n")
        (tmp_path / "bad2.yaml").write_text("id: r2\ntype: foo\nscope: default\nextras: [unterm\n")

        with pytest.raises(ValueError) as excinfo:
            load_all_resources(tmp_path)

        message = str(excinfo.value)
        assert "bad1.yaml" in message
        assert "bad2.yaml" in message
