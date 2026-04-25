"""Tests for the Risk-as-code parser service."""

from __future__ import annotations

from pathlib import Path

import pytest


def _valid_yaml(id_: str = "audit-log-loss") -> str:
    return (
        f"id: {id_}\n"
        "title: Loss of audit logs\n"
        "description: Audit bucket compromised or accidentally deleted.\n"
        "severity: high\n"
        "threatens:\n"
        "  - resource:prod-rds\n"
        "mitigated_by:\n"
        "  - control:nist-800-53:au-2\n"
    )


class TestLoadRisk:
    def test_loads_valid_yaml_file(self, tmp_path: Path):
        from lemma.services.risk import load_risk

        path = tmp_path / "r.yaml"
        path.write_text(_valid_yaml())

        r = load_risk(path)

        assert r.id == "audit-log-loss"
        assert r.severity.value == "high"
        assert r.threatens == ["resource:prod-rds"]

    def test_raises_on_malformed_yaml_with_line_number(self, tmp_path: Path):
        from lemma.services.risk import load_risk

        path = tmp_path / "broken.yaml"
        path.write_text("id: r1\ntitle: t\nseverity: high\nthreatens: [unterminated\n")

        with pytest.raises(ValueError) as excinfo:
            load_risk(path)

        message = str(excinfo.value)
        assert "broken.yaml" in message
        assert ":4:" in message or ":5:" in message

    def test_raises_on_schema_violation_naming_the_field(self, tmp_path: Path):
        from lemma.services.risk import load_risk

        path = tmp_path / "typo.yaml"
        path.write_text("id: r1\ntitle: t\nseverity: high\nseverities: [extra]\n")

        with pytest.raises(ValueError) as excinfo:
            load_risk(path)

        assert "typo.yaml" in str(excinfo.value)
        assert "severities" in str(excinfo.value)


class TestLoadAllRisks:
    def test_returns_empty_when_directory_missing(self, tmp_path: Path):
        from lemma.services.risk import load_all_risks

        assert load_all_risks(tmp_path / "nope") == []

    def test_loads_every_valid_file_sorted_by_id(self, tmp_path: Path):
        from lemma.services.risk import load_all_risks

        (tmp_path / "z.yaml").write_text(_valid_yaml("zulu-risk"))
        (tmp_path / "a.yaml").write_text(_valid_yaml("alpha-risk"))

        risks = load_all_risks(tmp_path)

        assert [r.id for r in risks] == ["alpha-risk", "zulu-risk"]

    def test_accumulates_errors_across_multiple_bad_files(self, tmp_path: Path):
        from lemma.services.risk import load_all_risks

        (tmp_path / "ok.yaml").write_text(_valid_yaml())
        (tmp_path / "bad1.yaml").write_text("id: r1\ntitle: t\nseverity: high\nseverities: [x]\n")
        (tmp_path / "bad2.yaml").write_text("id: r2\ntitle: t\nseverity: high\nthreatens: [unt\n")

        with pytest.raises(ValueError) as excinfo:
            load_all_risks(tmp_path)

        message = str(excinfo.value)
        assert "bad1.yaml" in message
        assert "bad2.yaml" in message
