"""Tests for the scope-as-code parser service."""

from __future__ import annotations

from pathlib import Path

import pytest


def _valid_yaml() -> str:
    return (
        "name: prod-us-east\n"
        "frameworks:\n"
        "  - nist-800-53\n"
        "  - nist-csf-2.0\n"
        'justification: "Customer-facing prod."\n'
        "match_rules:\n"
        "  - source: aws.tags.Environment\n"
        "    operator: equals\n"
        "    value: prod\n"
    )


class TestLoadScope:
    def test_loads_valid_yaml_file(self, tmp_path: Path):
        from lemma.services.scope import load_scope

        path = tmp_path / "default.yaml"
        path.write_text(_valid_yaml())

        scope = load_scope(path)

        assert scope.name == "prod-us-east"
        assert scope.frameworks == ["nist-800-53", "nist-csf-2.0"]
        assert len(scope.match_rules) == 1

    def test_raises_on_malformed_yaml_syntax_with_line_number(self, tmp_path: Path):
        from lemma.services.scope import load_scope

        path = tmp_path / "broken.yaml"
        path.write_text(
            "name: prod\n"
            "frameworks:\n"
            "  - nist-800-53\n"
            "match_rules:\n"
            "  - source: aws.tag\n"
            "    operator: equals\n"
            "    value: [prod\n"  # unterminated flow sequence on line 7
        )

        with pytest.raises(ValueError) as excinfo:
            load_scope(path)

        message = str(excinfo.value)
        assert "broken.yaml" in message
        # Error from an unterminated flow sequence points to line 7 or 8.
        assert ":7:" in message or ":8:" in message

    def test_raises_on_schema_violation_naming_the_field(self, tmp_path: Path):
        from lemma.services.scope import load_scope

        path = tmp_path / "typo.yaml"
        path.write_text(
            "name: prod\n"
            "frameworks:\n"
            "  - nist-800-53\n"
            "match_rule:\n"  # singular — typo
            "  - source: aws.tag\n"
            "    operator: equals\n"
            "    value: prod\n"
        )

        with pytest.raises(ValueError) as excinfo:
            load_scope(path)

        message = str(excinfo.value)
        assert "typo.yaml" in message
        assert "match_rule" in message


class TestLoadAllScopes:
    def test_returns_empty_list_when_directory_has_no_scope_files(self, tmp_path: Path):
        from lemma.services.scope import load_all_scopes

        assert load_all_scopes(tmp_path) == []

    def test_loads_every_valid_file_sorted_by_name(self, tmp_path: Path):
        from lemma.services.scope import load_all_scopes

        first = _valid_yaml().replace("prod-us-east", "alpha-scope")
        second = _valid_yaml().replace("prod-us-east", "zulu-scope")
        (tmp_path / "zulu.yaml").write_text(second)
        (tmp_path / "alpha.yaml").write_text(first)

        scopes = load_all_scopes(tmp_path)

        assert [s.name for s in scopes] == ["alpha-scope", "zulu-scope"]

    def test_accumulates_errors_across_multiple_bad_files(self, tmp_path: Path):
        from lemma.services.scope import load_all_scopes

        (tmp_path / "ok.yaml").write_text(_valid_yaml())
        (tmp_path / "bad1.yaml").write_text(
            "name: broken\nframeworks:\n  - nist-800-53\nmatch_rule:\n  []\n"
        )
        (tmp_path / "bad2.yaml").write_text(
            "name: second\nframeworks:\n  - nist-800-53\n  - [unterminated\n"
        )

        with pytest.raises(ValueError) as excinfo:
            load_all_scopes(tmp_path)

        message = str(excinfo.value)
        assert "bad1.yaml" in message
        assert "bad2.yaml" in message


_VALID_HCL = """\
name = "prod-us-east"
frameworks = ["nist-800-53"]
justification = "Prod."

match_rule {
  source   = "aws.tags.Environment"
  operator = "equals"
  value    = "prod"
}
"""


class TestLoadScopeHcl:
    def test_loads_valid_hcl_file(self, tmp_path: Path):
        from lemma.services.scope import load_scope

        path = tmp_path / "prod.hcl"
        path.write_text(_VALID_HCL)

        scope = load_scope(path)

        assert scope.name == "prod-us-east"
        assert scope.frameworks == ["nist-800-53"]
        assert scope.match_rules[0].source == "aws.tags.Environment"
        assert scope.match_rules[0].value == "prod"

    def test_hcl_with_typo_field_rejected_via_extra_forbid(self, tmp_path: Path):
        """Same Pydantic strictness as YAML — `match_rul` fails loud."""
        from lemma.services.scope import load_scope

        path = tmp_path / "typo.hcl"
        path.write_text(
            'name = "x"\nframeworks = ["nist-800-53"]\n\n'
            'match_rul {\n  source = "x"\n  operator = "equals"\n  value = "y"\n}\n'
        )

        with pytest.raises(ValueError) as excinfo:
            load_scope(path)

        msg = str(excinfo.value)
        assert "typo.hcl" in msg
        assert "match_rul" in msg

    def test_load_all_scopes_picks_up_hcl_alongside_yaml_sorted(self, tmp_path: Path):
        from lemma.services.scope import load_all_scopes

        (tmp_path / "alpha.yaml").write_text(_valid_yaml().replace("prod-us-east", "alpha"))
        (tmp_path / "zulu.hcl").write_text(_VALID_HCL.replace("prod-us-east", "zulu"))

        scopes = load_all_scopes(tmp_path)
        assert [s.name for s in scopes] == ["alpha", "zulu"]
