"""Tests for the Person-as-code parser service."""

from __future__ import annotations

from pathlib import Path

import pytest


def _valid_yaml(id_: str = "alice") -> str:
    return (
        f"id: {id_}\n"
        "name: Alice Chen\n"
        "email: alice@example.com\n"
        "role: Security Lead\n"
        "owns:\n"
        "  - control:nist-800-53:ac-2\n"
    )


class TestLoadPerson:
    def test_loads_valid_yaml_file(self, tmp_path: Path):
        from lemma.services.person import load_person

        path = tmp_path / "alice.yaml"
        path.write_text(_valid_yaml())

        p = load_person(path)

        assert p.id == "alice"
        assert p.name == "Alice Chen"
        assert p.owns == ["control:nist-800-53:ac-2"]

    def test_raises_on_malformed_yaml_with_line_number(self, tmp_path: Path):
        from lemma.services.person import load_person

        path = tmp_path / "broken.yaml"
        path.write_text("id: alice\nname: Alice\nowns: [unterminated\n")

        with pytest.raises(ValueError) as excinfo:
            load_person(path)

        message = str(excinfo.value)
        assert "broken.yaml" in message
        assert ":3:" in message or ":4:" in message

    def test_raises_on_schema_violation_naming_the_field(self, tmp_path: Path):
        from lemma.services.person import load_person

        path = tmp_path / "typo.yaml"
        path.write_text("id: bob\nname: Bob\nmanager: carol\n")

        with pytest.raises(ValueError) as excinfo:
            load_person(path)

        assert "typo.yaml" in str(excinfo.value)
        assert "manager" in str(excinfo.value)


class TestLoadAllPeople:
    def test_returns_empty_when_directory_missing(self, tmp_path: Path):
        from lemma.services.person import load_all_people

        assert load_all_people(tmp_path / "does-not-exist") == []

    def test_loads_every_valid_file_sorted_by_id(self, tmp_path: Path):
        from lemma.services.person import load_all_people

        (tmp_path / "z.yaml").write_text(_valid_yaml("zulu"))
        (tmp_path / "a.yaml").write_text(_valid_yaml("alpha"))

        people = load_all_people(tmp_path)

        assert [p.id for p in people] == ["alpha", "zulu"]

    def test_accumulates_errors_across_multiple_bad_files(self, tmp_path: Path):
        from lemma.services.person import load_all_people

        (tmp_path / "ok.yaml").write_text(_valid_yaml())
        (tmp_path / "bad1.yaml").write_text("id: r1\nname: R\nmanager: foo\n")
        (tmp_path / "bad2.yaml").write_text("id: r2\nname: R\nowns: [unterm\n")

        with pytest.raises(ValueError) as excinfo:
            load_all_people(tmp_path)

        message = str(excinfo.value)
        assert "bad1.yaml" in message
        assert "bad2.yaml" in message
