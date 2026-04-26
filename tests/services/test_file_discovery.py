"""Tests for manual CSV / JSON / JSONL bulk-import discovery (Refs #24).

Air-gapped on-prem source: pure file parsing, no network, no SDK auth.
All tests use ``tmp_path`` to write small fixture files.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _write(path: Path, body: str) -> Path:
    path.write_text(body)
    return path


class TestJSON:
    def test_happy_path_emits_resource_definition_with_nested_attributes(self, tmp_path: Path):
        from lemma.services.file_discovery import discover_resources_from_file

        body = json.dumps(
            [
                {
                    "id": "vm-prod-1",
                    "type": "vmware.vm",
                    "attributes": {
                        "vsphere": {
                            "host": "esxi-1",
                            "datacenter": "dc-east",
                            "tags": {"environment": "prod"},
                        }
                    },
                }
            ]
        )
        path = _write(tmp_path / "inventory.json", body)

        result = discover_resources_from_file(path)

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "vm-prod-1"
        assert rd.type == "vmware.vm"
        # Verbatim — no auto-wrapping.
        assert rd.attributes["vsphere"]["host"] == "esxi-1"
        assert rd.attributes["vsphere"]["tags"]["environment"] == "prod"


class TestJSONL:
    def test_three_records_on_three_lines(self, tmp_path: Path):
        from lemma.services.file_discovery import discover_resources_from_file

        body = "\n".join(
            json.dumps({"id": f"vm-{i}", "type": "vmware.vm", "attributes": {}}) for i in range(3)
        )
        path = _write(tmp_path / "inventory.jsonl", body)

        result = discover_resources_from_file(path)

        ids = {r.id for r in result}
        assert ids == {"vm-0", "vm-1", "vm-2"}


class TestCSV:
    def test_dotted_path_columns_expand_to_nested_attributes(self, tmp_path: Path):
        from lemma.services.file_discovery import discover_resources_from_file

        body = (
            "id,type,vsphere.host,vsphere.tags.environment\n"
            "vm-prod-1,vmware.vm,esxi-1,prod\n"
            "vm-staging-1,vmware.vm,esxi-2,staging\n"
        )
        path = _write(tmp_path / "inventory.csv", body)

        result = discover_resources_from_file(path)

        assert len(result) == 2
        by_id = {r.id: r for r in result}
        assert by_id["vm-prod-1"].type == "vmware.vm"
        assert by_id["vm-prod-1"].attributes["vsphere"]["host"] == "esxi-1"
        assert by_id["vm-prod-1"].attributes["vsphere"]["tags"]["environment"] == "prod"
        assert by_id["vm-staging-1"].attributes["vsphere"]["tags"]["environment"] == "staging"


class TestErrors:
    def test_missing_file_raises_file_not_found(self, tmp_path: Path):
        from lemma.services.file_discovery import discover_resources_from_file

        with pytest.raises(FileNotFoundError):
            discover_resources_from_file(tmp_path / "does-not-exist.json")

    def test_unknown_extension_raises_value_error(self, tmp_path: Path):
        from lemma.services.file_discovery import discover_resources_from_file

        path = _write(tmp_path / "inventory.txt", "id,type\nvm-1,vmware.vm\n")

        with pytest.raises(ValueError, match=r"(?i)\.txt|extension"):
            discover_resources_from_file(path)

    def test_duplicate_ids_raise_with_every_offender_named(self, tmp_path: Path):
        from lemma.services.file_discovery import discover_resources_from_file

        body = json.dumps(
            [
                {"id": "vm-1", "type": "vmware.vm"},
                {"id": "vm-1", "type": "vmware.vm"},
                {"id": "vm-2", "type": "vmware.vm"},
                {"id": "vm-2", "type": "vmware.vm"},
            ]
        )
        path = _write(tmp_path / "inventory.json", body)

        with pytest.raises(ValueError, match=r"(?i)duplicate") as exc_info:
            discover_resources_from_file(path)

        msg = str(exc_info.value)
        assert "vm-1" in msg
        assert "vm-2" in msg

    def test_missing_required_field_names_record_index(self, tmp_path: Path):
        from lemma.services.file_discovery import discover_resources_from_file

        # Record index 1 is missing 'type'.
        body = json.dumps(
            [
                {"id": "vm-1", "type": "vmware.vm"},
                {"id": "vm-2"},
            ]
        )
        path = _write(tmp_path / "inventory.json", body)

        with pytest.raises(ValueError, match=r"(?i)type|missing|record") as exc_info:
            discover_resources_from_file(path)

        # The error should name the offending record so an operator can find it.
        assert "1" in str(exc_info.value) or "vm-2" in str(exc_info.value)


class TestEmpty:
    def test_empty_json_array_returns_empty_list(self, tmp_path: Path):
        from lemma.services.file_discovery import discover_resources_from_file

        path = _write(tmp_path / "empty.json", "[]")
        assert discover_resources_from_file(path) == []

    def test_empty_jsonl_returns_empty_list(self, tmp_path: Path):
        from lemma.services.file_discovery import discover_resources_from_file

        path = _write(tmp_path / "empty.jsonl", "")
        assert discover_resources_from_file(path) == []

    def test_csv_header_only_returns_empty_list(self, tmp_path: Path):
        from lemma.services.file_discovery import discover_resources_from_file

        path = _write(tmp_path / "headers-only.csv", "id,type,vsphere.host\n")
        assert discover_resources_from_file(path) == []
