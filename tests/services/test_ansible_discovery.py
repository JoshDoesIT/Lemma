"""Tests for Ansible inventory discovery (Refs #24).

Operates on `ansible-inventory --list` JSON output. All tests use ``tmp_path``
to write small fixture JSON files; no Ansible install required.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _write(path: Path, payload: dict | str) -> Path:
    body = payload if isinstance(payload, str) else json.dumps(payload)
    path.write_text(body)
    return path


class TestSingleHost:
    def test_emits_resource_definition_with_group_projection(self, tmp_path: Path):
        from lemma.services.ansible_discovery import discover_resources_from_ansible

        inventory = {
            "_meta": {"hostvars": {"host1": {"ansible_host": "10.0.1.1"}}},
            "all": {"children": ["webservers"]},
            "webservers": {"hosts": ["host1"]},
        }
        path = _write(tmp_path / "inventory.json", inventory)

        result = discover_resources_from_ansible(path)

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "ansible-host1"
        assert rd.type == "ansible.host"
        assert rd.attributes["ansible"]["hostname"] == "host1"
        assert rd.attributes["ansible"]["groups"]["webservers"] is True


class TestHostVars:
    def test_host_vars_surface_and_ansible_host_lifted(self, tmp_path: Path):
        from lemma.services.ansible_discovery import discover_resources_from_ansible

        inventory = {
            "_meta": {
                "hostvars": {
                    "web-1": {
                        "ansible_host": "10.0.1.10",
                        "env": "prod",
                        "owner": "platform",
                    }
                }
            },
            "webservers": {"hosts": ["web-1"]},
        }
        path = _write(tmp_path / "inventory.json", inventory)

        rd = discover_resources_from_ansible(path)[0]
        # ansible_host lifted to the top of the namespace for convenience.
        assert rd.attributes["ansible"]["ansible_host"] == "10.0.1.10"
        # All host_vars preserved verbatim under host_vars.
        assert rd.attributes["ansible"]["host_vars"]["env"] == "prod"
        assert rd.attributes["ansible"]["host_vars"]["owner"] == "platform"


class TestMultipleHosts:
    def test_multiple_hosts_in_distinct_groups(self, tmp_path: Path):
        from lemma.services.ansible_discovery import discover_resources_from_ansible

        inventory = {
            "_meta": {
                "hostvars": {
                    "web-1": {},
                    "db-1": {},
                }
            },
            "webservers": {"hosts": ["web-1"]},
            "databases": {"hosts": ["db-1"]},
        }
        path = _write(tmp_path / "inventory.json", inventory)

        result = discover_resources_from_ansible(path)
        ids = {r.id for r in result}
        assert ids == {"ansible-web-1", "ansible-db-1"}


class TestMultipleGroups:
    def test_host_in_multiple_groups_gets_each_as_boolean(self, tmp_path: Path):
        from lemma.services.ansible_discovery import discover_resources_from_ansible

        inventory = {
            "_meta": {"hostvars": {"app-1": {}}},
            "webservers": {"hosts": ["app-1"]},
            "production": {"hosts": ["app-1"]},
            "monitored": {"hosts": ["app-1"]},
        }
        path = _write(tmp_path / "inventory.json", inventory)

        rd = discover_resources_from_ansible(path)[0]
        groups = rd.attributes["ansible"]["groups"]
        assert groups["webservers"] is True
        assert groups["production"] is True
        assert groups["monitored"] is True


class TestNestedGroups:
    def test_parent_group_membership_resolved_transitively(self, tmp_path: Path):
        from lemma.services.ansible_discovery import discover_resources_from_ansible

        # Hierarchy: production → webservers → host1.
        # Operators expect host1 to be in BOTH webservers AND production.
        inventory = {
            "_meta": {"hostvars": {"host1": {}}},
            "all": {"children": ["production"]},
            "production": {"children": ["webservers"]},
            "webservers": {"hosts": ["host1"]},
        }
        path = _write(tmp_path / "inventory.json", inventory)

        rd = discover_resources_from_ansible(path)[0]
        groups = rd.attributes["ansible"]["groups"]
        assert groups["webservers"] is True
        assert groups["production"] is True


class TestEmptyAndMalformed:
    def test_empty_inventory_returns_empty_list(self, tmp_path: Path):
        from lemma.services.ansible_discovery import discover_resources_from_ansible

        path = _write(tmp_path / "empty.json", {"_meta": {"hostvars": {}}})
        assert discover_resources_from_ansible(path) == []

    def test_missing_file_raises_file_not_found(self, tmp_path: Path):
        from lemma.services.ansible_discovery import discover_resources_from_ansible

        with pytest.raises(FileNotFoundError):
            discover_resources_from_ansible(tmp_path / "does-not-exist.json")

    def test_malformed_json_raises_value_error_naming_file(self, tmp_path: Path):
        from lemma.services.ansible_discovery import discover_resources_from_ansible

        path = _write(tmp_path / "bad.json", "not-json-at-all")

        with pytest.raises(ValueError, match=r"(?i)bad\.json|json"):
            discover_resources_from_ansible(path)
