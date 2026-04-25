"""Tests for Terraform state-file discovery (Refs #24)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


def _state_json(resources: list[dict]) -> dict:
    """Minimal Terraform state v4 shape."""
    return {
        "version": 4,
        "terraform_version": "1.7.0",
        "serial": 1,
        "lineage": "abcd-1234",
        "outputs": {},
        "resources": resources,
    }


def _resource(
    *,
    tf_type: str,
    name: str,
    attributes: dict[str, Any],
    mode: str = "managed",
    instances: list[dict] | None = None,
    sensitive_attributes: list | None = None,
    sensitive_values: dict | None = None,
    index_key: Any = None,
) -> dict:
    """Build a single state-file resource entry."""
    if instances is None:
        instance: dict[str, Any] = {
            "schema_version": 0,
            "attributes": attributes,
        }
        if sensitive_attributes is not None:
            instance["sensitive_attributes"] = sensitive_attributes
        if sensitive_values is not None:
            instance["sensitive_values"] = sensitive_values
        if index_key is not None:
            instance["index_key"] = index_key
        instances = [instance]
    return {
        "mode": mode,
        "type": tf_type,
        "name": name,
        "provider": f'provider["registry.terraform.io/hashicorp/{tf_type.split("_")[0]}"]',
        "instances": instances,
    }


def _write_state(path: Path, payload: dict) -> Path:
    state_file = path / "terraform.tfstate"
    state_file.write_text(json.dumps(payload))
    return state_file


class TestHappyPath:
    def test_aws_instance_emits_normalized_type_and_aws_wrapping(self, tmp_path: Path):
        from lemma.services.terraform_state import discover_resources_from_state

        state = _state_json(
            [
                _resource(
                    tf_type="aws_instance",
                    name="web",
                    attributes={
                        "id": "i-0abc123",
                        "instance_type": "t3.medium",
                        "region": "us-east-1",
                        "tags": {"Environment": "prod", "Owner": "alice"},
                    },
                )
            ]
        )
        path = _write_state(tmp_path, state)

        result = discover_resources_from_state(path)

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "tf-aws_instance.web"
        assert rd.type == "aws.ec2.instance"
        assert rd.attributes["aws"]["region"] == "us-east-1"
        assert rd.attributes["aws"]["service"] == "ec2"
        assert rd.attributes["aws"]["tags"] == {
            "Environment": "prod",
            "Owner": "alice",
        }
        # The original tf attributes spread through.
        assert rd.attributes["aws"]["instance_type"] == "t3.medium"

    def test_multi_provider_state_wraps_aws_under_aws_others_under_tf(self, tmp_path: Path):
        from lemma.services.terraform_state import discover_resources_from_state

        state = _state_json(
            [
                _resource(
                    tf_type="aws_instance",
                    name="web",
                    attributes={"id": "i-1", "tags": {"Environment": "prod"}},
                ),
                _resource(
                    tf_type="google_compute_instance",
                    name="vm",
                    attributes={"name": "vm-1", "zone": "us-central1-a"},
                ),
                _resource(
                    tf_type="azurerm_virtual_machine",
                    name="vm2",
                    attributes={"name": "vm-2", "location": "eastus"},
                ),
            ]
        )
        path = _write_state(tmp_path, state)

        result = discover_resources_from_state(path)
        by_type = {rd.type: rd for rd in result}
        assert by_type["aws.ec2.instance"].attributes["aws"]["tags"] == {"Environment": "prod"}
        # Unmapped types live under tf.*
        assert "tf" in by_type["google_compute_instance"].attributes
        assert by_type["google_compute_instance"].attributes["tf"]["zone"] == "us-central1-a"
        assert "tf" in by_type["azurerm_virtual_machine"].attributes


class TestModeAndEmpty:
    def test_mode_data_is_skipped(self, tmp_path: Path):
        from lemma.services.terraform_state import discover_resources_from_state

        state = _state_json(
            [
                _resource(
                    tf_type="aws_ami",
                    name="ubuntu",
                    attributes={"id": "ami-12345"},
                    mode="data",
                ),
                _resource(
                    tf_type="aws_instance",
                    name="web",
                    attributes={"id": "i-1"},
                ),
            ]
        )
        path = _write_state(tmp_path, state)

        result = discover_resources_from_state(path)
        ids = {rd.id for rd in result}
        assert "tf-aws_ami.ubuntu" not in ids
        assert "tf-aws_instance.web" in ids

    def test_empty_resources_returns_empty_list(self, tmp_path: Path):
        from lemma.services.terraform_state import discover_resources_from_state

        path = _write_state(tmp_path, _state_json([]))
        assert discover_resources_from_state(path) == []

    def test_resource_with_zero_instances_is_skipped(self, tmp_path: Path):
        from lemma.services.terraform_state import discover_resources_from_state

        state = _state_json(
            [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "ghost",
                    "provider": "x",
                    "instances": [],
                }
            ]
        )
        path = _write_state(tmp_path, state)
        assert discover_resources_from_state(path) == []


class TestIndexKeys:
    def test_count_indexed_instances_get_int_suffix(self, tmp_path: Path):
        from lemma.services.terraform_state import discover_resources_from_state

        state = _state_json(
            [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "web",
                    "provider": "x",
                    "instances": [
                        {"index_key": 0, "attributes": {"id": "i-0"}},
                        {"index_key": 1, "attributes": {"id": "i-1"}},
                    ],
                }
            ]
        )
        path = _write_state(tmp_path, state)

        ids = {rd.id for rd in discover_resources_from_state(path)}
        assert ids == {"tf-aws_instance.web[0]", "tf-aws_instance.web[1]"}

    def test_for_each_indexed_instances_get_string_suffix(self, tmp_path: Path):
        from lemma.services.terraform_state import discover_resources_from_state

        state = _state_json(
            [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "web",
                    "provider": "x",
                    "instances": [
                        {"index_key": "us-east-1a", "attributes": {"id": "i-a"}},
                        {"index_key": "us-east-1b", "attributes": {"id": "i-b"}},
                    ],
                }
            ]
        )
        path = _write_state(tmp_path, state)

        ids = {rd.id for rd in discover_resources_from_state(path)}
        assert ids == {
            "tf-aws_instance.web[us-east-1a]",
            "tf-aws_instance.web[us-east-1b]",
        }


class TestSensitiveRedaction:
    def test_top_level_string_sensitive_attribute_is_redacted(self, tmp_path: Path):
        from lemma.services.terraform_state import discover_resources_from_state

        state = _state_json(
            [
                _resource(
                    tf_type="aws_db_instance",
                    name="prod",
                    attributes={
                        "engine": "postgres",
                        "password": "supersecret",
                        "tags": {"Environment": "prod"},
                    },
                    sensitive_attributes=["password"],
                )
            ]
        )
        path = _write_state(tmp_path, state)

        rd = discover_resources_from_state(path)[0]
        assert rd.attributes["tf"]["password"] == "<redacted>"
        # Other attributes preserved.
        assert rd.attributes["tf"]["engine"] == "postgres"
        assert rd.attributes["tf"]["tags"] == {"Environment": "prod"}

    def test_step_list_sensitive_path_redacts_nested_node(self, tmp_path: Path):
        from lemma.services.terraform_state import discover_resources_from_state

        state = _state_json(
            [
                _resource(
                    tf_type="aws_secretsmanager_secret_version",
                    name="creds",
                    attributes={
                        "secret_string": "outer",
                        "config": {"api_key": "secret-value", "endpoint": "ok"},
                    },
                    sensitive_attributes=[
                        [
                            {"type": "get_attr", "value": "config"},
                            {"type": "get_attr", "value": "api_key"},
                        ]
                    ],
                )
            ]
        )
        path = _write_state(tmp_path, state)

        rd = discover_resources_from_state(path)[0]
        assert rd.attributes["tf"]["config"]["api_key"] == "<redacted>"
        assert rd.attributes["tf"]["config"]["endpoint"] == "ok"
        assert rd.attributes["tf"]["secret_string"] == "outer"

    def test_sensitive_values_mirror_dict_redacts_matching_nodes(self, tmp_path: Path):
        from lemma.services.terraform_state import discover_resources_from_state

        state = _state_json(
            [
                _resource(
                    tf_type="aws_db_instance",
                    name="prod",
                    attributes={
                        "engine": "postgres",
                        "password": "supersecret",
                        "config": {"token": "abc", "endpoint": "ok"},
                    },
                    sensitive_values={
                        "password": True,
                        "config": {"token": True},
                    },
                )
            ]
        )
        path = _write_state(tmp_path, state)

        rd = discover_resources_from_state(path)[0]
        assert rd.attributes["tf"]["password"] == "<redacted>"
        assert rd.attributes["tf"]["config"]["token"] == "<redacted>"
        assert rd.attributes["tf"]["config"]["endpoint"] == "ok"

    def test_sensitive_path_pointing_at_missing_attr_is_silent(self, tmp_path: Path):
        from lemma.services.terraform_state import discover_resources_from_state

        # password is named in sensitive_attributes but not in attributes.
        state = _state_json(
            [
                _resource(
                    tf_type="aws_db_instance",
                    name="prod",
                    attributes={"engine": "postgres"},
                    sensitive_attributes=["password"],
                )
            ]
        )
        path = _write_state(tmp_path, state)

        rd = discover_resources_from_state(path)[0]
        assert rd.attributes["tf"]["engine"] == "postgres"
        assert "password" not in rd.attributes["tf"]


class TestMalformed:
    def test_missing_terraform_version_raises_with_plan_hint(self, tmp_path: Path):
        from lemma.services.terraform_state import discover_resources_from_state

        # Plan-shaped JSON, not state-shaped. Has resource_changes, no terraform_version.
        path = tmp_path / "not-state.json"
        path.write_text(json.dumps({"format_version": "1.2", "resource_changes": []}))

        with pytest.raises(ValueError, match=r"(?i)terraform_version|state file|--plan"):
            discover_resources_from_state(path)
