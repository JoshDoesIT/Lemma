"""Tests for GCP discovery via Cloud Asset Inventory (Refs #24).

All Cloud Asset API calls are mocked via injected MagicMock clients. No real
GCP API traffic in CI.

Asset.resource.data is a real protobuf Struct so test fixtures exercise the
same MessageToDict path the production code runs.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from google.protobuf import struct_pb2
from google.protobuf.json_format import ParseDict


def _struct(data: dict) -> struct_pb2.Struct:
    s = struct_pb2.Struct()
    ParseDict(data, s)
    return s


def _asset(*, name: str, asset_type: str, data: dict) -> Any:
    a = MagicMock()
    a.name = name
    a.asset_type = asset_type
    a.resource = MagicMock()
    a.resource.data = _struct(data)
    return a


def _instance(
    *,
    project: str = "my-proj",
    zone: str = "us-central1-a",
    name: str = "my-vm",
    labels: dict | None = None,
    machine_type: str = "n1-standard-1",
    status: str = "RUNNING",
) -> Any:
    return _asset(
        name=f"//compute.googleapis.com/projects/{project}/zones/{zone}/instances/{name}",
        asset_type="compute.googleapis.com/Instance",
        data={
            "name": name,
            "zone": f"projects/{project}/zones/{zone}",
            "machine_type": machine_type,
            "status": status,
            "labels": labels if labels is not None else {},
        },
    )


def _bucket(
    *, project: str = "my-proj", name: str, location: str = "US", storage_class: str = "STANDARD"
) -> Any:
    return _asset(
        name=f"//storage.googleapis.com/projects/_/buckets/{name}",
        asset_type="storage.googleapis.com/Bucket",
        data={
            "name": name,
            "location": location,
            "storage_class": storage_class,
            "labels": {},
        },
    )


def _service_account(
    *, project: str = "my-proj", email: str | None = None, name: str = "sa-name"
) -> Any:
    actual_email = email or f"{name}@{project}.iam.gserviceaccount.com"
    return _asset(
        name=f"//iam.googleapis.com/projects/{project}/serviceAccounts/{actual_email}",
        asset_type="iam.googleapis.com/ServiceAccount",
        data={
            "name": f"projects/{project}/serviceAccounts/{actual_email}",
            "email": actual_email,
            "display_name": name,
        },
    )


def _fake_gcp_client(
    *,
    instances: list[Any] | None = None,
    buckets: list[Any] | None = None,
    service_accounts: list[Any] | None = None,
    list_raises: dict[str, Exception] | None = None,
) -> MagicMock:
    """Build a MagicMock CAI client that routes by asset_types in the request."""
    client = MagicMock()

    def _list_assets(request: Any = None, **_kwargs):
        types = list(request.asset_types) if request is not None else []
        # If a per-type exception is configured, raise it for that request.
        for t in types:
            if list_raises and t in list_raises:
                raise list_raises[t]
        out: list[Any] = []
        for t in types:
            if t == "compute.googleapis.com/Instance":
                out.extend(instances or [])
            elif t == "storage.googleapis.com/Bucket":
                out.extend(buckets or [])
            elif t == "iam.googleapis.com/ServiceAccount":
                out.extend(service_accounts or [])
        return iter(out)

    client.list_assets.side_effect = _list_assets
    return client


class TestDiscoverComputeInstance:
    def test_emits_resource_definition_with_project_in_id_and_labels(self):
        from lemma.services.gcp_discovery import discover_resources_from_gcp

        client = _fake_gcp_client(
            instances=[
                _instance(
                    project="my-proj",
                    name="web",
                    labels={"environment": "prod", "team": "platform"},
                )
            ]
        )

        result = discover_resources_from_gcp(
            asset_client=client,
            project="my-proj",
            asset_types=["compute.googleapis.com/Instance"],
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "gcp-my-proj-instance-web"
        assert rd.type == "gcp.compute.instance"
        assert rd.attributes["gcp"]["project"] == "my-proj"
        assert rd.attributes["gcp"]["kind"] == "Instance"
        assert rd.attributes["gcp"]["labels"] == {
            "environment": "prod",
            "team": "platform",
        }
        assert rd.attributes["gcp"]["machine_type"] == "n1-standard-1"
        assert rd.attributes["gcp"]["status"] == "RUNNING"


class TestDiscoverBucket:
    def test_bucket_listing_surfaces_storage_class(self):
        from lemma.services.gcp_discovery import discover_resources_from_gcp

        client = _fake_gcp_client(buckets=[_bucket(name="audit-logs", storage_class="NEARLINE")])

        result = discover_resources_from_gcp(
            asset_client=client,
            project="my-proj",
            asset_types=["storage.googleapis.com/Bucket"],
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "gcp-my-proj-bucket-audit-logs"
        assert rd.type == "gcp.storage.bucket"
        assert rd.attributes["gcp"]["storage_class"] == "NEARLINE"


class TestDiscoverServiceAccount:
    def test_service_account_surfaces_email(self):
        from lemma.services.gcp_discovery import discover_resources_from_gcp

        client = _fake_gcp_client(
            service_accounts=[_service_account(project="my-proj", name="ci-bot")]
        )

        result = discover_resources_from_gcp(
            asset_client=client,
            project="my-proj",
            asset_types=["iam.googleapis.com/ServiceAccount"],
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "gcp-my-proj-sa-ci-bot"
        assert rd.type == "gcp.iam.service_account"
        assert rd.attributes["gcp"]["email"] == "ci-bot@my-proj.iam.gserviceaccount.com"


class TestMultiZone:
    def test_multi_zone_compute_instances_get_distinct_ids(self):
        from lemma.services.gcp_discovery import discover_resources_from_gcp

        client = _fake_gcp_client(
            instances=[
                _instance(name="web", zone="us-central1-a"),
                _instance(name="web2", zone="us-east1-b"),
            ]
        )

        result = discover_resources_from_gcp(
            asset_client=client,
            project="my-proj",
            asset_types=["compute.googleapis.com/Instance"],
        )

        ids = {rd.id for rd in result}
        assert ids == {"gcp-my-proj-instance-web", "gcp-my-proj-instance-web2"}


class TestEdgeCases:
    def test_empty_labels_map_returns_empty_dict_attribute(self):
        from lemma.services.gcp_discovery import discover_resources_from_gcp

        client = _fake_gcp_client(instances=[_instance(name="nolabels", labels={})])

        result = discover_resources_from_gcp(
            asset_client=client,
            project="my-proj",
            asset_types=["compute.googleapis.com/Instance"],
        )

        assert result[0].attributes["gcp"]["labels"] == {}

    def test_asset_name_strip_removes_host_prefix(self):
        """The basename in the ID must be the asset name without //<host>/projects/.../."""
        from lemma.services.gcp_discovery import discover_resources_from_gcp

        client = _fake_gcp_client(instances=[_instance(name="my-special-vm")])

        result = discover_resources_from_gcp(
            asset_client=client,
            project="my-proj",
            asset_types=["compute.googleapis.com/Instance"],
        )

        # ID must use the basename only — not the full //compute.googleapis.com/... path.
        assert result[0].id == "gcp-my-proj-instance-my-special-vm"
        assert "//" not in result[0].id
        assert "compute.googleapis.com" not in result[0].id

    def test_service_account_with_email_project_differing_from_discovery_project(self):
        """Google-managed SAs have a different project in their email than --project.

        The Lemma ID must use --project (the discovery scope), not the project
        embedded in the SA email — otherwise IDs collide across discoveries.
        """
        from lemma.services.gcp_discovery import discover_resources_from_gcp

        client = _fake_gcp_client(
            service_accounts=[
                _service_account(
                    project="my-proj",
                    name="service-12345",
                    email="service-12345@compute-system.iam.gserviceaccount.com",
                )
            ]
        )

        result = discover_resources_from_gcp(
            asset_client=client,
            project="my-proj",
            asset_types=["iam.googleapis.com/ServiceAccount"],
        )

        assert result[0].id == "gcp-my-proj-sa-service-12345"
        # Email project differs but the ID uses --project.
        assert "compute-system" not in result[0].id
        # The full email is preserved in attributes.
        assert (
            result[0].attributes["gcp"]["email"]
            == "service-12345@compute-system.iam.gserviceaccount.com"
        )


class TestErrorHandling:
    def test_unknown_asset_type_raises_value_error(self):
        from lemma.services.gcp_discovery import discover_resources_from_gcp

        with pytest.raises(ValueError, match=r"(?i)unknown.*asset|cloudfunctions"):
            discover_resources_from_gcp(
                asset_client=_fake_gcp_client(),
                project="my-proj",
                asset_types=["cloudfunctions.googleapis.com/Function"],
            )

    def test_empty_asset_types_raises_value_error(self):
        from lemma.services.gcp_discovery import discover_resources_from_gcp

        with pytest.raises(ValueError, match=r"(?i)at least one|empty"):
            discover_resources_from_gcp(
                asset_client=_fake_gcp_client(),
                project="my-proj",
                asset_types=[],
            )

    def test_google_api_error_on_one_asset_type_continues_others(self):
        from google.api_core.exceptions import PermissionDenied

        from lemma.services.gcp_discovery import discover_resources_from_gcp

        client = _fake_gcp_client(
            buckets=[_bucket(name="ok-bucket")],
            service_accounts=[_service_account(name="ci")],
            list_raises={
                "compute.googleapis.com/Instance": PermissionDenied("compute API not enabled"),
            },
        )

        result = discover_resources_from_gcp(
            asset_client=client,
            project="my-proj",
            asset_types=[
                "compute.googleapis.com/Instance",
                "storage.googleapis.com/Bucket",
                "iam.googleapis.com/ServiceAccount",
            ],
        )

        types = {rd.type for rd in result}
        assert "gcp.compute.instance" not in types
        assert "gcp.storage.bucket" in types
        assert "gcp.iam.service_account" in types
