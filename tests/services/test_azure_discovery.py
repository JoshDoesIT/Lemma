"""Tests for Azure discovery via Resource Graph (Refs #24).

All Resource Graph API calls are mocked via injected MagicMock clients. No
real Azure API traffic in CI.

`client.resources(query)` returns a `QueryResponse` with `.data` as
`list[dict]` and an optional `.skip_token` for pagination — the SDK already
deserializes to plain dicts (unlike GCP's CAI which uses protobuf Struct),
so test fixtures are plain dicts.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest


def _vm_row(
    *,
    subscription: str = "sub-1",
    resource_group: str = "rg-prod",
    name: str = "vm-web",
    location: str = "eastus",
    tags: dict | None = None,
    vm_size: str = "Standard_D2s_v3",
) -> dict:
    return {
        "id": (
            f"/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/"
            f"Microsoft.Compute/virtualMachines/{name}"
        ),
        "name": name,
        "type": "microsoft.compute/virtualmachines",
        "location": location,
        "resourceGroup": resource_group,
        "subscriptionId": subscription,
        "tags": tags,
        "properties": {"hardwareProfile": {"vmSize": vm_size}},
    }


def _storage_row(
    *,
    subscription: str = "sub-1",
    resource_group: str = "rg-prod",
    name: str = "audit-logs",
    location: str = "eastus",
    sku_name: str = "Standard_LRS",
    storage_kind: str = "StorageV2",
    tags: dict | None = None,
) -> dict:
    return {
        "id": (
            f"/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/"
            f"Microsoft.Storage/storageAccounts/{name}"
        ),
        "name": name,
        "type": "microsoft.storage/storageaccounts",
        "location": location,
        "resourceGroup": resource_group,
        "subscriptionId": subscription,
        "tags": tags or {},
        "sku": {"name": sku_name},
        "kind": storage_kind,
    }


def _mi_row(
    *,
    subscription: str = "sub-1",
    resource_group: str = "rg-prod",
    name: str = "ci-runner",
    location: str = "eastus",
    principal_id: str = "00000000-1111-2222-3333-444444444444",
    tags: dict | None = None,
) -> dict:
    return {
        "id": (
            f"/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/"
            f"Microsoft.ManagedIdentity/userAssignedIdentities/{name}"
        ),
        "name": name,
        "type": "microsoft.managedidentity/userassignedidentities",
        "location": location,
        "resourceGroup": resource_group,
        "subscriptionId": subscription,
        "tags": tags or {},
        "properties": {"principalId": principal_id},
    }


def _fake_rg_client(
    *,
    vms: list[dict] | None = None,
    storage_accounts: list[dict] | None = None,
    managed_identities: list[dict] | None = None,
    list_raises: dict[str, Exception] | None = None,
    paginate: dict[str, list[list[dict]]] | None = None,
) -> MagicMock:
    """Build a MagicMock ResourceGraphClient.

    `paginate` lets a test return multiple pages for one resource type by
    providing a list of pages keyed by resource type. Each call advances
    one page; the final page returns no skip_token.
    """
    client = MagicMock()
    page_iters: dict[str, Any] = {}
    if paginate:
        page_iters = {t: iter(pages) for t, pages in paginate.items()}

    def _resources(query: Any) -> Any:
        kql = query.query
        # Identify which resource type this query is for by string match.
        target_type = None
        if "microsoft.compute/virtualmachines" in kql:
            target_type = "microsoft.compute/virtualmachines"
        elif "microsoft.storage/storageaccounts" in kql:
            target_type = "microsoft.storage/storageaccounts"
        elif "microsoft.managedidentity/userassignedidentities" in kql:
            target_type = "microsoft.managedidentity/userassignedidentities"

        if list_raises and target_type in list_raises:
            raise list_raises[target_type]

        if target_type and target_type in page_iters:
            try:
                page = next(page_iters[target_type])
            except StopIteration:
                page = []
            response = MagicMock()
            response.data = page
            # Final page in the iterator → no skip_token; otherwise emit one.
            response.skip_token = (
                "next-page" if page_iters[target_type].__length_hint__() > 0 else None
            )  # type: ignore[attr-defined]
            return response

        rows: list[dict] = []
        if target_type == "microsoft.compute/virtualmachines":
            rows = vms or []
        elif target_type == "microsoft.storage/storageaccounts":
            rows = storage_accounts or []
        elif target_type == "microsoft.managedidentity/userassignedidentities":
            rows = managed_identities or []
        response = MagicMock()
        response.data = rows
        response.skip_token = None
        return response

    client.resources.side_effect = _resources
    return client


class TestDiscoverVM:
    def test_emits_resource_definition_with_subscription_in_id_and_tags(self):
        from lemma.services.azure_discovery import discover_resources_from_azure

        client = _fake_rg_client(
            vms=[
                _vm_row(
                    subscription="sub-prod",
                    name="web",
                    tags={"environment": "prod", "team": "platform"},
                )
            ]
        )

        result = discover_resources_from_azure(
            rg_client=client,
            subscription="sub-prod",
            resource_types=["microsoft.compute/virtualmachines"],
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "azure-sub-prod-vm-web"
        assert rd.type == "azure.compute.vm"
        assert rd.attributes["azure"]["subscription"] == "sub-prod"
        assert rd.attributes["azure"]["kind"] == "VirtualMachine"
        assert rd.attributes["azure"]["resource_group"] == "rg-prod"
        assert rd.attributes["azure"]["location"] == "eastus"
        assert rd.attributes["azure"]["tags"] == {
            "environment": "prod",
            "team": "platform",
        }
        assert rd.attributes["azure"]["vm_size"] == "Standard_D2s_v3"


class TestDiscoverStorageAccount:
    def test_storage_account_surfaces_sku_and_kind(self):
        from lemma.services.azure_discovery import discover_resources_from_azure

        client = _fake_rg_client(
            storage_accounts=[
                _storage_row(name="audit-logs", sku_name="Standard_GRS", storage_kind="BlobStorage")
            ]
        )

        result = discover_resources_from_azure(
            rg_client=client,
            subscription="sub-1",
            resource_types=["microsoft.storage/storageaccounts"],
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "azure-sub-1-storage-audit-logs"
        assert rd.type == "azure.storage.account"
        assert rd.attributes["azure"]["sku"] == "Standard_GRS"
        assert rd.attributes["azure"]["storage_kind"] == "BlobStorage"


class TestDiscoverManagedIdentity:
    def test_managed_identity_surfaces_principal_id(self):
        from lemma.services.azure_discovery import discover_resources_from_azure

        client = _fake_rg_client(
            managed_identities=[_mi_row(name="ci-runner", principal_id="abc-principal-id")]
        )

        result = discover_resources_from_azure(
            rg_client=client,
            subscription="sub-1",
            resource_types=["microsoft.managedidentity/userassignedidentities"],
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "azure-sub-1-mi-ci-runner"
        assert rd.type == "azure.identity.user_assigned"
        assert rd.attributes["azure"]["principal_id"] == "abc-principal-id"


class TestMultiResourceGroup:
    def test_multi_rg_vms_get_distinct_ids(self):
        from lemma.services.azure_discovery import discover_resources_from_azure

        client = _fake_rg_client(
            vms=[
                _vm_row(name="web", resource_group="rg-prod"),
                _vm_row(name="api", resource_group="rg-staging"),
            ]
        )

        result = discover_resources_from_azure(
            rg_client=client,
            subscription="sub-1",
            resource_types=["microsoft.compute/virtualmachines"],
        )

        ids = {rd.id for rd in result}
        assert ids == {"azure-sub-1-vm-web", "azure-sub-1-vm-api"}


class TestEdgeCases:
    def test_vm_with_tags_none_returns_empty_dict(self):
        """Resource Graph returns tags=None for resources with no tags set."""
        from lemma.services.azure_discovery import discover_resources_from_azure

        client = _fake_rg_client(vms=[_vm_row(name="notags", tags=None)])

        result = discover_resources_from_azure(
            rg_client=client,
            subscription="sub-1",
            resource_types=["microsoft.compute/virtualmachines"],
        )

        assert result[0].attributes["azure"]["tags"] == {}

    def test_arm_id_basename_extraction(self):
        """The Lemma ID uses only the trailing ARM-id segment, not the full path."""
        from lemma.services.azure_discovery import discover_resources_from_azure

        client = _fake_rg_client(vms=[_vm_row(name="my-special-vm")])

        result = discover_resources_from_azure(
            rg_client=client,
            subscription="sub-1",
            resource_types=["microsoft.compute/virtualmachines"],
        )

        assert result[0].id == "azure-sub-1-vm-my-special-vm"
        assert "/" not in result[0].id
        assert "Microsoft.Compute" not in result[0].id


class TestErrorHandling:
    def test_unknown_resource_type_raises_value_error(self):
        from lemma.services.azure_discovery import discover_resources_from_azure

        with pytest.raises(ValueError, match=r"(?i)unknown.*resource|microsoft.bogus"):
            discover_resources_from_azure(
                rg_client=_fake_rg_client(),
                subscription="sub-1",
                resource_types=["microsoft.bogus/foo"],
            )

    def test_empty_resource_types_raises_value_error(self):
        from lemma.services.azure_discovery import discover_resources_from_azure

        with pytest.raises(ValueError, match=r"(?i)at least one|empty"):
            discover_resources_from_azure(
                rg_client=_fake_rg_client(),
                subscription="sub-1",
                resource_types=[],
            )

    def test_http_response_error_on_one_type_continues_others(self):
        from azure.core.exceptions import HttpResponseError

        from lemma.services.azure_discovery import discover_resources_from_azure

        client = _fake_rg_client(
            storage_accounts=[_storage_row(name="ok-storage")],
            managed_identities=[_mi_row(name="ci")],
            list_raises={
                "microsoft.compute/virtualmachines": HttpResponseError(
                    "Compute provider not registered"
                ),
            },
        )

        result = discover_resources_from_azure(
            rg_client=client,
            subscription="sub-1",
            resource_types=[
                "microsoft.compute/virtualmachines",
                "microsoft.storage/storageaccounts",
                "microsoft.managedidentity/userassignedidentities",
            ],
        )

        types = {rd.type for rd in result}
        assert "azure.compute.vm" not in types
        assert "azure.storage.account" in types
        assert "azure.identity.user_assigned" in types


class TestPagination:
    def test_skip_token_drives_second_page(self):
        from lemma.services.azure_discovery import discover_resources_from_azure

        page1 = [_vm_row(name="vm-1")]
        page2 = [_vm_row(name="vm-2")]
        client = _fake_rg_client(paginate={"microsoft.compute/virtualmachines": [page1, page2]})

        result = discover_resources_from_azure(
            rg_client=client,
            subscription="sub-1",
            resource_types=["microsoft.compute/virtualmachines"],
        )

        ids = {rd.id for rd in result}
        assert ids == {"azure-sub-1-vm-vm-1", "azure-sub-1-vm-vm-2"}
        # Two calls expected: first page + skip_token follow-up.
        assert client.resources.call_count == 2
