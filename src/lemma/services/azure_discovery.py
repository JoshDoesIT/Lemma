"""Azure discovery via Resource Graph (Refs #24).

Walks Azure Resource Graph (``Microsoft.ResourceGraph``) and yields a
``ResourceDefinition`` per discovered asset — same shape the AWS / TF /
k8s / GCP services return, so the scope-discover command feeds all five
sources through the existing matcher and graph-write loop.

v0 enumerates three resource types:

- ``microsoft.compute/virtualmachines``                 → ``azure.compute.vm``
- ``microsoft.storage/storageaccounts``                 → ``azure.storage.account``
- ``microsoft.managedidentity/userassignedidentities``  → ``azure.identity.user_assigned``

Identity choice rationale: Azure AD principals (Microsoft Entra users /
groups / service principals) live in Microsoft Graph API — a separate
SDK with a separate auth domain. Managed Identities live in Resource
Graph and are the workload identities, mapping cleanly to AWS-IAM-user
and GCP-service-account in audit framing.

The service does not load credentials; that lives in
``lemma.commands.scope._build_azure_clients`` so the auth seam is
monkeypatchable.
"""

from __future__ import annotations

import logging
from typing import Any

from azure.core.exceptions import HttpResponseError
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

from lemma.models.resource import ResourceDefinition

logger = logging.getLogger(__name__)

# Resource type → (lemma_type, kind label, ID short-kind)
_KNOWN_RESOURCE_TYPES: dict[str, tuple[str, str, str]] = {
    "microsoft.compute/virtualmachines": ("azure.compute.vm", "VirtualMachine", "vm"),
    "microsoft.storage/storageaccounts": (
        "azure.storage.account",
        "StorageAccount",
        "storage",
    ),
    "microsoft.managedidentity/userassignedidentities": (
        "azure.identity.user_assigned",
        "ManagedIdentity",
        "mi",
    ),
}


def discover_resources_from_azure(
    *,
    rg_client: Any,
    subscription: str,
    resource_types: list[str],
) -> list[ResourceDefinition]:
    """Discover Azure resources via Resource Graph.

    Args:
        rg_client: A ``ResourceGraphClient``-like object exposing
            ``resources(query)``. Tests pass a ``MagicMock``.
        subscription: Azure subscription id (used in
            ``QueryRequest.subscriptions``, *not* in the KQL body).
        resource_types: Non-empty list of Azure resource type strings.
            Each must be in ``_KNOWN_RESOURCE_TYPES``.

    Returns:
        List of ``ResourceDefinition``. Per-type ``HttpResponseError`` is
        logged and skipped; other types still produce results.

    Raises:
        ValueError: If ``resource_types`` is empty or contains an unknown
            type.
    """
    if not resource_types:
        msg = "At least one resource type required for Azure discovery."
        raise ValueError(msg)

    unknown = [t for t in resource_types if t not in _KNOWN_RESOURCE_TYPES]
    if unknown:
        msg = (
            f"Unknown Azure resource type(s): {', '.join(unknown)}. "
            f"Known: {', '.join(_KNOWN_RESOURCE_TYPES)}."
        )
        raise ValueError(msg)

    discovered: list[ResourceDefinition] = []
    for resource_type in resource_types:
        # NOTE: resource_type is interpolated into KQL but is closed-allow-list-validated
        # above. The subscription value never enters the KQL body — it goes into the
        # subscriptions=[] field of QueryRequest. Adding any new operator-supplied
        # input that flows into the query body must preserve this property.
        kql = (
            f"Resources | where type =~ '{resource_type}' "
            "| project id, name, type, location, resourceGroup, "
            "subscriptionId, tags, sku, kind, properties"
        )
        try:
            discovered.extend(_paginate(rg_client, subscription, kql, resource_type))
        except HttpResponseError as exc:
            logger.warning("Azure %s discovery skipped: %s", resource_type, exc)
            continue

    return discovered


def _paginate(
    rg_client: Any, subscription: str, kql: str, resource_type: str
) -> list[ResourceDefinition]:
    """Walk every page of a Resource Graph query, returning ResourceDefinitions."""
    out: list[ResourceDefinition] = []
    skip_token: str | None = None
    while True:
        options = QueryRequestOptions(skip_token=skip_token) if skip_token else None
        request = QueryRequest(
            subscriptions=[subscription],
            query=kql,
            options=options,
        )
        response = rg_client.resources(request)
        for row in response.data or []:
            rd = _build_resource_definition(row, resource_type, subscription)
            if rd is not None:
                out.append(rd)
        skip_token = getattr(response, "skip_token", None) or None
        if not skip_token:
            break
    return out


def _build_resource_definition(
    row: dict, resource_type: str, subscription: str
) -> ResourceDefinition | None:
    lemma_type, kind, short_kind = _KNOWN_RESOURCE_TYPES[resource_type]
    basename = _basename(row.get("id", "")) or row.get("name", "")
    if not basename:
        return None

    common: dict[str, Any] = {
        "kind": kind,
        "subscription": subscription,
        "resource_group": row.get("resourceGroup", ""),
        "name": basename,
        "location": row.get("location", ""),
        "resource_type": resource_type,
        "tags": row.get("tags") or {},
    }

    if resource_type == "microsoft.compute/virtualmachines":
        properties = row.get("properties") or {}
        hardware = properties.get("hardwareProfile") or {}
        common["vm_size"] = hardware.get("vmSize", "")
    elif resource_type == "microsoft.storage/storageaccounts":
        sku_block = row.get("sku") or {}
        common["sku"] = sku_block.get("name", "")
        common["storage_kind"] = row.get("kind", "")
    else:  # microsoft.managedidentity/userassignedidentities
        properties = row.get("properties") or {}
        common["principal_id"] = properties.get("principalId", "")

    return ResourceDefinition(
        id=f"azure-{subscription}-{short_kind}-{basename}",
        type=lemma_type,
        scope="",
        attributes={"azure": common},
    )


def _basename(arm_id: str) -> str:
    """Return the trailing path segment of a full ARM resource id.

    ARM ids look like ``/subscriptions/<sub>/resourceGroups/<rg>/providers/
    Microsoft.Compute/virtualMachines/<name>`` — only the trailing ``<name>``
    lands in the Lemma id.
    """
    if not arm_id:
        return ""
    return arm_id.rsplit("/", 1)[-1]
