"""GCP discovery via Cloud Asset Inventory (Refs #24).

Walks Google Cloud Asset Inventory (``cloudasset.googleapis.com``) and
yields a ``ResourceDefinition`` per discovered asset — same shape
``aws_discovery``, ``terraform_state``, and ``k8s_discovery`` return,
so the scope-discover command can feed all four sources through the
existing matcher and graph-write loop.

v0 enumerates three asset types:

- ``compute.googleapis.com/Instance``  → ``gcp.compute.instance``
- ``storage.googleapis.com/Bucket``    → ``gcp.storage.bucket``
- ``iam.googleapis.com/ServiceAccount`` → ``gcp.iam.service_account``

The service does not load credentials; that lives in
``lemma.commands.scope._build_gcp_client`` so the auth seam is
monkeypatchable. Tests inject a ``MagicMock`` ``asset_client`` whose
``list_assets()`` routes by the asset_types in the request.
"""

from __future__ import annotations

import logging
from typing import Any

from google.api_core.exceptions import GoogleAPIError
from google.cloud import asset_v1
from google.protobuf.json_format import MessageToDict

from lemma.models.resource import ResourceDefinition

logger = logging.getLogger(__name__)

# Asset-type → (lemma_type, kind label, ID short-kind, attribute extractor)
_ASSET_TYPE_CONFIG: dict[str, tuple[str, str, str]] = {
    "compute.googleapis.com/Instance": ("gcp.compute.instance", "Instance", "instance"),
    "storage.googleapis.com/Bucket": ("gcp.storage.bucket", "Bucket", "bucket"),
    "iam.googleapis.com/ServiceAccount": (
        "gcp.iam.service_account",
        "ServiceAccount",
        "sa",
    ),
}


def discover_resources_from_gcp(
    *,
    asset_client: Any,
    project: str,
    asset_types: list[str],
) -> list[ResourceDefinition]:
    """Discover GCP resources via Cloud Asset Inventory.

    Args:
        asset_client: A CAI client exposing ``list_assets(request=...)``.
            Tests pass a ``MagicMock``; production passes a real
            ``asset_v1.AssetServiceClient()``.
        project: GCP project id; the CAI scope is ``f"projects/{project}"``.
        asset_types: Non-empty list of CAI asset type names. Each must be
            in ``_ASSET_TYPE_CONFIG``.

    Returns:
        List of ``ResourceDefinition`` records, one per discovered asset.
        Per-asset-type ``GoogleAPIError`` (RBAC denial, quota, API not
        enabled) is logged and skipped; other types still produce results.

    Raises:
        ValueError: If ``asset_types`` is empty or contains an unknown type.
    """
    if not asset_types:
        msg = "At least one asset type required for GCP discovery."
        raise ValueError(msg)

    unknown = [t for t in asset_types if t not in _ASSET_TYPE_CONFIG]
    if unknown:
        msg = (
            f"Unknown GCP asset type(s): {', '.join(unknown)}. "
            f"Known: {', '.join(_ASSET_TYPE_CONFIG)}."
        )
        raise ValueError(msg)

    parent = f"projects/{project}"
    discovered: list[ResourceDefinition] = []

    for asset_type in asset_types:
        request = asset_v1.ListAssetsRequest(
            parent=parent,
            asset_types=[asset_type],
            content_type=asset_v1.ContentType.RESOURCE,
        )
        try:
            for asset in asset_client.list_assets(request=request):
                rd = _build_resource_definition(asset, asset_type, project)
                if rd is not None:
                    discovered.append(rd)
        except GoogleAPIError as exc:
            logger.warning("GCP %s discovery skipped: %s", asset_type, exc)
            continue

    return discovered


def _build_resource_definition(
    asset: Any, asset_type: str, project: str
) -> ResourceDefinition | None:
    lemma_type, kind, _short_kind = _ASSET_TYPE_CONFIG[asset_type]
    data = MessageToDict(asset.resource.data, preserving_proto_field_name=True)

    basename = _basename(asset.name)
    if not basename:
        return None

    common: dict[str, Any] = {
        "kind": kind,
        "project": project,
        "name": basename,
        "asset_type": asset_type,
        "labels": data.get("labels") or {},
    }

    if asset_type == "compute.googleapis.com/Instance":
        common["machine_type"] = data.get("machine_type", "")
        common["status"] = data.get("status", "")
        common["location"] = _zone_from_path(data.get("zone", ""))
        rid = f"gcp-{project}-instance-{basename}"
    elif asset_type == "storage.googleapis.com/Bucket":
        common["storage_class"] = data.get("storage_class", "")
        common["location"] = data.get("location", "")
        rid = f"gcp-{project}-bucket-{basename}"
    else:  # iam.googleapis.com/ServiceAccount
        email = data.get("email", "")
        common["email"] = email
        common["display_name"] = data.get("display_name", "")
        sa_basename = email.split("@", 1)[0] if email else basename
        rid = f"gcp-{project}-sa-{sa_basename}"

    return ResourceDefinition(
        id=rid,
        type=lemma_type,
        scope="",
        attributes={"gcp": common},
    )


def _basename(asset_name: str) -> str:
    """Return the trailing path segment of a CAI asset name.

    CAI returns names like
    ``//compute.googleapis.com/projects/foo/zones/us-central1-a/instances/my-vm``
    — the leading ``//<host>/`` and intervening path are not optional. The
    Lemma id only needs the trailing basename.
    """
    if not asset_name:
        return ""
    return asset_name.rsplit("/", 1)[-1]


def _zone_from_path(zone_path: str) -> str:
    """Extract the trailing zone name from ``projects/foo/zones/us-central1-a``."""
    if not zone_path:
        return ""
    return zone_path.rsplit("/", 1)[-1]
