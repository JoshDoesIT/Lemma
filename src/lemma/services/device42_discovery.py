"""Device42 CMDB discovery (Refs #24).

Reads devices from a Device42 deployment via the v1.0 Devices API
(``/api/1.0/devices/``) and emits one ``ResourceDefinition`` per row.
Same shape the cloud / file / ansible / servicenow discovery services
return, so the discover command feeds Device42-imported devices through
the existing matcher and graph-write loop.

Auth + base URL configured by ``lemma.commands.scope._build_device42_client``;
this service takes the prepared ``httpx.Client`` and the deployment URL,
walks paginated results, and normalizes Device42's quirky shapes into
matcher-friendly attribute dicts.

Type derives per row from the device's ``type`` field (``physical`` /
``virtual`` / ``cluster`` / etc.) so operators get fine-grained types
automatically without a Lemma-side mapping table.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

from lemma.models.resource import ResourceDefinition

logger = logging.getLogger(__name__)


def discover_resources_from_device42(
    *,
    client: Any,
    url: str,
    limit: int = 1000,
) -> list[ResourceDefinition]:
    """Discover devices from a Device42 deployment via the v1.0 Devices API.

    Args:
        client: A configured ``httpx.Client`` with base_url pointing at
            the Device42 deployment and Basic auth set.
        url: Full deployment URL; the host is extracted and baked into
            resource ids for multi-deployment disambiguation.
        limit: ``limit=`` per request. Default 1000.

    Returns:
        List of ``ResourceDefinition``, one per device with a ``device_id``.
        Rows missing ``device_id`` are silently skipped.

    Raises:
        ValueError: If the deployment returns an HTTP error (401, 403,
            5xx) or is unreachable.
    """
    host = _host_from_url(url)
    discovered: list[ResourceDefinition] = []
    offset = 0

    while True:
        try:
            response = client.get(
                "/api/1.0/devices/",
                params={"limit": str(limit), "offset": str(offset)},
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = (
                f"Device42 deployment '{url}' returned "
                f"{exc.response.status_code} for /api/1.0/devices/: "
                f"{exc.response.text[:200]}"
            )
            raise ValueError(msg) from exc
        except httpx.RequestError as exc:
            msg = f"Device42 deployment '{url}' is unreachable: {exc}"
            raise ValueError(msg) from exc

        payload = response.json()
        devices = payload.get("Devices") or []
        total_count = payload.get("total_count", len(devices))

        for row in devices:
            rd = _build_resource_definition(row, url, host)
            if rd is not None:
                discovered.append(rd)

        offset += limit
        if offset >= total_count or not devices:
            break

    return discovered


def _build_resource_definition(row: dict, url: str, host: str) -> ResourceDefinition | None:
    device_id = row.get("device_id")
    if device_id is None:
        # Data-quality issue; skip silently.
        return None

    device_type = row.get("type") or "device"
    lemma_type = f"device42.{device_type}"

    # Build attributes from the row verbatim, then overlay normalized fields.
    device42_attrs: dict[str, Any] = {"url": url}
    device42_attrs.update(row)
    device42_attrs["custom_fields"] = _normalize_custom_fields(row.get("custom_fields"))

    return ResourceDefinition(
        id=f"device42-{host}-{device_id}",
        type=lemma_type,
        scope="",
        attributes={"device42": device42_attrs},
    )


def _host_from_url(url: str) -> str:
    """Extract the host portion of a deployment URL for use in resource ids."""
    parsed = urlparse(url)
    return parsed.hostname or url


def _normalize_custom_fields(raw: Any) -> dict[str, Any]:
    """Convert Device42's ``[{key, value}, ...]`` custom-fields list to a flat dict.

    The list-of-objects shape isn't matcher-friendly; the dict form lets
    operators write rules against ``device42.custom_fields.<key>``.
    Returns ``{}`` for any non-list input or list rows missing ``key``.
    """
    if not isinstance(raw, list):
        return {}
    out: dict[str, Any] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        key = entry.get("key")
        if not isinstance(key, str) or not key:
            continue
        out[key] = entry.get("value")
    return out
