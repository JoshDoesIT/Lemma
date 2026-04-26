"""ServiceNow CMDB discovery (Refs #24).

Reads CIs from a ServiceNow instance via the Table API
(``/api/now/table/<class>``) and emits one ``ResourceDefinition`` per row.
Same shape the cloud / file / ansible discovery services return, so the
discover command feeds ServiceNow-imported CIs through the existing
matcher and graph-write loop.

Auth + base URL configured by ``lemma.commands.scope._build_servicenow_client``;
this service takes the prepared ``httpx.Client`` and an instance name and
walks paginated results.

Type derives per row from ``sys_class_name`` so operators get fine-grained
types (``snow.cmdb_ci_server``, ``snow.cmdb_ci_database``) automatically
without a Lemma-side mapping table that would drift against tenant-custom
classes (``u_acme_compute_node``).
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from lemma.models.resource import ResourceDefinition

logger = logging.getLogger(__name__)


def discover_resources_from_servicenow(
    *,
    client: Any,
    instance: str,
    ci_class: str = "cmdb_ci",
    page_size: int = 1000,
) -> list[ResourceDefinition]:
    """Discover CIs from a ServiceNow instance via the Table API.

    Args:
        client: A configured ``httpx.Client`` with base_url pointing at
            ``https://<instance>.service-now.com`` and Basic auth set.
        instance: ServiceNow instance name; baked into resource ids.
        ci_class: CI class to query. ``cmdb_ci`` (parent) returns every
            CI across all subclasses; passing a specific class restricts.
        page_size: ``sysparm_limit`` per request. Default 1000.

    Returns:
        List of ``ResourceDefinition``, one per CI with a ``sys_id``.
        Rows missing ``sys_id`` are silently skipped.

    Raises:
        ValueError: If the instance returns an HTTP error (401, 403, 5xx,
            etc.) or is unreachable.
    """
    discovered: list[ResourceDefinition] = []
    offset = 0

    while True:
        try:
            response = client.get(
                f"/api/now/table/{ci_class}",
                params={
                    "sysparm_limit": str(page_size),
                    "sysparm_offset": str(offset),
                    "sysparm_display_value": "false",
                },
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = (
                f"ServiceNow instance '{instance}' returned "
                f"{exc.response.status_code} for {ci_class}: "
                f"{exc.response.text[:200]}"
            )
            raise ValueError(msg) from exc
        except httpx.RequestError as exc:
            msg = f"ServiceNow instance '{instance}' is unreachable: {exc}"
            raise ValueError(msg) from exc

        rows = response.json().get("result") or []
        for row in rows:
            rd = _build_resource_definition(row, instance)
            if rd is not None:
                discovered.append(rd)

        if len(rows) < page_size:
            break
        offset += page_size

    return discovered


def _build_resource_definition(row: dict, instance: str) -> ResourceDefinition | None:
    sys_id = row.get("sys_id")
    if not sys_id or not isinstance(sys_id, str):
        # Data-quality issue; skip silently.
        return None

    sys_class_name = row.get("sys_class_name", "cmdb_ci")
    lemma_type = f"snow.{sys_class_name}"

    # Build attributes preserving every field verbatim under snow.*; ServiceNow
    # rows are flat dicts of strings so there's no protobuf bloat to filter.
    snow_attrs: dict[str, Any] = {"instance": instance}
    snow_attrs.update(row)

    return ResourceDefinition(
        id=f"snow-{instance}-{sys_id}",
        type=lemma_type,
        scope="",
        attributes={"snow": snow_attrs},
    )
