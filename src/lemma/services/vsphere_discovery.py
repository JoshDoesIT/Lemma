"""VMware vSphere / vCenter discovery for the scope engine (Refs #24).

Walks a vCenter's managed-object graph via pyVmomi's ``ContainerView`` and
yields a ``ResourceDefinition`` per discovered VM / Host / Datastore — same
shape every other discovery service returns, so the scope-discover command
feeds vSphere through the same matcher and graph-write loop as AWS / k8s /
GCP / Azure / Ansible / ServiceNow / Device42.

v0 enumerates three pillars:

- ``vm``        → ``vim.VirtualMachine`` (compute)
- ``host``      → ``vim.HostSystem``     (hypervisor)
- ``datastore`` → ``vim.Datastore``      (storage)

Authentication and the ``ServiceInstance`` lifecycle live in
``lemma.commands.scope._build_vsphere_clients`` so the auth seam is
monkeypatchable. Tests inject a ``MagicMock`` ``content`` matching the
``vim.ServiceInstanceContent`` shape (``rootFolder``,
``viewManager.CreateContainerView``, ``customFieldsManager.field``).
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from pyVmomi import vim

from lemma.models.resource import ResourceDefinition

logger = logging.getLogger(__name__)

_KIND_TO_VIM_TYPE: dict[str, Any] = {
    "vm": vim.VirtualMachine,
    "host": vim.HostSystem,
    "datastore": vim.Datastore,
}

# When a datacenter filter is active, each kind's ContainerView is rooted at
# that datacenter's dedicated inventory folder rather than the global
# ``content.rootFolder``.
_KIND_TO_DC_FOLDER: dict[str, str] = {
    "vm": "vmFolder",
    "host": "hostFolder",
    "datastore": "datastoreFolder",
}

# Datacenters can be nested inside vim.Folder objects in vCenter; bound the
# recursive descent so a malformed/cyclic inventory can't spin forever.
_MAX_FOLDER_DEPTH = 50


def discover_resources_from_vsphere(
    *,
    content: Any,
    vc_host: str,
    datacenter: str | None = None,
    kinds: list[str],
) -> list[ResourceDefinition]:
    """Discover vSphere resources across the requested kinds.

    Args:
        content: A ``vim.ServiceInstanceContent`` (or MagicMock matching its
            shape) exposing ``rootFolder``, ``viewManager``, and
            ``customFieldsManager``. Production passes
            ``si.RetrieveContent()``.
        vc_host: vCenter hostname; baked into resource ids so multi-vCenter
            discovery doesn't collide.
        datacenter: Optional datacenter-name filter. ``None`` = walk every
            datacenter rooted at ``content.rootFolder`` (the global view).
            When set, each kind's ContainerView is rooted at the matching
            datacenter's per-kind inventory folder (``vmFolder`` /
            ``hostFolder`` / ``datastoreFolder``), so a multi-datacenter
            vCenter only yields the requested datacenter's fleet. An
            unmatched name raises ``ValueError`` naming the available
            datacenters.
        kinds: List of ``{"vm", "host", "datastore"}``. Unknown kind raises
            ``ValueError``. Empty list raises ``ValueError``.

    Returns:
        List of ``ResourceDefinition`` records, one per discovered managed
        object. Per-kind ``vim.fault.NoPermission`` /
        ``vim.fault.NotAuthenticated`` is logged and skipped; other kinds
        still produce results.

    Raises:
        ValueError: If ``kinds`` is empty, contains an unknown kind, or
            ``datacenter`` is set but no datacenter of that name exists.
    """
    if not kinds:
        msg = "discover_resources_from_vsphere requires at least one kind."
        raise ValueError(msg)

    unknown = [k for k in kinds if k not in _KIND_TO_VIM_TYPE]
    if unknown:
        known = ", ".join(_KIND_TO_VIM_TYPE.keys())
        msg = f"Unknown vSphere kind(s): {', '.join(unknown)}. Known: {known}."
        raise ValueError(msg)

    # Resolve the datacenter filter once up front so a typo'd name fails fast
    # for every kind rather than per-kind.
    matched_datacenters: list[Any] | None = None
    if datacenter:
        all_datacenters = _find_all_datacenters(content.rootFolder)
        matched_datacenters = [dc for dc in all_datacenters if dc.name == datacenter]
        if not matched_datacenters:
            available = ", ".join(sorted(dc.name for dc in all_datacenters)) or "(none)"
            msg = (
                f"vSphere datacenter '{datacenter}' not found at {vc_host}. "
                f"Available datacenters: {available}."
            )
            raise ValueError(msg)

    field_name_by_key = _build_custom_field_index(content)

    discovered: list[ResourceDefinition] = []
    for kind in kinds:
        vim_type = _KIND_TO_VIM_TYPE[kind]
        roots = _container_roots(content, kind, matched_datacenters)
        for root in roots:
            try:
                view = content.viewManager.CreateContainerView(root, [vim_type], True)
            except (vim.fault.NoPermission, vim.fault.NotAuthenticated) as exc:
                logger.warning("vSphere %s discovery skipped: %s", kind, exc)
                continue

            try:
                objects = list(view.view or [])
            finally:
                destroy = getattr(view, "Destroy", None)
                if callable(destroy):
                    with contextlib.suppress(Exception):
                        destroy()

            for obj in objects:
                if kind == "vm":
                    discovered.append(_project_vm(obj, vc_host, field_name_by_key))
                elif kind == "host":
                    discovered.append(_project_host(obj, vc_host, field_name_by_key))
                elif kind == "datastore":
                    discovered.append(_project_datastore(obj, vc_host, field_name_by_key))

    return discovered


def _container_roots(content: Any, kind: str, datacenters: list[Any] | None) -> list[Any]:
    """ContainerView roots for ``kind``.

    No datacenter filter → the global ``content.rootFolder`` (one view).
    A filter → the matching datacenters' per-kind inventory folders.
    """
    if datacenters is None:
        return [content.rootFolder]
    folder_attr = _KIND_TO_DC_FOLDER[kind]
    return [getattr(dc, folder_attr) for dc in datacenters]


def _find_all_datacenters(root_folder: Any) -> list[Any]:
    """Collect every ``vim.Datacenter`` reachable from ``root_folder``.

    vCenter lets operators nest datacenters inside ``vim.Folder`` objects, so
    descend through child folders (bounded by ``_MAX_FOLDER_DEPTH``).
    """
    found: list[Any] = []
    _collect_datacenters(root_folder, found, depth=0)
    return found


def _collect_datacenters(folder: Any, acc: list[Any], depth: int) -> None:
    if depth > _MAX_FOLDER_DEPTH:
        return
    for child in getattr(folder, "childEntity", None) or []:
        if isinstance(child, vim.Datacenter):
            acc.append(child)
        elif isinstance(child, vim.Folder):
            _collect_datacenters(child, acc, depth + 1)


def _build_custom_field_index(content: Any) -> dict[int, str]:
    fields = getattr(getattr(content, "customFieldsManager", None), "field", None) or []
    return {fd.key: fd.name for fd in fields}


def _project_tags(obj: Any, field_name_by_key: dict[int, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for cv in getattr(obj, "customValue", None) or []:
        name = field_name_by_key.get(cv.key)
        if name:
            out[name] = cv.value
    return out


def _project_vm(vm: Any, vc_host: str, field_name_by_key: dict[int, str]) -> ResourceDefinition:
    summary = vm.summary
    config = summary.config
    runtime = summary.runtime
    return ResourceDefinition(
        id=f"vsphere-{vc_host}-vm-{vm._moId}",
        type="vsphere.vm",
        scopes=[""],
        attributes={
            "vsphere": {
                "kind": "VirtualMachine",
                "vc_host": vc_host,
                "moid": vm._moId,
                "name": config.name,
                "guest_os": config.guestFullName,
                "power_state": runtime.powerState,
                "cpu_count": config.numCpu,
                "memory_mb": config.memorySizeMB,
                "tags": _project_tags(vm, field_name_by_key),
            }
        },
    )


def _project_host(host: Any, vc_host: str, field_name_by_key: dict[int, str]) -> ResourceDefinition:
    summary = host.summary
    config = summary.config
    runtime = summary.runtime
    hardware = summary.hardware
    return ResourceDefinition(
        id=f"vsphere-{vc_host}-host-{host._moId}",
        type="vsphere.host",
        scopes=[""],
        attributes={
            "vsphere": {
                "kind": "HostSystem",
                "vc_host": vc_host,
                "moid": host._moId,
                "name": config.name,
                "version": config.product.version,
                "connection_state": runtime.connectionState,
                "cpu_count": hardware.numCpuCores,
                "memory_mb": hardware.memorySize // (1024 * 1024),
                "vendor": hardware.vendor,
                "model": hardware.model,
                "tags": _project_tags(host, field_name_by_key),
            }
        },
    )


def _project_datastore(
    ds: Any, vc_host: str, field_name_by_key: dict[int, str]
) -> ResourceDefinition:
    summary = ds.summary
    return ResourceDefinition(
        id=f"vsphere-{vc_host}-datastore-{ds._moId}",
        type="vsphere.datastore",
        scopes=[""],
        attributes={
            "vsphere": {
                "kind": "Datastore",
                "vc_host": vc_host,
                "moid": ds._moId,
                "name": summary.name,
                "type": summary.type,
                "capacity_bytes": summary.capacity,
                "free_bytes": summary.freeSpace,
                "tags": _project_tags(ds, field_name_by_key),
            }
        },
    )
