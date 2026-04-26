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
            datacenter rooted at ``content.rootFolder``. v0 reserves the
            argument; per-datacenter filtering at the ContainerView level is
            a follow-up.
        kinds: List of ``{"vm", "host", "datastore"}``. Unknown kind raises
            ``ValueError``. Empty list raises ``ValueError``.

    Returns:
        List of ``ResourceDefinition`` records, one per discovered managed
        object. Per-kind ``vim.fault.NoPermission`` /
        ``vim.fault.NotAuthenticated`` is logged and skipped; other kinds
        still produce results.

    Raises:
        ValueError: If ``kinds`` is empty or contains an unknown kind.
    """
    if not kinds:
        msg = "discover_resources_from_vsphere requires at least one kind."
        raise ValueError(msg)

    unknown = [k for k in kinds if k not in _KIND_TO_VIM_TYPE]
    if unknown:
        known = ", ".join(_KIND_TO_VIM_TYPE.keys())
        msg = f"Unknown vSphere kind(s): {', '.join(unknown)}. Known: {known}."
        raise ValueError(msg)

    field_name_by_key = _build_custom_field_index(content)

    discovered: list[ResourceDefinition] = []
    for kind in kinds:
        vim_type = _KIND_TO_VIM_TYPE[kind]
        try:
            view = content.viewManager.CreateContainerView(content.rootFolder, [vim_type], True)
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
        scope="",
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
        scope="",
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
        scope="",
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
