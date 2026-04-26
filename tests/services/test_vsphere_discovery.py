"""Tests for vSphere / vCenter discovery (Refs #24).

All vSphere SDK calls are mocked via injected MagicMock content objects.
No real vCenter access in CI.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from pyVmomi import vim


def _make_vm(
    *,
    moid: str = "vm-1",
    name: str = "vm-prod-1",
    guest_os: str = "Ubuntu Linux (64-bit)",
    power_state: str = "poweredOn",
    cpu_count: int = 4,
    memory_mb: int = 8192,
    custom_value: list | None = None,
) -> Any:
    vm = MagicMock(spec=vim.VirtualMachine)
    vm._moId = moid
    vm.summary = MagicMock()
    vm.summary.config = MagicMock()
    vm.summary.config.name = name
    vm.summary.config.guestFullName = guest_os
    vm.summary.config.numCpu = cpu_count
    vm.summary.config.memorySizeMB = memory_mb
    vm.summary.runtime = MagicMock()
    vm.summary.runtime.powerState = power_state
    vm.customValue = custom_value if custom_value is not None else []
    return vm


def _make_host(
    *,
    moid: str = "host-1",
    name: str = "esxi-1",
    version: str = "8.0.2",
    connection_state: str = "connected",
    cpu_count: int = 32,
    memory_bytes: int = 256 * 1024 * 1024 * 1024,  # 256 GiB
    vendor: str = "Dell Inc.",
    model: str = "PowerEdge R750",
) -> Any:
    host = MagicMock(spec=vim.HostSystem)
    host._moId = moid
    host.summary = MagicMock()
    host.summary.config = MagicMock()
    host.summary.config.name = name
    host.summary.config.product = MagicMock()
    host.summary.config.product.version = version
    host.summary.runtime = MagicMock()
    host.summary.runtime.connectionState = connection_state
    host.summary.hardware = MagicMock()
    host.summary.hardware.numCpuCores = cpu_count
    host.summary.hardware.memorySize = memory_bytes
    host.summary.hardware.vendor = vendor
    host.summary.hardware.model = model
    host.customValue = []
    return host


def _make_datastore(
    *,
    moid: str = "datastore-1",
    name: str = "ds-prod-1",
    type_: str = "VMFS",
    capacity: int = 1024 * 1024 * 1024 * 1024,  # 1 TiB
    free_space: int = 512 * 1024 * 1024 * 1024,  # 512 GiB
) -> Any:
    ds = MagicMock(spec=vim.Datastore)
    ds._moId = moid
    ds.summary = MagicMock()
    ds.summary.name = name
    ds.summary.type = type_
    ds.summary.capacity = capacity
    ds.summary.freeSpace = free_space
    ds.customValue = []
    return ds


def _custom_value(key: int, value: str) -> Any:
    cv = MagicMock()
    cv.key = key
    cv.value = value
    return cv


def _custom_field_def(key: int, name: str) -> Any:
    fd = MagicMock()
    fd.key = key
    fd.name = name
    return fd


def _fake_content(
    *,
    vms: list | None = None,
    hosts: list | None = None,
    datastores: list | None = None,
    custom_fields: list | None = None,
    raises_on: dict | None = None,
) -> MagicMock:
    """Return a MagicMock matching the vim.ServiceInstanceContent shape."""
    content = MagicMock()
    content.rootFolder = MagicMock()
    content.customFieldsManager = MagicMock()
    content.customFieldsManager.field = custom_fields or []

    raises_on = raises_on or {}

    def _create_view(folder: Any, types: list, recursive: bool) -> Any:
        type_obj = types[0]
        type_name = type_obj.__name__
        if type_name in raises_on:
            raise raises_on[type_name]
        view = MagicMock()
        if type_obj is vim.VirtualMachine:
            view.view = vms or []
        elif type_obj is vim.HostSystem:
            view.view = hosts or []
        elif type_obj is vim.Datastore:
            view.view = datastores or []
        else:
            view.view = []
        return view

    content.viewManager = MagicMock()
    content.viewManager.CreateContainerView.side_effect = _create_view
    return content


class TestSingleVM:
    def test_emits_resource_definition_with_vc_host_in_id(self):
        from lemma.services.vsphere_discovery import discover_resources_from_vsphere

        content = _fake_content(vms=[_make_vm(moid="vm-42", name="web-1")])

        result = discover_resources_from_vsphere(
            content=content,
            vc_host="vcenter.example.com",
            kinds=["vm"],
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "vsphere-vcenter.example.com-vm-vm-42"
        assert rd.type == "vsphere.vm"
        assert rd.attributes["vsphere"]["vc_host"] == "vcenter.example.com"
        assert rd.attributes["vsphere"]["kind"] == "VirtualMachine"
        assert rd.attributes["vsphere"]["moid"] == "vm-42"
        assert rd.attributes["vsphere"]["name"] == "web-1"
        assert rd.attributes["vsphere"]["guest_os"] == "Ubuntu Linux (64-bit)"
        assert rd.attributes["vsphere"]["power_state"] == "poweredOn"
        assert rd.attributes["vsphere"]["cpu_count"] == 4
        assert rd.attributes["vsphere"]["memory_mb"] == 8192


class TestSingleHost:
    def test_host_projects_vendor_model_version(self):
        from lemma.services.vsphere_discovery import discover_resources_from_vsphere

        content = _fake_content(
            hosts=[
                _make_host(
                    moid="host-99",
                    name="esxi-99",
                    version="8.0.2",
                    vendor="Dell Inc.",
                    model="PowerEdge R750",
                )
            ]
        )

        rd = discover_resources_from_vsphere(
            content=content, vc_host="vc.example.com", kinds=["host"]
        )[0]

        assert rd.id == "vsphere-vc.example.com-host-host-99"
        assert rd.type == "vsphere.host"
        assert rd.attributes["vsphere"]["vendor"] == "Dell Inc."
        assert rd.attributes["vsphere"]["model"] == "PowerEdge R750"
        assert rd.attributes["vsphere"]["version"] == "8.0.2"
        assert rd.attributes["vsphere"]["connection_state"] == "connected"
        # Memory normalized from bytes to MiB.
        assert rd.attributes["vsphere"]["memory_mb"] == 256 * 1024


class TestSingleDatastore:
    def test_datastore_projects_type_and_capacity(self):
        from lemma.services.vsphere_discovery import discover_resources_from_vsphere

        content = _fake_content(
            datastores=[
                _make_datastore(
                    moid="ds-7",
                    name="vsan-prod",
                    type_="vsan",
                    capacity=2 * 1024**4,
                    free_space=1 * 1024**4,
                )
            ]
        )

        rd = discover_resources_from_vsphere(content=content, vc_host="vc", kinds=["datastore"])[0]

        assert rd.id == "vsphere-vc-datastore-ds-7"
        assert rd.type == "vsphere.datastore"
        assert rd.attributes["vsphere"]["type"] == "vsan"
        assert rd.attributes["vsphere"]["capacity_bytes"] == 2 * 1024**4
        assert rd.attributes["vsphere"]["free_bytes"] == 1 * 1024**4


class TestMultipleVMs:
    def test_distinct_moids_produce_distinct_ids(self):
        from lemma.services.vsphere_discovery import discover_resources_from_vsphere

        content = _fake_content(
            vms=[
                _make_vm(moid="vm-1"),
                _make_vm(moid="vm-2"),
                _make_vm(moid="vm-3"),
            ]
        )

        result = discover_resources_from_vsphere(content=content, vc_host="vc", kinds=["vm"])

        ids = {r.id for r in result}
        assert ids == {
            "vsphere-vc-vm-vm-1",
            "vsphere-vc-vm-vm-2",
            "vsphere-vc-vm-vm-3",
        }


class TestCustomAttributes:
    def test_custom_attributes_project_to_tags_dict(self):
        from lemma.services.vsphere_discovery import discover_resources_from_vsphere

        # Two custom-field definitions registered on the vCenter:
        # key 100 → "environment", key 200 → "owner".
        custom_fields = [
            _custom_field_def(100, "environment"),
            _custom_field_def(200, "owner"),
        ]
        # The VM has both custom values set.
        vm = _make_vm(
            moid="vm-10",
            custom_value=[
                _custom_value(100, "prod"),
                _custom_value(200, "platform-team"),
            ],
        )
        content = _fake_content(vms=[vm], custom_fields=custom_fields)

        rd = discover_resources_from_vsphere(content=content, vc_host="vc", kinds=["vm"])[0]

        assert rd.attributes["vsphere"]["tags"] == {
            "environment": "prod",
            "owner": "platform-team",
        }

    def test_no_custom_values_returns_empty_tags_dict(self):
        from lemma.services.vsphere_discovery import discover_resources_from_vsphere

        content = _fake_content(vms=[_make_vm(custom_value=[])])

        rd = discover_resources_from_vsphere(content=content, vc_host="vc", kinds=["vm"])[0]

        assert rd.attributes["vsphere"]["tags"] == {}


class TestErrorHandling:
    def test_unknown_kind_raises_value_error(self):
        from lemma.services.vsphere_discovery import discover_resources_from_vsphere

        with pytest.raises(ValueError, match=r"(?i)unknown.*kind|cluster"):
            discover_resources_from_vsphere(
                content=_fake_content(),
                vc_host="vc",
                kinds=["cluster"],
            )

    def test_empty_kinds_raises_value_error(self):
        from lemma.services.vsphere_discovery import discover_resources_from_vsphere

        with pytest.raises(ValueError, match=r"(?i)at least one|empty"):
            discover_resources_from_vsphere(
                content=_fake_content(),
                vc_host="vc",
                kinds=[],
            )

    def test_no_permission_on_one_kind_continues_others(self):
        from lemma.services.vsphere_discovery import discover_resources_from_vsphere

        # NoPermission on hosts; vms + datastores still succeed.
        content = _fake_content(
            vms=[_make_vm(moid="vm-1")],
            datastores=[_make_datastore(moid="ds-1")],
            raises_on={"HostSystem": vim.fault.NoPermission()},
        )

        result = discover_resources_from_vsphere(
            content=content,
            vc_host="vc",
            kinds=["vm", "host", "datastore"],
        )

        types = {r.type for r in result}
        assert "vsphere.host" not in types
        assert "vsphere.vm" in types
        assert "vsphere.datastore" in types
