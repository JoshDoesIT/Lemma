"""Ansible inventory discovery (Refs #24).

Reads ``ansible-inventory --list`` JSON output and emits one
``ResourceDefinition`` per host. Same shape the cloud / file discovery
services return, so the discover command feeds Ansible-imported hosts
through the existing matcher and graph-write loop.

Operator generates the JSON themselves via::

    ansible-inventory --list -i my-hosts > inventory.json

This means no Ansible install is required on Lemma's host. The JSON
shape is universal across static INI / static YAML / dynamic plugin
inventories — the operator's existing Ansible toolchain handles the
inventory-format details.

Group-as-boolean projection: each group a host belongs to becomes
``attributes["ansible"]["groups"][<group>] = True`` so scope rules can
target group membership via the existing matcher's ``equals`` operator.
The matcher's ``CONTAINS`` is string-substring-only and ``IN`` requires
``actual in rule.value list`` — neither supports list-membership-of-
groups cleanly, so the boolean projection is the cleanest way to keep
the matcher unchanged.

Group hierarchy is resolved transitively: a host in ``webservers`` that
is a child of ``production`` is recorded as belonging to BOTH groups.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lemma.models.resource import ResourceDefinition


def discover_resources_from_ansible(path: Path) -> list[ResourceDefinition]:
    """Parse an Ansible inventory JSON file and return ResourceDefinition records.

    Args:
        path: Path to a JSON file produced by ``ansible-inventory --list``.

    Returns:
        List of ``ResourceDefinition``, one per host in ``_meta.hostvars``.
        Empty inventory returns ``[]`` (not an error).

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        ValueError: If the file is not valid JSON.
    """
    if not path.exists():
        msg = f"File not found: {path}"
        raise FileNotFoundError(msg)

    try:
        inventory = json.loads(path.read_text() or "{}")
    except json.JSONDecodeError as exc:
        msg = f"Could not parse {path} as JSON: {exc}"
        raise ValueError(msg) from exc

    if not isinstance(inventory, dict):
        return []

    host_to_groups = _resolve_host_groups(inventory)
    hostvars_block = inventory.get("_meta", {}).get("hostvars", {}) or {}

    discovered: list[ResourceDefinition] = []
    for hostname, host_vars in hostvars_block.items():
        host_vars = host_vars or {}
        groups = host_to_groups.get(hostname, set())
        attributes: dict[str, Any] = {
            "ansible": {
                "hostname": hostname,
                "ansible_host": host_vars.get("ansible_host", ""),
                "host_vars": dict(host_vars),
                "groups": {group: True for group in sorted(groups)},
            }
        }
        discovered.append(
            ResourceDefinition(
                id=f"ansible-{hostname}",
                type="ansible.host",
                scope="",
                attributes=attributes,
            )
        )

    return discovered


def _resolve_host_groups(inventory: dict) -> dict[str, set[str]]:
    """Build ``host -> {transitively-reachable groups}`` from an inventory dict.

    Walks ``hosts`` lists for direct membership, then unwinds ``children``
    relationships so a host in ``webservers`` (a child of ``production``)
    appears in both groups.
    """
    # Direct membership: host -> groups it's directly listed in.
    direct: dict[str, set[str]] = {}
    # Group hierarchy: child -> parents-that-list-it-as-a-child.
    parents: dict[str, set[str]] = {}

    for key, value in inventory.items():
        if key == "_meta" or not isinstance(value, dict):
            continue
        for host in value.get("hosts", []) or []:
            direct.setdefault(host, set()).add(key)
        for child in value.get("children", []) or []:
            parents.setdefault(child, set()).add(key)

    # Walk transitive closure: for each direct group, follow `parents` chains.
    resolved: dict[str, set[str]] = {}
    for host, host_groups in direct.items():
        all_groups: set[str] = set()
        stack = list(host_groups)
        while stack:
            group = stack.pop()
            if group in all_groups:
                continue
            all_groups.add(group)
            stack.extend(parents.get(group, set()))
        # Drop the implicit "all" / "ungrouped" groups — operators almost
        # never want to write rules against those.
        all_groups.discard("all")
        all_groups.discard("ungrouped")
        resolved[host] = all_groups

    return resolved
