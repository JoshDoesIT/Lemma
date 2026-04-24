"""Terraform plan parser.

Reads the JSON output of ``terraform show -json plan.tfplan`` and
extracts the ``resource_changes`` list into typed records. No-op
changes are dropped because they don't move scope membership.

Full plan JSON format is documented at
https://developer.hashicorp.com/terraform/internals/json-format;
this parser cares only about the ``resource_changes`` subtree.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ResourceChange:
    """A single resource change from a Terraform plan.

    Attributes:
        address: Terraform resource address, e.g. ``aws_s3_bucket.main``.
        type: Terraform resource type, e.g. ``aws_s3_bucket``.
        actions: Sequence of actions from the plan
            (``create``, ``update``, ``delete``, ``read``, ``no-op``).
        before: Resource state before the change, or ``None`` for creates.
        after: Resource state after the change, or ``None`` for deletes.
    """

    address: str
    type: str
    actions: list[str]
    before: dict | None
    after: dict | None


def parse_terraform_plan(path: Path) -> list[ResourceChange]:
    """Parse a Terraform plan JSON file into a list of ResourceChange records.

    No-op changes are filtered out — a plan row whose only action is
    ``no-op`` cannot move a resource between scopes.

    Raises:
        ValueError: On malformed JSON or a plan file missing the
            ``resource_changes`` key.
    """
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        msg = f"{path.name}: could not parse JSON ({exc.msg} at line {exc.lineno})."
        raise ValueError(msg) from exc

    if "resource_changes" not in data:
        msg = (
            f"{path.name}: no 'resource_changes' key. Did you generate this "
            "with 'terraform show -json plan.tfplan > plan.json'?"
        )
        raise ValueError(msg)

    changes: list[ResourceChange] = []
    for entry in data["resource_changes"]:
        change_block = entry.get("change", {})
        actions = list(change_block.get("actions", []))
        if actions == ["no-op"]:
            continue
        changes.append(
            ResourceChange(
                address=entry["address"],
                type=entry.get("type", ""),
                actions=actions,
                before=change_block.get("before"),
                after=change_block.get("after"),
            )
        )
    return changes
