"""Terraform state-file discovery for the scope engine (Refs #24).

Parses a Terraform state file (``terraform.tfstate``) and yields a
``ResourceDefinition`` per managed resource instance — the same shape
``lemma.services.aws_discovery`` returns, so the scope-discover command
can feed both sources through the existing matcher and graph-write loop.

Distinct from ``terraform_plan.parse_terraform_plan``: state files
encode the current set of deployed resources (top-level ``resources[]``),
plan files encode proposed changes (top-level ``resource_changes[]``).
The two parsers live side-by-side; passing a plan file here raises with
a hint pointing at ``lemma scope impact --plan``.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from lemma.models.resource import ResourceDefinition

_REDACTED = "<redacted>"

# Three-entry v0 map. Maintain consistency with aws_discovery emit shapes
# only for types that already have an AWS-API discovery counterpart. Add
# a row the day a scope rule needs another type ported across sources.
_TYPE_MAP: dict[str, tuple[str, str]] = {
    # tf_type -> (lemma_type, aws_service)
    "aws_instance": ("aws.ec2.instance", "ec2"),
    "aws_s3_bucket": ("aws.s3.bucket", "s3"),
    "aws_iam_user": ("aws.iam.user", "iam"),
}


def discover_resources_from_state(path: Path) -> list[ResourceDefinition]:
    """Parse a Terraform state file and return ResourceDefinition candidates.

    Args:
        path: Path to a ``terraform.tfstate`` file (local JSON).

    Returns:
        List of ``ResourceDefinition``. Each managed resource instance
        becomes one entry. ``mode: "data"`` resources, empty
        ``instances`` lists, and tfstate without any ``resources[]``
        produce no entries.

    Raises:
        ValueError: If the file is not valid JSON or doesn't look like a
            Terraform state file (missing ``terraform_version``). When
            the file looks like a plan instead, the error names
            ``lemma scope impact --plan`` so the operator can switch.
    """
    raw = path.read_text()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        msg = f"Could not parse {path} as JSON: {exc}"
        raise ValueError(msg) from exc

    if not isinstance(payload, dict) or "terraform_version" not in payload:
        if isinstance(payload, dict) and "resource_changes" in payload:
            msg = (
                f"{path} looks like a Terraform plan, not a state file. "
                "Use 'lemma scope impact --plan' for plans."
            )
        else:
            msg = (
                f"{path} is missing 'terraform_version' — does not look like a "
                "Terraform state file."
            )
        raise ValueError(msg)

    resources_block = payload.get("resources") or []
    if not isinstance(resources_block, list):
        return []

    discovered: list[ResourceDefinition] = []
    for resource in resources_block:
        if not isinstance(resource, dict):
            continue
        if resource.get("mode") != "managed":
            continue

        tf_type = str(resource.get("type", ""))
        name = str(resource.get("name", ""))
        if not tf_type or not name:
            continue

        instances = resource.get("instances") or []
        if not isinstance(instances, list):
            continue

        for instance in instances:
            if not isinstance(instance, dict):
                continue
            attributes_raw = instance.get("attributes") or {}
            if not isinstance(attributes_raw, dict):
                continue

            redacted_attrs = _apply_redaction(
                copy.deepcopy(attributes_raw),
                instance.get("sensitive_attributes") or [],
                instance.get("sensitive_values") or {},
            )

            lemma_type, wrapped_attrs = _wrap_attributes(tf_type, redacted_attrs)

            discovered.append(
                ResourceDefinition(
                    id=_resource_id(tf_type, name, instance.get("index_key")),
                    type=lemma_type,
                    scope="",
                    attributes=wrapped_attrs,
                )
            )
    return discovered


def _resource_id(tf_type: str, name: str, index_key: Any) -> str:
    """Return a stable, address-derived ResourceDefinition id.

    ``count``-indexed instances use int suffixes (``[0]``);
    ``for_each``-indexed instances use string suffixes (``[us-east-1a]``).
    Un-indexed instances get no suffix.
    """
    if index_key is None:
        return f"tf-{tf_type}.{name}"
    return f"tf-{tf_type}.{name}[{index_key}]"


def _wrap_attributes(tf_type: str, attrs: dict) -> tuple[str, dict]:
    """Map TF type to Lemma type and wrap attributes per source convention.

    Mapped AWS types share AWS-API discovery's ``attributes["aws"][...]``
    shape so existing scope rules port; everything else lives under
    ``attributes["tf"]`` so operators write source-specific rules
    deliberately.
    """
    if tf_type in _TYPE_MAP:
        lemma_type, aws_service = _TYPE_MAP[tf_type]
        # Spread first, then overwrite canonical keys.
        canonical = {
            **{k: v for k, v in attrs.items() if k not in {"service", "region", "tags"}},
            "service": aws_service,
            "region": attrs.get("region", ""),
            "tags": attrs.get("tags") or {},
        }
        return lemma_type, {"aws": canonical}

    return tf_type, {"tf": attrs}


def _apply_redaction(
    attrs: dict,
    sensitive_attributes: list,
    sensitive_values: dict,
) -> dict:
    """Replace sensitive values with ``<redacted>`` in-place and return ``attrs``.

    Walks both encoding formats Terraform uses for sensitivity:

    * ``sensitive_attributes`` — a list whose entries are either plain
      strings (top-level keys) or step lists with ``get_attr`` / ``index``
      objects describing a path into the attribute tree.
    * ``sensitive_values`` — a dict that mirrors ``attributes`` with
      ``True`` markers at sensitive nodes.

    Paths that don't resolve in ``attrs`` are silently skipped (stale
    state vs current schema).
    """
    for entry in sensitive_attributes or []:
        if isinstance(entry, str):
            if entry in attrs:
                attrs[entry] = _REDACTED
        elif isinstance(entry, list):
            _redact_step_path(attrs, entry)

    if sensitive_values:
        _redact_via_mirror(attrs, sensitive_values)

    return attrs


def _redact_step_path(node: Any, steps: list) -> None:
    """Walk a ``[{type, value}, ...]`` step list and redact the target node."""
    current = node
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            return
        step_type = step.get("type")
        key: Any = step.get("value")
        if step_type == "index" and isinstance(key, dict):
            key = key.get("value")

        is_last = i == len(steps) - 1
        if step_type == "get_attr":
            if not isinstance(current, dict) or key not in current:
                return
            if is_last:
                current[key] = _REDACTED
                return
            current = current[key]
        elif step_type == "index":
            if not isinstance(current, list):
                return
            try:
                idx = int(key)
            except (TypeError, ValueError):
                return
            if idx < 0 or idx >= len(current):
                return
            if is_last:
                current[idx] = _REDACTED
                return
            current = current[idx]
        else:
            return


def _redact_via_mirror(node: Any, mirror: Any) -> None:
    """Walk ``mirror`` (parallel structure with True at sensitive nodes) and redact ``node``."""
    if mirror is True:
        return  # Caller handles top-level boolean.
    if isinstance(mirror, dict) and isinstance(node, dict):
        for key, sub_mirror in mirror.items():
            if key not in node:
                continue
            if sub_mirror is True:
                node[key] = _REDACTED
            else:
                _redact_via_mirror(node[key], sub_mirror)
    elif isinstance(mirror, list) and isinstance(node, list):
        for idx, sub_mirror in enumerate(mirror):
            if idx >= len(node):
                continue
            if sub_mirror is True:
                node[idx] = _REDACTED
            else:
                _redact_via_mirror(node[idx], sub_mirror)
