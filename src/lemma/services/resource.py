"""Resource-as-code parser.

Reads ``resources/*.yaml`` and ``resources/*.hcl`` files from a Lemma
project and validates them against the strict ``ResourceDefinition``
schema. Both formats converge on
``ResourceDefinition.model_validate(dict_)`` — the Pydantic model is
format-agnostic. Errors carry enough context (file, line, column when
available for YAML) for operators to jump straight to the offending
record.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from lemma.models.resource import ResourceDefinition
from lemma.services.resource_hcl import parse_resource_hcl


def _yaml_error_to_value_error(path: Path, exc: yaml.MarkedYAMLError) -> ValueError:
    mark = exc.problem_mark or exc.context_mark
    location = f"{path.name}:{mark.line + 1}:{mark.column + 1}" if mark is not None else path.name
    reason = exc.problem or exc.context or "invalid YAML"
    return ValueError(f"{location}: {reason}")


def _validation_error_to_value_error(path: Path, exc: ValidationError) -> ValueError:
    details = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "(root)"
        details.append(f"{loc}: {err['msg']}")
    return ValueError(f"{path.name}: " + "; ".join(details))


def load_resource(path: Path) -> ResourceDefinition:
    """Parse and validate a single resource-as-code file (YAML or HCL)."""
    text = path.read_text()
    if path.suffix == ".hcl":
        try:
            data = parse_resource_hcl(text)
        except ValueError as exc:
            raise ValueError(f"{path.name}: {exc}") from exc
    else:
        try:
            data = yaml.safe_load(text)
        except yaml.MarkedYAMLError as exc:
            raise _yaml_error_to_value_error(path, exc) from exc

    if not isinstance(data, dict):
        msg = f"{path.name}: top-level must be a mapping, got {type(data).__name__}."
        raise ValueError(msg)

    try:
        return ResourceDefinition.model_validate(data)
    except ValidationError as exc:
        raise _validation_error_to_value_error(path, exc) from exc


def load_all_resources(resources_dir: Path) -> list[ResourceDefinition]:
    """Parse every ``*.yaml`` / ``*.yml`` / ``*.hcl`` file in the directory.

    Accumulates all errors across files before raising, so operators
    editing multiple resources see the full picture in one pass.
    """
    if not resources_dir.exists():
        return []

    files = sorted(
        list(resources_dir.glob("*.yaml"))
        + list(resources_dir.glob("*.yml"))
        + list(resources_dir.glob("*.hcl")),
        key=lambda p: p.name,
    )

    resources: list[ResourceDefinition] = []
    errors: list[str] = []
    for path in files:
        try:
            resources.append(load_resource(path))
        except ValueError as exc:
            errors.append(str(exc))

    if errors:
        raise ValueError("\n".join(errors))

    resources.sort(key=lambda r: r.id)
    return resources
