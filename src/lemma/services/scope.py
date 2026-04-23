"""Scope-as-code parser.

Reads ``scopes/*.yaml`` files from a Lemma project and validates them
against the strict ``ScopeDefinition`` schema. Errors carry enough
context (file, line, column when available) for operators to jump
straight to the offending record.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from lemma.models.scope import ScopeDefinition


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


def load_scope(path: Path) -> ScopeDefinition:
    """Parse and validate a single scope-as-code YAML file."""
    text = path.read_text()
    try:
        data = yaml.safe_load(text)
    except yaml.MarkedYAMLError as exc:
        raise _yaml_error_to_value_error(path, exc) from exc

    if not isinstance(data, dict):
        msg = f"{path.name}: top-level YAML must be a mapping, got {type(data).__name__}."
        raise ValueError(msg)

    try:
        return ScopeDefinition.model_validate(data)
    except ValidationError as exc:
        raise _validation_error_to_value_error(path, exc) from exc


def load_all_scopes(scopes_dir: Path) -> list[ScopeDefinition]:
    """Parse every ``*.yaml`` / ``*.yml`` file in the directory.

    Accumulates all errors across files before raising, so operators
    editing multiple scopes see the full picture in one pass.
    """
    if not scopes_dir.exists():
        return []

    files = sorted(
        list(scopes_dir.glob("*.yaml")) + list(scopes_dir.glob("*.yml")),
        key=lambda p: p.name,
    )

    scopes: list[ScopeDefinition] = []
    errors: list[str] = []
    for path in files:
        try:
            scopes.append(load_scope(path))
        except ValueError as exc:
            errors.append(str(exc))

    if errors:
        raise ValueError("\n".join(errors))

    scopes.sort(key=lambda s: s.name)
    return scopes
