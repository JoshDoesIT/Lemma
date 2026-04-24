"""Person-as-code parser.

Reads ``people/*.yaml`` files from a Lemma project and validates them
against the strict ``PersonDefinition`` schema. Errors carry enough
context (file, line, column) for operators to jump straight to the
offending record.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from lemma.models.person import PersonDefinition


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


def load_person(path: Path) -> PersonDefinition:
    """Parse and validate a single person-as-code YAML file."""
    text = path.read_text()
    try:
        data = yaml.safe_load(text)
    except yaml.MarkedYAMLError as exc:
        raise _yaml_error_to_value_error(path, exc) from exc

    if not isinstance(data, dict):
        msg = f"{path.name}: top-level YAML must be a mapping, got {type(data).__name__}."
        raise ValueError(msg)

    try:
        return PersonDefinition.model_validate(data)
    except ValidationError as exc:
        raise _validation_error_to_value_error(path, exc) from exc


def load_all_people(people_dir: Path) -> list[PersonDefinition]:
    """Parse every ``*.yaml`` / ``*.yml`` file in the directory.

    Accumulates all errors across files before raising, so operators
    editing multiple people see the full picture in one pass.
    """
    if not people_dir.exists():
        return []

    files = sorted(
        list(people_dir.glob("*.yaml")) + list(people_dir.glob("*.yml")),
        key=lambda p: p.name,
    )

    people: list[PersonDefinition] = []
    errors: list[str] = []
    for path in files:
        try:
            people.append(load_person(path))
        except ValueError as exc:
            errors.append(str(exc))

    if errors:
        raise ValueError("\n".join(errors))

    people.sort(key=lambda p: p.id)
    return people
