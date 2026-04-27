"""Minimal SARIF 2.1.0 Pydantic subset for `lemma check --format sarif`.

Only the fields Lemma actually emits — emitting one result per failed
control so GitHub Code Scanning / GitLab CI surface compliance failures
alongside SAST findings. Avoids pulling in a full SARIF library for what
is effectively a 50-line schema slice.

SARIF mandates camelCase on the wire. To keep Python identifiers
snake_case (and ruff's N815 happy), every camelCase field uses a
Pydantic alias. Callers must serialize with ``model_dump(by_alias=True)``
or ``model_dump_json(by_alias=True)`` to emit the spec-conformant shape.

Spec reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

_MODEL_CONFIG = ConfigDict(populate_by_name=True)


class SarifMessage(BaseModel):
    text: str


class SarifArtifactLocation(BaseModel):
    uri: str


class SarifPhysicalLocation(BaseModel):
    model_config = _MODEL_CONFIG
    artifact_location: SarifArtifactLocation = Field(alias="artifactLocation")


class SarifLocation(BaseModel):
    model_config = _MODEL_CONFIG
    physical_location: SarifPhysicalLocation = Field(alias="physicalLocation")


class SarifResult(BaseModel):
    model_config = _MODEL_CONFIG
    rule_id: str = Field(alias="ruleId")
    level: Literal["error", "warning", "note", "none"]
    message: SarifMessage
    locations: list[SarifLocation]
    properties: dict[str, Any] = Field(default_factory=dict)


class SarifRule(BaseModel):
    model_config = _MODEL_CONFIG
    id: str
    name: str
    short_description: SarifMessage = Field(alias="shortDescription")
    help_uri: str | None = Field(default=None, alias="helpUri")


class SarifDriver(BaseModel):
    model_config = _MODEL_CONFIG
    name: str
    version: str
    information_uri: str = Field(
        default="https://github.com/JoshDoesIT/Lemma", alias="informationUri"
    )
    rules: list[SarifRule]


class SarifTool(BaseModel):
    driver: SarifDriver


class SarifRun(BaseModel):
    tool: SarifTool
    results: list[SarifResult]


class SarifLog(BaseModel):
    model_config = _MODEL_CONFIG
    version: Literal["2.1.0"] = "2.1.0"
    schema_uri: str = Field(
        default="https://json.schemastore.org/sarif-2.1.0.json", alias="$schema"
    )
    runs: list[SarifRun]
