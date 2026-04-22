"""OCSF (Open Cybersecurity Schema Framework) event type models.

Defines a minimal set of OCSF v1.x event classes used to normalize
evidence collected by future connectors (SIEM, CSPM, ITSM, IdP) into a
common, vendor-agnostic schema before it enters Lemma's compliance
graph.

Divergence from the repo's ``StrEnum`` convention: OCSF uses integer
identifiers on the wire (``class_uid``, ``category_uid``,
``severity_id`` are all ints), so the enums below are ``IntEnum`` to
serialize correctly without coercion. See
https://schema.ocsf.io/ for the authoritative schema.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, Field, model_validator


class OcsfCategory(IntEnum):
    """OCSF top-level event categories."""

    FINDINGS = 2000
    IAM = 3000


class OcsfSeverity(IntEnum):
    """OCSF severity levels (``severity_id`` field)."""

    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


class OcsfBaseEvent(BaseModel):
    """Shared fields for every OCSF event.

    Attributes:
        class_uid: OCSF class identifier (e.g. 2003 for Compliance Finding).
        class_name: Human-readable class name.
        category_uid: Top-level category identifier (e.g. 2000 for Findings).
        category_name: Human-readable category name.
        type_uid: Specific type within the class (class-specific encoding).
        time: Event occurrence time (defaults to now, UTC).
        severity_id: OCSF severity level; defaults to INFORMATIONAL.
        activity_id: Class-specific activity identifier.
        metadata: OCSF metadata object (product, version, etc.).
        status_id: Class-specific status code (0 = Unknown).
        message: Free-form event message.
    """

    class_uid: int
    class_name: str
    category_uid: int
    category_name: str
    type_uid: int
    time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    severity_id: OcsfSeverity = OcsfSeverity.INFORMATIONAL
    activity_id: int
    metadata: dict[str, Any] = Field(default_factory=dict)
    status_id: int = 0
    message: str = ""


class _CategoryPinnedEvent(OcsfBaseEvent):
    """Base for concrete classes that pin a specific OCSF category.

    Subclasses declare ``_expected_category`` and a ``Literal`` default
    on ``class_uid``; the validator below asserts ``category_uid``
    matches the declared category so miswired producers fail loudly.
    """

    _expected_category: ClassVar[int]

    @model_validator(mode="after")
    def _enforce_category(self) -> _CategoryPinnedEvent:
        if self.category_uid != self._expected_category:
            msg = (
                f"{type(self).__name__} requires category_uid="
                f"{self._expected_category}, got {self.category_uid}."
            )
            raise ValueError(msg)
        return self


class ComplianceFinding(_CategoryPinnedEvent):
    """OCSF Compliance Finding (class_uid=2003, Findings category)."""

    _expected_category: ClassVar[int] = OcsfCategory.FINDINGS
    class_uid: Literal[2003] = 2003


class DetectionFinding(_CategoryPinnedEvent):
    """OCSF Detection Finding (class_uid=2004, Findings category).

    Detection Finding replaces the deprecated Security Finding (2001)
    in OCSF 1.1+ and is the preferred class for modern producers.
    """

    _expected_category: ClassVar[int] = OcsfCategory.FINDINGS
    class_uid: Literal[2004] = 2004


class AuthenticationEvent(_CategoryPinnedEvent):
    """OCSF Authentication (class_uid=3002, IAM category)."""

    _expected_category: ClassVar[int] = OcsfCategory.IAM
    class_uid: Literal[3002] = 3002
