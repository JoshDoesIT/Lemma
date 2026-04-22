"""OCSF event normalization.

Accepts raw OCSF payloads (as dicts or JSON strings) and returns the
matching concrete Pydantic model from ``lemma.models.ocsf``. A single
Pydantic discriminated-union ``TypeAdapter`` drives dispatch: the
``class_uid`` field on every OCSF event is the sole discriminator.

The same adapter is exported as ``ocsf_adapter`` for reuse by the
evidence log when reading JSONL lines back into typed events.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, TypeAdapter

from lemma.models.ocsf import (
    AuthenticationEvent,
    ComplianceFinding,
    DetectionFinding,
    OcsfBaseEvent,
)

OcsfEvent = Annotated[
    ComplianceFinding | DetectionFinding | AuthenticationEvent,
    Field(discriminator="class_uid"),
]

ocsf_adapter: TypeAdapter[OcsfEvent] = TypeAdapter(OcsfEvent)


def normalize(payload: dict) -> OcsfBaseEvent:
    """Validate and dispatch an OCSF payload to its concrete model.

    Args:
        payload: OCSF-shaped dict. Must include ``class_uid``.

    Returns:
        The concrete event model keyed by ``class_uid``.

    Raises:
        ValueError: On missing/unknown ``class_uid``, validation errors
            from the discriminated union, or a naive (tz-less) ``time``
            value — OCSF is UTC on the wire, so a naive datetime at the
            ingest boundary is almost certainly a producer bug.
    """
    event = ocsf_adapter.validate_python(payload)
    if event.time.tzinfo is None:
        msg = (
            "OCSF event 'time' must carry tzinfo (UTC). Got a naive datetime "
            f"for {type(event).__name__} (class_uid={event.class_uid})."
        )
        raise ValueError(msg)
    return event
