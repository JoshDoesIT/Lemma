"""AI trace model — structured audit trail for every AI decision.

Every AI operation in Lemma (mapping, evaluation, summarization) produces
an AITrace record. Traces are append-only and version-controlled, ensuring
full transparency and auditability of AI-generated compliance assertions.

Trace lifecycle:
    PROPOSED → ACCEPTED (engineer approves)
    PROPOSED → REJECTED (engineer rejects with rationale)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class TraceStatus(StrEnum):
    """Review status for an AI trace entry.

    Attributes:
        PROPOSED: AI output awaiting human review.
        ACCEPTED: Engineer has approved the AI determination.
        REJECTED: Engineer has rejected with rationale.
    """

    PROPOSED = "PROPOSED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class AITrace(BaseModel):
    """A single AI decision trace record.

    Captures the full context of an AI operation: what went in,
    what prompt was used, which model produced the output, and
    the resulting determination with confidence.

    Attributes:
        trace_id: Unique identifier for this trace entry.
        timestamp: UTC timestamp of when the trace was created.
        operation: Type of AI operation (e.g., 'map', 'evaluate').
        input_text: The input text provided to the AI.
        prompt: The full prompt sent to the model.
        model_id: Model identifier (e.g., 'ollama/llama3.2').
        model_version: Model version string.
        raw_output: The raw response from the model.
        confidence: AI-generated confidence score (0.0-1.0).
        determination: The AI's determination (e.g., 'MAPPED', 'LOW_CONFIDENCE').
        control_id: Target control identifier.
        framework: Target framework name.
        status: Human review status (PROPOSED, ACCEPTED, REJECTED).
        review_rationale: Rationale for acceptance/rejection (required for REJECTED).
        parent_trace_id: For review entries, the trace_id of the original trace.
        auto_accepted: True if the review entry was produced by confidence-gated
            automation rather than a human reviewer.
        related_control_id: Secondary control identifier for pair events
            (e.g. harmonization equivalences link two controls). Empty for
            single-control operations like ``map``.
        related_framework: Secondary framework name for pair events.
    """

    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    operation: str
    input_text: str
    prompt: str
    model_id: str
    model_version: str
    raw_output: str
    confidence: float
    determination: str
    control_id: str
    framework: str
    status: TraceStatus = TraceStatus.PROPOSED
    review_rationale: str = ""
    parent_trace_id: str = ""
    auto_accepted: bool = False
    related_control_id: str = ""
    related_framework: str = ""
    operation_kind: Literal["decision", "read"] = "decision"
