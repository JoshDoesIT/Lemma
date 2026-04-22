"""Structured query plan produced by the NL → graph translator.

The LLM takes a natural-language question and returns a ``QueryPlan``
describing a bounded traversal the executor knows how to run. The
plan is the contract between the model (which gets to be creative)
and the executor (which only does what's in the plan).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class QueryTraversal(StrEnum):
    """Kinds of traversal the executor supports.

    Attributes:
        NEIGHBORS: One-hop traversal from ``entry_node``; the most
            general shape, refined by ``edge_filter`` and ``direction``.
        IMPACT: ``ComplianceGraph.impact`` — downstream controls and
            frameworks reachable from the entry node.
        FRAMEWORK_CONTROL_COUNT: Scalar count of controls in a framework.
    """

    NEIGHBORS = "NEIGHBORS"
    IMPACT = "IMPACT"
    FRAMEWORK_CONTROL_COUNT = "FRAMEWORK_CONTROL_COUNT"


class QueryPlan(BaseModel):
    """A bounded, executor-validated graph traversal plan.

    Attributes:
        entry_node: Fully qualified starting node ID (e.g.
            ``"control:nist-800-53:ac-2"``). Short names like ``"ac-2"``
            are resolved against the graph before execution.
        traversal: Which kind of walk to perform.
        edge_filter: When non-empty, only edges whose relationship is in
            this list are traversed. Applies to NEIGHBORS.
        direction: Filter on edge direction relative to ``entry_node``.
            ``"out"`` = only outgoing edges, ``"in"`` = only incoming,
            ``"both"`` = no direction filter.
        output_shape: ``"list"`` returns a list of result dicts;
            ``"count"`` returns an integer.
    """

    entry_node: str
    traversal: QueryTraversal
    edge_filter: list[str] = Field(default_factory=list)
    direction: Literal["in", "out", "both"] = "both"
    output_shape: Literal["list", "count"] = "list"
