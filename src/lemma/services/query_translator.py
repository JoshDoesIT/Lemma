"""Translate natural-language questions into structured ``QueryPlan``s.

The translator is the bridge between the LLM (which gets to be creative
about interpreting the user's intent) and the executor (which only runs
bounded plans). It does three things:

1. Summarize the graph schema so the LLM knows what node types,
   relationship types, and entry-node IDs actually exist.
2. Prompt the LLM for a JSON plan matching ``QueryPlan``. Retry once
   with validation feedback on malformed output. Fail loud after that.
3. Resolve short entry-node names (e.g. ``"ac-2"``) against the real
   graph, because LLMs routinely drop the framework qualifier.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from pydantic import TypeAdapter, ValidationError

from lemma.models.query_plan import QueryPlan
from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.llm import LLMClient

_plan_adapter: TypeAdapter[QueryPlan] = TypeAdapter(QueryPlan)

_PROMPT_TEMPLATE = """\
You are translating a user's natural-language question into a structured
graph query plan for the Lemma compliance knowledge graph.

Respond ONLY with a JSON object matching this schema:
  {{
    "entry_node": "<fully qualified node id, e.g. 'control:nist-800-53:ac-2'>",
    "traversal": "NEIGHBORS" | "IMPACT" | "FRAMEWORK_CONTROL_COUNT",
    "edge_filter": ["<relationship>", ...] (optional; pick from the relationship
        types in the schema summary below),
    "direction": "in" | "out" | "both" (optional, default "both"),
    "output_shape": "list" | "count" (optional, default "list"),
    "time_range": ["<ISO-8601 start>", "<ISO-8601 end>"] (optional; half-open),
    "severity": ["HIGH", "CRITICAL", ...] (optional; OCSF severity names),
    "producer": ["GitHub", "AWS", ...] (optional; Evidence producer names),
    "class_uid": [3002, ...] (optional; OCSF class_uid ints),
    "follow": [{{ "edge_filter": [...], "direction": "...", "node_filter": {{...}} }}, ...]
        (optional; max 2 entries — total traversal capped at 3 hops)
  }}

Graph schema (what actually exists today):
{schema_summary}

Edge type cheatsheet — pick the right filter and direction:
  - SATISFIES (Policy -> Control): "Which policies satisfy AC-2?" direction=in
  - HARMONIZED_WITH (Control <-> Control): "What controls harmonize with AC-2?"
  - CONTAINS (Framework -> Control): "List controls in NIST 800-53"
  - EVIDENCES (Evidence -> Control): "What evidence supports CC6.1?" direction=in
  - SCOPED_TO (Resource -> Scope): "What resources are in prod scope?" direction=in
  - OWNS (Person -> Control|Resource): "Who owns AC-2?" direction=in from the target
  - IMPACTS (Resource -> Control): "Which resources impact AU-2?" direction=in
  - THREATENS (Risk -> Resource): "What risks threaten the audit bucket?" direction=in
  - MITIGATED_BY (Risk -> Control): "What risks does CP-9 mitigate?" direction=in
  - APPLIES_TO (Scope -> Framework): "What scopes apply to NIST CSF?" direction=in
Disambiguation: IMPACTS connects Resource to Control; MITIGATED_BY connects Risk
to Control. A question about which Resource depends on a Control uses IMPACTS;
a question about which Risk a Control mitigates uses MITIGATED_BY.

Multi-hop chains (use only when the question genuinely needs more than one
edge; single-hop questions stay single-hop). Each entry in "follow" adds one
more hop from the prior hop's results. Max 3 hops total (entry + 2 follow).
Per-hop "node_filter" narrows the *prior hop's results* before walking the
current edge — read it as "from prior-hop nodes matching X, walk edge Y."
  - "What harmonized controls cover framework nist-csf-2.0?"
      entry_node="framework:nist-csf-2.0", edge_filter=["CONTAINS"], direction="out",
      follow=[{{"edge_filter": ["HARMONIZED_WITH"]}}]
  - "Which policies satisfy controls in the IA family?"
      entry_node="framework:nist-800-53", edge_filter=["CONTAINS"], direction="out",
      follow=[{{"node_filter": {{"family": "IA"}},
                "edge_filter": ["SATISFIES"], "direction": "in"}}]

Evidence attribute filters (apply only to Evidence-typed nodes; non-Evidence
nodes reached by the same plan walk through unchanged):
  - time_range: ["2026-04-26T00:00:00+00:00", "2026-04-27T00:00:00+00:00"]
      "What evidence landed in the last 24 hours?" — half-open [start, end).
  - severity: ["HIGH", "CRITICAL"]
      "Show me critical-severity findings." — OCSF severity *names*.
  - producer: ["GitHub", "AWS"]
      "Authentication events from the GitHub connector."
  - class_uid: [3002]
      "Auth events" — OCSF class_uid (e.g. 3002 = Authentication).

Example entry nodes in this graph:
{example_nodes}

User question:
{question}

{feedback}Return JSON only. No markdown fences, no commentary."""


def _schema_summary(graph: ComplianceGraph) -> str:
    export = graph.export_json()
    node_type_counts = Counter(n.get("type", "Unknown") for n in export["nodes"])
    edge_type_counts = Counter(e.get("relationship", "Unknown") for e in export["edges"])
    lines = ["Node types:"]
    for ntype, count in sorted(node_type_counts.items()):
        lines.append(f"  - {ntype} ({count})")
    lines.append("Relationship types:")
    for etype, count in sorted(edge_type_counts.items()):
        lines.append(f"  - {etype} ({count})")
    return "\n".join(lines)


def _example_nodes(graph: ComplianceGraph, limit: int = 5) -> str:
    export = graph.export_json()
    ids_by_type: dict[str, list[str]] = {}
    for node in export["nodes"]:
        ntype = node.get("type", "Unknown")
        ids_by_type.setdefault(ntype, []).append(node["id"])
    lines: list[str] = []
    for ntype, ids in sorted(ids_by_type.items()):
        lines.append(f"  {ntype}:")
        for nid in ids[:limit]:
            lines.append(f"    - {nid}")
    return "\n".join(lines)


def _resolve_entry_node(raw: str, graph: ComplianceGraph) -> str:
    """Resolve an LLM-supplied entry_node against real graph node IDs.

    Resolution order:
      1. Exact match — return as-is.
      2. Case-insensitive suffix match on ``:{raw}`` — e.g. ``"ac-2"``
         resolves to ``"control:nist-800-53:ac-2"``.
      3. Zero candidates → return the raw value; ``execute`` raises the
         standard "entry_node not found" error with consistent wording.
      4. Multiple candidates → raise listing all of them.
    """
    export = graph.export_json()
    all_ids = [n["id"] for n in export["nodes"]]

    if raw in all_ids:
        return raw

    suffix = f":{raw.lower()}"
    candidates = [nid for nid in all_ids if nid.lower().endswith(suffix)]
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        listed = ", ".join(candidates)
        msg = (
            f"entry_node '{raw}' is ambiguous — multiple nodes match: {listed}. "
            f"Rephrase the question with a framework qualifier."
        )
        raise ValueError(msg)
    return raw


def _build_prompt(question: str, graph: ComplianceGraph, feedback: str = "") -> str:
    return _PROMPT_TEMPLATE.format(
        schema_summary=_schema_summary(graph),
        example_nodes=_example_nodes(graph),
        question=question,
        feedback=(feedback + "\n\n") if feedback else "",
    )


def _try_parse(raw: str) -> tuple[QueryPlan | None, str]:
    """Return ``(plan, error)`` — exactly one is non-empty."""
    try:
        payload: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"Response is not valid JSON: {exc}"
    try:
        return _plan_adapter.validate_python(payload), ""
    except ValidationError as exc:
        return None, f"Response did not match QueryPlan: {exc}"


def translate(
    *,
    question: str,
    graph: ComplianceGraph,
    llm_client: LLMClient,
) -> QueryPlan:
    """Produce a validated, graph-resolved ``QueryPlan`` for ``question``.

    Retries once with validation feedback on the first invalid response.
    Raises ``ValueError`` if the second attempt is also invalid, or if
    the LLM's ``entry_node`` is ambiguous against the real graph.
    """
    prompt = _build_prompt(question, graph)
    raw = llm_client.generate(prompt)
    plan, error = _try_parse(raw)

    if plan is None:
        feedback = (
            "Your previous response was invalid and could not be parsed as "
            f"a QueryPlan. The error was: {error}. Respond only with JSON "
            "matching the schema exactly."
        )
        retry_prompt = _build_prompt(question, graph, feedback=feedback)
        raw = llm_client.generate(retry_prompt)
        plan, error = _try_parse(raw)

    if plan is None:
        msg = f"Could not translate question into a QueryPlan: {error}"
        raise ValueError(msg)

    resolved_entry = _resolve_entry_node(plan.entry_node, graph)
    if resolved_entry != plan.entry_node:
        plan = plan.model_copy(update={"entry_node": resolved_entry})
    return plan
