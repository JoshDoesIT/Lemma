"""Tests for the NL → QueryPlan translator."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest


def _build_graph():
    from lemma.services.knowledge_graph import ComplianceGraph

    graph = ComplianceGraph()
    graph.add_framework("nist-800-53")
    graph.add_control(
        framework="nist-800-53", control_id="ac-2", title="Account Management", family="AC"
    )
    graph.add_control(
        framework="nist-800-53",
        control_id="au-3",
        title="Content of Audit Records",
        family="AU",
    )
    graph.add_framework("nist-csf-2.0")
    graph.add_control(
        framework="nist-csf-2.0", control_id="pr.aa-1", title="Identities", family="PR"
    )
    graph.add_harmonization(
        framework_a="nist-800-53",
        control_a="ac-2",
        framework_b="nist-csf-2.0",
        control_b="pr.aa-1",
        similarity=0.92,
    )
    return graph


def test_translate_happy_path_returns_query_plan():
    from lemma.models.query_plan import QueryPlan, QueryTraversal
    from lemma.services.query_translator import translate

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {
            "entry_node": "control:nist-800-53:ac-2",
            "traversal": "NEIGHBORS",
            "edge_filter": ["HARMONIZED_WITH"],
            "direction": "both",
            "output_shape": "list",
        }
    )

    plan = translate(
        question="Which controls does NIST AC-2 harmonize with?",
        graph=_build_graph(),
        llm_client=mock_llm,
    )

    assert isinstance(plan, QueryPlan)
    assert plan.entry_node == "control:nist-800-53:ac-2"
    assert plan.traversal == QueryTraversal.NEIGHBORS
    assert plan.edge_filter == ["HARMONIZED_WITH"]


def test_translate_retries_once_with_validation_feedback():
    """Malformed JSON on first call; valid plan on retry — return the retry's plan."""
    from lemma.services.query_translator import translate

    mock_llm = MagicMock()
    mock_llm.generate.side_effect = [
        "not-json-at-all",
        json.dumps(
            {
                "entry_node": "control:nist-800-53:ac-2",
                "traversal": "NEIGHBORS",
            }
        ),
    ]

    plan = translate(
        question="anything",
        graph=_build_graph(),
        llm_client=mock_llm,
    )

    assert plan.entry_node == "control:nist-800-53:ac-2"
    # Two attempts total: one original, one retry.
    assert mock_llm.generate.call_count == 2

    # The retry prompt should mention the parse error so the LLM can correct.
    retry_call_prompt = mock_llm.generate.call_args_list[1].args[0]
    assert "previous" in retry_call_prompt.lower() or "invalid" in retry_call_prompt.lower()


def test_translate_raises_after_second_failure():
    from lemma.services.query_translator import translate

    mock_llm = MagicMock()
    mock_llm.generate.return_value = "never-valid-json"

    with pytest.raises(ValueError, match=r"(?i)plan|json"):
        translate(
            question="anything",
            graph=_build_graph(),
            llm_client=mock_llm,
        )

    assert mock_llm.generate.call_count == 2  # original + one retry


def test_translate_resolves_short_entry_node_against_graph():
    """LLM says 'ac-2'; translator resolves to 'control:nist-800-53:ac-2'."""
    from lemma.services.query_translator import translate

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps({"entry_node": "ac-2", "traversal": "NEIGHBORS"})

    plan = translate(
        question="Which controls does AC-2 harmonize with?",
        graph=_build_graph(),
        llm_client=mock_llm,
    )

    assert plan.entry_node == "control:nist-800-53:ac-2"


def test_translate_raises_when_entry_node_ambiguous():
    """Two frameworks with the same control_id → clear error listing candidates."""
    from lemma.services.knowledge_graph import ComplianceGraph
    from lemma.services.query_translator import translate

    # Both frameworks have a control "ac-2".
    graph = ComplianceGraph()
    graph.add_framework("nist-800-53")
    graph.add_framework("other-fw")
    graph.add_control(framework="nist-800-53", control_id="ac-2", title="A", family="AC")
    graph.add_control(framework="other-fw", control_id="ac-2", title="B", family="AC")

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps({"entry_node": "ac-2", "traversal": "NEIGHBORS"})

    with pytest.raises(ValueError, match=r"ambiguous|multiple"):
        translate(question="anything", graph=graph, llm_client=mock_llm)


def test_translate_passes_through_when_entry_node_already_fully_qualified():
    from lemma.services.query_translator import translate

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {"entry_node": "control:nist-csf-2.0:pr.aa-1", "traversal": "NEIGHBORS"}
    )

    plan = translate(
        question="anything",
        graph=_build_graph(),
        llm_client=mock_llm,
    )
    assert plan.entry_node == "control:nist-csf-2.0:pr.aa-1"


def _build_full_edge_graph():
    """Graph covering every edge type the translator should advertise."""
    from lemma.services.knowledge_graph import ComplianceGraph

    graph = ComplianceGraph()
    graph.add_framework("nist-csf-2.0")
    graph.add_control(
        framework="nist-csf-2.0", control_id="de.cm-01", title="Monitoring", family="DE"
    )
    graph.add_control(
        framework="nist-csf-2.0", control_id="pr.aa-1", title="Identities", family="PR"
    )
    graph.add_framework("nist-800-53")
    graph.add_control(
        framework="nist-800-53", control_id="ac-2", title="Account Management", family="AC"
    )
    graph.add_harmonization(
        framework_a="nist-csf-2.0",
        control_a="pr.aa-1",
        framework_b="nist-800-53",
        control_b="ac-2",
        similarity=0.9,
    )
    graph.add_policy("access-control.md", title="Access Control")
    graph.add_mapping(
        policy="access-control.md",
        framework="nist-csf-2.0",
        control_id="pr.aa-1",
        confidence=0.9,
    )
    graph.add_scope(name="prod", frameworks=["nist-csf-2.0"])
    graph.add_resource(
        resource_id="audit-bucket",
        type_="aws.s3.bucket",
        scopes=["prod"],
        attributes={},
        impacts=["control:nist-csf-2.0:de.cm-01"],
    )
    graph.add_evidence(
        entry_hash="a" * 64,
        producer="connector:test",
        class_name="ComplianceFinding",
        time_iso="2026-04-01T00:00:00Z",
        control_refs=["nist-csf-2.0:de.cm-01"],
    )
    graph.add_person(
        person_id="alice",
        name="Alice",
        email="alice@example.com",
        owns=["control:nist-csf-2.0:pr.aa-1", "resource:audit-bucket"],
    )
    graph.add_risk(
        risk_id="data-loss",
        title="Audit log loss",
        description="",
        severity="high",
        threatens=["resource:audit-bucket"],
        mitigated_by=["control:nist-csf-2.0:de.cm-01"],
    )
    return graph


def test_prompt_enumerates_all_edge_types_from_schema():
    """The rendered prompt must name every edge type present in the graph."""
    from lemma.services.query_translator import _build_prompt

    graph = _build_full_edge_graph()
    prompt = _build_prompt("anything", graph)

    for edge in (
        "SATISFIES",
        "HARMONIZED_WITH",
        "CONTAINS",
        "EVIDENCES",
        "SCOPED_TO",
        "OWNS",
        "IMPACTS",
        "THREATENS",
        "MITIGATED_BY",
        "APPLIES_TO",
    ):
        assert edge in prompt, f"prompt should advertise {edge}"


def test_prompt_includes_direction_hint_for_owns():
    """The cheatsheet must explain that OWNS queries from a Control use direction=in.

    Without this hint the LLM consistently guesses direction=out and returns
    empty results for "who owns AC-2?".
    """
    from lemma.services.query_translator import _build_prompt

    graph = _build_full_edge_graph()
    prompt = _build_prompt("Who owns AC-2?", graph)

    # The OWNS line should mention direction guidance for the asker.
    lowered = prompt.lower()
    assert "owns" in lowered
    # Direction guidance appears somewhere near the OWNS line.
    owns_section = prompt[prompt.find("OWNS") :]
    assert "direction" in owns_section.lower() or "in from" in owns_section.lower()


def test_entry_node_resolution_accepts_new_prefixes():
    """Short-name resolution must work for every node-type prefix #76 introduced.

    The resolver (_resolve_entry_node) does a case-insensitive suffix match on
    ":{raw}" — this exercises each new prefix including person:alice@example.com
    which has an @ in it and is worth an explicit guard.
    """
    from lemma.services.query_translator import _resolve_entry_node

    graph = _build_full_edge_graph()

    # Short forms resolve to the corresponding fully qualified id.
    assert _resolve_entry_node("audit-bucket", graph) == "resource:audit-bucket"
    assert _resolve_entry_node("prod", graph) == "scope:prod"
    assert _resolve_entry_node("alice", graph) == "person:alice"
    assert _resolve_entry_node("data-loss", graph) == "risk:data-loss"

    # Fully qualified pass-through.
    assert _resolve_entry_node("resource:audit-bucket", graph) == "resource:audit-bucket"
    assert _resolve_entry_node("risk:data-loss", graph) == "risk:data-loss"


def test_entry_node_resolution_handles_email_in_person_id(tmp_path):
    """person:alice@example.com has an @ in its id — make sure suffix logic still works."""
    from lemma.services.knowledge_graph import ComplianceGraph
    from lemma.services.query_translator import _resolve_entry_node

    graph = ComplianceGraph()
    graph.add_person(person_id="alice@example.com", name="Alice", email="alice@example.com")

    # Short form — "alice@example.com" resolves to "person:alice@example.com".
    assert _resolve_entry_node("alice@example.com", graph) == "person:alice@example.com"
    # Already-qualified form passes through.
    assert _resolve_entry_node("person:alice@example.com", graph) == "person:alice@example.com"


def test_prompt_does_not_hardcode_three_edge_enum():
    """Regression guard: the JSON-shape block must not cap edge_filter to the Phase 2 three.

    Before this PR the prompt read:
        "edge_filter": ["SATISFIES" | "HARMONIZED_WITH" | "CONTAINS"]
    which made the LLM blind to every edge type shipped in #76. The new prompt
    either lists every edge explicitly or uses free-form guidance pointing at
    the schema summary.
    """
    from lemma.services.query_translator import _build_prompt

    graph = _build_full_edge_graph()
    prompt = _build_prompt("anything", graph)

    forbidden = '["SATISFIES" | "HARMONIZED_WITH" | "CONTAINS"]'
    assert forbidden not in prompt, (
        "prompt still hardcodes the Phase 2 three-edge whitelist in the JSON schema block"
    )
