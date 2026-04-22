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
