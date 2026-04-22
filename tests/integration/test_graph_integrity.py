"""Graph integrity tests — orphan detection and edge consistency.

Asserts invariants that every future PR touching the knowledge graph
must preserve:

- Policy nodes produced by a real `lemma map` run have at least one
  `SATISFIES` edge (orphan policies indicate a mapping pipeline bug).
- Every edge in the exported graph has both endpoints as real nodes
  (no dangling references).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch


def test_graph_from_full_pipeline_has_no_phantom_edges(lemma_project: Path, monkeypatch):
    """Every edge endpoint resolves to a node present in the graph."""
    from typer.testing import CliRunner

    from lemma.cli import app
    from lemma.services.knowledge_graph import ComplianceGraph

    runner = CliRunner()
    monkeypatch.chdir(lemma_project)

    (lemma_project / "policies" / "logging.md").write_text(
        "# Logging\n\nAll production systems emit audit logs retained 90 days.\n"
    )
    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {"confidence": 0.82, "rationale": "matches logging controls"}
    )

    with patch("lemma.commands.map.get_llm_client", return_value=mock_llm):
        runner.invoke(app, ["map", "--framework", "nist-csf-2.0"])

    graph = ComplianceGraph.load(lemma_project / ".lemma" / "graph.json")
    export = graph.export_json()

    node_ids = {n["id"] for n in export["nodes"]}
    for edge in export["edges"]:
        assert edge["source"] in node_ids, f"phantom source {edge['source']}"
        assert edge["target"] in node_ids, f"phantom target {edge['target']}"


def test_mapped_policies_are_never_orphaned(lemma_project: Path, monkeypatch):
    """A policy that went through `lemma map` must have at least one SATISFIES edge."""
    from typer.testing import CliRunner

    from lemma.cli import app
    from lemma.services.knowledge_graph import ComplianceGraph

    runner = CliRunner()
    monkeypatch.chdir(lemma_project)

    (lemma_project / "policies" / "identity.md").write_text(
        "# Identity\n\nMulti-factor authentication is required for all accounts.\n"
    )
    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {"confidence": 0.91, "rationale": "identity + access control"}
    )

    with patch("lemma.commands.map.get_llm_client", return_value=mock_llm):
        runner.invoke(app, ["map", "--framework", "nist-csf-2.0"])

    graph = ComplianceGraph.load(lemma_project / ".lemma" / "graph.json")
    export = graph.export_json()

    policy_nodes = {n["id"] for n in export["nodes"] if n["id"].startswith("policy:")}
    satisfied_sources = {
        edge["source"] for edge in export["edges"] if edge.get("relationship") == "SATISFIES"
    }

    orphaned = policy_nodes - satisfied_sources
    assert not orphaned, f"policies with no SATISFIES edge: {orphaned}"
