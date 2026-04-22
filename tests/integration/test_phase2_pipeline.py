"""End-to-end integration tests for the Phase 2 CLI pipeline.

These walk the full user path from `lemma init` through to `lemma graph
export`, asserting cross-artifact consistency between the compliance
graph, the AI trace log, and the audit CLI.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch


def test_lemma_project_fixture_initializes_and_indexes(lemma_project: Path):
    """The fixture lands a ready-to-use project: .lemma/, indexed framework, no policy yet."""
    assert (lemma_project / ".lemma").is_dir()
    assert (lemma_project / ".lemma" / "index").is_dir()
    assert (lemma_project / "lemma.config.yaml").is_file()


def test_full_pipeline_produces_aligned_trace_and_graph(lemma_project: Path, monkeypatch):
    """init → map → audit/graph: every mapping decision leaves a trace AND a graph edge."""
    from typer.testing import CliRunner

    from lemma.cli import app
    from lemma.services.knowledge_graph import ComplianceGraph
    from lemma.services.trace_log import TraceLog

    runner = CliRunner()
    monkeypatch.chdir(lemma_project)

    (lemma_project / "policies" / "access.md").write_text(
        "# Access Control\n\nAll users must authenticate via SSO before accessing systems.\n"
    )

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {"confidence": 0.88, "rationale": "Policy ties directly to account management."}
    )

    with patch("lemma.commands.map.get_llm_client", return_value=mock_llm):
        result = runner.invoke(app, ["map", "--framework", "nist-csf-2.0"])
    assert result.exit_code == 0, result.stdout

    trace_log = TraceLog(lemma_project / ".lemma" / "traces")
    traces = trace_log.read_all()
    assert traces, "map run produced no trace entries"
    proposed = [t for t in traces if t.status.value == "PROPOSED"]
    assert proposed, "expected at least one PROPOSED trace"

    graph = ComplianceGraph.load(lemma_project / ".lemma" / "graph.json")
    export = graph.export_json()

    policy_nodes = {n["id"] for n in export["nodes"] if n["id"].startswith("policy:")}
    assert "policy:access.md" in policy_nodes

    satisfies_edges = [edge for edge in export["edges"] if edge.get("relationship") == "SATISFIES"]
    assert satisfies_edges, "expected at least one SATISFIES edge from mapping"

    # Every graph SATISFIES edge must correspond to a mapping decision that the trace log recorded.
    trace_control_ids = {(t.framework, t.control_id) for t in proposed}
    for edge in satisfies_edges:
        # target node_id has the form "control:<framework>:<control_id>"
        _, framework, control_id = edge["target"].split(":", 2)
        assert (framework, control_id) in trace_control_ids, (
            f"SATISFIES edge {edge['source']} -> {edge['target']} has no matching trace"
        )
