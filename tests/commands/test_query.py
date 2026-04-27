"""Tests for the `lemma query` CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

runner = CliRunner()


def _seed_graph_in_lemma_project(project: Path):
    """Put a small graph at <project>/.lemma/graph.json."""
    from lemma.services.knowledge_graph import ComplianceGraph

    graph = ComplianceGraph()
    graph.add_framework("nist-800-53")
    graph.add_framework("nist-csf-2.0")
    graph.add_control(
        framework="nist-800-53",
        control_id="ac-2",
        title="Account Management",
        family="AC",
    )
    graph.add_control(
        framework="nist-csf-2.0",
        control_id="pr.aa-1",
        title="Identities",
        family="PR",
    )
    graph.add_harmonization(
        framework_a="nist-800-53",
        control_a="ac-2",
        framework_b="nist-csf-2.0",
        control_b="pr.aa-1",
        similarity=0.92,
    )
    graph.save(project / ".lemma" / "graph.json")


def test_query_requires_lemma_project(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["query", "anything"])
    assert result.exit_code == 1
    stdout = result.stdout.lower()
    assert "not a lemma project" in stdout or "lemma init" in stdout


def test_query_end_to_end_emits_trace_with_operation_query(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.services.trace_log import TraceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_graph_in_lemma_project(tmp_path)

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {
            "entry_node": "ac-2",  # short form — resolver fills in framework
            "traversal": "NEIGHBORS",
            "edge_filter": ["HARMONIZED_WITH"],
        }
    )

    with patch("lemma.commands.query.get_llm_client", return_value=mock_llm):
        result = runner.invoke(app, ["query", "Which controls does NIST AC-2 harmonize with?"])

    assert result.exit_code == 0, result.stdout
    # The harmonized CSF control appears in the output.
    assert "pr.aa-1" in result.stdout

    # One trace entry landed in the log with operation="query".
    traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
    query_traces = [t for t in traces if t.operation == "query"]
    assert len(query_traces) == 1
    trace = query_traces[0]
    # Convention for read ops: confidence=0.0, determination="QUERY_EXECUTED".
    assert trace.confidence == 0.0
    assert trace.determination == "QUERY_EXECUTED"
    assert trace.prompt  # the actual prompt sent to the LLM
    assert trace.raw_output  # the LLM's raw response


def test_query_verbose_shows_resolved_plan(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_graph_in_lemma_project(tmp_path)

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {
            "entry_node": "ac-2",
            "traversal": "NEIGHBORS",
            "edge_filter": ["HARMONIZED_WITH"],
        }
    )

    with patch("lemma.commands.query.get_llm_client", return_value=mock_llm):
        result = runner.invoke(
            app,
            ["query", "--verbose", "Which controls does NIST AC-2 harmonize with?"],
        )

    assert result.exit_code == 0
    # Resolved entry_node (full form) should appear in the output because --verbose
    # renders the plan.
    assert "control:nist-800-53:ac-2" in result.stdout
    assert "NEIGHBORS" in result.stdout


def _seed_graph_with_evidence_and_risk(project: Path):
    """Graph where a Control has Evidence + Risk neighbors with provenance."""
    from lemma.services.knowledge_graph import ComplianceGraph

    graph = ComplianceGraph()
    graph.add_framework("nist-csf-2.0")
    graph.add_control(
        framework="nist-csf-2.0",
        control_id="de.cm-01",
        title="Monitoring",
        family="DE",
    )
    graph.add_evidence(
        entry_hash="a" * 64,
        producer="connector:cloudtrail",
        class_name="ComplianceFinding",
        time_iso="2026-04-01T00:00:00Z",
        control_refs=["nist-csf-2.0:de.cm-01"],
    )
    graph.add_risk(
        risk_id="data-loss",
        title="Audit log loss",
        description="",
        severity="high",
        threatens=[],
        mitigated_by=["control:nist-csf-2.0:de.cm-01"],
    )
    graph.save(project / ".lemma" / "graph.json")


def test_query_output_shows_provenance_for_evidence_result(tmp_path: Path, monkeypatch):
    """Evidence results render the producer and time_iso so operators see where it came from."""
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_graph_with_evidence_and_risk(tmp_path)

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {
            "entry_node": "de.cm-01",
            "traversal": "NEIGHBORS",
            "edge_filter": ["EVIDENCES"],
            "direction": "in",
        }
    )

    with patch("lemma.commands.query.get_llm_client", return_value=mock_llm):
        result = runner.invoke(app, ["query", "What evidence supports de.cm-01?"])

    assert result.exit_code == 0, result.stdout
    assert "connector:cloudtrail" in result.stdout
    assert "2026-04-01" in result.stdout


def test_query_output_shows_severity_tag_for_risk_result(tmp_path: Path, monkeypatch):
    """Risk results render the severity so the worst risks are visually prominent."""
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_graph_with_evidence_and_risk(tmp_path)

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {
            "entry_node": "de.cm-01",
            "traversal": "NEIGHBORS",
            "edge_filter": ["MITIGATED_BY"],
            "direction": "in",
        }
    )

    with patch("lemma.commands.query.get_llm_client", return_value=mock_llm):
        result = runner.invoke(app, ["query", "What risks does de.cm-01 mitigate?"])

    assert result.exit_code == 0, result.stdout
    assert "Audit log loss" in result.stdout
    assert "high" in result.stdout.lower()


def test_query_trace_carries_operation_kind_read(tmp_path: Path, monkeypatch):
    """Every `lemma query` trace must be tagged operation_kind='read'."""
    from lemma.cli import app
    from lemma.services.trace_log import TraceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_graph_in_lemma_project(tmp_path)

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {
            "entry_node": "ac-2",
            "traversal": "NEIGHBORS",
        }
    )

    with patch("lemma.commands.query.get_llm_client", return_value=mock_llm):
        result = runner.invoke(app, ["query", "anything"])

    assert result.exit_code == 0, result.stdout
    traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
    assert len(traces) == 1
    assert traces[0].operation_kind == "read"


def test_query_trace_uses_evidence_query_operation_when_filters_present(
    tmp_path: Path, monkeypatch
):
    """A plan with any evidence-attribute filter switches operation to 'evidence_query'."""
    from lemma.cli import app
    from lemma.services.trace_log import TraceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_graph_in_lemma_project(tmp_path)

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {
            "entry_node": "ac-2",
            "traversal": "NEIGHBORS",
            "edge_filter": ["EVIDENCES"],
            "direction": "in",
            "severity": ["HIGH"],
        }
    )

    with patch("lemma.commands.query.get_llm_client", return_value=mock_llm):
        result = runner.invoke(app, ["query", "high-severity evidence for ac-2"])

    assert result.exit_code == 0, result.stdout
    traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
    assert len(traces) == 1
    assert traces[0].operation == "evidence_query"
    assert traces[0].operation_kind == "read"


def test_query_trace_uses_query_operation_when_no_evidence_filters(tmp_path: Path, monkeypatch):
    """A plain graph-shaped plan keeps operation='query' (not 'evidence_query')."""
    from lemma.cli import app
    from lemma.services.trace_log import TraceLog

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_graph_in_lemma_project(tmp_path)

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {
            "entry_node": "ac-2",
            "traversal": "NEIGHBORS",
            "edge_filter": ["HARMONIZED_WITH"],
        }
    )

    with patch("lemma.commands.query.get_llm_client", return_value=mock_llm):
        result = runner.invoke(app, ["query", "what harmonizes with ac-2?"])

    assert result.exit_code == 0, result.stdout
    traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
    assert len(traces) == 1
    assert traces[0].operation == "query"


def test_query_exits_non_zero_when_entry_node_not_found(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    _seed_graph_in_lemma_project(tmp_path)

    mock_llm = MagicMock()
    mock_llm.generate.return_value = json.dumps(
        {
            "entry_node": "control:nist-800-53:doesnotexist",
            "traversal": "NEIGHBORS",
        }
    )

    with patch("lemma.commands.query.get_llm_client", return_value=mock_llm):
        result = runner.invoke(app, ["query", "anything"])

    assert result.exit_code == 1
    assert "not found" in result.stdout.lower() or "entry_node" in result.stdout.lower()
