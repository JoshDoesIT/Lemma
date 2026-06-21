"""End-to-end scope-as-code lifecycle test (Refs #30).

Exercises the full declarative scope pipeline through the CLI, offline:
``lemma init`` → declare scopes + resources → ``scope load`` → ``scope
status`` → ``scope matches`` → ``scope posture``. No network, no discovery
providers — just the local YAML → graph path the docs describe.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()

_PROD_SCOPE = (
    "name: prod-us-east\n"
    "frameworks:\n"
    "  - nist-800-53\n"
    'justification: "Production workloads in us-east."\n'
    "match_rules:\n"
    "  - source: aws.tags.Environment\n"
    "    operator: equals\n"
    "    value: prod\n"
)

_DEV_SCOPE = (
    "name: dev-us-east\n"
    "frameworks:\n"
    "  - nist-800-53\n"
    'justification: "Dev sandbox."\n'
    "match_rules:\n"
    "  - source: aws.tags.Environment\n"
    "    operator: equals\n"
    "    value: dev\n"
)


def _resource(rid: str, env: str) -> str:
    return (
        f"id: {rid}\n"
        "type: aws.rds.instance\n"
        "scopes:\n"
        "  - prod-us-east\n"
        "attributes:\n"
        "  aws:\n"
        "    tags:\n"
        f"      Environment: {env}\n"
    )


def _init_project(tmp_path: Path) -> None:
    from lemma.cli import app

    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0, result.stdout
    (tmp_path / "scopes").mkdir(exist_ok=True)
    (tmp_path / "resources").mkdir(exist_ok=True)


def test_scope_lifecycle_end_to_end(tmp_path: Path, monkeypatch):
    from lemma.cli import app
    from lemma.services.knowledge_graph import ComplianceGraph

    monkeypatch.chdir(tmp_path)
    _init_project(tmp_path)

    # Precondition: scopes can only reference frameworks already in the graph.
    graph_path = tmp_path / ".lemma" / "graph.json"
    g = ComplianceGraph.load(graph_path)
    g.add_framework("nist-800-53", title="NIST 800-53")
    g.save(graph_path)

    (tmp_path / "scopes" / "prod.yaml").write_text(_PROD_SCOPE)
    (tmp_path / "scopes" / "dev.yaml").write_text(_DEV_SCOPE)
    (tmp_path / "resources" / "web.yaml").write_text(_resource("web-1", "prod"))
    (tmp_path / "resources" / "test.yaml").write_text(_resource("test-1", "dev"))

    # 1. Load the declared scopes into the graph.
    loaded = runner.invoke(app, ["scope", "load"])
    assert loaded.exit_code == 0, loaded.stdout
    assert "2 scope" in loaded.stdout

    # 2. Status reflects both declared scopes.
    status = runner.invoke(app, ["scope", "status"])
    assert status.exit_code == 0, status.stdout
    assert "prod-us-east" in status.stdout
    assert "dev-us-east" in status.stdout

    # 3. Rule-based matching: the prod resource matches the prod scope only.
    web = runner.invoke(app, ["scope", "matches", "web-1"])
    assert web.exit_code == 0, web.stdout
    assert "prod-us-east" in web.stdout
    assert "dev-us-east" not in web.stdout

    # 4. The dev resource matches the dev scope only.
    test = runner.invoke(app, ["scope", "matches", "test-1"])
    assert test.exit_code == 0, test.stdout
    assert "dev-us-east" in test.stdout
    assert "prod-us-east" not in test.stdout

    # 5. The graph carries both scope nodes after load.
    graph = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
    assert graph.get_node("scope:prod-us-east") is not None
    assert graph.get_node("scope:dev-us-east") is not None

    # 6. Posture runs cleanly over the loaded scopes.
    posture = runner.invoke(app, ["scope", "posture"])
    assert posture.exit_code == 0, posture.stdout


def test_scope_matches_unknown_resource_errors(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _init_project(tmp_path)
    (tmp_path / "scopes" / "prod.yaml").write_text(_PROD_SCOPE)

    result = runner.invoke(app, ["scope", "matches", "ghost-1"])
    assert result.exit_code == 1
    assert "ghost-1" in result.stdout


def test_scope_load_rejects_invalid_scope_yaml(tmp_path: Path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _init_project(tmp_path)
    # `frameworks` must be a list; a scalar is a schema violation.
    (tmp_path / "scopes" / "bad.yaml").write_text(
        "name: bad\nframeworks: nist-800-53\njustification: x\nmatch_rules: []\n"
    )

    result = runner.invoke(app, ["scope", "load"])
    assert result.exit_code == 1
