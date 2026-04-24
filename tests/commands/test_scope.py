"""Tests for the `lemma scope` CLI commands."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def _valid_yaml(name: str = "prod-us-east") -> str:
    return (
        f"name: {name}\n"
        "frameworks:\n"
        "  - nist-800-53\n"
        'justification: "Prod."\n'
        "match_rules:\n"
        "  - source: aws.tags.Environment\n"
        "    operator: equals\n"
        "    value: prod\n"
    )


class TestScopeInit:
    def test_creates_default_yaml(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "init"])

        assert result.exit_code == 0, result.stdout
        target = tmp_path / "scopes" / "default.yaml"
        assert target.exists()
        # Starter content must be a valid scope that parses.
        from lemma.services.scope import load_scope

        scope = load_scope(target)
        assert scope.name  # non-empty
        assert scope.frameworks  # at least one framework in the template

    def test_custom_name_writes_that_file(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "init", "--name", "prod"])

        assert result.exit_code == 0, result.stdout
        assert (tmp_path / "scopes" / "prod.yaml").exists()

    def test_refuses_to_overwrite_existing(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        existing = scopes_dir / "default.yaml"
        existing.write_text("hand-authored: true\n")

        result = runner.invoke(app, ["scope", "init"])

        assert result.exit_code == 1
        assert "exists" in result.stdout.lower() or "overwrite" in result.stdout.lower()
        # Untouched.
        assert existing.read_text() == "hand-authored: true\n"

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "init"])
        assert result.exit_code == 1


class TestScopeStatus:
    def test_empty_state_exits_zero_with_hint(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "status"])

        assert result.exit_code == 0, result.stdout
        assert "lemma scope init" in result.stdout.lower() or "no scopes" in result.stdout.lower()

    def test_renders_table_for_valid_scopes(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "prod.yaml").write_text(_valid_yaml("prod-us-east"))
        (scopes_dir / "dev.yaml").write_text(_valid_yaml("dev-us-east"))

        result = runner.invoke(app, ["scope", "status"])

        assert result.exit_code == 0, result.stdout
        assert "prod-us-east" in result.stdout
        assert "dev-us-east" in result.stdout
        assert "nist-800-53" in result.stdout

    def test_exits_nonzero_when_any_scope_has_parse_error(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "ok.yaml").write_text(_valid_yaml("ok"))
        (scopes_dir / "broken.yaml").write_text(
            "name: broken\nframeworks:\n  - nist-800-53\nmatch_rule:\n  []\n"
        )

        result = runner.invoke(app, ["scope", "status"])

        assert result.exit_code == 1
        assert "broken.yaml" in result.stdout

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "status"])
        assert result.exit_code == 1

    def test_in_graph_column_reflects_load_state(self, tmp_path: Path, monkeypatch):
        """status must show ✓ after scope load, ✗ beforehand."""
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        from lemma.services.knowledge_graph import ComplianceGraph

        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.save(tmp_path / ".lemma" / "graph.json")

        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "prod.yaml").write_text(_valid_yaml("prod-us-east"))

        before = runner.invoke(app, ["scope", "status"])
        assert before.exit_code == 0
        assert "In Graph" in before.stdout
        assert "✗" in before.stdout  # not yet loaded

        assert runner.invoke(app, ["scope", "load"]).exit_code == 0

        after = runner.invoke(app, ["scope", "status"])
        assert after.exit_code == 0
        assert "✓" in after.stdout


def _graph_with_framework(tmp_path: Path, framework: str = "nist-800-53") -> None:
    """Seed .lemma/graph.json with a single indexed framework."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework(framework, title=framework.upper())
    g.save(tmp_path / ".lemma" / "graph.json")


class TestScopeLoad:
    def test_adds_scopes_and_edges_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_framework(tmp_path)
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "prod.yaml").write_text(_valid_yaml("prod-us-east"))

        result = runner.invoke(app, ["scope", "load"])
        assert result.exit_code == 0, result.stdout
        assert "prod-us-east" in result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("scope:prod-us-east") is not None
        edges = g.get_edges("scope:prod-us-east", "framework:nist-800-53")
        assert any(e.get("relationship") == "APPLIES_TO" for e in edges)

    def test_errors_on_unknown_framework(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_framework(tmp_path)  # only nist-800-53 indexed
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "bad.yaml").write_text(
            "name: bad\nframeworks:\n  - iso-27001\njustification: ''\nmatch_rules: []\n"
        )

        result = runner.invoke(app, ["scope", "load"])
        assert result.exit_code == 1
        assert "iso-27001" in result.stdout

        # Graph stays clean on failure.
        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("scope:bad") is None

    def test_empty_scopes_directory_is_not_an_error(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_framework(tmp_path)
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "load"])
        assert result.exit_code == 0, result.stdout
        assert "no scopes" in result.stdout.lower() or "lemma scope init" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "load"])
        assert result.exit_code == 1


def _scope_yaml(name: str, rules: list[dict]) -> str:
    lines = [f"name: {name}", "frameworks:", "  - nist-800-53"]
    if rules:
        lines.append("match_rules:")
        for rule in rules:
            lines.append(f"  - source: {rule['source']}")
            lines.append(f"    operator: {rule['operator']}")
            lines.append(f"    value: {rule['value']}")
    else:
        lines.append("match_rules: []")
    return "\n".join(lines) + "\n"


def _resource_yaml(id_: str, scope: str, attributes: dict) -> str:
    lines = [f"id: {id_}", "type: aws.rds.instance", f"scope: {scope}", "attributes:"]
    for k, v in attributes.items():
        lines.append(f"  {k}: {v}")
    return "\n".join(lines) + "\n"


class TestScopeMatches:
    def _setup(self, tmp_path: Path):
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()
        (tmp_path / "resources").mkdir()
        (tmp_path / "scopes" / "prod.yaml").write_text(
            _scope_yaml(
                "prod-us-east",
                [
                    {"source": "env", "operator": "equals", "value": "prod"},
                    {"source": "region", "operator": "equals", "value": "us-east-1"},
                ],
            )
        )
        (tmp_path / "scopes" / "dev.yaml").write_text(
            _scope_yaml(
                "dev",
                [{"source": "env", "operator": "equals", "value": "dev"}],
            )
        )
        (tmp_path / "resources" / "rds.yaml").write_text(
            _resource_yaml("prod-rds", "prod-us-east", {"env": "prod", "region": "us-east-1"})
        )

    def test_prints_matching_scopes(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._setup(tmp_path)

        result = runner.invoke(app, ["scope", "matches", "prod-rds"])
        assert result.exit_code == 0, result.stdout
        assert "prod-us-east" in result.stdout
        # dev scope should not appear in the matched list.
        assert "dev" not in result.stdout.replace("prod-us-east", "")

    def test_unknown_resource_id_exits_1(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._setup(tmp_path)

        result = runner.invoke(app, ["scope", "matches", "does-not-exist"])
        assert result.exit_code == 1
        assert "does-not-exist" in result.stdout

    def test_no_scope_matches_prints_empty_hint(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()
        (tmp_path / "resources").mkdir()
        # Declare a resource whose env doesn't match any scope.
        (tmp_path / "scopes" / "prod.yaml").write_text(
            _scope_yaml(
                "prod",
                [{"source": "env", "operator": "equals", "value": "prod"}],
            )
        )
        (tmp_path / "resources" / "stg.yaml").write_text(
            _resource_yaml("stg-rds", "prod", {"env": "staging"})
        )

        result = runner.invoke(app, ["scope", "matches", "stg-rds"])
        assert result.exit_code == 0
        assert "no matching scope" in result.stdout.lower() or "0 scope" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "matches", "anything"])
        assert result.exit_code == 1


def _plan_file(tmp_path: Path, changes: list[dict]) -> Path:
    import json as _json

    path = tmp_path / "plan.json"
    path.write_text(
        _json.dumps(
            {
                "format_version": "1.2",
                "terraform_version": "1.7.0",
                "resource_changes": changes,
            }
        )
    )
    return path


def _change(address: str, type_: str, actions: list[str], *, before=None, after=None):
    return {
        "address": address,
        "type": type_,
        "change": {"actions": actions, "before": before, "after": after},
    }


class TestScopeImpactPlan:
    def _setup_scopes(self, tmp_path: Path):
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()
        (tmp_path / "scopes" / "prod.yaml").write_text(
            _scope_yaml(
                "prod",
                [{"source": "env", "operator": "equals", "value": "prod"}],
            )
        )

    def test_change_entering_scope_exits_nonzero(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._setup_scopes(tmp_path)
        plan = _plan_file(
            tmp_path,
            [_change("aws_s3_bucket.new", "aws_s3_bucket", ["create"], after={"env": "prod"})],
        )

        result = runner.invoke(app, ["scope", "impact", "--plan", str(plan)])
        assert result.exit_code == 1
        assert "prod" in result.stdout
        assert "aws_s3_bucket.new" in result.stdout

    def test_change_without_scope_impact_exits_zero(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._setup_scopes(tmp_path)
        plan = _plan_file(
            tmp_path,
            [
                _change(
                    "aws_s3_bucket.staging",
                    "aws_s3_bucket",
                    ["create"],
                    after={"env": "staging"},
                )
            ],
        )

        result = runner.invoke(app, ["scope", "impact", "--plan", str(plan)])
        assert result.exit_code == 0, result.stdout
        assert "no scope" in result.stdout.lower() or "0 scope" in result.stdout.lower()

    def test_exit_action_shows_exited_scope(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._setup_scopes(tmp_path)
        plan = _plan_file(
            tmp_path,
            [_change("aws_s3_bucket.b", "aws_s3_bucket", ["delete"], before={"env": "prod"})],
        )

        result = runner.invoke(app, ["scope", "impact", "--plan", str(plan)])
        assert result.exit_code == 1
        assert "exited" in result.stdout.lower() or "exit" in result.stdout.lower()

    def test_malformed_plan_errors_loudly(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._setup_scopes(tmp_path)
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid")

        result = runner.invoke(app, ["scope", "impact", "--plan", str(bad)])
        assert result.exit_code == 1
        assert "json" in result.stdout.lower() or "parse" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        plan = _plan_file(tmp_path, [])
        result = runner.invoke(app, ["scope", "impact", "--plan", str(plan)])
        assert result.exit_code == 1


def _graph_with_scope_framework_and_evidence(tmp_path: Path):
    """Seed .lemma/graph.json with a scope, its framework, controls, and mixed coverage."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53")
    g.add_control(framework="nist-800-53", control_id="ac-2", title="AC-2", family="AC")
    g.add_control(framework="nist-800-53", control_id="ac-3", title="AC-3", family="AC")
    g.add_control(framework="nist-800-53", control_id="au-2", title="AU-2", family="AU")

    g.add_policy("access.md", title="Access Policy")
    g.add_mapping(policy="access.md", framework="nist-800-53", control_id="ac-2", confidence=0.9)
    g.add_mapping(policy="access.md", framework="nist-800-53", control_id="ac-3", confidence=0.9)

    g.add_evidence(
        entry_hash="a" * 64,
        producer="Lemma",
        class_name="Compliance Finding",
        time_iso="2026-04-24T12:00:00+00:00",
        control_refs=["nist-800-53:ac-2"],
    )
    g.add_evidence(
        entry_hash="b" * 64,
        producer="Lemma",
        class_name="Compliance Finding",
        time_iso="2026-04-24T12:00:00+00:00",
        control_refs=["nist-800-53:au-2"],
    )

    g.add_scope(
        name="prod",
        frameworks=["nist-800-53"],
        justification="seeded",
        rule_count=0,
    )
    g.save(tmp_path / ".lemma" / "graph.json")


class TestScopePosture:
    def test_with_scope_name_shows_per_framework_counts(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope_framework_and_evidence(tmp_path)

        result = runner.invoke(app, ["scope", "posture", "prod"])
        assert result.exit_code == 0, result.stdout
        # Framework name, total, mapped, evidenced, covered should all appear.
        assert "nist-800-53" in result.stdout
        assert "3" in result.stdout  # total controls
        # mapped=2 (ac-2, ac-3), evidenced=2 (ac-2, au-2), covered=1 (ac-2).

    def test_no_scope_name_summarizes_every_scope(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope_framework_and_evidence(tmp_path)
        # Add a second scope to prove the summary includes both.
        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        g.add_scope(
            name="dev",
            frameworks=["nist-800-53"],
            justification="seeded",
            rule_count=0,
        )
        g.save(tmp_path / ".lemma" / "graph.json")

        result = runner.invoke(app, ["scope", "posture"])
        assert result.exit_code == 0, result.stdout
        assert "prod" in result.stdout
        assert "dev" in result.stdout

    def test_unknown_scope_exits_1(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope_framework_and_evidence(tmp_path)

        result = runner.invoke(app, ["scope", "posture", "does-not-exist"])
        assert result.exit_code == 1
        assert "does-not-exist" in result.stdout

    def test_empty_graph_prints_hint(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()

        result = runner.invoke(app, ["scope", "posture"])
        assert result.exit_code == 0, result.stdout
        assert "no scope" in result.stdout.lower() or "lemma scope load" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "posture"])
        assert result.exit_code == 1


class TestScopeVisualize:
    def test_emits_dot_to_stdout(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope_framework_and_evidence(tmp_path)

        result = runner.invoke(app, ["scope", "visualize"])
        assert result.exit_code == 0, result.stdout
        assert "digraph" in result.stdout
        assert "scope:prod" in result.stdout

    def test_with_scope_name_filters_to_that_scope(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope_framework_and_evidence(tmp_path)
        # Add a second scope. Filter should exclude it.
        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        g.add_scope(name="dev", frameworks=["nist-800-53"], justification="", rule_count=0)
        g.save(tmp_path / ".lemma" / "graph.json")

        result = runner.invoke(app, ["scope", "visualize", "prod"])
        assert result.exit_code == 0, result.stdout
        assert "scope:prod" in result.stdout
        assert "scope:dev" not in result.stdout

    def test_unknown_scope_exits_1(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope_framework_and_evidence(tmp_path)

        result = runner.invoke(app, ["scope", "visualize", "does-not-exist"])
        assert result.exit_code == 1
        assert "does-not-exist" in result.stdout

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "visualize"])
        assert result.exit_code == 1
