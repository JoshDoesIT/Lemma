"""Tests for the OPA/Rego policy engine behind `lemma check --policy-dir` (Refs #121).

The default runner shells out to the ``opa`` binary; these tests inject a
fake runner (or monkeypatch ``shutil.which`` / ``subprocess.run``) so CI
never needs ``opa`` installed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lemma.models.check_result import CheckStatus


def _write_policy(policy_dir: Path, name: str, body: str = "package lemma\n") -> Path:
    policy_dir.mkdir(parents=True, exist_ok=True)
    path = policy_dir / name
    path.write_text(body)
    return path


class TestEvaluatePolicies:
    def test_violations_become_failed_outcomes(self, tmp_path: Path):
        from lemma.services.policy_engine import evaluate_policies

        _write_policy(tmp_path, "mfa.rego")

        def _runner(rego_file: Path, _input: dict) -> list[str]:
            return ["user alice has no MFA", "user bob has no MFA"]

        outcomes = evaluate_policies(policy_dir=tmp_path, input_document={}, opa_runner=_runner)

        assert len(outcomes) == 2
        assert all(o.status == CheckStatus.FAILED for o in outcomes)
        assert {o.message for o in outcomes} == {
            "user alice has no MFA",
            "user bob has no MFA",
        }
        assert all(o.policy_file == "mfa.rego" for o in outcomes)

    def test_no_violations_yields_single_passed_outcome(self, tmp_path: Path):
        from lemma.services.policy_engine import evaluate_policies

        _write_policy(tmp_path, "mfa.rego")

        outcomes = evaluate_policies(
            policy_dir=tmp_path, input_document={}, opa_runner=lambda *_: []
        )

        assert len(outcomes) == 1
        assert outcomes[0].status == CheckStatus.PASSED
        assert outcomes[0].policy_file == "mfa.rego"

    def test_multiple_policy_files_each_evaluated(self, tmp_path: Path):
        from lemma.services.policy_engine import evaluate_policies

        _write_policy(tmp_path, "a.rego")
        _write_policy(tmp_path, "b.rego")

        seen: list[str] = []

        def _runner(rego_file: Path, _input: dict) -> list[str]:
            seen.append(rego_file.name)
            return []

        evaluate_policies(policy_dir=tmp_path, input_document={}, opa_runner=_runner)

        assert sorted(seen) == ["a.rego", "b.rego"]

    def test_empty_dir_yields_no_outcomes(self, tmp_path: Path):
        from lemma.services.policy_engine import evaluate_policies

        (tmp_path / "policies").mkdir()
        outcomes = evaluate_policies(
            policy_dir=tmp_path / "policies", input_document={}, opa_runner=lambda *_: []
        )
        assert outcomes == []

    def test_missing_dir_raises(self, tmp_path: Path):
        from lemma.services.policy_engine import evaluate_policies

        with pytest.raises(ValueError, match=r"(?i)policy.*dir|not.*exist|directory"):
            evaluate_policies(
                policy_dir=tmp_path / "nope", input_document={}, opa_runner=lambda *_: []
            )


class TestDefaultOpaRunner:
    def test_missing_opa_binary_raises_with_install_hint(self, tmp_path, monkeypatch):
        from lemma.services import policy_engine

        monkeypatch.setattr(policy_engine.shutil, "which", lambda _name: None)
        rego = _write_policy(tmp_path, "p.rego")

        with pytest.raises(ValueError, match=r"(?i)opa"):
            policy_engine._default_opa_runner(rego, {"graph": {}})

    def test_parses_deny_set_from_opa_json(self, tmp_path, monkeypatch):
        from lemma.services import policy_engine

        monkeypatch.setattr(policy_engine.shutil, "which", lambda _name: "/usr/bin/opa")

        opa_payload = {
            "result": [
                {
                    "expressions": [
                        {
                            "value": ["violation one", "violation two"],
                            "text": "data.lemma.deny",
                        }
                    ]
                }
            ]
        }

        class _Completed:
            returncode = 0
            stdout = json.dumps(opa_payload)
            stderr = ""

        captured: dict = {}

        def _fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["input"] = kwargs.get("input")
            return _Completed()

        monkeypatch.setattr(policy_engine.subprocess, "run", _fake_run)

        rego = _write_policy(tmp_path, "p.rego")
        violations = policy_engine._default_opa_runner(rego, {"graph": {"nodes": []}})

        assert violations == ["violation one", "violation two"]
        # The query targets data.lemma.deny and the rego file is passed as data.
        assert any("data.lemma.deny" in str(part) for part in captured["cmd"])
        assert any(str(rego) in str(part) for part in captured["cmd"])
        # Input document is forwarded as JSON on stdin.
        assert json.loads(captured["input"]) == {"graph": {"nodes": []}}

    def test_undefined_deny_rule_is_no_violations(self, tmp_path, monkeypatch):
        from lemma.services import policy_engine

        monkeypatch.setattr(policy_engine.shutil, "which", lambda _name: "/usr/bin/opa")

        class _Completed:
            returncode = 0
            stdout = json.dumps({"result": []})  # opa emits empty result when undefined
            stderr = ""

        monkeypatch.setattr(policy_engine.subprocess, "run", lambda *a, **k: _Completed())

        rego = _write_policy(tmp_path, "p.rego")
        assert policy_engine._default_opa_runner(rego, {}) == []

    def test_invalid_rego_raises_naming_file(self, tmp_path, monkeypatch):
        from lemma.services import policy_engine

        monkeypatch.setattr(policy_engine.shutil, "which", lambda _name: "/usr/bin/opa")

        class _Completed:
            returncode = 1
            stdout = ""
            stderr = "1 error occurred: p.rego:3: rego_parse_error: unexpected token"

        monkeypatch.setattr(policy_engine.subprocess, "run", lambda *a, **k: _Completed())

        rego = _write_policy(tmp_path, "p.rego")
        with pytest.raises(ValueError, match=r"p\.rego"):
            policy_engine._default_opa_runner(rego, {})
