"""Validate the reusable CI wrappers (Refs #28, #120).

The `lemma-check` composite GitHub Action and the GitLab CI template are shipped
as repo artifacts other projects reference. These tests assert they are
well-formed YAML with the structure GitHub/GitLab require and that they actually
invoke `lemma check`, so a malformed wrapper can't silently ship.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_ACTION = _ROOT / "actions" / "lemma-check" / "action.yml"
_GITLAB = _ROOT / "ci" / "gitlab" / "lemma-check.yml"


def test_github_action_is_a_valid_composite_action():
    assert _ACTION.is_file()
    spec = yaml.safe_load(_ACTION.read_text())

    assert spec["name"]
    assert spec["description"]
    assert spec["runs"]["using"] == "composite"

    # The inputs an operator gates on must exist.
    for required in ("framework", "min-confidence", "format", "comment-on-pr"):
        assert required in spec["inputs"], required

    steps = spec["runs"]["steps"]
    run_blocks = "\n".join(s.get("run", "") for s in steps if isinstance(s, dict))
    assert "lemma" in run_blocks and "check" in run_blocks
    # The result is gated (a step exits with the check's exit code).
    assert "exit_code" in run_blocks
    # A PR-comment step exists (closes #120's "posts results as PR comments").
    assert any(isinstance(s, dict) and "github-script" in str(s.get("uses", "")) for s in steps)


def test_gitlab_template_defines_a_lemma_check_job():
    assert _GITLAB.is_file()
    spec = yaml.safe_load(_GITLAB.read_text())

    assert "lemma-check" in spec
    job = spec["lemma-check"]
    assert job["image"]
    script = "\n".join(job["script"]) if isinstance(job["script"], list) else str(job["script"])
    assert "lemma" in script and "check" in script
    # Operator-overridable knobs are declared as variables.
    for var in ("LEMMA_FRAMEWORK", "LEMMA_MIN_CONFIDENCE", "LEMMA_FORMAT"):
        assert var in job["variables"], var
