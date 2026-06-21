"""Guard tests for GitHub Actions workflow hardening (Refs #140).

These encode two OpenSSF Scorecard checks so a future workflow edit can't
silently regress them:

- **Pinned-Dependencies**: every third-party action is pinned to a full commit
  SHA, not a floating tag (``@v4``) or branch (``@master``).
- **Token-Permissions**: every workflow declares an explicit ``permissions``
  block (top-level, or on every job), instead of inheriting broad repo
  defaults.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_WORKFLOW_DIR = Path(__file__).resolve().parents[2] / ".github" / "workflows"
_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)", re.MULTILINE)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _workflow_files() -> list[Path]:
    files = sorted(_WORKFLOW_DIR.glob("*.yml")) + sorted(_WORKFLOW_DIR.glob("*.yaml"))
    assert files, f"no workflow files found under {_WORKFLOW_DIR}"
    return files


@pytest.mark.parametrize("workflow", _workflow_files(), ids=lambda p: p.name)
def test_external_actions_are_sha_pinned(workflow: Path) -> None:
    text = workflow.read_text(encoding="utf-8")
    unpinned: list[str] = []
    for ref in _USES_RE.findall(text):
        if ref.startswith("./"):
            continue  # local action — no version to pin
        _, _, version = ref.partition("@")
        if not _SHA_RE.match(version):
            unpinned.append(ref)
    assert not unpinned, (
        f"{workflow.name}: these actions must be pinned to a full commit SHA "
        f"(OpenSSF Pinned-Dependencies): {unpinned}"
    )


@pytest.mark.parametrize("workflow", _workflow_files(), ids=lambda p: p.name)
def test_workflow_declares_explicit_permissions(workflow: Path) -> None:
    doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    if "permissions" in doc:
        return  # explicit top-level permissions
    jobs = doc.get("jobs", {})
    missing = [name for name, job in jobs.items() if "permissions" not in job]
    assert not missing, (
        f"{workflow.name}: declare an explicit `permissions:` block at the "
        f"workflow level or on every job (OpenSSF Token-Permissions). "
        f"Jobs missing it: {missing}"
    )
