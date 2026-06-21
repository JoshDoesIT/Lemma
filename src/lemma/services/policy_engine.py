"""OPA/Rego policy engine for ``lemma check --policy-dir`` (Refs #121).

``lemma check`` v0 is a thin coverage gate (does every control have a
satisfying policy?). Real compliance needs richer assertions — "no IAM user
without MFA", "every change ticket was approved". OPA/Rego is the standard
policy-as-code language for that, so this module lets operators drop ``.rego``
files into a directory and have them evaluated against the compliance graph
and evidence log as the Rego ``input`` document.

**Embedding strategy.** We shell out to the ``opa`` binary (``opa eval``)
rather than vendoring a Rego interpreter — same pattern as the network
discovery service shelling out to ``nmap``. The binary is required at runtime
and produces a clear install hint when missing; CI mocks the runner so it is
never needed for tests.

**Policy contract.** Each policy declares ``package lemma`` and a ``deny``
rule that is a set of human-readable violation strings:

    package lemma

    deny[msg] {
        some node in input.graph.nodes
        node.type == "Control"
        not covered(node)
        msg := sprintf("control %s is uncovered", [node.control_id])
    }

We query ``data.lemma.deny`` per file; each returned string is one violation.
An empty set (or an undefined ``deny``) means the policy passed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from lemma.models.check_result import CheckStatus, PolicyCheckOutcome

# A runner evaluates one .rego file against an input document and returns the
# list of violation messages it produced.
OpaRunner = Callable[[Path, dict], list[str]]

_DENY_QUERY = "data.lemma.deny"
_OPA_TIMEOUT_SECONDS = 60


def evaluate_policies(
    *,
    policy_dir: Path,
    input_document: dict,
    opa_runner: OpaRunner | None = None,
) -> list[PolicyCheckOutcome]:
    """Evaluate every ``.rego`` file in ``policy_dir`` against ``input_document``.

    Args:
        policy_dir: Directory containing ``.rego`` policy files (non-recursive).
        input_document: The Rego ``input`` document (typically ``{"graph":
            ..., "evidence": [...]}``).
        opa_runner: Override the evaluation backend (used by tests). Defaults
            to shelling out to the ``opa`` binary.

    Returns:
        One ``PASSED`` outcome per policy file with no violations; one
        ``FAILED`` outcome per violation message. Files are processed in
        sorted order for deterministic output.

    Raises:
        ValueError: If ``policy_dir`` does not exist, or a policy fails to
            evaluate (invalid Rego, missing ``opa`` binary).
    """
    if not policy_dir.is_dir():
        msg = f"Policy directory '{policy_dir}' does not exist or is not a directory."
        raise ValueError(msg)

    runner = opa_runner or _default_opa_runner

    outcomes: list[PolicyCheckOutcome] = []
    for rego_file in sorted(policy_dir.glob("*.rego")):
        violations = runner(rego_file, input_document)
        if violations:
            outcomes.extend(
                PolicyCheckOutcome(
                    policy_file=rego_file.name,
                    status=CheckStatus.FAILED,
                    message=message,
                )
                for message in violations
            )
        else:
            outcomes.append(
                PolicyCheckOutcome(policy_file=rego_file.name, status=CheckStatus.PASSED)
            )
    return outcomes


def _default_opa_runner(rego_file: Path, input_document: dict) -> list[str]:
    """Evaluate ``data.lemma.deny`` for one policy by shelling out to ``opa``."""
    if shutil.which("opa") is None:
        msg = (
            "lemma check --policy-dir requires the `opa` binary (Open Policy "
            "Agent). Install it from https://www.openpolicyagent.org/docs/latest/#running-opa "
            "or `brew install opa` (macOS), then re-run."
        )
        raise ValueError(msg)

    cmd = [
        "opa",
        "eval",
        "--format",
        "json",
        "--data",
        str(rego_file),
        "--stdin-input",
        _DENY_QUERY,
    ]
    completed = subprocess.run(
        cmd,
        input=json.dumps(input_document),
        capture_output=True,
        text=True,
        timeout=_OPA_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        msg = f"Rego evaluation of '{rego_file.name}' failed: {detail}"
        raise ValueError(msg)

    return _parse_deny(completed.stdout, rego_file)


def _parse_deny(opa_stdout: str, rego_file: Path) -> list[str]:
    """Pull the ``deny`` set out of ``opa eval --format json`` output."""
    try:
        payload = json.loads(opa_stdout or "{}")
    except json.JSONDecodeError as exc:
        msg = f"Could not parse opa output for '{rego_file.name}': {exc}"
        raise ValueError(msg) from exc

    results = payload.get("result") or []
    if not results:
        # Undefined deny rule (or no result) → the policy raised nothing.
        return []

    expressions = results[0].get("expressions") or []
    if not expressions:
        return []

    value = expressions[0].get("value")
    if not isinstance(value, list):
        return []
    return [str(v) for v in value]
