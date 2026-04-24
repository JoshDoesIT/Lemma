"""Meta-tests for the --run-eval gating mechanism.

Verifies that the `--run-eval` pytest flag is registered. The actual
evaluation suite that depends on it lives in the other files in this
directory and is skipped by default.
"""

from __future__ import annotations


def test_eval_flag_is_registered_on_parser(pytestconfig):
    """The --run-eval flag must exist at the pytest-config level."""
    value = pytestconfig.getoption("--run-eval")
    assert value is False or value is True  # bool option, either default or set
