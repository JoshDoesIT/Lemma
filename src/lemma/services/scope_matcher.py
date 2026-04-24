"""Scope match-rule evaluator.

Given a resource's ``attributes`` dict, determine which declared scopes
contain it. This is the runtime side of scope-as-code: parsing lives in
``lemma.services.scope``, the rules are defined in ``lemma.models.scope``,
and this module answers the "is this resource inside this scope?" question.

A scope contains a resource when **every** one of its ``match_rules``
evaluates to true against the resource's attributes. A scope with zero
match rules is a catch-all and matches everything — operators use this
deliberately for org-wide scopes.

``source`` paths use dotted traversal: ``aws.tags.Environment`` walks
``{"aws": {"tags": {"Environment": ...}}}``. A missing path does not
match (returns False) rather than raising — missing fields are normal
in heterogeneous resource attributes.
"""

from __future__ import annotations

import re
from typing import Any

from lemma.models.scope import MatchOperator, MatchRule, ScopeDefinition


def _resolve(attributes: dict, source: str) -> Any:
    """Walk the dotted source path. Return ``None`` if any segment is missing."""
    current: Any = attributes
    for segment in source.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    return current


def matches(rule: MatchRule, attributes: dict) -> bool:
    """True when ``rule`` evaluates to a truthy match against ``attributes``."""
    actual = _resolve(attributes, rule.source)
    if actual is None:
        return False

    if rule.operator == MatchOperator.EQUALS:
        return actual == rule.value

    if rule.operator == MatchOperator.CONTAINS:
        if not isinstance(actual, str) or not isinstance(rule.value, str):
            return False
        return rule.value in actual

    if rule.operator == MatchOperator.IN:
        if not isinstance(rule.value, list):
            msg = (
                f"match rule on '{rule.source}' uses operator=in but value is not "
                "a list; declare value as a YAML list to use this operator."
            )
            raise ValueError(msg)
        return actual in rule.value

    if rule.operator == MatchOperator.MATCHES:
        if not isinstance(actual, str) or not isinstance(rule.value, str):
            return False
        return re.search(rule.value, actual) is not None

    # Unreachable — the enum is closed, but be loud if a new operator is added
    # without a matching branch here.
    msg = f"unhandled match operator: {rule.operator!r}"
    raise ValueError(msg)


def scopes_containing(attributes: dict, scopes: list[ScopeDefinition]) -> list[str]:
    """Return the names of every scope whose rules are all satisfied by ``attributes``."""
    result = []
    for scope in scopes:
        if all(matches(rule, attributes) for rule in scope.match_rules):
            result.append(scope.name)
    return result
