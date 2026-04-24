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
from dataclasses import dataclass, field
from typing import Any

from lemma.models.scope import MatchOperator, MatchRule, ScopeDefinition


@dataclass(frozen=True)
class ScopeImpact:
    """Delta between pre-change and post-change scope membership.

    - ``entered``: scopes the resource will belong to *after* the change
      but did not belong to *before*.
    - ``exited``: scopes the resource belonged to *before* but will not
      *after*. Populated for deletes too.
    - ``unchanged``: scopes whose membership is stable across the change.
    """

    entered: list[str] = field(default_factory=list)
    exited: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)


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


def scope_impact_for_change(
    *,
    before: dict | None,
    after: dict | None,
    scopes: list[ScopeDefinition],
) -> ScopeImpact:
    """Compare pre- and post-change scope membership for a single resource.

    Creates pass ``before=None``; deletes pass ``after=None``. Either
    side being ``None`` is treated as "zero matching scopes on that
    side" — so a create can only enter scopes, a delete can only exit.
    """
    before_scopes = set(scopes_containing(before, scopes)) if before is not None else set()
    after_scopes = set(scopes_containing(after, scopes)) if after is not None else set()

    return ScopeImpact(
        entered=sorted(after_scopes - before_scopes),
        exited=sorted(before_scopes - after_scopes),
        unchanged=sorted(after_scopes & before_scopes),
    )
