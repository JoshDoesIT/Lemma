"""Tests for the Person Pydantic model."""

from __future__ import annotations

import pytest


class TestPersonDefinition:
    def test_accepts_valid_dict(self):
        from lemma.models.person import PersonDefinition

        p = PersonDefinition(
            id="alice",
            name="Alice Chen",
            email="alice@example.com",
            role="Security Lead",
            owns=["control:nist-800-53:ac-2", "resource:prod-us-east-rds"],
        )
        assert p.id == "alice"
        assert p.email == "alice@example.com"
        assert p.owns == ["control:nist-800-53:ac-2", "resource:prod-us-east-rds"]

    def test_optional_fields_default_to_empty(self):
        from lemma.models.person import PersonDefinition

        p = PersonDefinition(id="bob", name="Bob")
        assert p.email == ""
        assert p.role == ""
        assert p.owns == []

    def test_rejects_unknown_top_level_field(self):
        """A typo like `owner` must fail loud."""
        from lemma.models.person import PersonDefinition

        with pytest.raises(ValueError, match=r"(?i)manager"):
            PersonDefinition(
                id="alice",
                name="Alice",
                manager="bob",  # type: ignore[call-arg]
            )
