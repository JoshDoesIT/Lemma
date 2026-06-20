"""Tests for current-principal resolution (Refs #38)."""

from __future__ import annotations

import pytest


class TestCurrentRole:
    def test_defaults_to_owner_when_unset(self, monkeypatch):
        from lemma.models.rbac import Role
        from lemma.services.principal import current_role

        monkeypatch.delenv("LEMMA_ROLE", raising=False)
        assert current_role() is Role.OWNER

    def test_reads_role_from_env_case_insensitive(self, monkeypatch):
        from lemma.models.rbac import Role
        from lemma.services.principal import current_role

        monkeypatch.setenv("LEMMA_ROLE", "Auditor")
        assert current_role() is Role.AUDITOR

    def test_blank_env_defaults_to_owner(self, monkeypatch):
        from lemma.models.rbac import Role
        from lemma.services.principal import current_role

        monkeypatch.setenv("LEMMA_ROLE", "   ")
        assert current_role() is Role.OWNER

    def test_unknown_role_raises(self, monkeypatch):
        from lemma.services.principal import current_role

        monkeypatch.setenv("LEMMA_ROLE", "superuser")
        with pytest.raises(ValueError, match=r"(?i)unknown role"):
            current_role()


class TestRequirePermission:
    def test_owner_passes(self, monkeypatch):
        from lemma.models.rbac import Permission
        from lemma.services.principal import require_permission

        monkeypatch.setenv("LEMMA_ROLE", "owner")
        require_permission(Permission.MANAGE_USERS)  # no raise

    def test_auditor_blocked_on_write(self, monkeypatch):
        from lemma.models.rbac import AccessDeniedError, Permission
        from lemma.services.principal import require_permission

        monkeypatch.setenv("LEMMA_ROLE", "auditor")
        with pytest.raises(AccessDeniedError):
            require_permission(Permission.WRITE_MAPPING)
