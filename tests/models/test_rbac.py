"""Tests for the RBAC role/permission model (Refs #38)."""

from __future__ import annotations

import pytest


class TestRolesAndPermissions:
    def test_three_roles_exist(self):
        from lemma.models.rbac import Role

        assert {r.value for r in Role} == {"owner", "engineer", "auditor"}

    def test_owner_has_every_permission(self):
        from lemma.models.rbac import Permission, Role, authorize

        for perm in Permission:
            assert authorize(Role.OWNER, perm), f"owner should hold {perm}"

    def test_auditor_is_read_only(self):
        from lemma.models.rbac import Permission, Role, authorize

        # Auditor can read and verify/export, but cannot mutate anything.
        assert authorize(Role.AUDITOR, Permission.READ)
        assert authorize(Role.AUDITOR, Permission.VERIFY_EVIDENCE)
        assert authorize(Role.AUDITOR, Permission.EXPORT)
        for perm in (
            Permission.WRITE_MAPPING,
            Permission.REVIEW_DECISION,
            Permission.MANAGE_SCOPES,
            Permission.MANAGE_KEYS,
            Permission.MANAGE_USERS,
        ):
            assert not authorize(Role.AUDITOR, perm), f"auditor must not hold {perm}"

    def test_engineer_can_write_but_not_administer(self):
        from lemma.models.rbac import Permission, Role, authorize

        # Engineers do the compliance work...
        assert authorize(Role.ENGINEER, Permission.READ)
        assert authorize(Role.ENGINEER, Permission.WRITE_MAPPING)
        assert authorize(Role.ENGINEER, Permission.REVIEW_DECISION)
        assert authorize(Role.ENGINEER, Permission.MANAGE_SCOPES)
        # ...but not user/role administration.
        assert not authorize(Role.ENGINEER, Permission.MANAGE_USERS)

    def test_roles_are_ordered_by_privilege(self):
        from lemma.models.rbac import Permission, Role, authorize

        # Every permission an auditor holds, an engineer also holds; every
        # permission an engineer holds, an owner also holds.
        for perm in Permission:
            if authorize(Role.AUDITOR, perm):
                assert authorize(Role.ENGINEER, perm)
            if authorize(Role.ENGINEER, perm):
                assert authorize(Role.OWNER, perm)


class TestRequire:
    def test_require_passes_for_authorized(self):
        from lemma.models.rbac import Permission, Role, require

        require(Role.ENGINEER, Permission.WRITE_MAPPING)  # no raise

    def test_require_raises_for_unauthorized(self):
        from lemma.models.rbac import AccessDeniedError, Permission, Role, require

        with pytest.raises(AccessDeniedError, match=r"(?i)auditor.*manage_users|not permitted"):
            require(Role.AUDITOR, Permission.MANAGE_USERS)


class TestRoleParsing:
    def test_from_string_case_insensitive(self):
        from lemma.models.rbac import Role

        assert Role.from_string("Owner") is Role.OWNER
        assert Role.from_string("AUDITOR") is Role.AUDITOR

    def test_from_string_unknown_raises(self):
        from lemma.models.rbac import Role

        with pytest.raises(ValueError, match=r"(?i)unknown role|owner, engineer, auditor"):
            Role.from_string("superuser")
