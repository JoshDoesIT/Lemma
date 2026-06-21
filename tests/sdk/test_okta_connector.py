"""Tests for the first-party Okta connector.

Uses httpx.MockTransport to stub the Okta API — no network calls in CI.
"""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path

import httpx
import pytest


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(base_url="https://example.okta.com", transport=httpx.MockTransport(handler))


def _default_handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if "/api/v1/policies" in url and "type=MFA_ENROLL" in url:
        return httpx.Response(
            200,
            json=[
                {
                    "id": "00p1abc",
                    "name": "Default MFA Policy",
                    "status": "ACTIVE",
                    "system": True,
                }
            ],
        )
    if "/api/v1/policies" in url and "type=PASSWORD" in url:
        return httpx.Response(
            200,
            json=[
                {"id": "00p2pwd", "name": "Default Password Policy", "status": "ACTIVE"},
            ],
        )
    if "/api/v1/apps" in url:
        return httpx.Response(
            200,
            json=[
                {"id": "0oa1", "status": "ACTIVE", "label": "Workday"},
                {"id": "0oa2", "status": "ACTIVE", "label": "GitHub"},
                {"id": "0oa3", "status": "INACTIVE", "label": "Legacy"},
            ],
        )
    if "/api/v1/users" in url:
        return httpx.Response(
            200,
            json=[
                {"id": "u1", "status": "ACTIVE"},
                {"id": "u2", "status": "ACTIVE"},
                {"id": "u3", "status": "SUSPENDED"},
                {"id": "u4", "status": "DEPROVISIONED"},
            ],
        )
    if "/api/v1/groups" in url:
        return httpx.Response(
            200,
            json=[
                {"id": "g1", "type": "OKTA_GROUP", "profile": {"name": "Everyone"}},
                {"id": "g2", "type": "OKTA_GROUP", "profile": {"name": "Admins"}},
                {"id": "g3", "type": "BUILT_IN", "profile": {"name": "Super Admins"}},
            ],
        )
    if "/api/v1/logs" in url:
        return httpx.Response(
            200,
            json=[
                {
                    "uuid": "e1",
                    "eventType": "user.authentication.sso",
                    "outcome": {"result": "SUCCESS"},
                },
                {"uuid": "e2", "eventType": "user.session.start", "outcome": {"result": "FAILURE"}},
                {
                    "uuid": "e3",
                    "eventType": "user.authentication.sso",
                    "outcome": {"result": "SUCCESS"},
                },
            ],
        )
    return httpx.Response(404, json={"errorSummary": "Not Found"})


class TestOktaConnectorManifest:
    def test_manifest_pins_producer_and_name(self):
        from lemma.sdk.connectors.okta import OktaConnector

        connector = OktaConnector(
            domain="example.okta.com",
            client=_mock_client(_default_handler),
            token="ssws-test",
        )

        assert connector.manifest.name == "okta"
        assert connector.manifest.producer == "Okta"
        assert "mfa-policy" in connector.manifest.capabilities


class TestMFAPolicy:
    def test_active_mfa_policy_emits_compliance_finding(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.okta import OktaConnector

        connector = OktaConnector(
            domain="example.okta.com",
            client=_mock_client(_default_handler),
            token="ssws-test",
        )
        events = list(connector.collect())
        mfa = [
            e
            for e in events
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("okta:mfa-policy:")
        ]
        assert len(mfa) == 1
        assert "active" in mfa[0].message.lower() or "mfa" in mfa[0].message.lower()

    def test_no_mfa_policies_emits_absent_finding(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.okta import OktaConnector

        def handler(req: httpx.Request) -> httpx.Response:
            if "/api/v1/policies" in str(req.url):
                return httpx.Response(200, json=[])
            return _default_handler(req)

        connector = OktaConnector(
            domain="example.okta.com",
            client=_mock_client(handler),
            token="ssws-test",
        )
        mfa = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("okta:mfa-policy:")
        ]
        assert len(mfa) == 1
        assert "no" in mfa[0].message.lower() or "absent" in mfa[0].message.lower()


class TestSSOApps:
    def test_sso_apps_finding_counts_active_and_total(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.okta import OktaConnector

        connector = OktaConnector(
            domain="example.okta.com",
            client=_mock_client(_default_handler),
            token="ssws-test",
        )
        apps = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("okta:sso-apps:")
        ]
        assert len(apps) == 1
        # Default handler returns 2 active + 1 inactive — message or metadata reflects that.
        assert apps[0].metadata.get("active_count") == 2
        assert apps[0].metadata.get("total_count") == 3


class TestUserInventory:
    def test_user_inventory_counts_by_lifecycle_status(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.okta import OktaConnector

        connector = OktaConnector(
            domain="example.okta.com",
            client=_mock_client(_default_handler),
            token="ssws-test",
        )
        users = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("okta:user-inventory:")
        ]
        assert len(users) == 1
        md = users[0].metadata
        assert md["active_count"] == 2
        assert md["suspended_count"] == 1
        assert md["deprovisioned_count"] == 1
        assert md["total_count"] == 4
        assert users[0].status_id == 1

    def test_user_inventory_unknown_when_call_fails(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.okta import OktaConnector

        def handler(req: httpx.Request) -> httpx.Response:
            if "/api/v1/users" in str(req.url):
                return httpx.Response(500, json={"errorSummary": "boom"})
            return _default_handler(req)

        connector = OktaConnector(
            domain="example.okta.com", client=_mock_client(handler), token="t"
        )
        users = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("okta:user-inventory:")
        ]
        assert len(users) == 1
        assert users[0].status_id == 0


class TestGroups:
    def test_groups_finding_flags_admin_groups(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.okta import OktaConnector

        connector = OktaConnector(
            domain="example.okta.com",
            client=_mock_client(_default_handler),
            token="ssws-test",
        )
        groups = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("okta:groups:")
        ]
        assert len(groups) == 1
        md = groups[0].metadata
        assert md["group_count"] == 3
        assert md["admin_group_count"] == 2
        assert "Admins" in md["admin_groups"]
        assert "Super Admins" in md["admin_groups"]


class TestPasswordPolicy:
    def test_active_password_policy_passes(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.okta import OktaConnector

        connector = OktaConnector(
            domain="example.okta.com",
            client=_mock_client(_default_handler),
            token="ssws-test",
        )
        pw = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("okta:password-policy:")
        ]
        assert len(pw) == 1
        assert pw[0].status_id == 1
        assert pw[0].metadata["active_policy_count"] == 1

    def test_no_password_policy_fails(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.okta import OktaConnector

        def handler(req: httpx.Request) -> httpx.Response:
            if "/api/v1/policies" in str(req.url) and "type=PASSWORD" in str(req.url):
                return httpx.Response(200, json=[])
            return _default_handler(req)

        connector = OktaConnector(
            domain="example.okta.com", client=_mock_client(handler), token="t"
        )
        pw = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("okta:password-policy:")
        ]
        assert len(pw) == 1
        assert pw[0].status_id == 2


class TestAuthEvents:
    def test_auth_events_emit_authentication_event_class_3002(self):
        from lemma.models.ocsf import AuthenticationEvent
        from lemma.sdk.connectors.okta import OktaConnector

        connector = OktaConnector(
            domain="example.okta.com",
            client=_mock_client(_default_handler),
            token="ssws-test",
        )
        auth = [e for e in connector.collect() if isinstance(e, AuthenticationEvent)]
        assert len(auth) == 1
        ev = auth[0]
        assert ev.class_uid == 3002
        assert ev.category_uid == 3000
        assert ev.metadata["success_count"] == 2
        assert ev.metadata["failure_count"] == 1
        assert ev.metadata["product"]["uid"].startswith("okta:auth-events:")

    def test_auth_events_degrade_when_log_api_unavailable(self):
        from lemma.models.ocsf import AuthenticationEvent
        from lemma.sdk.connectors.okta import OktaConnector

        def handler(req: httpx.Request) -> httpx.Response:
            if "/api/v1/logs" in str(req.url):
                return httpx.Response(403, json={"errorSummary": "no log scope"})
            return _default_handler(req)

        connector = OktaConnector(
            domain="example.okta.com", client=_mock_client(handler), token="t"
        )
        auth = [e for e in connector.collect() if isinstance(e, AuthenticationEvent)]
        assert len(auth) == 1
        assert auth[0].status_id == 0
        assert auth[0].metadata["success_count"] == 0


class TestAuth:
    def test_ssws_auth_header_present_when_token_configured(self):
        from lemma.sdk.connectors.okta import OktaConnector

        seen_headers: list[dict] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen_headers.append(dict(req.headers))
            return _default_handler(req)

        connector = OktaConnector(
            domain="example.okta.com",
            client=_mock_client(handler),
            token="00abcdef",
        )
        list(connector.collect())

        assert any(h.get("authorization") == "SSWS 00abcdef" for h in seen_headers)

    def test_missing_token_raises_at_construction(self, monkeypatch):
        from lemma.sdk.connectors.okta import OktaConnector

        monkeypatch.delenv("LEMMA_OKTA_TOKEN", raising=False)
        with pytest.raises(ValueError, match=r"(?i)token"):
            OktaConnector(domain="example.okta.com", client=_mock_client(_default_handler))

    def test_token_read_from_environment(self, monkeypatch):
        from lemma.sdk.connectors.okta import OktaConnector

        monkeypatch.setenv("LEMMA_OKTA_TOKEN", "env-token")
        connector = OktaConnector(domain="example.okta.com", client=_mock_client(_default_handler))
        assert connector._token == "env-token"


class TestRateLimit:
    def test_429_raises_clean_value_error(self):
        from lemma.sdk.connectors.okta import OktaConnector

        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(429, json={"errorSummary": "Too Many Requests"})

        connector = OktaConnector(
            domain="example.okta.com",
            client=_mock_client(handler),
            token="ssws-test",
        )
        with pytest.raises(ValueError, match=r"(?i)rate.?limit"):
            list(connector.collect())


class TestDedupeStability:
    def test_metadata_uid_stable_per_domain_and_day(self, monkeypatch):
        from lemma.sdk.connectors.okta import OktaConnector

        fixed_now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=UTC)

        class _FixedNow:
            @staticmethod
            def now(tz=None):
                return fixed_now

        monkeypatch.setattr("lemma.sdk.connectors.okta.datetime", _FixedNow)

        first = {
            e.metadata["product"]["uid"]
            for e in OktaConnector(
                domain="example.okta.com",
                client=_mock_client(_default_handler),
                token="t",
            ).collect()
        }
        second = {
            e.metadata["product"]["uid"]
            for e in OktaConnector(
                domain="example.okta.com",
                client=_mock_client(_default_handler),
                token="t",
            ).collect()
        }

        assert first == second
        assert all(uid.endswith(":2026-04-24") for uid in first)


class TestEndToEnd:
    def test_full_run_signs_and_chains_every_event(self, tmp_path: Path):
        from lemma.sdk.connectors.okta import OktaConnector
        from lemma.services.evidence_log import EvidenceLog

        connector = OktaConnector(
            domain="example.okta.com",
            client=_mock_client(_default_handler),
            token="ssws-test",
        )
        log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")

        result = connector.run(log)
        assert result.ingested > 0

        envelopes = log.read_envelopes()
        assert len(envelopes) == result.ingested
        assert all(env.signer_key_id.startswith("ed25519:") for env in envelopes)
        for prior, current in pairwise(envelopes):
            assert current.prev_hash == prior.entry_hash
