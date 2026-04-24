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
    if "/api/v1/apps" in url:
        return httpx.Response(
            200,
            json=[
                {"id": "0oa1", "status": "ACTIVE", "label": "Workday"},
                {"id": "0oa2", "status": "ACTIVE", "label": "GitHub"},
                {"id": "0oa3", "status": "INACTIVE", "label": "Legacy"},
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
