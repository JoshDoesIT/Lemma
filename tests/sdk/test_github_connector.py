"""Tests for the first-party GitHub connector.

Uses httpx.MockTransport to stub the GitHub API — no network calls in CI.
"""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path

import httpx
import pytest


def _mock_client(handler) -> httpx.Client:
    """Return an httpx.Client with a MockTransport wired to ``handler``."""
    return httpx.Client(base_url="https://api.github.com", transport=httpx.MockTransport(handler))


def _default_handler(request: httpx.Request) -> httpx.Response:
    """Stub that returns sensible defaults for every endpoint the connector hits."""
    url = str(request.url)
    if "/branches/main/protection" in url:
        return httpx.Response(
            200,
            json={
                "required_pull_request_reviews": {"required_approving_review_count": 2},
                "required_status_checks": {"strict": True, "contexts": ["ci"]},
                "enforce_admins": {"enabled": True},
            },
        )
    if "/contents/CODEOWNERS" in url:
        return httpx.Response(
            200,
            json={
                "content": "KipENyYS00LnB5IEBqb3NoCg==",  # base64 of "src/app/*.py @josh\n"
                "encoding": "base64",
            },
        )
    if "/dependabot/alerts" in url:
        return httpx.Response(
            200,
            json=[
                {"state": "open", "security_advisory": {"severity": "high"}},
                {"state": "open", "security_advisory": {"severity": "medium"}},
                {"state": "open", "security_advisory": {"severity": "medium"}},
            ],
        )
    return httpx.Response(404, json={"message": "Not Found"})


class TestGitHubConnectorManifest:
    def test_manifest_pins_producer_and_name(self):
        from lemma.sdk.connectors.github import GitHubConnector

        connector = GitHubConnector(repo="JoshDoesIT/Lemma", client=_mock_client(_default_handler))

        assert connector.manifest.name == "github"
        assert connector.manifest.producer == "GitHub"
        assert "branch-protection" in connector.manifest.capabilities


class TestBranchProtection:
    def test_protected_main_emits_compliance_finding_with_protected_state(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.github import GitHubConnector

        connector = GitHubConnector(repo="JoshDoesIT/Lemma", client=_mock_client(_default_handler))
        events = list(connector.collect())
        bp_events = [
            e
            for e in events
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("github:branch-protection:")
        ]

        assert len(bp_events) == 1
        bp = bp_events[0]
        assert "protected" in bp.message.lower()
        assert bp.metadata["repo"] == "JoshDoesIT/Lemma"

    def test_unprotected_main_still_emits_a_finding(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.github import GitHubConnector

        def handler(req: httpx.Request) -> httpx.Response:
            if "/branches/main/protection" in str(req.url):
                # GitHub returns 404 when branch protection isn't configured.
                return httpx.Response(404, json={"message": "Branch not protected"})
            return _default_handler(req)

        connector = GitHubConnector(repo="JoshDoesIT/Lemma", client=_mock_client(handler))
        bp_events = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("github:branch-protection:")
        ]
        assert len(bp_events) == 1
        msg = bp_events[0].message.lower()
        assert "unprotected" in msg or "not protected" in msg


class TestCodeowners:
    def test_codeowners_present_emits_finding(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.github import GitHubConnector

        connector = GitHubConnector(repo="JoshDoesIT/Lemma", client=_mock_client(_default_handler))
        events = list(connector.collect())
        co_events = [
            e
            for e in events
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("github:codeowners:")
        ]
        assert len(co_events) == 1
        assert "codeowners" in co_events[0].message.lower()

    def test_codeowners_absent_still_emits_a_finding(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.github import GitHubConnector

        def handler(req: httpx.Request) -> httpx.Response:
            if "/contents/CODEOWNERS" in str(req.url):
                return httpx.Response(404, json={"message": "Not Found"})
            return _default_handler(req)

        connector = GitHubConnector(repo="JoshDoesIT/Lemma", client=_mock_client(handler))
        co_events = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("github:codeowners:")
        ]
        assert len(co_events) == 1
        assert "absent" in co_events[0].message.lower() or "missing" in co_events[0].message.lower()


class TestDependabot:
    def test_dependabot_emits_detection_finding_per_severity(self):
        from lemma.models.ocsf import DetectionFinding
        from lemma.sdk.connectors.github import GitHubConnector

        connector = GitHubConnector(repo="JoshDoesIT/Lemma", client=_mock_client(_default_handler))
        detections = [e for e in connector.collect() if isinstance(e, DetectionFinding)]
        by_severity = {e.metadata["severity"]: e for e in detections}

        # Default handler returns 1 high + 2 medium — one event per non-zero severity bucket.
        assert "high" in by_severity
        assert "medium" in by_severity
        assert by_severity["high"].metadata["alert_count"] == 1
        assert by_severity["medium"].metadata["alert_count"] == 2


class TestAuth:
    def test_auth_header_present_when_token_configured(self):
        from lemma.sdk.connectors.github import GitHubConnector

        seen_headers: list[dict] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen_headers.append(dict(req.headers))
            return _default_handler(req)

        client = _mock_client(handler)
        connector = GitHubConnector(repo="JoshDoesIT/Lemma", client=client, token="gh-test-token")
        list(connector.collect())

        assert any(h.get("authorization") == "Bearer gh-test-token" for h in seen_headers)

    def test_no_auth_header_when_token_absent(self):
        from lemma.sdk.connectors.github import GitHubConnector

        seen_headers: list[dict] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen_headers.append(dict(req.headers))
            return _default_handler(req)

        client = _mock_client(handler)
        connector = GitHubConnector(repo="JoshDoesIT/Lemma", client=client)
        list(connector.collect())

        assert all("authorization" not in h for h in seen_headers)


class TestRateLimit:
    def test_rate_limited_response_raises_clear_error(self):
        from lemma.sdk.connectors.github import GitHubConnector

        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                429, headers={"x-ratelimit-remaining": "0"}, json={"message": "API rate limit"}
            )

        connector = GitHubConnector(repo="JoshDoesIT/Lemma", client=_mock_client(handler))
        with pytest.raises(ValueError, match=r"(?i)rate.?limit"):
            list(connector.collect())


class TestDedupeStability:
    def test_metadata_uid_is_stable_per_event_type_repo_and_day(self, monkeypatch):
        """Re-running the connector on the same day dedupes against itself."""
        from lemma.sdk.connectors.github import GitHubConnector

        # Freeze time so both runs land on the same UTC date.
        fixed_now = datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC)

        class _FixedNow:
            @staticmethod
            def now(tz=None):
                return fixed_now

        monkeypatch.setattr("lemma.sdk.connectors.github.datetime", _FixedNow)

        first_uids = {
            e.metadata["product"]["uid"]
            for e in GitHubConnector(
                repo="JoshDoesIT/Lemma", client=_mock_client(_default_handler)
            ).collect()
        }
        second_uids = {
            e.metadata["product"]["uid"]
            for e in GitHubConnector(
                repo="JoshDoesIT/Lemma", client=_mock_client(_default_handler)
            ).collect()
        }

        assert first_uids == second_uids
        assert all(uid.endswith(":2026-04-22") for uid in first_uids)


class TestEndToEnd:
    def test_full_run_signs_and_chains_every_event(self, tmp_path: Path):
        from lemma.sdk.connectors.github import GitHubConnector
        from lemma.services.evidence_log import EvidenceLog

        connector = GitHubConnector(repo="JoshDoesIT/Lemma", client=_mock_client(_default_handler))
        evidence_log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")

        result = connector.run(evidence_log)
        assert result.ingested > 0

        envelopes = evidence_log.read_envelopes()
        assert len(envelopes) == result.ingested
        # Each envelope is signed by the "GitHub" producer.
        assert all(env.signer_key_id.startswith("ed25519:") for env in envelopes)
        # Chain: second entry's prev_hash == first entry's entry_hash, etc.
        for prior, current in pairwise(envelopes):
            assert current.prev_hash == prior.entry_hash
