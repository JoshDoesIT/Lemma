"""First-party GitHub connector.

Emits OCSF compliance evidence for repository-level posture that
matters to governance reviews:

- Branch protection on ``main`` — present/absent + configuration detail.
- CODEOWNERS file — present/absent + owner count.
- Dependabot alert summary — one ``DetectionFinding`` per non-zero
  severity bucket.

Auth: an optional bearer token (env ``LEMMA_GITHUB_TOKEN`` or
constructor ``token=...``). Token-less runs hit the public API under
GitHub's 60-requests-per-hour unauthenticated limit; with a token the
limit is 5000/hour. Private repos require a token.

Tests inject a custom ``httpx.Client`` with a ``MockTransport`` so CI
never touches ``api.github.com``.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import UTC, datetime

import httpx

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import ComplianceFinding, DetectionFinding, OcsfBaseEvent
from lemma.sdk.connector import Connector

_API_BASE = "https://api.github.com"
_PRODUCER = "GitHub"


def _today_utc_iso_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _metadata(repo: str, uid: str) -> dict:
    return {
        "version": "1.3.0",
        "product": {"name": _PRODUCER, "vendor_name": "GitHub, Inc.", "uid": uid},
        "repo": repo,
        "uid": uid,
    }


class GitHubConnector(Connector):
    """Collect compliance posture from a GitHub repository."""

    def __init__(
        self,
        *,
        repo: str,
        client: httpx.Client | None = None,
        token: str | None = None,
    ) -> None:
        self._repo = repo
        self._client = client or httpx.Client(base_url=_API_BASE)
        self._token = token or os.environ.get("LEMMA_GITHUB_TOKEN") or None

        self.manifest = ConnectorManifest(
            name="github",
            version="0.1.0",
            producer=_PRODUCER,
            description="GitHub repository posture: branch protection, CODEOWNERS, Dependabot.",
            capabilities=["branch-protection", "codeowners", "dependabot"],
        )

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _get(self, path: str) -> httpx.Response:
        response = self._client.get(path, headers=self._headers())
        if response.status_code == 429 or (
            response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0"
        ):
            msg = (
                f"GitHub API rate-limit exceeded while fetching {path}. "
                "Configure LEMMA_GITHUB_TOKEN or retry after the quota resets."
            )
            raise ValueError(msg)
        return response

    def _branch_protection_finding(self) -> ComplianceFinding:
        response = self._get(f"/repos/{self._repo}/branches/main/protection")
        uid = f"github:branch-protection:{self._repo}:{_today_utc_iso_date()}"

        if response.status_code == 404:
            message = f"main branch is unprotected in {self._repo}."
            status_id = 2
        elif response.is_success:
            data = response.json()
            reviews = data.get("required_pull_request_reviews", {}) or {}
            checks = data.get("required_status_checks", {}) or {}
            message = (
                f"main branch in {self._repo} is protected: "
                f"required reviews={reviews.get('required_approving_review_count', 0)}, "
                f"strict checks={checks.get('strict', False)}."
            )
            status_id = 1
        else:
            message = (
                f"Could not read branch protection for {self._repo}: HTTP {response.status_code}"
            )
            status_id = 0

        return ComplianceFinding(
            class_name="Compliance Finding",
            category_uid=2000,
            category_name="Findings",
            type_uid=200301,
            activity_id=1,
            time=datetime.now(UTC),
            message=message,
            status_id=status_id,
            metadata=_metadata(self._repo, uid),
        )

    def _codeowners_finding(self) -> ComplianceFinding:
        response = self._get(f"/repos/{self._repo}/contents/CODEOWNERS")
        uid = f"github:codeowners:{self._repo}:{_today_utc_iso_date()}"

        if response.status_code == 404:
            message = f"CODEOWNERS file is absent in {self._repo}."
            status_id = 2
        elif response.is_success:
            message = f"CODEOWNERS file is present in {self._repo}."
            status_id = 1
        else:
            message = f"Could not read CODEOWNERS for {self._repo}: HTTP {response.status_code}"
            status_id = 0

        return ComplianceFinding(
            class_name="Compliance Finding",
            category_uid=2000,
            category_name="Findings",
            type_uid=200302,
            activity_id=1,
            time=datetime.now(UTC),
            message=message,
            status_id=status_id,
            metadata=_metadata(self._repo, uid),
        )

    def _dependabot_findings(self) -> list[DetectionFinding]:
        response = self._get(f"/repos/{self._repo}/dependabot/alerts?state=open")
        if response.status_code == 404:
            return []
        alerts = response.json() if response.is_success else []
        if not isinstance(alerts, list):
            return []

        counts: dict[str, int] = {}
        for alert in alerts:
            severity = alert.get("security_advisory", {}).get("severity", "unknown")
            counts[severity] = counts.get(severity, 0) + 1

        out: list[DetectionFinding] = []
        for severity, count in sorted(counts.items()):
            uid = f"github:dependabot:{self._repo}:{severity}:{_today_utc_iso_date()}"
            md = _metadata(self._repo, uid)
            md["severity"] = severity
            md["alert_count"] = count
            out.append(
                DetectionFinding(
                    class_name="Detection Finding",
                    category_uid=2000,
                    category_name="Findings",
                    type_uid=200401,
                    activity_id=1,
                    time=datetime.now(UTC),
                    message=(
                        f"Dependabot: {count} open {severity}-severity alert(s) in {self._repo}."
                    ),
                    status_id=2 if severity in {"high", "critical"} else 1,
                    metadata=md,
                )
            )
        return out

    def collect(self) -> Iterable[OcsfBaseEvent]:
        yield self._branch_protection_finding()
        yield self._codeowners_finding()
        yield from self._dependabot_findings()
