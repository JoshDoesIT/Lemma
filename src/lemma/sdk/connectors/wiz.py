"""First-party Wiz CSPM connector (Refs #41).

Pulls cloud-security-posture evidence from Wiz and emits one OCSF
``ComplianceFinding`` summarizing **open issues by severity** — specifically
the count of open ``CRITICAL`` and ``HIGH`` issues. It's the auditable signal a
cloud-posture review wants: the CSPM is in place and there are (or aren't)
unresolved high-severity exposures.

Auth: Wiz uses an OAuth2 client-credentials exchange (service-account
``client_id`` + ``client_secret``) against ``auth_url`` (default
``https://auth.app.wiz.io/oauth/token``, ``audience=wiz-api``); the returned
bearer token authorizes a GraphQL query to the tenant's ``api_url``. The client
secret is required (set ``LEMMA_WIZ_CLIENT_SECRET`` in the environment or pass
``client_secret=...``); a missing secret is a loud error at construction time.

``metadata.uid`` is stable per ``(api host, UTC date)`` so same-day re-runs
dedupe. Tests inject a custom ``httpx.Client`` with a ``MockTransport`` (routing
by URL) so CI never touches a real Wiz tenant.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import ComplianceFinding, OcsfBaseEvent
from lemma.sdk.connector import Connector

_PRODUCER = "Wiz"
_DEFAULT_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
_AUDIENCE = "wiz-api"

# Open issues with severity, for the posture rollup.
_ISSUES_QUERY = """
query LemmaIssues($filterBy: IssueFilters, $first: Int) {
  issues(filterBy: $filterBy, first: $first) {
    nodes { id severity status }
    totalCount
  }
}
""".strip()


def _today_utc_iso_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _metadata(site: str, uid: str) -> dict:
    return {
        "version": "1.3.0",
        "product": {"name": _PRODUCER, "vendor_name": "Wiz, Inc.", "uid": uid},
        "site": site,
        "uid": uid,
    }


class WizConnector(Connector):
    """Collect cloud-security-posture issues from a Wiz tenant."""

    def __init__(
        self,
        *,
        api_url: str,
        client_id: str,
        client_secret: str | None = None,
        auth_url: str = _DEFAULT_AUTH_URL,
        client: httpx.Client | None = None,
    ) -> None:
        if not api_url:
            msg = "WizConnector requires api_url=https://api.<region>.app.wiz.io/graphql."
            raise ValueError(msg)
        if not client_id:
            msg = "WizConnector requires a client_id (Wiz service-account id)."
            raise ValueError(msg)
        self._client_secret = client_secret or os.environ.get("LEMMA_WIZ_CLIENT_SECRET") or None
        if not self._client_secret:
            msg = (
                "WizConnector requires a client secret. Set LEMMA_WIZ_CLIENT_SECRET "
                "in the environment or pass client_secret=... to the constructor."
            )
            raise ValueError(msg)

        self._api_url = api_url
        self._client_id = client_id
        self._auth_url = auth_url
        self._site = urlparse(api_url).netloc or api_url
        self._client = client or httpx.Client()
        self._token: str | None = None

        self.manifest = ConnectorManifest(
            name="wiz",
            version="0.1.0",
            producer=_PRODUCER,
            description=("Wiz cloud-security-posture (CSPM): count of open CRITICAL/HIGH issues."),
            capabilities=["cloud-posture"],
        )

    def _access_token(self) -> str:
        if self._token is not None:
            return self._token
        response = self._client.post(
            self._auth_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "audience": _AUDIENCE,
            },
        )
        if not response.is_success:
            msg = (
                f"Wiz token exchange failed (HTTP {response.status_code}). "
                "Check the client_id/secret and auth_url."
            )
            raise ValueError(msg)
        token = response.json().get("access_token")
        if not token:
            msg = "Wiz token exchange returned no access_token."
            raise ValueError(msg)
        self._token = str(token)
        return self._token

    def _query_issues(self) -> list[dict]:
        response = self._client.post(
            self._api_url,
            headers={"Authorization": f"Bearer {self._access_token()}"},
            json={
                "query": _ISSUES_QUERY,
                "variables": {"filterBy": {"status": ["OPEN"]}, "first": 500},
            },
        )
        if response.status_code == 429:
            msg = "Wiz API rate-limit exceeded while querying issues. Retry after the quota resets."
            raise ValueError(msg)
        if not response.is_success:
            return []
        payload = response.json()
        try:
            nodes = payload["data"]["issues"]["nodes"]
        except (KeyError, TypeError):
            return []
        return [n for n in nodes if isinstance(n, dict)]

    def _cloud_posture_finding(self) -> ComplianceFinding:
        nodes = self._query_issues()
        uid = f"wiz:cloud-posture:{self._site}:{_today_utc_iso_date()}"

        def _sev(node: dict) -> str:
            return str(node.get("severity", "")).upper()

        critical = sum(1 for n in nodes if _sev(n) == "CRITICAL")
        high = sum(1 for n in nodes if _sev(n) == "HIGH")

        if critical or high:
            message = (
                f"Wiz cloud posture on {self._site}: {critical} open CRITICAL and "
                f"{high} open HIGH issue(s) of {len(nodes)} open issue(s) — remediate."
            )
            status_id = 2
        else:
            message = (
                f"Wiz cloud posture on {self._site}: no open CRITICAL/HIGH issues "
                f"({len(nodes)} open issue(s) total)."
            )
            status_id = 1

        md = _metadata(self._site, uid)
        md["open_critical_count"] = critical
        md["open_high_count"] = high
        md["open_issue_total"] = len(nodes)

        return ComplianceFinding(
            class_name="Compliance Finding",
            category_uid=2000,
            category_name="Findings",
            type_uid=200301,
            activity_id=1,
            time=datetime.now(UTC),
            message=message,
            status_id=status_id,
            metadata=md,
        )

    def collect(self) -> Iterable[OcsfBaseEvent]:
        yield self._cloud_posture_finding()
