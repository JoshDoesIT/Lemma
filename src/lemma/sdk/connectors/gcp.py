"""First-party GCP connector (Refs #115).

Pulls compliance posture from a Google Cloud project and emits two
``ComplianceFinding`` events covering foundational posture every
auditor asks about first:

- **IAM service-account keys** — count of user-managed keys on every
  service account in the project, and how many are older than the
  90-day rotation window. ``status_id=1`` when no stale keys exist,
  ``status_id=2`` when at least one is stale.
- **Cloud Audit Logs sink presence** — count of project log sinks
  whose destination is BigQuery or Cloud Storage (the two destinations
  that give durable, queryable retention). ``status_id=1`` when at
  least one durable sink exists, ``status_id=2`` when none do.

**Auth.** GCP's canonical JWT-bearer-assertion → access-token flow
needs ``google-auth`` as a heavyweight dependency. The pragmatic v0
takes a pre-minted access token via ``access_token=...`` or the
``LEMMA_GCP_ACCESS_TOKEN`` env var; operators with a service-account
JSON mint a token out-of-band (``gcloud auth ...`` /
``google.oauth2.service_account.Credentials``) and pass it in. The
token is sent as ``Authorization: Bearer <token>`` on every request.

Rate-limited responses (HTTP 429) raise a clean ``ValueError`` naming
the endpoint, mirroring the Okta and Jira connectors.

Tests inject a custom ``httpx.Client`` with a ``MockTransport`` so CI
never touches a real GCP project.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from datetime import datetime as _datetime_for_parse

import httpx

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import ComplianceFinding, OcsfBaseEvent
from lemma.sdk.connector import Connector

_PRODUCER = "GCP"
_KEY_ROTATION_DAYS = 90


def _today_utc_iso_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _metadata(project_id: str, uid: str) -> dict:
    return {
        "version": "1.3.0",
        "product": {"name": _PRODUCER, "vendor_name": "Google LLC", "uid": uid},
        "project_id": project_id,
        "uid": uid,
    }


class GCPConnector(Connector):
    """Collect project-level posture from a Google Cloud project."""

    def __init__(
        self,
        *,
        project_id: str,
        access_token: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        if not project_id:
            msg = "GCPConnector requires a project_id (the Google Cloud project name)."
            raise ValueError(msg)
        self._project_id = project_id
        self._access_token = access_token or os.environ.get("LEMMA_GCP_ACCESS_TOKEN") or None
        if not self._access_token:
            msg = (
                "GCPConnector requires an access_token. Set "
                "LEMMA_GCP_ACCESS_TOKEN in the environment or pass "
                "access_token=... to the constructor. The pragmatic v0 "
                "expects a pre-minted OAuth2 access token; mint one with "
                "`gcloud auth print-access-token` or "
                "google.oauth2.service_account.Credentials."
            )
            raise ValueError(msg)

        # Single client across both endpoints — IAM and Logging are both
        # under googleapis.com, only the path prefix differs.
        self._client = client or httpx.Client(base_url="https://googleapis.com")

        self.manifest = ConnectorManifest(
            name="gcp",
            version="0.1.0",
            producer=_PRODUCER,
            description=(
                "GCP project posture: IAM service-account key age, Cloud Audit Logs sink presence."
            ),
            capabilities=["iam-sa-keys", "audit-log-sinks"],
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._access_token}",
        }

    def _get(self, path: str, endpoint_label: str) -> httpx.Response:
        response = self._client.get(path, headers=self._headers())
        if response.status_code == 429:
            msg = (
                f"GCP API rate-limit exceeded while fetching {endpoint_label} "
                f"({path}). Retry after the quota resets."
            )
            raise ValueError(msg)
        return response

    def _iam_sa_keys_finding(self) -> ComplianceFinding:
        path = f"/v1/projects/{self._project_id}/serviceAccounts/-/keys"
        response = self._get(path, endpoint_label="IAM serviceAccounts keys")
        uid = f"gcp:iam-sa-keys:{self._project_id}:{_today_utc_iso_date()}"

        keys: list[dict] = []
        if response.is_success:
            payload = response.json()
            if isinstance(payload, dict):
                raw = payload.get("keys")
                if isinstance(raw, list):
                    keys = [k for k in raw if isinstance(k, dict)]

        cutoff = datetime.now(UTC) - timedelta(days=_KEY_ROTATION_DAYS)
        stale_count = sum(1 for k in keys if _is_stale_key(k, cutoff))
        key_count = len(keys)

        if not response.is_success:
            message = (
                f"Failed to read IAM service-account keys for GCP project "
                f"{self._project_id} (HTTP {response.status_code})."
            )
            status_id = 0
        elif stale_count == 0:
            message = (
                f"GCP project {self._project_id}: {key_count} IAM service-account "
                f"key(s), 0 older than {_KEY_ROTATION_DAYS} days."
            )
            status_id = 1
        else:
            message = (
                f"GCP project {self._project_id}: {stale_count} of {key_count} "
                f"IAM service-account key(s) are older than {_KEY_ROTATION_DAYS} "
                "days and should be rotated."
            )
            status_id = 2

        md = _metadata(self._project_id, uid)
        md["key_count"] = key_count
        md["stale_keys"] = stale_count
        md["rotation_days"] = _KEY_ROTATION_DAYS

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

    def _audit_log_sinks_finding(self) -> ComplianceFinding:
        path = f"/v2/projects/{self._project_id}/sinks"
        response = self._get(path, endpoint_label="Logging sinks")
        uid = f"gcp:audit-log-sinks:{self._project_id}:{_today_utc_iso_date()}"

        sinks: list[dict] = []
        if response.is_success:
            payload = response.json()
            if isinstance(payload, dict):
                raw = payload.get("sinks")
                if isinstance(raw, list):
                    sinks = [s for s in raw if isinstance(s, dict)]

        durable = [s for s in sinks if _is_durable_sink_destination(s.get("destination", ""))]

        if not response.is_success:
            message = (
                f"Failed to read Cloud Audit Logs sinks for GCP project "
                f"{self._project_id} (HTTP {response.status_code})."
            )
            status_id = 0
        elif durable:
            names = ", ".join(s.get("name", "(unnamed)") for s in durable)
            message = (
                f"GCP project {self._project_id} has {len(durable)} durable "
                f"audit-log sink(s) (BigQuery / Cloud Storage): {names}."
            )
            status_id = 1
        else:
            message = (
                f"GCP project {self._project_id} has no durable audit-log sink "
                "(BigQuery or Cloud Storage destination). Pub/Sub-only sinks "
                "do not give the long-term retention auditors expect."
            )
            status_id = 2

        md = _metadata(self._project_id, uid)
        md["sink_count"] = len(sinks)
        md["durable_sink_count"] = len(durable)

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
        yield self._iam_sa_keys_finding()
        yield self._audit_log_sinks_finding()


def _is_stale_key(key: dict, cutoff: datetime) -> bool:
    """A key is stale when its ``validAfterTime`` predates the cutoff."""
    raw = key.get("validAfterTime")
    if not isinstance(raw, str) or not raw:
        return False
    # GCP returns RFC 3339 with a trailing Z; fromisoformat below 3.11
    # rejects Z, and we target 3.12+, but normalize defensively.
    iso = raw.replace("Z", "+00:00")
    try:
        # Use the directly-imported `datetime` class via a private alias so
        # tests that monkeypatch the module-level ``datetime`` name (to
        # freeze ``now()``) don't clobber the parser too.
        ts = _datetime_for_parse.fromisoformat(iso)
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts < cutoff


def _is_durable_sink_destination(destination: str) -> bool:
    """BigQuery and Cloud Storage destinations give durable retention."""
    return destination.startswith("bigquery.googleapis.com") or destination.startswith(
        "storage.googleapis.com"
    )
