"""First-party AWS connector.

Emits OCSF compliance evidence for foundational AWS posture that
every auditor asks about first:

- IAM root-account MFA — enabled / not enabled.
- IAM password policy — present + minimum length, or absent.
- CloudTrail — at least one multi-region trail exists.

Auth: boto3's default credential chain (env vars, AWS profile, IMDS).
No custom Lemma env var is introduced; AWS conventions apply. A
missing-credentials failure at account-id lookup is caught and raised
as a clean ``ValueError`` at construction time so operators aren't
surprised mid-collect.

Tests inject a fake ``boto3.Session`` via the ``session=`` constructor
argument so CI never touches a real AWS account.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import ComplianceFinding, OcsfBaseEvent
from lemma.sdk.connector import Connector

_PRODUCER = "AWS"


def _today_utc_iso_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _metadata(account_id: str, region: str, uid: str) -> dict:
    return {
        "version": "1.3.0",
        "product": {"name": _PRODUCER, "vendor_name": "Amazon Web Services", "uid": uid},
        "account_id": account_id,
        "region": region,
        "uid": uid,
    }


class AWSConnector(Connector):
    """Collect account-level posture from an AWS account."""

    def __init__(
        self,
        *,
        region: str = "us-east-1",
        session: Any | None = None,
    ) -> None:
        self._region = region
        self._session = session or boto3.Session(region_name=region)

        sts = self._session.client("sts")
        try:
            identity = sts.get_caller_identity()
        except NoCredentialsError as exc:
            msg = (
                "AWSConnector could not resolve credentials. "
                "Configure the AWS credential chain (env vars, "
                "AWS profile, or instance metadata) and try again."
            )
            raise ValueError(msg) from exc
        self._account_id = identity["Account"]

        self.manifest = ConnectorManifest(
            name="aws",
            version="0.1.0",
            producer=_PRODUCER,
            description="AWS account posture: IAM root MFA, password policy, CloudTrail.",
            capabilities=["iam-root-mfa", "iam-password-policy", "cloudtrail-multi-region"],
        )

    def _iam_root_mfa_finding(self) -> ComplianceFinding:
        iam = self._session.client("iam")
        summary = iam.get_account_summary().get("SummaryMap", {})
        enabled = bool(summary.get("AccountMFAEnabled"))
        uid = f"aws:iam-root-mfa:{self._account_id}:{_today_utc_iso_date()}"

        if enabled:
            message = f"AWS root-account MFA is enabled on account {self._account_id}."
            status_id = 1
        else:
            message = (
                f"AWS root-account MFA is disabled on account {self._account_id}. "
                "Root credentials without MFA are the single worst IAM exposure."
            )
            status_id = 2

        md = _metadata(self._account_id, self._region, uid)
        md["root_mfa_enabled"] = enabled

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

    def _iam_password_policy_finding(self) -> ComplianceFinding:
        iam = self._session.client("iam")
        uid = f"aws:iam-password-policy:{self._account_id}:{_today_utc_iso_date()}"
        md = _metadata(self._account_id, self._region, uid)

        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NoSuchEntity":
                md["policy_present"] = False
                return ComplianceFinding(
                    class_name="Compliance Finding",
                    category_uid=2000,
                    category_name="Findings",
                    type_uid=200301,
                    activity_id=1,
                    time=datetime.now(UTC),
                    message=(
                        f"No IAM password policy on account {self._account_id}. "
                        "Default AWS policy is weak — set an explicit one."
                    ),
                    status_id=2,
                    metadata=md,
                )
            raise

        min_len = policy.get("MinimumPasswordLength", 0)
        md["policy_present"] = True
        md["minimum_password_length"] = min_len
        md["require_symbols"] = bool(policy.get("RequireSymbols", False))

        message = (
            f"IAM password policy on account {self._account_id}: "
            f"minimum length {min_len}, require symbols "
            f"{policy.get('RequireSymbols', False)}."
        )
        # Status: 1 if minimum length ≥ 14 (NIST recommendation), else 2.
        status_id = 1 if min_len >= 14 else 2

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

    def _cloudtrail_finding(self) -> ComplianceFinding:
        trail = self._session.client("cloudtrail")
        trails = trail.describe_trails().get("trailList", [])
        multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
        uid = f"aws:cloudtrail-multi-region:{self._account_id}:{_today_utc_iso_date()}"

        if multi_region:
            names = ", ".join(t.get("Name", "?") for t in multi_region)
            message = f"CloudTrail multi-region trails on account {self._account_id}: {names}."
            status_id = 1
        else:
            message = (
                f"No multi-region CloudTrail on account {self._account_id}. "
                "Regional-only trails miss activity outside their home region."
            )
            status_id = 2

        md = _metadata(self._account_id, self._region, uid)
        md["trail_count"] = len(multi_region)
        md["total_trail_count"] = len(trails)

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
        yield self._iam_root_mfa_finding()
        yield self._iam_password_policy_finding()
        yield self._cloudtrail_finding()
