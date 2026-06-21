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
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import ComplianceFinding, OcsfBaseEvent
from lemma.sdk.connector import Connector

_PRODUCER = "AWS"
_ACCESS_KEY_MAX_AGE_DAYS = 90


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
            description=(
                "AWS account posture across IAM, CloudTrail, Config, S3, and VPC: "
                "IAM root MFA, password policy, user/access-key inventory, "
                "multi-region CloudTrail, Config recorder, S3 account public-access "
                "block, VPC flow logs, and default security-group lockdown."
            ),
            capabilities=[
                "iam-root-mfa",
                "iam-password-policy",
                "iam-inventory",
                "cloudtrail-multi-region",
                "config-recorder",
                "s3-public-access-block",
                "vpc-flow-logs",
                "default-sg",
            ],
        )

    def _finding(self, uid: str, message: str, status_id: int, md: dict) -> ComplianceFinding:
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

    def _iam_inventory_finding(self) -> ComplianceFinding:
        iam = self._session.client("iam")
        uid = f"aws:iam-inventory:{self._account_id}:{_today_utc_iso_date()}"
        md = _metadata(self._account_id, self._region, uid)

        try:
            users = [
                user
                for page in iam.get_paginator("list_users").paginate()
                for user in page.get("Users", [])
            ]
            cutoff = datetime.now(UTC) - timedelta(days=_ACCESS_KEY_MAX_AGE_DAYS)
            stale = 0
            for user in users:
                keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
                for key in keys:
                    created = key.get("CreateDate")
                    if isinstance(created, datetime) and created < cutoff:
                        stale += 1
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            md["error"] = code
            return self._finding(
                uid,
                f"Failed to read IAM user inventory on account {self._account_id} ({code}).",
                0,
                md,
            )

        md["user_count"] = len(users)
        md["stale_access_key_count"] = stale
        md["access_key_max_age_days"] = _ACCESS_KEY_MAX_AGE_DAYS

        if stale:
            message = (
                f"AWS IAM inventory on account {self._account_id}: {len(users)} user(s), "
                f"{stale} access key(s) older than {_ACCESS_KEY_MAX_AGE_DAYS} days — rotate them."
            )
            status_id = 2
        else:
            message = (
                f"AWS IAM inventory on account {self._account_id}: {len(users)} user(s), "
                f"no access keys older than {_ACCESS_KEY_MAX_AGE_DAYS} days."
            )
            status_id = 1
        return self._finding(uid, message, status_id, md)

    def _config_recorder_finding(self) -> ComplianceFinding:
        config = self._session.client("config")
        uid = f"aws:config-recorder:{self._account_id}:{_today_utc_iso_date()}"
        md = _metadata(self._account_id, self._region, uid)

        recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
        statuses = config.describe_configuration_recorder_status().get(
            "ConfigurationRecordersStatus", []
        )
        recording = [s for s in statuses if s.get("recording")]
        md["recorder_count"] = len(recorders)
        md["recording_count"] = len(recording)

        if recording:
            message = (
                f"AWS Config is recording on account {self._account_id} "
                f"({len(recording)} active recorder(s))."
            )
            status_id = 1
        else:
            message = (
                f"No recording AWS Config configuration recorder on account "
                f"{self._account_id}. Config records resource state for drift + audit."
            )
            status_id = 2
        return self._finding(uid, message, status_id, md)

    def _s3_public_access_block_finding(self) -> ComplianceFinding:
        s3control = self._session.client("s3control")
        uid = f"aws:s3-public-access-block:{self._account_id}:{_today_utc_iso_date()}"
        md = _metadata(self._account_id, self._region, uid)

        try:
            cfg = s3control.get_public_access_block(AccountId=self._account_id).get(
                "PublicAccessBlockConfiguration", {}
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NoSuchPublicAccessBlockConfiguration":
                md["block_configured"] = False
                return self._finding(
                    uid,
                    f"No account-level S3 Block Public Access on account "
                    f"{self._account_id}. Buckets can be made public per-resource.",
                    2,
                    md,
                )
            raise

        flags = {
            "block_public_acls": bool(cfg.get("BlockPublicAcls")),
            "ignore_public_acls": bool(cfg.get("IgnorePublicAcls")),
            "block_public_policy": bool(cfg.get("BlockPublicPolicy")),
            "restrict_public_buckets": bool(cfg.get("RestrictPublicBuckets")),
        }
        md["block_configured"] = True
        md.update(flags)
        all_blocked = all(flags.values())

        if all_blocked:
            message = f"Account-level S3 Block Public Access fully enabled on {self._account_id}."
            status_id = 1
        else:
            disabled = ", ".join(k for k, v in flags.items() if not v)
            message = (
                f"Account-level S3 Block Public Access incomplete on "
                f"{self._account_id}: {disabled} not enabled."
            )
            status_id = 2
        return self._finding(uid, message, status_id, md)

    def _vpc_flow_logs_finding(self) -> ComplianceFinding:
        ec2 = self._session.client("ec2")
        uid = f"aws:vpc-flow-logs:{self._account_id}:{_today_utc_iso_date()}"
        md = _metadata(self._account_id, self._region, uid)

        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        covered = {fl.get("ResourceId") for fl in ec2.describe_flow_logs().get("FlowLogs", [])}
        vpc_ids = [v.get("VpcId") for v in vpcs]
        with_logs = [vid for vid in vpc_ids if vid in covered]
        md["vpc_count"] = len(vpcs)
        md["vpcs_with_flow_logs"] = len(with_logs)

        if not vpcs:
            message = f"No VPCs found in {self._region} on account {self._account_id}."
            status_id = 0
        elif len(with_logs) == len(vpcs):
            message = (
                f"All {len(vpcs)} VPC(s) in {self._region} have flow logs on "
                f"account {self._account_id}."
            )
            status_id = 1
        else:
            message = (
                f"{len(vpcs) - len(with_logs)} of {len(vpcs)} VPC(s) in {self._region} "
                f"lack flow logs on account {self._account_id}."
            )
            status_id = 2
        return self._finding(uid, message, status_id, md)

    def _default_sg_finding(self) -> ComplianceFinding:
        ec2 = self._session.client("ec2")
        uid = f"aws:default-sg:{self._account_id}:{_today_utc_iso_date()}"
        md = _metadata(self._account_id, self._region, uid)

        groups = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["default"]}]
        ).get("SecurityGroups", [])
        open_sgs = [g for g in groups if g.get("IpPermissions") or g.get("IpPermissionsEgress")]
        md["default_sg_count"] = len(groups)
        md["open_default_sg_count"] = len(open_sgs)

        if not groups:
            message = f"No default security groups found on account {self._account_id}."
            status_id = 0
        elif open_sgs:
            message = (
                f"{len(open_sgs)} of {len(groups)} default security group(s) on account "
                f"{self._account_id} still carry rules — CIS 5.3 wants them empty."
            )
            status_id = 2
        else:
            message = (
                f"All {len(groups)} default security group(s) on account "
                f"{self._account_id} restrict all traffic (no rules)."
            )
            status_id = 1
        return self._finding(uid, message, status_id, md)

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
        yield self._iam_inventory_finding()
        yield self._cloudtrail_finding()
        yield self._config_recorder_finding()
        yield self._s3_public_access_block_finding()
        yield self._vpc_flow_logs_finding()
        yield self._default_sg_finding()
