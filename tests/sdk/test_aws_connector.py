"""Tests for the first-party AWS connector.

Mocks boto3 clients per service — CI never touches real AWS.
"""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def _iam_mock() -> MagicMock:
    """A fully-configured IAM client mock: root MFA on, a 14-char password policy,
    two paginated users, and one fresh access key. Tests override the return value
    for whichever signal they exercise."""
    iam = MagicMock()
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
    iam.get_account_password_policy.return_value = {
        "PasswordPolicy": {"MinimumPasswordLength": 14, "RequireSymbols": True}
    }
    iam.get_paginator.return_value.paginate.return_value = [
        {"Users": [{"UserName": "alice"}, {"UserName": "bob"}]},
    ]
    iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {"AccessKeyId": "AKIAFRESH", "Status": "Active", "CreateDate": datetime.now(UTC)}
        ]
    }
    return iam


def _fake_session(
    *,
    account_id: str = "123456789012",
    iam_client: MagicMock | None = None,
    cloudtrail_client: MagicMock | None = None,
    sts_client: MagicMock | None = None,
    config_client: MagicMock | None = None,
    s3control_client: MagicMock | None = None,
    ec2_client: MagicMock | None = None,
) -> MagicMock:
    """Build a MagicMock boto3 Session that returns the given clients."""
    session = MagicMock()
    sts = sts_client or MagicMock()
    if sts_client is None:
        sts.get_caller_identity.return_value = {"Account": account_id}
    iam = iam_client or _iam_mock()
    trail = cloudtrail_client or MagicMock()
    if cloudtrail_client is None:
        trail.describe_trails.return_value = {
            "trailList": [
                {"Name": "org-trail", "IsMultiRegionTrail": True, "HomeRegion": "us-east-1"}
            ]
        }
    config = config_client or MagicMock()
    if config_client is None:
        config.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": [{"name": "default"}]
        }
        config.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [
                {"name": "default", "recording": True, "lastStatus": "SUCCESS"}
            ]
        }
    s3c = s3control_client or MagicMock()
    if s3control_client is None:
        s3c.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
    ec2 = ec2_client or MagicMock()
    if ec2_client is None:
        ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1"}]}
        ec2.describe_flow_logs.return_value = {"FlowLogs": [{"ResourceId": "vpc-1"}]}
        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupName": "default",
                    "GroupId": "sg-1",
                    "IpPermissions": [],
                    "IpPermissionsEgress": [],
                }
            ]
        }

    clients = {
        "iam": iam,
        "cloudtrail": trail,
        "sts": sts,
        "config": config,
        "s3control": s3c,
        "ec2": ec2,
    }

    def _client(service_name: str, **_kwargs):
        return clients[service_name]

    session.client.side_effect = _client
    return session


class TestAWSConnectorManifest:
    def test_manifest_pins_producer_and_name(self):
        from lemma.sdk.connectors.aws import AWSConnector

        connector = AWSConnector(region="us-east-1", session=_fake_session())
        assert connector.manifest.name == "aws"
        assert connector.manifest.producer == "AWS"
        assert "iam-root-mfa" in connector.manifest.capabilities


class TestIAMRootMFA:
    def test_enabled_emits_compliant_finding(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        connector = AWSConnector(region="us-east-1", session=_fake_session())
        events = list(connector.collect())
        mfa = [
            e
            for e in events
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("aws:iam-root-mfa:")
        ]
        assert len(mfa) == 1
        assert mfa[0].status_id == 1
        assert "enabled" in mfa[0].message.lower()

    def test_disabled_emits_noncompliant_finding(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        iam = _iam_mock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
        connector = AWSConnector(region="us-east-1", session=_fake_session(iam_client=iam))
        mfa = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("aws:iam-root-mfa:")
        ]
        assert mfa[0].status_id == 2
        assert "disabled" in mfa[0].message.lower() or "not enabled" in mfa[0].message.lower()


class TestIAMPasswordPolicy:
    def test_present_policy_reports_min_length(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        connector = AWSConnector(region="us-east-1", session=_fake_session())
        pw = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("aws:iam-password-policy:")
        ]
        assert len(pw) == 1
        assert pw[0].metadata.get("minimum_password_length") == 14

    def test_absent_policy_emits_noncompliant_finding(self):
        from botocore.exceptions import ClientError

        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        iam = _iam_mock()
        iam.get_account_password_policy.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "no policy"}},
            "GetAccountPasswordPolicy",
        )
        connector = AWSConnector(region="us-east-1", session=_fake_session(iam_client=iam))
        pw = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {}).get("uid", "").startswith("aws:iam-password-policy:")
        ]
        assert pw[0].status_id == 2
        assert "no" in pw[0].message.lower()


class TestCloudTrail:
    def test_multi_region_trail_emits_compliant_finding(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        connector = AWSConnector(region="us-east-1", session=_fake_session())
        ct = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {})
            .get("uid", "")
            .startswith("aws:cloudtrail-multi-region:")
        ]
        assert len(ct) == 1
        assert ct[0].status_id == 1
        assert ct[0].metadata.get("trail_count") == 1

    def test_no_multi_region_trail_emits_noncompliant_finding(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        trail = MagicMock()
        trail.describe_trails.return_value = {
            "trailList": [
                {"Name": "single", "IsMultiRegionTrail": False, "HomeRegion": "us-east-1"}
            ]
        }
        connector = AWSConnector(region="us-east-1", session=_fake_session(cloudtrail_client=trail))
        ct = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding)
            and e.metadata.get("product", {})
            .get("uid", "")
            .startswith("aws:cloudtrail-multi-region:")
        ]
        assert ct[0].status_id == 2


def _uid_prefix(event, prefix: str) -> bool:
    return event.metadata.get("product", {}).get("uid", "").startswith(prefix)


class TestIAMInventory:
    def test_paginated_user_inventory_counts_all_pages(self):

        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        iam = _iam_mock()
        # Two pages — a single-page reader would under-count (the capped-at-100 bug).
        iam.get_paginator.return_value.paginate.return_value = [
            {"Users": [{"UserName": "a"}, {"UserName": "b"}]},
            {"Users": [{"UserName": "c"}]},
        ]
        iam.list_access_keys.return_value = {"AccessKeyMetadata": []}

        connector = AWSConnector(region="us-east-1", session=_fake_session(iam_client=iam))
        inv = [
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding) and _uid_prefix(e, "aws:iam-inventory:")
        ]
        assert len(inv) == 1
        assert inv[0].metadata["user_count"] == 3
        iam.get_paginator.assert_called_with("list_users")

    def test_stale_access_key_fails(self):
        from datetime import timedelta

        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        iam = _iam_mock()
        iam.get_paginator.return_value.paginate.return_value = [{"Users": [{"UserName": "old"}]}]
        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAOLD",
                    "Status": "Active",
                    "CreateDate": datetime.now(UTC) - timedelta(days=400),
                }
            ]
        }

        connector = AWSConnector(region="us-east-1", session=_fake_session(iam_client=iam))
        inv = next(
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding) and _uid_prefix(e, "aws:iam-inventory:")
        )
        assert inv.status_id == 2
        assert inv.metadata["stale_access_key_count"] == 1


class TestConfigRecorder:
    def test_recording_recorder_passes(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        connector = AWSConnector(region="us-east-1", session=_fake_session())
        cfg = next(
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding) and _uid_prefix(e, "aws:config-recorder:")
        )
        assert cfg.status_id == 1

    def test_no_recorder_fails(self):
        from unittest.mock import MagicMock

        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        config = MagicMock()
        config.describe_configuration_recorders.return_value = {"ConfigurationRecorders": []}
        config.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": []
        }
        connector = AWSConnector(region="us-east-1", session=_fake_session(config_client=config))
        cfg = next(
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding) and _uid_prefix(e, "aws:config-recorder:")
        )
        assert cfg.status_id == 2


class TestS3PublicAccessBlock:
    def test_all_blocked_passes(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        connector = AWSConnector(region="us-east-1", session=_fake_session())
        s3 = next(
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding) and _uid_prefix(e, "aws:s3-public-access-block:")
        )
        assert s3.status_id == 1

    def test_missing_block_fails(self):
        from unittest.mock import MagicMock

        from botocore.exceptions import ClientError

        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        s3c = MagicMock()
        s3c.get_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}, "GetPublicAccessBlock"
        )
        connector = AWSConnector(region="us-east-1", session=_fake_session(s3control_client=s3c))
        s3 = next(
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding) and _uid_prefix(e, "aws:s3-public-access-block:")
        )
        assert s3.status_id == 2


class TestVPCFlowLogs:
    def test_all_vpcs_covered_passes(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        connector = AWSConnector(region="us-east-1", session=_fake_session())
        vpc = next(
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding) and _uid_prefix(e, "aws:vpc-flow-logs:")
        )
        assert vpc.status_id == 1
        assert vpc.metadata["vpcs_with_flow_logs"] == 1

    def test_uncovered_vpc_fails(self):
        from unittest.mock import MagicMock

        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        ec2 = MagicMock()
        ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1"}, {"VpcId": "vpc-2"}]}
        ec2.describe_flow_logs.return_value = {"FlowLogs": [{"ResourceId": "vpc-1"}]}
        ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        connector = AWSConnector(region="us-east-1", session=_fake_session(ec2_client=ec2))
        vpc = next(
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding) and _uid_prefix(e, "aws:vpc-flow-logs:")
        )
        assert vpc.status_id == 2
        assert vpc.metadata["vpc_count"] == 2
        assert vpc.metadata["vpcs_with_flow_logs"] == 1


class TestDefaultSecurityGroup:
    def test_locked_down_default_sg_passes(self):
        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        connector = AWSConnector(region="us-east-1", session=_fake_session())
        sg = next(
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding) and _uid_prefix(e, "aws:default-sg:")
        )
        assert sg.status_id == 1

    def test_default_sg_with_rules_fails(self):
        from unittest.mock import MagicMock

        from lemma.models.ocsf import ComplianceFinding
        from lemma.sdk.connectors.aws import AWSConnector

        ec2 = MagicMock()
        ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1"}]}
        ec2.describe_flow_logs.return_value = {"FlowLogs": [{"ResourceId": "vpc-1"}]}
        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupName": "default",
                    "GroupId": "sg-open",
                    "IpPermissions": [{"IpProtocol": "-1"}],
                    "IpPermissionsEgress": [],
                }
            ]
        }
        connector = AWSConnector(region="us-east-1", session=_fake_session(ec2_client=ec2))
        sg = next(
            e
            for e in connector.collect()
            if isinstance(e, ComplianceFinding) and _uid_prefix(e, "aws:default-sg:")
        )
        assert sg.status_id == 2
        assert sg.metadata["open_default_sg_count"] == 1


class TestCredentialsMissing:
    def test_no_credentials_raises_clean_value_error(self):
        from botocore.exceptions import NoCredentialsError

        from lemma.sdk.connectors.aws import AWSConnector

        sts = MagicMock()
        sts.get_caller_identity.side_effect = NoCredentialsError()
        with pytest.raises(ValueError, match=r"(?i)credentials"):
            AWSConnector(region="us-east-1", session=_fake_session(sts_client=sts))


class TestDedupeStability:
    def test_metadata_uid_stable_per_account_and_day(self, monkeypatch):
        from lemma.sdk.connectors.aws import AWSConnector

        fixed_now = datetime(2026, 4, 25, 12, 0, 0, tzinfo=UTC)

        class _FixedNow:
            @staticmethod
            def now(tz=None):
                return fixed_now

        monkeypatch.setattr("lemma.sdk.connectors.aws.datetime", _FixedNow)

        first = {
            e.metadata["product"]["uid"]
            for e in AWSConnector(region="us-east-1", session=_fake_session()).collect()
        }
        second = {
            e.metadata["product"]["uid"]
            for e in AWSConnector(region="us-east-1", session=_fake_session()).collect()
        }
        assert first == second
        assert all(uid.endswith(":2026-04-25") for uid in first)


class TestEndToEnd:
    def test_full_run_signs_and_chains_every_event(self, tmp_path: Path):
        from lemma.sdk.connectors.aws import AWSConnector
        from lemma.services.evidence_log import EvidenceLog

        connector = AWSConnector(region="us-east-1", session=_fake_session())
        log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
        result = connector.run(log)

        # 8 signals: IAM root MFA + password policy + inventory, CloudTrail,
        # Config recorder, S3 public-access block, VPC flow logs, default SG.
        assert result.ingested == 8
        envelopes = log.read_envelopes()
        assert all(env.signer_key_id.startswith("ed25519:") for env in envelopes)
        for prior, current in pairwise(envelopes):
            assert current.prev_hash == prior.entry_hash
