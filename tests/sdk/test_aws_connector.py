"""Tests for the first-party AWS connector.

Mocks boto3 clients per service — CI never touches real AWS.
"""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def _fake_session(
    *,
    account_id: str = "123456789012",
    iam_client: MagicMock | None = None,
    cloudtrail_client: MagicMock | None = None,
    sts_client: MagicMock | None = None,
) -> MagicMock:
    """Build a MagicMock boto3 Session that returns the given clients."""
    session = MagicMock()
    sts = sts_client or MagicMock()
    if sts_client is None:
        sts.get_caller_identity.return_value = {"Account": account_id}
    iam = iam_client or MagicMock()
    if iam_client is None:
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {"MinimumPasswordLength": 14, "RequireSymbols": True}
        }
    trail = cloudtrail_client or MagicMock()
    if cloudtrail_client is None:
        trail.describe_trails.return_value = {
            "trailList": [
                {"Name": "org-trail", "IsMultiRegionTrail": True, "HomeRegion": "us-east-1"}
            ]
        }

    def _client(service_name: str, **_kwargs):
        return {"iam": iam, "cloudtrail": trail, "sts": sts}[service_name]

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

        iam = MagicMock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {"MinimumPasswordLength": 14}
        }
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

        iam = MagicMock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
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

        assert result.ingested == 3  # IAM root MFA + password policy + CloudTrail
        envelopes = log.read_envelopes()
        assert all(env.signer_key_id.startswith("ed25519:") for env in envelopes)
        for prior, current in pairwise(envelopes):
            assert current.prev_hash == prior.entry_hash
