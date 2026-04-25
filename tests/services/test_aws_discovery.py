"""Tests for AWS auto-discovery (Refs #24).

All boto3 calls are mocked via injected MagicMock sessions. No real AWS API
traffic in CI.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


def _fake_session(
    *,
    account_id: str = "123456789012",
    ec2_client: MagicMock | None = None,
    s3_client: MagicMock | None = None,
    iam_client: MagicMock | None = None,
    sts_client: MagicMock | None = None,
) -> MagicMock:
    """Build a MagicMock boto3 Session that returns the given clients.

    Mirrors the fixture in tests/sdk/test_aws_connector.py — copy rather than
    cross-import to keep the discovery test module self-contained.
    """
    session = MagicMock()
    sts = sts_client or MagicMock()
    if sts_client is None:
        sts.get_caller_identity.return_value = {"Account": account_id}
    ec2 = ec2_client or MagicMock()
    s3 = s3_client or MagicMock()
    iam = iam_client or MagicMock()

    def _client(service_name: str, **_kwargs):
        return {"sts": sts, "ec2": ec2, "s3": s3, "iam": iam}[service_name]

    session.client.side_effect = _client
    return session


def _ec2_paginator(*pages: list[dict]) -> MagicMock:
    """Build a MagicMock EC2 paginator that yields the given pages."""
    paginator = MagicMock()
    paginator.paginate.return_value = iter([{"Reservations": page} for page in pages])
    return paginator


def _iam_users_paginator(*pages: list[dict]) -> MagicMock:
    paginator = MagicMock()
    paginator.paginate.return_value = iter([{"Users": page} for page in pages])
    return paginator


class TestDiscoverEC2:
    def test_emits_resource_definition_with_dotted_path_tags(self):
        from lemma.services.aws_discovery import discover_resources

        ec2 = MagicMock()
        ec2.get_paginator.return_value = _ec2_paginator(
            [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-0abc123",
                            "InstanceType": "t3.medium",
                            "State": {"Name": "running"},
                            "Placement": {"AvailabilityZone": "us-east-1a"},
                            "Tags": [
                                {"Key": "Environment", "Value": "prod"},
                                {"Key": "Owner", "Value": "alice"},
                            ],
                        }
                    ]
                }
            ]
        )

        result = discover_resources(
            session=_fake_session(ec2_client=ec2),
            region="us-east-1",
            services=["ec2"],
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "aws-ec2-i-0abc123"
        assert rd.type == "aws.ec2.instance"
        # Dotted-path keys the matcher expects.
        assert rd.attributes["aws"]["region"] == "us-east-1"
        assert rd.attributes["aws"]["service"] == "ec2"
        assert rd.attributes["aws"]["state"] == "running"
        assert rd.attributes["aws"]["instance_type"] == "t3.medium"
        assert rd.attributes["aws"]["tags"] == {
            "Environment": "prod",
            "Owner": "alice",
        }

    def test_paginates_across_pages(self):
        from lemma.services.aws_discovery import discover_resources

        ec2 = MagicMock()
        ec2.get_paginator.return_value = _ec2_paginator(
            [{"Instances": [{"InstanceId": "i-1", "State": {"Name": "running"}, "Tags": []}]}],
            [{"Instances": [{"InstanceId": "i-2", "State": {"Name": "running"}, "Tags": []}]}],
        )

        result = discover_resources(
            session=_fake_session(ec2_client=ec2),
            region="us-east-1",
            services=["ec2"],
        )

        ids = {r.id for r in result}
        assert ids == {"aws-ec2-i-1", "aws-ec2-i-2"}


class TestDiscoverS3:
    def test_lists_buckets_with_region_from_get_bucket_location(self):
        from lemma.services.aws_discovery import discover_resources

        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "audit-logs"}, {"Name": "data"}]}
        s3.get_bucket_location.side_effect = [
            {"LocationConstraint": "us-east-1"},
            {"LocationConstraint": "eu-west-1"},
        ]

        result = discover_resources(
            session=_fake_session(s3_client=s3),
            region="us-east-1",
            services=["s3"],
        )

        by_id = {r.id: r for r in result}
        assert by_id["aws-s3-audit-logs"].attributes["aws"]["region"] == "us-east-1"
        assert by_id["aws-s3-data"].attributes["aws"]["region"] == "eu-west-1"
        assert all(r.type == "aws.s3.bucket" for r in result)

    def test_skips_bucket_when_get_bucket_location_access_denied(self):
        from botocore.exceptions import ClientError

        from lemma.services.aws_discovery import discover_resources

        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "no-access"}, {"Name": "ok"}]}
        s3.get_bucket_location.side_effect = [
            ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "forbidden"}},
                "GetBucketLocation",
            ),
            {"LocationConstraint": "us-west-2"},
        ]

        result = discover_resources(
            session=_fake_session(s3_client=s3),
            region="us-east-1",
            services=["s3"],
        )

        ids = {r.id for r in result}
        assert "aws-s3-no-access" not in ids
        assert "aws-s3-ok" in ids


class TestDiscoverIAM:
    def test_paginates_users(self):
        from lemma.services.aws_discovery import discover_resources

        iam = MagicMock()
        iam.get_paginator.return_value = _iam_users_paginator(
            [
                {"UserName": "alice", "Path": "/", "CreateDate": "2024-01-01T00:00:00Z"},
            ],
            [
                {"UserName": "bob", "Path": "/", "CreateDate": "2024-02-01T00:00:00Z"},
            ],
        )

        result = discover_resources(
            session=_fake_session(iam_client=iam),
            region="us-east-1",
            services=["iam"],
        )

        ids = {r.id for r in result}
        assert ids == {"aws-iam-user-alice", "aws-iam-user-bob"}
        assert all(r.type == "aws.iam.user" for r in result)


class TestDiscoverErrorHandling:
    def test_unknown_service_raises_value_error(self):
        from lemma.services.aws_discovery import discover_resources

        with pytest.raises(ValueError, match=r"(?i)unknown.*service|foo"):
            discover_resources(
                session=_fake_session(),
                region="us-east-1",
                services=["foo"],
            )

    def test_skips_service_on_client_error_continues_others(self):
        """If EC2 raises AccessDenied, S3 and IAM still run."""
        from botocore.exceptions import ClientError

        from lemma.services.aws_discovery import discover_resources

        ec2 = MagicMock()
        ec2.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "no perms"}},
            "DescribeInstances",
        )

        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "ok"}]}
        s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}

        iam = MagicMock()
        iam.get_paginator.return_value = _iam_users_paginator(
            [{"UserName": "alice", "Path": "/", "CreateDate": "2024-01-01T00:00:00Z"}]
        )

        result = discover_resources(
            session=_fake_session(ec2_client=ec2, s3_client=s3, iam_client=iam),
            region="us-east-1",
            services=["ec2", "s3", "iam"],
        )

        ids = {r.id for r in result}
        # EC2 was skipped (no aws-ec2-* ids); S3 and IAM produced results.
        assert not any(i.startswith("aws-ec2-") for i in ids)
        assert "aws-s3-ok" in ids
        assert "aws-iam-user-alice" in ids
