"""AWS auto-discovery for the scope engine (Refs #24).

Walks AWS APIs (EC2 / S3 / IAM for v0) via boto3 and yields a
``ResourceDefinition`` per discovered asset. Designed for the same
default credential chain the AWS connector uses (env vars, AWS profile,
IMDS) and accepts an injected ``boto3.Session`` so tests stay offline.

The service builds candidate ``ResourceDefinition`` records but does
not match them against scopes or write to the graph — that's the
``lemma scope discover aws`` command's job. Single-responsibility split
keeps the service unit-testable without a graph fixture.
"""

from __future__ import annotations

import logging
from typing import Any

from botocore.exceptions import ClientError

from lemma.models.resource import ResourceDefinition

logger = logging.getLogger(__name__)

_KNOWN_SERVICES = ("ec2", "s3", "iam")


def discover_resources(
    *,
    session: Any,
    region: str,
    services: list[str],
) -> list[ResourceDefinition]:
    """Discover AWS resources across the requested services.

    Args:
        session: A ``boto3.Session``-like object exposing ``client(name)``.
            Tests pass in a ``MagicMock``; production passes in a real
            ``boto3.Session``.
        region: AWS region for region-scoped APIs (EC2). Ignored for
            globally-scoped services (S3, IAM) — they ignore region.
        services: List of service names to enumerate. Each must be one
            of ``{"ec2", "s3", "iam"}``; an unknown name raises before
            any API call.

    Returns:
        List of ``ResourceDefinition`` records, one per discovered asset.
        Resources from a service whose API call fails (AccessDenied,
        rate-limit) are silently dropped with a warning log; other
        services in the request still run.

    Raises:
        ValueError: If ``services`` contains a name outside ``_KNOWN_SERVICES``.
    """
    unknown = [s for s in services if s not in _KNOWN_SERVICES]
    if unknown:
        msg = f"Unknown AWS service(s): {', '.join(unknown)}. Known: {', '.join(_KNOWN_SERVICES)}."
        raise ValueError(msg)

    resources: list[ResourceDefinition] = []

    for service in services:
        try:
            if service == "ec2":
                resources.extend(_discover_ec2(session, region))
            elif service == "s3":
                resources.extend(_discover_s3(session))
            elif service == "iam":
                resources.extend(_discover_iam_users(session))
        except ClientError as exc:
            logger.warning("AWS %s discovery skipped: %s", service, exc)
            continue

    return resources


def _discover_ec2(session: Any, region: str) -> list[ResourceDefinition]:
    client = session.client("ec2")
    paginator = client.get_paginator("describe_instances")

    discovered: list[ResourceDefinition] = []
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId")
                if not instance_id:
                    continue
                tags = {t.get("Key", ""): t.get("Value", "") for t in instance.get("Tags", [])}
                attributes: dict[str, Any] = {
                    "aws": {
                        "service": "ec2",
                        "region": region,
                        "instance_type": instance.get("InstanceType", ""),
                        "state": instance.get("State", {}).get("Name", ""),
                        "availability_zone": instance.get("Placement", {}).get(
                            "AvailabilityZone", ""
                        ),
                        "tags": tags,
                    }
                }
                discovered.append(
                    ResourceDefinition(
                        id=f"aws-ec2-{instance_id}",
                        type="aws.ec2.instance",
                        scope="",  # filled in by the command after scope-matching
                        attributes=attributes,
                    )
                )
    return discovered


def _discover_s3(session: Any) -> list[ResourceDefinition]:
    client = session.client("s3")
    response = client.list_buckets()

    discovered: list[ResourceDefinition] = []
    for bucket in response.get("Buckets", []):
        name = bucket.get("Name")
        if not name:
            continue
        try:
            location = client.get_bucket_location(Bucket=name)
        except ClientError as exc:
            logger.warning("Skipping S3 bucket %s: %s", name, exc)
            continue
        # AWS returns None for us-east-1 (legacy quirk); normalize.
        bucket_region = location.get("LocationConstraint") or "us-east-1"
        attributes: dict[str, Any] = {
            "aws": {
                "service": "s3",
                "region": bucket_region,
                "name": name,
            }
        }
        discovered.append(
            ResourceDefinition(
                id=f"aws-s3-{name}",
                type="aws.s3.bucket",
                scope="",
                attributes=attributes,
            )
        )
    return discovered


def _discover_iam_users(session: Any) -> list[ResourceDefinition]:
    client = session.client("iam")
    paginator = client.get_paginator("list_users")

    discovered: list[ResourceDefinition] = []
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user.get("UserName")
            if not user_name:
                continue
            create_date = user.get("CreateDate", "")
            attributes: dict[str, Any] = {
                "aws": {
                    "service": "iam",
                    "user_name": user_name,
                    "path": user.get("Path", "/"),
                    "create_date": str(create_date),
                }
            }
            discovered.append(
                ResourceDefinition(
                    id=f"aws-iam-user-{user_name}",
                    type="aws.iam.user",
                    scope="",
                    attributes=attributes,
                )
            )
    return discovered
