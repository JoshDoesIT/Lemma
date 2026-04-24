"""Tests for the Terraform plan parser."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _plan_json(changes: list[dict]) -> dict:
    """Minimal Terraform plan JSON shape (from `terraform show -json`)."""
    return {
        "format_version": "1.2",
        "terraform_version": "1.7.0",
        "resource_changes": changes,
    }


def _change(
    address: str,
    type_: str,
    actions: list[str],
    *,
    before: dict | None = None,
    after: dict | None = None,
) -> dict:
    return {
        "address": address,
        "type": type_,
        "change": {"actions": actions, "before": before, "after": after},
    }


class TestParseTerraformPlan:
    def test_parses_create_action(self, tmp_path: Path):
        from lemma.services.terraform_plan import parse_terraform_plan

        plan = _plan_json(
            [
                _change(
                    "aws_s3_bucket.main",
                    "aws_s3_bucket",
                    ["create"],
                    before=None,
                    after={"bucket": "lemma-prod", "region": "us-east-1"},
                )
            ]
        )
        path = tmp_path / "plan.json"
        path.write_text(json.dumps(plan))

        changes = parse_terraform_plan(path)
        assert len(changes) == 1
        c = changes[0]
        assert c.address == "aws_s3_bucket.main"
        assert c.type == "aws_s3_bucket"
        assert c.actions == ["create"]
        assert c.before is None
        assert c.after == {"bucket": "lemma-prod", "region": "us-east-1"}

    def test_parses_delete_action(self, tmp_path: Path):
        from lemma.services.terraform_plan import parse_terraform_plan

        plan = _plan_json(
            [
                _change(
                    "aws_s3_bucket.legacy",
                    "aws_s3_bucket",
                    ["delete"],
                    before={"bucket": "old-bucket"},
                    after=None,
                )
            ]
        )
        path = tmp_path / "plan.json"
        path.write_text(json.dumps(plan))

        (c,) = parse_terraform_plan(path)
        assert c.actions == ["delete"]
        assert c.before == {"bucket": "old-bucket"}
        assert c.after is None

    def test_skips_no_op_changes(self, tmp_path: Path):
        """`terraform plan` includes no-op rows; we drop them since they don't change posture."""
        from lemma.services.terraform_plan import parse_terraform_plan

        plan = _plan_json(
            [
                _change(
                    "aws_vpc.main",
                    "aws_vpc",
                    ["no-op"],
                    before={"id": "vpc-1"},
                    after={"id": "vpc-1"},
                ),
                _change(
                    "aws_s3_bucket.new",
                    "aws_s3_bucket",
                    ["create"],
                    before=None,
                    after={"bucket": "x"},
                ),
            ]
        )
        path = tmp_path / "plan.json"
        path.write_text(json.dumps(plan))

        changes = parse_terraform_plan(path)
        assert [c.address for c in changes] == ["aws_s3_bucket.new"]

    def test_parses_update_with_before_and_after(self, tmp_path: Path):
        from lemma.services.terraform_plan import parse_terraform_plan

        plan = _plan_json(
            [
                _change(
                    "aws_s3_bucket.b",
                    "aws_s3_bucket",
                    ["update"],
                    before={"tags": {"Environment": "dev"}},
                    after={"tags": {"Environment": "prod"}},
                )
            ]
        )
        path = tmp_path / "plan.json"
        path.write_text(json.dumps(plan))

        (c,) = parse_terraform_plan(path)
        assert c.actions == ["update"]
        assert c.before == {"tags": {"Environment": "dev"}}
        assert c.after == {"tags": {"Environment": "prod"}}

    def test_raises_on_missing_resource_changes_key(self, tmp_path: Path):
        from lemma.services.terraform_plan import parse_terraform_plan

        path = tmp_path / "plan.json"
        path.write_text(json.dumps({"format_version": "1.2"}))

        with pytest.raises(ValueError, match=r"(?i)resource_changes"):
            parse_terraform_plan(path)

    def test_raises_on_invalid_json(self, tmp_path: Path):
        from lemma.services.terraform_plan import parse_terraform_plan

        path = tmp_path / "plan.json"
        path.write_text("{not valid json")

        with pytest.raises(ValueError, match=r"(?i)json|parse"):
            parse_terraform_plan(path)
