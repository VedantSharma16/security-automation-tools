import pytest

from iac_scanner.models import IacScannerError
from iac_scanner.parser import parse_plan_dict


def test_resource_changes_shape_parses_create_actions():
    plan = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.data",
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "data",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {"actions": ["create"], "before": None, "after": {"bucket": "b"}},
            }
        ]
    }
    resources = parse_plan_dict(plan)
    assert len(resources) == 1
    assert resources[0].address == "aws_s3_bucket.data"
    assert resources[0].attributes == {"bucket": "b"}


def test_resource_changes_skips_pure_deletes():
    plan = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.old",
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "old",
                "provider_name": "p",
                "change": {"actions": ["delete"], "before": {"bucket": "b"}, "after": None},
            }
        ]
    }
    assert parse_plan_dict(plan) == []


def test_resource_changes_skips_after_none():
    plan = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.weird",
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "weird",
                "provider_name": "p",
                "change": {"actions": ["no-op"], "before": None, "after": None},
            }
        ]
    }
    assert parse_plan_dict(plan) == []


def test_resource_changes_keeps_update_and_replace_actions():
    plan = {
        "resource_changes": [
            {
                "address": "a",
                "mode": "managed",
                "type": "aws_db_instance",
                "name": "x",
                "provider_name": "p",
                "change": {"actions": ["update"], "before": {}, "after": {"engine": "postgres"}},
            },
            {
                "address": "b",
                "mode": "managed",
                "type": "aws_db_instance",
                "name": "y",
                "provider_name": "p",
                "change": {"actions": ["delete", "create"], "before": {}, "after": {"engine": "mysql"}},
            },
        ]
    }
    resources = parse_plan_dict(plan)
    assert {r.address for r in resources} == {"a", "b"}


def test_planned_values_shape_recurses_child_modules():
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.top",
                        "mode": "managed",
                        "type": "aws_s3_bucket",
                        "name": "top",
                        "provider_name": "p",
                        "values": {"bucket": "top-bucket"},
                    }
                ],
                "child_modules": [
                    {
                        "resources": [
                            {
                                "address": "module.child.aws_s3_bucket.nested",
                                "mode": "managed",
                                "type": "aws_s3_bucket",
                                "name": "nested",
                                "provider_name": "p",
                                "values": {"bucket": "nested-bucket"},
                            }
                        ],
                        "child_modules": [],
                    }
                ],
            }
        }
    }
    resources = parse_plan_dict(plan)
    addresses = {r.address for r in resources}
    assert addresses == {"aws_s3_bucket.top", "module.child.aws_s3_bucket.nested"}


def test_unrecognized_shape_raises():
    with pytest.raises(IacScannerError):
        parse_plan_dict({"something_else": True})


def test_non_dict_plan_raises():
    with pytest.raises(IacScannerError):
        parse_plan_dict(["not", "a", "dict"])
