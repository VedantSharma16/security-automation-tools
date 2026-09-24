import json

from iac_scanner.rules import iam
from tests.helpers import make_resource


def _policy_resource(statement, rtype="aws_iam_policy"):
    document = {"Version": "2012-10-17", "Statement": statement}
    return make_resource(rtype, {"policy": json.dumps(document)})


def test_wildcard_action_and_resource_is_critical():
    resource = _policy_resource({"Effect": "Allow", "Action": "*", "Resource": "*"})
    findings = list(iam.check([resource]))
    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-001"
    assert findings[0].severity == "critical"


def test_wildcard_action_only_is_high():
    resource = _policy_resource({"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"})
    findings = list(iam.check([resource]))
    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-002"
    assert findings[0].severity == "high"


def test_scoped_policy_has_no_findings():
    resource = _policy_resource(
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"]}
    )
    assert list(iam.check([resource])) == []


def test_deny_statement_with_wildcards_is_ignored():
    resource = _policy_resource({"Effect": "Deny", "Action": "*", "Resource": "*"})
    assert list(iam.check([resource])) == []


def test_covers_all_policy_resource_types():
    for rtype in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
        resource = _policy_resource({"Effect": "Allow", "Action": "*", "Resource": "*"}, rtype=rtype)
        findings = list(iam.check([resource]))
        assert len(findings) == 1, rtype


def test_multiple_statements_each_evaluated():
    resource = _policy_resource(
        [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:x"]},
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
        ]
    )
    findings = list(iam.check([resource]))
    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-001"


def test_malformed_policy_json_does_not_raise():
    resource = make_resource("aws_iam_policy", {"policy": "{not valid json"})
    assert list(iam.check([resource])) == []


def test_non_policy_resource_ignored():
    resource = make_resource("aws_instance", {"ami": "ami-123"})
    assert list(iam.check([resource])) == []
