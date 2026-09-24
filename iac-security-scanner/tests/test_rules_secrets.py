from iac_scanner.rules import secrets
from tests.helpers import make_resource


def _ids(findings):
    return [f.rule_id for f in findings]


def test_aws_access_key_id_detected():
    resource = make_resource("aws_iam_access_key", {"note": "backup key AKIAABCDEFGHIJKLMNOP"})
    findings = list(secrets.check([resource]))
    assert _ids(findings) == ["SECRETS-001"]
    assert findings[0].severity == "critical"


def test_password_field_detected():
    resource = make_resource("aws_db_instance", {"master_password": "SuperSecret123!"})
    findings = list(secrets.check([resource]))
    assert _ids(findings) == ["SECRETS-002"]
    assert findings[0].severity == "high"


def test_nested_secret_field_detected_via_path():
    resource = make_resource("aws_lambda_function", {"environment": [{"variables": {"API_KEY": "sk-live-abc123"}}]})
    findings = list(secrets.check([resource]))
    assert _ids(findings) == ["SECRETS-002"]


def test_kms_key_id_field_not_flagged():
    resource = make_resource("aws_ebs_volume", {"encrypted": True, "kms_key_id": "arn:aws:kms:us-east-1:123:key/abc"})
    assert list(secrets.check([resource])) == []


def test_empty_or_non_string_values_ignored():
    resource = make_resource("aws_db_instance", {"master_password": "", "storage_encrypted": True, "port": 5432})
    assert list(secrets.check([resource])) == []


def test_benign_string_field_not_flagged():
    resource = make_resource("aws_s3_bucket", {"bucket": "my-app-logs"})
    assert list(secrets.check([resource])) == []
