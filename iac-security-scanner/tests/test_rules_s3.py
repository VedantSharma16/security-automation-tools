from iac_scanner.rules import s3
from tests.helpers import make_resource


def _ids(findings):
    return {f.rule_id for f in findings}


def test_public_acl_flagged():
    bucket = make_resource("aws_s3_bucket", {"bucket": "b", "acl": "public-read"})
    findings = list(s3.check([bucket]))
    assert "S3-001" in _ids(findings)


def test_missing_public_access_block_flagged():
    bucket = make_resource("aws_s3_bucket", {"bucket": "b", "acl": "private"})
    findings = list(s3.check([bucket]))
    assert "S3-002" in _ids(findings)


def test_partial_public_access_block_still_flagged():
    bucket = make_resource("aws_s3_bucket", {"bucket": "b", "acl": "private"})
    pab = make_resource(
        "aws_s3_bucket_public_access_block",
        {"bucket": "b", "block_public_acls": True, "block_public_policy": False,
         "ignore_public_acls": True, "restrict_public_buckets": True},
    )
    findings = list(s3.check([bucket, pab]))
    assert "S3-002" in _ids(findings)


def test_missing_encryption_flagged():
    bucket = make_resource("aws_s3_bucket", {"bucket": "b", "acl": "private"})
    findings = list(s3.check([bucket]))
    assert "S3-003" in _ids(findings)


def test_missing_versioning_flagged():
    bucket = make_resource("aws_s3_bucket", {"bucket": "b", "acl": "private"})
    findings = list(s3.check([bucket]))
    assert "S3-004" in _ids(findings)


def test_fully_hardened_bucket_has_no_findings():
    bucket = make_resource("aws_s3_bucket", {"bucket": "b", "acl": "private"})
    pab = make_resource(
        "aws_s3_bucket_public_access_block",
        {"bucket": "b", "block_public_acls": True, "block_public_policy": True,
         "ignore_public_acls": True, "restrict_public_buckets": True},
    )
    sse = make_resource(
        "aws_s3_bucket_server_side_encryption_configuration",
        {"bucket": "b", "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
    )
    versioning = make_resource(
        "aws_s3_bucket_versioning",
        {"bucket": "b", "versioning_configuration": {"status": "Enabled"}},
    )
    findings = list(s3.check([bucket, pab, sse, versioning]))
    assert findings == []


def test_non_bucket_resources_ignored():
    other = make_resource("aws_instance", {"ami": "ami-123"})
    assert list(s3.check([other])) == []
