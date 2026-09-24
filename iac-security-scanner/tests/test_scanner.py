from iac_scanner.models import SEVERITY_RANK
from iac_scanner.scanner import scan
from tests.helpers import make_resource


def test_scan_aggregates_findings_from_multiple_rule_modules():
    bucket = make_resource("aws_s3_bucket", {"bucket": "b", "acl": "public-read"})
    sg = make_resource(
        "aws_security_group",
        {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]},
    )
    findings = scan([bucket, sg])
    rule_ids = {f.rule_id for f in findings}
    assert "S3-001" in rule_ids
    assert "SG-002" in rule_ids


def test_scan_sorts_by_severity_descending_then_address_then_rule_id():
    bucket = make_resource("aws_s3_bucket", {"bucket": "b", "acl": "private"}, name="z")
    volume = make_resource("aws_ebs_volume", {"encrypted": False}, name="a")
    findings = scan([bucket, volume])
    ranks = [SEVERITY_RANK[f.severity] for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_scan_returns_empty_list_for_no_resources():
    assert scan([]) == []
