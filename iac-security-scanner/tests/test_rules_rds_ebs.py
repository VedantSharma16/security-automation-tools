from iac_scanner.rules import ebs, rds
from tests.helpers import make_resource


def test_publicly_accessible_rds_flagged():
    db = make_resource("aws_db_instance", {"publicly_accessible": True, "storage_encrypted": True})
    findings = list(rds.check([db]))
    assert [f.rule_id for f in findings] == ["RDS-001"]


def test_unencrypted_rds_storage_flagged():
    db = make_resource("aws_db_instance", {"publicly_accessible": False, "storage_encrypted": False})
    findings = list(rds.check([db]))
    assert [f.rule_id for f in findings] == ["RDS-002"]


def test_missing_storage_encrypted_defaults_to_flagged():
    db = make_resource("aws_db_instance", {"publicly_accessible": False})
    findings = list(rds.check([db]))
    assert [f.rule_id for f in findings] == ["RDS-002"]


def test_hardened_rds_has_no_findings():
    db = make_resource("aws_db_instance", {"publicly_accessible": False, "storage_encrypted": True})
    assert list(rds.check([db])) == []


def test_unencrypted_ebs_volume_flagged():
    volume = make_resource("aws_ebs_volume", {"encrypted": False})
    findings = list(ebs.check([volume]))
    assert [f.rule_id for f in findings] == ["EBS-001"]


def test_encrypted_ebs_volume_clean():
    volume = make_resource("aws_ebs_volume", {"encrypted": True})
    assert list(ebs.check([volume])) == []


def test_unencrypted_instance_root_volume_flagged():
    instance = make_resource("aws_instance", {"root_block_device": [{"encrypted": False}]})
    findings = list(ebs.check([instance]))
    assert [f.rule_id for f in findings] == ["EBS-002"]


def test_encrypted_instance_root_volume_clean():
    instance = make_resource("aws_instance", {"root_block_device": [{"encrypted": True}]})
    assert list(ebs.check([instance])) == []
