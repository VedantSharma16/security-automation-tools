from iac_scanner.rules import security_group
from tests.helpers import make_resource


def _ids(findings):
    return [f.rule_id for f in findings]


def test_all_ports_open_to_internet_is_critical_sg001():
    sg = make_resource(
        "aws_security_group",
        {"ingress": [{"from_port": 0, "to_port": 65535, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}]},
    )
    findings = list(security_group.check([sg]))
    assert _ids(findings) == ["SG-001"]
    assert findings[0].severity == "critical"


def test_sensitive_port_open_to_internet_is_sg002():
    sg = make_resource(
        "aws_security_group",
        {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]},
    )
    findings = list(security_group.check([sg]))
    assert _ids(findings) == ["SG-002"]
    assert "SSH" in findings[0].title


def test_port_range_covering_multiple_sensitive_ports_flags_each():
    sg = make_resource(
        "aws_security_group",
        {"ingress": [{"from_port": 20, "to_port": 25, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]},
    )
    findings = list(security_group.check([sg]))
    # ports 20, 21, 22, 23 all fall in SENSITIVE_PORTS and within [20,25]
    assert set(_ids(findings)) == {"SG-002"}
    assert len(findings) == 4


def test_restricted_cidr_not_flagged():
    sg = make_resource(
        "aws_security_group",
        {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]}]},
    )
    assert list(security_group.check([sg])) == []


def test_https_to_internet_not_flagged():
    sg = make_resource(
        "aws_security_group",
        {"ingress": [{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]},
    )
    assert list(security_group.check([sg])) == []


def test_standalone_security_group_rule_resource():
    rule = make_resource(
        "aws_security_group_rule",
        {"type": "ingress", "from_port": 3389, "to_port": 3389, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]},
    )
    findings = list(security_group.check([rule]))
    assert "RDP" in findings[0].title


def test_egress_rule_on_security_group_rule_ignored():
    rule = make_resource(
        "aws_security_group_rule",
        {"type": "egress", "from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]},
    )
    assert list(security_group.check([rule])) == []


def test_vpc_security_group_ingress_rule_resource():
    rule = make_resource(
        "aws_vpc_security_group_ingress_rule",
        {"from_port": 5432, "to_port": 5432, "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"},
    )
    findings = list(security_group.check([rule]))
    assert "PostgreSQL" in findings[0].title


def test_ipv6_open_cidr_flagged():
    sg = make_resource(
        "aws_security_group",
        {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]}]},
    )
    findings = list(security_group.check([sg]))
    assert _ids(findings) == ["SG-002"]
