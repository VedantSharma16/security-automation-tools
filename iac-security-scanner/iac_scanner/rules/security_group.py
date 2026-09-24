"""Security group checks: ingress rules that expose sensitive services or
all ports/protocols to the entire internet.

Handles the three shapes Terraform's AWS provider uses for ingress rules:
inline `ingress {}` blocks on `aws_security_group`, standalone
`aws_security_group_rule` resources, and the newer per-rule
`aws_vpc_security_group_ingress_rule` resources.
"""

from __future__ import annotations

from ..models import Finding

OPEN_CIDRS = {"0.0.0.0/0"}
OPEN_IPV6_CIDRS = {"::/0"}

SENSITIVE_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5984: "CouchDB",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

REFERENCES = ("https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",)


def _port_range_covers(from_port, to_port, target: int) -> bool:
    if from_port is None or to_port is None:
        return True  # unbounded/all-ports rule
    return from_port <= target <= to_port


def _is_all_ports(from_port, to_port, protocol) -> bool:
    if protocol in ("-1", -1):
        return True
    if from_port is None or to_port is None:
        return True
    return int(from_port) <= 0 and int(to_port) >= 65535


def _cidrs_open(cidrs) -> bool:
    return bool(set(cidrs or []) & OPEN_CIDRS)


def _ipv6_open(cidrs) -> bool:
    return bool(set(cidrs or []) & OPEN_IPV6_CIDRS)


def _iter_ingress_rules(resources: list):
    """Yield (resource, from_port, to_port, protocol, cidrs, ipv6_cidrs) for
    every ingress rule found across all supported resource shapes."""
    for resource in resources:
        if resource.type == "aws_security_group":
            for block in resource.get("ingress") or []:
                yield (
                    resource,
                    block.get("from_port"),
                    block.get("to_port"),
                    str(block.get("protocol")),
                    block.get("cidr_blocks") or [],
                    block.get("ipv6_cidr_blocks") or [],
                )
        elif resource.type == "aws_security_group_rule" and resource.get("type") == "ingress":
            yield (
                resource,
                resource.get("from_port"),
                resource.get("to_port"),
                str(resource.get("protocol")),
                resource.get("cidr_blocks") or [],
                resource.get("ipv6_cidr_blocks") or [],
            )
        elif resource.type == "aws_vpc_security_group_ingress_rule":
            cidr = resource.get("cidr_ipv4")
            ipv6 = resource.get("cidr_ipv6")
            yield (
                resource,
                resource.get("from_port"),
                resource.get("to_port"),
                str(resource.get("ip_protocol")),
                [cidr] if cidr else [],
                [ipv6] if ipv6 else [],
            )


def check(resources: list):
    for resource, from_port, to_port, protocol, cidrs, ipv6_cidrs in _iter_ingress_rules(resources):
        open_to_internet = _cidrs_open(cidrs) or _ipv6_open(ipv6_cidrs)
        if not open_to_internet:
            continue

        if _is_all_ports(from_port, to_port, protocol):
            yield Finding(
                rule_id="SG-001",
                severity="critical",
                resource_address=resource.address,
                resource_type=resource.type,
                title="Security group allows all traffic from the internet",
                description="An ingress rule permits all ports and/or all protocols from "
                "0.0.0.0/0 or ::/0.",
                remediation="Scope the rule to the specific ports and protocols required, "
                "and to specific source CIDRs instead of the whole internet.",
                references=REFERENCES,
            )
            continue

        for port, service in SENSITIVE_PORTS.items():
            if _port_range_covers(from_port, to_port, port):
                yield Finding(
                    rule_id="SG-002",
                    severity="critical",
                    resource_address=resource.address,
                    resource_type=resource.type,
                    title=f"Security group exposes {service} (port {port}) to the internet",
                    description=f"An ingress rule opens port {port} ({service}) to 0.0.0.0/0 "
                    "or ::/0, making the service reachable and bruteforceable from anywhere.",
                    remediation=f"Restrict the rule's source CIDR to known, trusted ranges "
                    f"(e.g. a VPN or bastion) instead of the internet, or move {service} "
                    "behind a private subnet.",
                    references=REFERENCES,
                )
