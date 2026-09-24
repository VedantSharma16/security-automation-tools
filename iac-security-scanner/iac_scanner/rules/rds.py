"""RDS checks: public accessibility and storage encryption."""

from __future__ import annotations

from ..models import Finding

REFERENCES = ("https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.Security.html",)


def check(resources: list):
    for resource in resources:
        if resource.type != "aws_db_instance":
            continue

        if resource.get("publicly_accessible") is True:
            yield Finding(
                rule_id="RDS-001",
                severity="high",
                resource_address=resource.address,
                resource_type=resource.type,
                title="RDS instance is publicly accessible",
                description="publicly_accessible=true assigns the instance a public DNS name "
                "and IP, exposing the database directly to the internet.",
                remediation="Set publicly_accessible to false and access the database "
                "through a VPN, bastion, or app-tier resources inside the VPC.",
                references=REFERENCES,
            )

        if resource.get("storage_encrypted") is not True:
            yield Finding(
                rule_id="RDS-002",
                severity="medium",
                resource_address=resource.address,
                resource_type=resource.type,
                title="RDS instance storage is not encrypted",
                description="storage_encrypted is not set to true, so data at rest is not "
                "encrypted with KMS (this defaults to false and can't be changed after creation).",
                remediation="Set storage_encrypted = true (and optionally kms_key_id) before "
                "the instance is created.",
                references=REFERENCES,
            )
