"""EBS encryption checks: standalone volumes and instance root block devices."""

from __future__ import annotations

from ..models import Finding

REFERENCES = ("https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",)


def check(resources: list):
    for resource in resources:
        if resource.type == "aws_ebs_volume" and resource.get("encrypted") is not True:
            yield Finding(
                rule_id="EBS-001",
                severity="medium",
                resource_address=resource.address,
                resource_type=resource.type,
                title="EBS volume is not encrypted at rest",
                description="encrypted is not set to true for this standalone EBS volume.",
                remediation="Set encrypted = true (optionally with a customer-managed "
                "kms_key_id), or enable account-level EBS encryption by default.",
                references=REFERENCES,
            )

        if resource.type == "aws_instance":
            for device in resource.get("root_block_device") or []:
                if device.get("encrypted") is not True:
                    yield Finding(
                        rule_id="EBS-002",
                        severity="medium",
                        resource_address=resource.address,
                        resource_type=resource.type,
                        title="Instance root volume is not encrypted at rest",
                        description="The root_block_device block does not set encrypted = true.",
                        remediation="Set encrypted = true on the root_block_device block, or "
                        "enable account-level EBS encryption by default.",
                        references=REFERENCES,
                    )
