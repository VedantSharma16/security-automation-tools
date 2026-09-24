"""Generic hardcoded-secret detection across every resource's attributes.

Plan JSON only ever contains resolved literal values (Terraform has already
substituted variables/data sources by the time a plan is rendered), so a
non-empty string sitting in a credential-shaped field or matching a known
secret format is a real hardcoded secret, not a variable reference.
"""

from __future__ import annotations

import re

from ..models import Finding
from ._util import walk_leaves

AWS_ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")

SECRET_FIELD_RE = re.compile(r"(password|secret|api[_-]?key|access[_-]?key|token)", re.IGNORECASE)
# Fields where a "secret"-looking name is actually just a reference/ID, not a value.
FIELD_NAME_ALLOWLIST = {"kms_key_id", "kms_key_arn"}

REFERENCES = ("https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html",)


def check(resources: list):
    for resource in resources:
        for path, value in walk_leaves(resource.attributes):
            if not isinstance(value, str) or not value:
                continue

            if AWS_ACCESS_KEY_RE.search(value):
                yield Finding(
                    rule_id="SECRETS-001",
                    severity="critical",
                    resource_address=resource.address,
                    resource_type=resource.type,
                    title="Hardcoded AWS access key ID found in resource configuration",
                    description=f"Field '{path}' contains a literal AWS access key ID.",
                    remediation="Remove the credential from source and rotate the key "
                    "immediately; use IAM roles/instance profiles instead of static keys.",
                    references=REFERENCES,
                )
                continue

            field_name = path.rsplit(".", 1)[-1]
            if field_name in FIELD_NAME_ALLOWLIST:
                continue
            if SECRET_FIELD_RE.search(field_name):
                yield Finding(
                    rule_id="SECRETS-002",
                    severity="high",
                    resource_address=resource.address,
                    resource_type=resource.type,
                    title=f"Potential hardcoded secret in field '{field_name}'",
                    description=f"Field '{path}' looks credential-shaped and holds a literal "
                    "string value in the plan.",
                    remediation="Move the value to a secret manager (AWS Secrets Manager, "
                    "SSM Parameter Store) and reference it, or mark the Terraform variable "
                    "sensitive and source it from the environment/CI secret store.",
                    references=REFERENCES,
                )
