"""IAM policy checks: overly permissive Allow statements.

Policy documents arrive in plan JSON as a JSON-encoded string (the usual
`jsonencode({...})` pattern), so we parse that string per-resource rather
than relying on Terraform to have already structured it for us.
"""

from __future__ import annotations

import json

from ..models import Finding

POLICY_RESOURCE_TYPES = (
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
)

REFERENCES = ("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",)


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _iter_statements(resource):
    raw = resource.get("policy")
    if not isinstance(raw, str):
        return
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return
    if not isinstance(document, dict):
        return
    for statement in _as_list(document.get("Statement")):
        if isinstance(statement, dict):
            yield statement


def check(resources: list):
    for resource in resources:
        if resource.type not in POLICY_RESOURCE_TYPES:
            continue

        for statement in _iter_statements(resource):
            if statement.get("Effect") != "Allow":
                continue

            actions = {a for a in _as_list(statement.get("Action"))}
            iam_resources = {r for r in _as_list(statement.get("Resource"))}

            if "*" in actions and "*" in iam_resources:
                yield Finding(
                    rule_id="IAM-001",
                    severity="critical",
                    resource_address=resource.address,
                    resource_type=resource.type,
                    title="IAM policy grants full administrative access",
                    description="A statement allows Action: \"*\" on Resource: \"*\", which "
                    "is equivalent to AdministratorAccess.",
                    remediation="Enumerate only the specific actions and resource ARNs the "
                    "role/user actually needs.",
                    references=REFERENCES,
                )
            elif "*" in actions:
                yield Finding(
                    rule_id="IAM-002",
                    severity="high",
                    resource_address=resource.address,
                    resource_type=resource.type,
                    title="IAM policy statement uses a wildcard action",
                    description="A statement allows Action: \"*\", granting every action for "
                    "the listed resource(s) rather than the specific ones required.",
                    remediation="Replace the wildcard with the exact set of actions needed "
                    "(e.g. s3:GetObject, s3:PutObject).",
                    references=REFERENCES,
                )
