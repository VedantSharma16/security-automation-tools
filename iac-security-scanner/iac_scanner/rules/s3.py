"""S3 bucket checks: public ACLs, missing public-access blocks, missing
encryption, and missing versioning.

Newer AWS provider versions (v4+) split what used to be inline
`aws_s3_bucket` arguments into separate resources
(`aws_s3_bucket_public_access_block`, `aws_s3_bucket_server_side_encryption_configuration`,
`aws_s3_bucket_versioning`) that reference the bucket via a `bucket`
argument. We correlate those back to the owning bucket by matching that
`bucket` argument against the bucket resource's own `bucket`/`id`
attribute, which is how they're wired together in real Terraform state.
"""

from __future__ import annotations

from ..models import Finding

PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}

REFERENCES = ("https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",)


def _bucket_key(resource) -> str:
    return resource.get("bucket") or resource.get("id") or resource.name


def _related(resources, rtype: str, bucket_key: str):
    return [r for r in resources if r.type == rtype and r.get("bucket") == bucket_key]


def check(resources: list):
    buckets = [r for r in resources if r.type == "aws_s3_bucket"]

    for bucket in buckets:
        key = _bucket_key(bucket)

        acl = bucket.get("acl")
        if acl in PUBLIC_ACLS:
            yield Finding(
                rule_id="S3-001",
                severity="critical",
                resource_address=bucket.address,
                resource_type=bucket.type,
                title="S3 bucket has a public ACL",
                description=f"Bucket has acl={acl!r}, which grants read or write access to "
                "anyone on the internet or any authenticated AWS user.",
                remediation="Set acl to \"private\" and use bucket policies or IAM for "
                "any access that's actually required.",
                references=REFERENCES,
            )

        pab = _related(resources, "aws_s3_bucket_public_access_block", key)
        blocking_fields = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
        if not pab or not all(pab[0].get(field) is True for field in blocking_fields):
            yield Finding(
                rule_id="S3-002",
                severity="high",
                resource_address=bucket.address,
                resource_type=bucket.type,
                title="S3 bucket is missing a fully-restrictive public access block",
                description="No aws_s3_bucket_public_access_block resource covers this bucket "
                "with all four blocking options enabled, so public ACLs or bucket "
                "policies could still expose it." if not pab else
                "aws_s3_bucket_public_access_block exists for this bucket but does not "
                "enable all four blocking options.",
                remediation="Attach an aws_s3_bucket_public_access_block resource for this "
                "bucket with block_public_acls, block_public_policy, ignore_public_acls, "
                "and restrict_public_buckets all set to true.",
                references=REFERENCES,
            )

        sse = _related(resources, "aws_s3_bucket_server_side_encryption_configuration", key)
        if not sse and not bucket.get("server_side_encryption_configuration"):
            yield Finding(
                rule_id="S3-003",
                severity="medium",
                resource_address=bucket.address,
                resource_type=bucket.type,
                title="S3 bucket does not enforce server-side encryption",
                description="Neither an aws_s3_bucket_server_side_encryption_configuration "
                "resource nor an inline encryption block was found for this bucket.",
                remediation="Add a default encryption configuration (SSE-S3 or SSE-KMS) "
                "for the bucket.",
                references=REFERENCES,
            )

        versioning = _related(resources, "aws_s3_bucket_versioning", key)
        versioning_enabled = any(
            v.get("versioning_configuration", {}).get("status") == "Enabled" for v in versioning
        )
        inline_versioning = bucket.get("versioning")
        if isinstance(inline_versioning, list) and inline_versioning:
            inline_versioning = inline_versioning[0]
        inline_enabled = bool(isinstance(inline_versioning, dict) and inline_versioning.get("enabled"))
        if not versioning_enabled and not inline_enabled:
            yield Finding(
                rule_id="S3-004",
                severity="low",
                resource_address=bucket.address,
                resource_type=bucket.type,
                title="S3 bucket versioning is not enabled",
                description="Versioning protects against accidental deletion/overwrite and "
                "is a prerequisite for reliable ransomware/accidental-loss recovery, but "
                "isn't enabled for this bucket.",
                remediation="Enable versioning via aws_s3_bucket_versioning (or the inline "
                "versioning block) with status = \"Enabled\".",
                references=REFERENCES,
            )
