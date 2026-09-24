"""Rule registry: each check module exposes `check(resources) -> Iterator[Finding]`."""

from __future__ import annotations

from ._util import walk_leaves
from . import ebs, iam, rds, secrets, security_group, s3

ALL_CHECKS = (
    s3.check,
    security_group.check,
    iam.check,
    rds.check,
    ebs.check,
    secrets.check,
)

__all__ = ["ALL_CHECKS", "walk_leaves"]
