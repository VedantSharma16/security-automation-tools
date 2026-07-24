"""Intentionally leaky sample file, used by the README's "try it" walkthrough.

The AWS key below is Amazon's own publicly documented example credential
(used throughout AWS's docs and SDK samples) - it is not a real secret, but
it *is* a real AWS Access Key ID in valid format, so the scanner flags it
exactly like it would flag a genuine leak.
"""

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

DATABASE_URL = "postgres://app:app@localhost:5432/app"  # not a secret - clean by design
