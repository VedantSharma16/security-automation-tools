# IaC Security Scanner

A static security scanner for Terraform plan JSON. It catches common AWS
misconfigurations — public S3 buckets, wide-open security groups,
over-permissive IAM policies, unencrypted storage, and hardcoded secrets —
**before** they're applied, by scanning the output of `terraform show -json`
in CI, the same way `tfsec`/`checkov` are typically wired into a pipeline.

## Why this exists

A huge share of real-world cloud breaches trace back to a misconfiguration
that was checked into version control and applied without a second look: a
security group open to `0.0.0.0/0` on port 22/3389, an S3 bucket with a
public ACL, an IAM policy granting `Action: "*"` / `Resource: "*"`. Catching
these at plan time — as a required CI check — is cheaper than catching them
in an incident. This project is a small, dependency-free demonstration of
that "shift-left" security model: parse infrastructure-as-code, run it
through a rule engine, fail the build.

## How it works

1. Generate a plan: `terraform plan -out=tf.plan && terraform show -json tf.plan > plan.json`
2. Parse `plan.json` into a flat list of planned resources (handles both the
   `resource_changes` shape from `terraform show -json` and the
   `planned_values.root_module` shape, including nested child modules).
3. Run every resource through a set of independent rule modules.
4. Score, sort, and render findings as colored console text, Markdown, or JSON.
5. Exit non-zero if anything at or above `--fail-on` (default: `high`) was found.

## Checks implemented

| Rule ID | Severity | Check |
|---|---|---|
| S3-001 | Critical | S3 bucket has a public ACL (`public-read`, `public-read-write`, `authenticated-read`) |
| S3-002 | High | S3 bucket has no (or an incomplete) `aws_s3_bucket_public_access_block` |
| S3-003 | Medium | S3 bucket has no server-side encryption configured |
| S3-004 | Low | S3 bucket versioning is not enabled |
| SG-001 | Critical | Security group allows all ports/protocols from the internet |
| SG-002 | Critical | Security group exposes a sensitive service (SSH, RDP, databases, Telnet, ...) to the internet |
| IAM-001 | Critical | IAM policy statement allows `Action: "*"` on `Resource: "*"` |
| IAM-002 | High | IAM policy statement uses a wildcard action |
| RDS-001 | High | RDS instance is publicly accessible |
| RDS-002 | Medium | RDS instance storage is not encrypted |
| EBS-001 | Medium | Standalone EBS volume is not encrypted |
| EBS-002 | Medium | EC2 instance root volume is not encrypted |
| SECRETS-001 | Critical | Literal AWS access key ID (`AKIA.../ASIA...`) found anywhere in a resource |
| SECRETS-002 | High | Credential-shaped field (`password`, `secret`, `api_key`, `token`, ...) holds a literal string |

S3, security group, and IAM checks correlate across multiple resource types
(e.g. an `aws_s3_bucket` plus its separate `aws_s3_bucket_public_access_block`
and `aws_s3_bucket_server_side_encryption_configuration`), the way the AWS
provider v4+ actually models these resources.

## Usage

```bash
pip install -e ".[dev]"

# human-readable console report, exits 1 if anything high/critical is found
iac-scanner examples/insecure_plan.json

# CI-friendly: write a Markdown report, only fail on critical
iac-scanner plan.json --format markdown --output report.md --fail-on critical

# machine-readable
iac-scanner plan.json --format json --fail-on none
```

Try it against the two bundled example plans to see the contrast:

```bash
iac-scanner examples/insecure_plan.json   # exits 1, ~10 findings across every rule
iac-scanner examples/secure_plan.json     # exits 0, clean scan
```

### CLI flags

- `--format {text,markdown,json}` — report format (default: `text`)
- `--min-severity {low,medium,high,critical}` — only include findings at or above this level (default: `low`)
- `--fail-on {none,low,medium,high,critical}` — exit `1` if any finding at or above this level exists (default: `high`)
- `--output PATH` — write the report to a file instead of stdout
- `--no-color` — disable ANSI colors in text output

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` couldn't read/parse the plan file.

## Project layout

```
iac_scanner/
  parser.py    # terraform show -json -> list[Resource]
  models.py    # Resource, Finding, severity ranking
  rules/       # one module per check category (s3, security_group, iam, rds, ebs, secrets)
  scanner.py   # runs every rule, sorts findings
  report.py    # text / markdown / json rendering
  cli.py       # argparse entry point + exit codes
examples/      # a fully-insecure and a fully-hardened sample plan
tests/         # pytest suite: parser, each rule module, scanner, report, cli
```

## Testing

```bash
pytest
```

Every rule module, the parser (both plan JSON shapes), report rendering, and
the CLI (including its exit codes against the bundled example plans) are
covered — no AWS credentials or live Terraform run required.

## Limitations / possible extensions

- Only AWS resource types are covered; Azure/GCP equivalents would be
  additional rule modules following the same `check(resources) -> Iterator[Finding]`
  interface.
- Resource correlation (e.g. bucket ↔ public-access-block) matches on the
  `bucket` argument's literal value, which is how real plans wire these
  together — but a scan run *before* any apply where that value is still an
  unresolved interpolation would need the raw HCL instead of plan JSON.
- Suppressions/inline waivers (e.g. `# iac-scanner:ignore SG-002`) aren't
  implemented; every finding is currently unconditional.
