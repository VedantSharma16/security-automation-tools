"""Generate a fuller local-only secrets demo file.

examples/vulnerable_sample/config.py is committed to git and intentionally
leaves out a couple of formats -- Stripe live secret keys and Slack webhook
URLs -- because their shape alone is realistic enough that GitHub's own
push protection blocks a commit containing one, fake or not. That's a
useful confirmation the signatures in rules/default_rules.yaml match real
formats; it just means those two can't live in a committed file.

This script builds them at runtime (never as a literal string in source)
and writes a second demo file that stays out of git via .gitignore, so you
can still see every rule fire locally:

    python examples/generate_demo_secrets.py
    python -m secretscan.cli examples/vulnerable_sample/generated_config.py
"""

from __future__ import annotations

from pathlib import Path

OUTPUT_PATH = Path(__file__).parent / "vulnerable_sample" / "generated_config.py"


def _fake_stripe_key() -> str:
    return "sk_" + "live_" + "4242424242424242424242424242"


def _fake_slack_webhook() -> str:
    return "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X" * 24


def build_content() -> str:
    return (
        '"""Locally generated demo file -- gitignored, not committed.\n\n'
        "Regenerate with: python examples/generate_demo_secrets.py\n"
        '"""\n\n'
        f'STRIPE_SECRET_KEY = "{_fake_stripe_key()}"\n'
        f'SLACK_WEBHOOK = "{_fake_slack_webhook()}"\n'
    )


def main() -> None:
    OUTPUT_PATH.write_text(build_content())
    print(f"wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
