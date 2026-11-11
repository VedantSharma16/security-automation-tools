"""Regression guard: every labeled sample must keep its expected classification."""

from pathlib import Path

import pytest

from phishtriage.evaluate import evaluate

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
RESULT = evaluate(SAMPLES)


@pytest.mark.parametrize("row", RESULT.rows, ids=lambda r: r["file"])
def test_sample_classified_correctly(row):
    assert row["outcome"] in ("TP", "TN"), row


def test_benign_samples_score_low():
    assert all(r["risk_score"] < 25 for r in RESULT.rows if r["label"] == "benign")
