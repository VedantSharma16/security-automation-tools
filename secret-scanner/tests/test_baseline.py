import json

from secretscan.baseline import build_baseline, load_baseline, save_baseline
from secretscan.models import Finding

FINDING = Finding(
    rule_id="aws-access-key-id",
    description="AWS Access Key ID",
    severity="HIGH",
    file="config.py",
    line=3,
    redacted="AKIA…MPLE",
    fingerprint="deadbeefcafef00d",
)


def test_build_baseline_captures_fingerprints():
    baseline = build_baseline([FINDING])
    assert baseline["version"] == 1
    assert baseline["entries"] == [
        {"fingerprint": "deadbeefcafef00d", "rule_id": "aws-access-key-id", "file": "config.py"}
    ]


def test_save_and_load_baseline_roundtrip(tmp_path):
    path = tmp_path / "baseline.json"
    save_baseline([FINDING], str(path))

    loaded = load_baseline(str(path))

    assert loaded == {"deadbeefcafef00d"}
    on_disk = json.loads(path.read_text())
    assert on_disk["entries"][0]["file"] == "config.py"


def test_load_baseline_missing_file_returns_empty_set(tmp_path):
    assert load_baseline(str(tmp_path / "does_not_exist.json")) == set()
