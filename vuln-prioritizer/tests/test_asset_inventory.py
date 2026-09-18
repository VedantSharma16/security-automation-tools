import json
from pathlib import Path

import pytest

from vuln_prioritizer.asset_inventory import InventoryFormatError, get_asset, load_inventory


def _write_inventory(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "assets.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path


def test_loads_inventory_case_insensitively(tmp_path):
    path = _write_inventory(
        tmp_path,
        [{"hostname": "Web01.Example.com", "criticality": "critical", "internet_facing": True, "tags": ["public"]}],
    )
    inventory = load_inventory(path)
    asset = get_asset(inventory, "web01.example.com")
    assert asset.criticality == "critical"
    assert asset.internet_facing is True
    assert asset.tags == ("public",)


def test_unknown_host_falls_back_to_medium_default(tmp_path):
    path = _write_inventory(tmp_path, [{"hostname": "web01", "criticality": "critical"}])
    inventory = load_inventory(path)
    asset = get_asset(inventory, "totally-unknown-host")
    assert asset.criticality == "medium"
    assert asset.internet_facing is False
    assert asset.hostname == "totally-unknown-host"


def test_invalid_criticality_falls_back_to_medium(tmp_path):
    path = _write_inventory(tmp_path, [{"hostname": "web01", "criticality": "apocalyptic"}])
    inventory = load_inventory(path)
    assert inventory["web01"].criticality == "medium"


def test_entry_without_hostname_is_skipped(tmp_path):
    path = _write_inventory(tmp_path, [{"criticality": "high"}, {"hostname": "web01", "criticality": "high"}])
    inventory = load_inventory(path)
    assert len(inventory) == 1


def test_non_list_json_raises(tmp_path):
    path = tmp_path / "assets.json"
    path.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    with pytest.raises(InventoryFormatError):
        load_inventory(path)


def test_malformed_json_raises(tmp_path):
    path = tmp_path / "assets.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(InventoryFormatError):
        load_inventory(path)


def test_sample_assets_fixture_loads():
    sample = Path(__file__).resolve().parent.parent / "examples" / "sample_assets.json"
    inventory = load_inventory(sample)
    assert "web01.example.com" in inventory
    assert inventory["web01.example.com"].internet_facing is True
