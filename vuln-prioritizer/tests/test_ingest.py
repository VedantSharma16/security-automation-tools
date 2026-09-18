import csv
import io
from pathlib import Path

import pytest

from vuln_prioritizer.ingest import ScanFormatError, parse_scan_csv


def _write_csv(tmp_path: Path, rows: list[dict], fieldnames: list[str]) -> Path:
    path = tmp_path / "scan.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_parses_standard_columns(tmp_path):
    path = _write_csv(
        tmp_path,
        [
            {
                "host": "web01",
                "ip": "10.0.0.1",
                "port": "443",
                "cve_id": "cve-2021-44228",
                "plugin_name": "Log4Shell",
                "severity": "Critical",
                "cvss_score": "10.0",
                "description": "RCE via JNDI",
            }
        ],
        ["host", "ip", "port", "cve_id", "plugin_name", "severity", "cvss_score", "description"],
    )

    findings = parse_scan_csv(path)
    assert len(findings) == 1
    f = findings[0]
    assert f.host == "web01"
    assert f.ip == "10.0.0.1"
    assert f.port == 443
    assert f.cve_id == "CVE-2021-44228"
    assert f.title == "Log4Shell"
    assert f.severity == "critical"
    assert f.cvss_score == 10.0


def test_accepts_alias_column_names(tmp_path):
    path = _write_csv(
        tmp_path,
        [
            {
                "hostname": "db01",
                "ip_address": "10.0.0.2",
                "cve": "CVE-2020-1472",
                "title": "Zerologon",
                "risk": "critical",
                "cvss": "10.0",
                "summary": "EoP",
            }
        ],
        ["hostname", "ip_address", "cve", "title", "risk", "cvss", "summary"],
    )

    findings = parse_scan_csv(path)
    assert findings[0].host == "db01"
    assert findings[0].cve_id == "CVE-2020-1472"
    assert findings[0].cvss_score == 10.0


def test_finding_without_cve_is_kept(tmp_path):
    path = _write_csv(
        tmp_path,
        [{"host": "web01", "plugin_name": "Outdated jQuery", "severity": "info", "cvss_score": ""}],
        ["host", "plugin_name", "severity", "cvss_score"],
    )

    findings = parse_scan_csv(path)
    assert len(findings) == 1
    assert findings[0].cve_id is None
    assert findings[0].cvss_score is None
    assert findings[0].title == "Outdated jQuery"


def test_missing_host_column_raises(tmp_path):
    path = _write_csv(tmp_path, [{"plugin_name": "X"}], ["plugin_name"])
    with pytest.raises(ScanFormatError):
        parse_scan_csv(path)


def test_invalid_cvss_is_dropped_not_raised(tmp_path):
    path = _write_csv(
        tmp_path,
        [{"host": "web01", "plugin_name": "X", "cvss_score": "not-a-number"}],
        ["host", "plugin_name", "cvss_score"],
    )
    findings = parse_scan_csv(path)
    assert findings[0].cvss_score is None


def test_cvss_out_of_range_is_clamped(tmp_path):
    path = _write_csv(
        tmp_path,
        [{"host": "web01", "plugin_name": "X", "cvss_score": "15.0"}],
        ["host", "plugin_name", "cvss_score"],
    )
    findings = parse_scan_csv(path)
    assert findings[0].cvss_score == 10.0


def test_no_header_row_raises(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ScanFormatError):
        parse_scan_csv(path)


def test_sample_scan_fixture_parses():
    sample = Path(__file__).resolve().parent.parent / "examples" / "sample_scan.csv"
    findings = parse_scan_csv(sample)
    assert len(findings) == 8
    assert any(f.cve_id == "CVE-2021-44228" for f in findings)
    assert any(f.cve_id is None for f in findings)
