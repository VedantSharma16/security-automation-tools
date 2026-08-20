from pathlib import Path

from asm.cve_matcher import load_rules, match_hosts
from asm.nmap_parser import parse_file
from asm.report import build_report, stamp_generated_at, to_json, to_markdown
from asm.scoring import score_matches

EXAMPLES = Path(__file__).parent.parent / "examples"
DATA = Path(__file__).parent.parent / "data" / "cve_db.json"


def _sample_report():
    hosts = parse_file(EXAMPLES / "sample_scan.xml")
    rules = load_rules(DATA)
    matches = match_hosts(hosts, rules)
    scored = score_matches(matches)
    return build_report(EXAMPLES / "sample_scan.xml", hosts, scored)


def test_build_report_counts_hosts_and_ports():
    report = _sample_report()
    assert report["hosts_scanned"] == 2
    assert report["open_ports_scanned"] == 8


def test_build_report_finds_known_vulnerabilities():
    report = _sample_report()
    rule_ids = {f["rule_id"] for f in report["findings"]}
    assert "CVE-2011-2523" in rule_ids  # vsftpd 2.3.4 backdoor
    assert "CVE-2021-41773" in rule_ids  # Apache 2.4.49 path traversal


def test_build_report_ranks_findings_by_score_descending():
    report = _sample_report()
    scores = [f["score"] for f in report["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_build_report_host_ranking_is_consistent_with_findings():
    report = _sample_report()
    ranked_hosts = {r["host"] for r in report["host_risk_ranking"]}
    finding_hosts = {f["host"] for f in report["findings"]}
    assert ranked_hosts == finding_hosts


def test_build_report_with_no_findings_has_zero_overall_score():
    report = build_report("empty.xml", [], [])
    assert report["summary"]["overall_score"] == 0.0
    assert report["summary"]["overall_severity"] == "info"
    assert report["findings"] == []


def test_stamp_generated_at_sets_timestamp():
    report = build_report("empty.xml", [], [])
    assert report["generated_at"] is None
    stamp_generated_at(report)
    assert report["generated_at"] is not None


def test_to_json_round_trips():
    import json

    report = _sample_report()
    parsed = json.loads(to_json(report))
    assert parsed["summary"]["total_findings"] == report["summary"]["total_findings"]


def test_to_markdown_includes_severity_and_findings():
    report = _sample_report()
    md = to_markdown(report)
    assert "# Attack Surface Report" in md
    assert "Host Risk Ranking" in md
    assert "vsftpd 2.3.4 backdoor" in md


def test_to_markdown_handles_no_findings():
    report = build_report("empty.xml", [], [])
    md = to_markdown(report)
    assert "No known CVE" in md
