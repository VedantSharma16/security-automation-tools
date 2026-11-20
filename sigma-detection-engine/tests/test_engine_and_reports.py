import json
from pathlib import Path

from sigma_engine.engine import read_events, scan
from sigma_engine.report import attack_coverage, render_coverage_markdown, render_scan_markdown
from sigma_engine.rule import load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules([ROOT / "rules"])
SAMPLE = ROOT / "samples" / "intrusion_chain.jsonl"


def test_sample_intrusion_chain_end_to_end():
    result = scan(RULES, read_events(SAMPLE))
    assert result.events_scanned == 22
    titles = {a.rule_title for a in result.alerts}
    assert "LSASS Memory Dump via Comsvcs MiniDump or ProcDump" in titles
    assert "Linux Reverse Shell Via Bash Or Netcat" in titles
    # benign noise host must stay quiet (SCCM filter, private-IP filter, read-only commands)
    assert not [a for a in result.alerts if a.host.startswith("WS-HR-02")]
    # linux event mimicking vssadmin is excluded by logsource
    assert not [a for a in result.alerts if a.host == "web01" and "Shadow" in a.rule_title]
    assert result.max_level() == "critical"
    assert "T1003.001" in result.techniques


def test_timeline_is_ordered_per_host():
    timeline = scan(RULES, read_events(SAMPLE)).timeline()
    assert set(timeline) == {"WS-FIN-07.corp.example", "web01"}
    stamps = [a.timestamp for a in timeline["WS-FIN-07.corp.example"]]
    assert stamps == sorted(stamps)


def test_min_level_filters_rules():
    result = scan(RULES, read_events(SAMPLE), min_level="critical")
    assert result.alerts and {a.level for a in result.alerts} == {"critical"}


def test_read_events_formats_and_malformed_lines(tmp_path, capsys):
    jl = tmp_path / "e.jsonl"
    jl.write_text('{"a": 1}\n\n# comment\nnot json\n[1,2]\n{"b": 2}\n')
    assert list(read_events(jl)) == [{"a": 1}, {"b": 2}]
    assert "malformed" in capsys.readouterr().err
    arr = tmp_path / "e.json"
    arr.write_text(json.dumps([{"a": 1}, 5, {"b": 2}]))
    assert list(read_events(arr)) == [{"a": 1}, {"b": 2}]


def test_json_and_markdown_rendering():
    result = scan(RULES, read_events(SAMPLE))
    data = result.to_dict()
    json.dumps(data)  # serialisable
    assert data["summary"]["alerts"] == len(result.alerts)
    md = render_scan_markdown(result)
    assert "## Host timelines" in md and "rundll32.exe -> 203.0.113.50:443" in md
    assert "_No detections fired._" in render_scan_markdown(scan(RULES, []))


def test_attack_coverage_matrix():
    cov = attack_coverage(RULES)
    assert "T1003.001" in cov["credential_access"]
    assert list(cov)[0] == "initial_access"  # kill-chain ordering
    md = render_coverage_markdown(RULES)
    assert "Tactic gaps" in md and "Credential Access" in md
