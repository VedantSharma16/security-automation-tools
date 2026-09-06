from codesec_agent.rules import scan_source


def _rule_ids(source: str) -> set[str]:
    return {f.rule_id for f in scan_source(source)}


def test_clean_code_has_no_findings():
    source = """
import hashlib
import subprocess

def run(cmd_parts):
    subprocess.run(cmd_parts, shell=False)
    return hashlib.sha256(b"data").hexdigest()
"""
    assert scan_source(source) == []


def test_os_system_dynamic_command_flagged():
    source = "import os\ndef f(x):\n    os.system(x)\n"
    findings = scan_source(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "command-injection"
    assert findings[0].cwe == "CWE-78"
    assert findings[0].severity == "high"


def test_os_system_constant_not_flagged():
    source = 'import os\nos.system("ls -la")\n'
    assert scan_source(source) == []


def test_subprocess_shell_true_dynamic_is_high_constant_is_medium():
    dynamic = "import subprocess\ndef f(cmd):\n    subprocess.run(cmd, shell=True)\n"
    findings = scan_source(dynamic)
    assert findings[0].severity == "high"

    constant = 'import subprocess\nsubprocess.run("ls -la", shell=True)\n'
    findings = scan_source(constant)
    assert findings[0].severity == "medium"


def test_subprocess_without_shell_true_not_flagged():
    source = 'import subprocess\nsubprocess.run(["ls", "-la"])\n'
    assert scan_source(source) == []


def test_eval_and_exec_flagged():
    source = "def f(expr):\n    return eval(expr)\n"
    findings = scan_source(source)
    assert findings[0].rule_id == "eval-exec"
    assert findings[0].cwe == "CWE-95"

    source_exec = "def f(code):\n    exec(code)\n"
    assert scan_source(source_exec)[0].rule_id == "eval-exec"


def test_pickle_load_flagged():
    source = "import pickle\ndef f(blob):\n    return pickle.loads(blob)\n"
    findings = scan_source(source)
    assert findings[0].rule_id == "insecure-deserialization"
    assert findings[0].cwe == "CWE-502"


def test_yaml_load_without_safe_loader_flagged():
    source = "import yaml\ndef f(raw):\n    return yaml.load(raw)\n"
    assert scan_source(source)[0].rule_id == "insecure-deserialization"


def test_yaml_safe_load_not_flagged():
    source = "import yaml\ndef f(raw):\n    return yaml.safe_load(raw)\n"
    assert scan_source(source) == []


def test_yaml_load_with_safe_loader_not_flagged():
    source = "import yaml\ndef f(raw):\n    return yaml.load(raw, Loader=yaml.SafeLoader)\n"
    assert scan_source(source) == []


def test_sql_injection_via_concatenation_flagged():
    source = 'def f(cur, user_id):\n    cur.execute("SELECT * FROM users WHERE id = " + user_id)\n'
    findings = scan_source(source)
    assert findings[0].rule_id == "sql-injection"
    assert findings[0].cwe == "CWE-89"


def test_sql_injection_via_fstring_flagged():
    source = 'def f(cur, user_id):\n    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    assert scan_source(source)[0].rule_id == "sql-injection"


def test_parameterized_query_not_flagged():
    source = 'def f(cur, user_id):\n    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    assert scan_source(source) == []


def test_weak_hash_flagged():
    source = "import hashlib\nhashlib.md5(b'x')\n"
    findings = scan_source(source)
    assert findings[0].rule_id == "weak-hash"

    source_sha1 = "import hashlib\nhashlib.sha1(b'x')\n"
    assert scan_source(source_sha1)[0].rule_id == "weak-hash"


def test_sha256_not_flagged():
    source = "import hashlib\nhashlib.sha256(b'x')\n"
    assert scan_source(source) == []


def test_hardcoded_secret_flagged():
    source = 'password = "hunter2-prod-password"\n'
    findings = scan_source(source)
    assert findings[0].rule_id == "hardcoded-secret"
    assert findings[0].cwe == "CWE-798"
    assert findings[0].severity == "high"


def test_hardcoded_secret_placeholder_not_flagged():
    source = 'password = ""\napi_key = "changeme"\n'
    assert scan_source(source) == []


def test_hardcoded_private_key_is_critical():
    source = 'private_key = "-----BEGIN RSA PRIVATE KEY-----abc"\n'
    assert scan_source(source)[0].severity == "critical"


def test_aws_key_pattern_flagged():
    source = 'AWS_ACCESS_KEY_ID = "AKIAABCDEFGHIJKLMNOP"\n'
    findings = scan_source(source)
    assert any(f.rule_id == "hardcoded-secret" and f.severity == "critical" for f in findings)


def test_secret_in_dict_literal_flagged_by_regex_sweep():
    source = 'config = {"api_key": "sk-live-abcdef1234567890"}\n'
    findings = scan_source(source)
    assert any(f.rule_id == "hardcoded-secret" for f in findings)


def test_weak_randomness_for_token_flagged():
    source = "import random\ndef f():\n    token = random.choice('abcdef')\n"
    findings = scan_source(source)
    assert findings[0].rule_id == "weak-randomness"
    assert findings[0].cwe == "CWE-330"


def test_random_for_non_secret_variable_not_flagged():
    source = "import random\ndice_roll = random.randint(1, 6)\n"
    assert scan_source(source) == []


def test_disabled_tls_verification_flagged():
    source = "import requests\nrequests.get('https://x', verify=False)\n"
    findings = scan_source(source)
    assert findings[0].rule_id == "disabled-tls-verification"
    assert findings[0].cwe == "CWE-295"


def test_tls_verification_enabled_not_flagged():
    source = "import requests\nrequests.get('https://x', verify=True)\n"
    assert scan_source(source) == []


def test_debug_mode_enabled_flagged():
    source = "app.run(host='0.0.0.0', debug=True)\n"
    findings = scan_source(source)
    assert findings[0].rule_id == "debug-mode-enabled"
    assert findings[0].cwe == "CWE-489"


def test_debug_mode_false_not_flagged():
    source = "app.run(debug=False)\n"
    assert scan_source(source) == []


def test_path_traversal_from_parameter_flagged():
    source = "def read(filename):\n    return open(filename).read()\n"
    findings = scan_source(source)
    assert findings[0].rule_id == "path-traversal"
    assert findings[0].cwe == "CWE-22"


def test_open_with_constant_path_not_flagged():
    source = 'def read():\n    return open("config.yaml").read()\n'
    assert scan_source(source) == []


def test_finding_to_dict_has_expected_keys():
    source = "import os\ndef f(x):\n    os.system(x)\n"
    finding = scan_source(source)[0]
    d = finding.to_dict()
    assert set(d.keys()) == {"rule_id", "cwe", "title", "severity", "file", "line", "snippet", "remediation"}
    assert d["line"] == 3


def test_vulnerable_sample_file_trips_every_rule_category():
    from pathlib import Path

    sample = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_sample.py"
    findings = scan_source(sample.read_text(), filename=str(sample))
    found_rule_ids = {f.rule_id for f in findings}
    expected = {
        "command-injection",
        "sql-injection",
        "insecure-deserialization",
        "eval-exec",
        "weak-hash",
        "weak-randomness",
        "disabled-tls-verification",
        "path-traversal",
        "hardcoded-secret",
        "debug-mode-enabled",
    }
    assert expected <= found_rule_ids
