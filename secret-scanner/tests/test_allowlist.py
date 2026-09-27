from secret_scanner.allowlist import Allowlist, load_allowlist_file


def test_default_ignored_directories():
    al = Allowlist()
    assert al.is_path_ignored("node_modules/left-pad/index.js")
    assert al.is_path_ignored("vendor/lib/thing.go")
    assert al.is_path_ignored(".git/refs/heads/main")
    assert not al.is_path_ignored("src/app.py")


def test_default_ignored_extensions():
    al = Allowlist()
    assert al.is_path_ignored("assets/logo.png")
    assert not al.is_path_ignored("src/main.py")


def test_known_safe_aws_example_key_is_a_placeholder():
    al = Allowlist()
    assert al.is_value_placeholder("AKIAIOSFODNN7EXAMPLE")


def test_placeholder_substrings_are_caught():
    al = Allowlist()
    for value in ["your_api_key_here", "CHANGEME", "sample-token-value", "dummy_secret_123"]:
        assert al.is_value_placeholder(value)


def test_repeated_character_value_is_a_placeholder():
    al = Allowlist()
    assert al.is_value_placeholder("xxxxxxxxxxxxxxxxxxxx")
    assert al.is_value_placeholder("0000000000000000")


def test_realistic_looking_value_is_not_a_placeholder():
    al = Allowlist()
    assert not al.is_value_placeholder("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEYabcd"[:32])
    assert not al.is_value_placeholder("aB3xQ9zR7mK1pL5vN2wJ8fT6")


def test_inline_suppress_marker():
    al = Allowlist()
    assert al.is_line_suppressed("token = 'whatever'  # secret-scanner:ignore")
    assert not al.is_line_suppressed("token = 'whatever'")


def test_load_allowlist_file_path_globs(tmp_path):
    ignore_file = tmp_path / ".secretscanignore"
    ignore_file.write_text("path:tests/fixtures/*\n# comment\n\nbare/path/glob.py\n")
    al = load_allowlist_file(ignore_file)
    assert al.is_path_ignored("tests/fixtures/sample.py")
    assert al.is_path_ignored("bare/path/glob.py")
    assert not al.is_path_ignored("src/app.py")


def test_load_allowlist_file_value_patterns(tmp_path):
    ignore_file = tmp_path / ".secretscanignore"
    ignore_file.write_text("value:^TEST-.*\n")
    al = load_allowlist_file(ignore_file)
    assert al.is_value_placeholder("TEST-not-a-real-secret-abc123")
    assert not al.is_value_placeholder("aB3xQ9zR7mK1pL5vN2wJ8fT6")
