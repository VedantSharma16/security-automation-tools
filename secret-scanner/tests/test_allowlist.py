import pytest

from secretscan.allowlist import Allowlist, load


class TestBuiltinPlaceholders:
    def test_common_placeholder_is_always_allowed(self):
        allowlist = Allowlist()
        assert allowlist.is_allowed(file_path="app.py", rule_id="generic-password-assignment", matched_text="changeme")

    def test_real_looking_secret_is_not_allowed_by_default(self):
        allowlist = Allowlist()
        assert not allowlist.is_allowed(
            file_path="app.py", rule_id="aws-access-key-id", matched_text="AKIAIOSFODNN7EXAMPLE"
        )


class TestLoad:
    def test_missing_file_yields_empty_allowlist(self, tmp_path):
        allowlist = load(tmp_path / "does-not-exist")
        assert allowlist.path_globs == ()
        assert allowlist.rule_ids == frozenset()

    def test_parses_all_entry_kinds(self, tmp_path):
        allow_file = tmp_path / ".secretsallowlist"
        allow_file.write_text(
            "\n".join(
                [
                    "# a comment",
                    "",
                    "path:tests/fixtures/**",
                    "rule:jwt",
                    "regex:^AKIAFAKEEXAMPLE",
                    "literal:hunter2",
                ]
            )
        )
        allowlist = load(allow_file)
        assert allowlist.path_globs == ("tests/fixtures/**",)
        assert allowlist.rule_ids == frozenset({"jwt"})
        assert allowlist.literals == frozenset({"hunter2"})
        assert len(allowlist.regexes) == 1

    def test_unknown_entry_kind_raises(self, tmp_path):
        allow_file = tmp_path / ".secretsallowlist"
        allow_file.write_text("bogus:whatever\n")
        with pytest.raises(ValueError):
            load(allow_file)

    def test_malformed_line_raises(self, tmp_path):
        allow_file = tmp_path / ".secretsallowlist"
        allow_file.write_text("no-colon-here\n")
        with pytest.raises(ValueError):
            load(allow_file)


class TestIsAllowed:
    def test_path_glob_suppresses_matching_files(self):
        allowlist = Allowlist(path_globs=("tests/fixtures/**",))
        assert allowlist.is_allowed(
            file_path="tests/fixtures/sample.py", rule_id="jwt", matched_text="eyFake.Token.Here"
        )
        assert not allowlist.is_allowed(file_path="app/config.py", rule_id="jwt", matched_text="eyFake.Token.Here")

    def test_rule_id_suppresses_everywhere(self):
        allowlist = Allowlist(rule_ids=frozenset({"jwt"}))
        assert allowlist.is_allowed(file_path="anywhere.py", rule_id="jwt", matched_text="anything")
        assert not allowlist.is_allowed(file_path="anywhere.py", rule_id="github-pat", matched_text="anything")

    def test_regex_matches_against_raw_secret_text(self):
        import re

        allowlist = Allowlist(regexes=(re.compile(r"^AKIAFAKEEXAMPLE"),))
        assert allowlist.is_allowed(
            file_path="x.py", rule_id="aws-access-key-id", matched_text="AKIAFAKEEXAMPLE1234567"
        )
        assert not allowlist.is_allowed(
            file_path="x.py", rule_id="aws-access-key-id", matched_text="AKIAREALLOOKING1234567"
        )

    def test_literal_match_is_case_insensitive_and_quote_stripped(self):
        allowlist = Allowlist(literals=frozenset({"hunter2"}))
        assert allowlist.is_allowed(file_path="x.py", rule_id="generic-password-assignment", matched_text="'HUNTER2'")
