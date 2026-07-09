from triage_agent.parser import parse_file, parse_lines


def test_parse_lines_skips_blank_lines():
    text = "line one\n\n  \nline two\n"
    events = parse_lines(text, source="test")
    assert [e.raw for e in events] == ["line one", "line two"]


def test_parse_lines_preserves_original_line_numbers():
    text = "a\n\nb\n"
    events = parse_lines(text, source="test")
    assert [e.line_number for e in events] == [1, 3]


def test_parse_lines_tags_source():
    events = parse_lines("only line", source="my-source")
    assert events[0].source == "my-source"


def test_parse_file_reads_from_disk(tmp_path):
    p = tmp_path / "log.txt"
    p.write_text("hello\nworld\n")
    events = parse_file(p)
    assert [e.raw for e in events] == ["hello", "world"]
    assert events[0].source == str(p)


def test_parse_file_missing_raises(tmp_path):
    missing = tmp_path / "does_not_exist.log"
    try:
        parse_file(missing)
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass
