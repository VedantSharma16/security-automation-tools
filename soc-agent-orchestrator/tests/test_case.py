from soc_orchestrator.case import load_case


def test_load_case_classifies_files_by_extension(tmp_path):
    (tmp_path / "auth.log").write_text("log contents", encoding="utf-8")
    (tmp_path / "alert.txt").write_text("alert contents", encoding="utf-8")
    (tmp_path / "notes.bin").write_bytes(b"\x00\x01")

    case = load_case(tmp_path)

    kinds = {f.path.name: f.kind for f in case.files}
    assert kinds == {"auth.log": "log", "alert.txt": "alert", "notes.bin": "other"}


def test_load_case_classifies_by_name_even_without_log_extension(tmp_path):
    (tmp_path / "sshd_log.txt").write_text("...", encoding="utf-8")
    case = load_case(tmp_path)
    assert case.files[0].kind == "log"


def test_load_case_reads_description_file_when_none_passed(tmp_path):
    (tmp_path / "description.txt").write_text("  paged for anomalous SSH activity  ", encoding="utf-8")
    (tmp_path / "auth.log").write_text("...", encoding="utf-8")

    case = load_case(tmp_path)

    assert case.incident_description == "paged for anomalous SSH activity"
    assert "description.txt" not in {f.path.name for f in case.files}


def test_load_case_explicit_description_overrides_file(tmp_path):
    (tmp_path / "description.txt").write_text("from file", encoding="utf-8")
    case = load_case(tmp_path, incident_description="from caller")
    assert case.incident_description == "from caller"


def test_load_case_missing_directory_raises(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        load_case(tmp_path / "does-not-exist")


def test_files_of_kind_filters_correctly(tmp_path):
    (tmp_path / "a.log").write_text("...", encoding="utf-8")
    (tmp_path / "b.txt").write_text("...", encoding="utf-8")

    case = load_case(tmp_path)

    assert [f.path.name for f in case.files_of_kind("log")] == ["a.log"]
    assert [f.path.name for f in case.files_of_kind("alert")] == ["b.txt"]


def test_manifest_to_dict_round_trips_files(tmp_path):
    (tmp_path / "a.log").write_text("...", encoding="utf-8")
    case = load_case(tmp_path, incident_description="desc")
    d = case.to_dict()
    assert d["incident_description"] == "desc"
    assert d["files"] == [{"path": str(tmp_path / "a.log"), "kind": "log"}]
