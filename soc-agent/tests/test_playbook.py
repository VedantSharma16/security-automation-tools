from soc_agent.playbook import AlertCase


def test_from_dict_with_all_fields():
    data = {
        "alert_id": "ALT-1",
        "description": "test",
        "timestamp": "2026-01-01T00:00:00Z",
        "hostname": "host1",
        "source_ip": "1.2.3.4",
        "dest_ip": "5.6.7.8",
        "username": "bob",
        "process_name": "evil.exe",
    }
    alert = AlertCase.from_dict(data)
    assert alert.alert_id == "ALT-1"
    assert alert.hostname == "host1"
    assert alert.process_name == "evil.exe"


def test_from_dict_defaults_missing_optional_fields_to_none():
    alert = AlertCase.from_dict({"alert_id": "ALT-2", "description": "minimal"})
    assert alert.hostname is None
    assert alert.source_ip is None
    assert alert.dest_ip is None
    assert alert.username is None
    assert alert.process_name is None


def test_from_dict_defaults_missing_description_to_empty_string():
    alert = AlertCase.from_dict({"alert_id": "ALT-3"})
    assert alert.description == ""
