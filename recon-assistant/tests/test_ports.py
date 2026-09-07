import pytest

from recon_assistant.ports import parse_ports


def test_parse_single_ports():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_range():
    assert parse_ports("8000-8003") == [8000, 8001, 8002, 8003]


def test_parse_mixed_list_and_range_dedupes_and_sorts():
    assert parse_ports("443,80,80-82") == [80, 81, 82, 443]


def test_invalid_range_raises():
    with pytest.raises(ValueError):
        parse_ports("100-50")


def test_out_of_range_port_raises():
    with pytest.raises(ValueError):
        parse_ports("70000")
