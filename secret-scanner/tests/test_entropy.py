import secret_fixtures as fx
from secret_scanner.entropy import EntropyConfig, find_high_entropy_tokens, shannon_entropy


def test_shannon_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaaaaaa") == 0.0


def test_shannon_entropy_of_diverse_string_is_positive():
    assert shannon_entropy("aB3xQ9zR7mK1") > 2.5


def test_repeated_char_token_is_not_flagged_despite_length():
    line = "padding = '" + ("a" * 40) + "'"
    assert list(find_high_entropy_tokens(line)) == []


def test_short_token_is_not_flagged():
    token = fx.random_high_entropy_token(num_bytes=6)  # short base64 output
    line = f"x = '{token}'"
    if len(token) < 20:
        assert list(find_high_entropy_tokens(line)) == []


def test_random_base64_token_is_flagged():
    token = fx.random_high_entropy_token(num_bytes=32)
    line = f"session_key = '{token}'"
    hits = list(find_high_entropy_tokens(line))
    assert any(t == token for t, *_ in hits)


def test_low_threshold_flags_more_than_high_threshold():
    token = fx.random_high_entropy_token(num_bytes=32)
    line = f"session_key = '{token}'"
    lenient = list(find_high_entropy_tokens(line, EntropyConfig(base64_threshold=0.0)))
    strict = list(find_high_entropy_tokens(line, EntropyConfig(base64_threshold=100.0)))
    assert len(lenient) >= len(strict)
    assert strict == []


def test_hex_like_token_uses_hex_threshold():
    hex_token = "0123456789abcdef0123456789abcdef01234567"  # 41 hex chars, decent entropy
    line = f"digest = {hex_token}"
    hits = list(find_high_entropy_tokens(line, EntropyConfig(hex_threshold=1.0)))
    assert any(t == hex_token for t, *_ in hits)


def test_ordinary_identifier_is_not_flagged():
    line = "def calculate_running_total_for_invoice(invoice_items_list):"
    assert list(find_high_entropy_tokens(line)) == []
