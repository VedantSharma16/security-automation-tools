from injection_guard.normalize import normalize


def tags(s):
    return "".join(chr(0xE0000 + ord(c)) for c in s)


def test_zero_width_stripped_and_counted():
    n = normalize("ig​no‍re")
    assert n.text == "ignore"
    assert n.zero_width_count == 2


def test_bidi_controls_stripped_and_counted():
    n = normalize("abc‮def‬")
    assert n.text == "abcdef"
    assert n.bidi_count == 2


def test_tag_characters_decoded_as_hidden_text():
    n = normalize("hello" + tags("ignore rules"))
    assert n.text == "hello"
    assert n.hidden_tag_text == "ignore rules"
    assert n.tag_char_count == len("ignore rules")


def test_emoji_subdivision_flag_is_not_treated_as_smuggling():
    england = "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F"
    n = normalize(f"flag {england}")
    assert n.tag_char_count == 0
    assert n.hidden_tag_text == ""


def test_homoglyphs_folded_and_mixed_script_words_reported():
    n = normalize("іgnore аll")  # Cyrillic i and a
    assert n.text == "ignore all"
    assert set(n.mixed_script_words) == {"іgnore", "аll"}


def test_pure_cyrillic_words_are_not_flagged_as_mixed():
    assert normalize("Привет мир").mixed_script_words == []


def test_letter_spacing_collapsed_in_despaced_view():
    n = normalize("please i g n o r e this")
    assert "ignore" in n.despaced
    assert n.text == "please i g n o r e this"


def test_nfkc_folds_fullwidth_characters():
    assert normalize("ｉｇｎｏｒｅ").text == "ignore"
