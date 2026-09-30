from ember.lexer import parse_number, tokenize


def kinds(src):
    return [(t.kind, t.value) for t in tokenize(src)]


def test_names_numbers_ops():
    assert kinds("local x = 0x1F + 1_000") == [
        ("name", "local"), ("name", "x"), ("op", "="), ("number", "0x1F"), ("op", "+"), ("number", "1_000"),
    ]


def test_escapes_are_decoded_and_counted():
    tok = next(tokenize(r'"\114\101\113\117\105\114\101"'))
    assert tok.value == "require"
    assert tok.escapes == 7


def test_hex_unicode_and_z_escapes():
    tok = next(tokenize('"\\x41\\u{42}\\z   \n  C"'))
    assert tok.value == "ABC"


def test_long_strings_and_comments():
    toks = list(tokenize("--[==[ a\n]] b ]==] x = [[\nhello]] -- tail\ny"))
    assert toks[0].kind == "comment"
    assert toks[1].value == "x" and toks[1].line == 2
    assert toks[3].kind == "string" and toks[3].value == "hello"
    assert toks[-1].value == "y" and toks[-1].line == 4


def test_unterminated_input_does_not_raise():
    list(tokenize('"never closed\nlocal y = [[ open'))


def test_parse_number():
    assert parse_number("0xFF") == 255
    assert parse_number("0b101") == 5
    assert parse_number("1e3") == 1000
    assert parse_number("12_345") == 12345
    assert parse_number("0xZZ") is None
