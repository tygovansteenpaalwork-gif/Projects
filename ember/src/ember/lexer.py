"""A small, forgiving Lua/Luau tokenizer.

It never raises on malformed input: obfuscated and hand-mangled scripts are
exactly what Ember needs to read, so unknown characters become single-char
operator tokens and unterminated strings/comments run to end of file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, List, Optional

_SIMPLE_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "\\": "\\",
    '"': '"',
    "'": "'",
    "\n": "\n",
}

_OPS3 = ("...", "..=", "//=")
_OPS2 = ("==", "~=", "<=", ">=", "..", "::", "//", "+=", "-=", "*=", "/=", "%=", "^=", "->")


@dataclass(frozen=True)
class Token:
    kind: str  # name | number | string | op | comment
    value: str  # decoded text for strings, raw text otherwise
    line: int
    col: int
    escapes: int = 0  # numeric escapes (\ddd, \xHH, \u{...}) inside a string

    def is_op(self, *ops: str) -> bool:
        return self.kind == "op" and self.value in ops

    def is_name(self, *names: str) -> bool:
        return self.kind == "name" and (not names or self.value in names)


def _long_bracket_level(src: str, i: int) -> Optional[int]:
    """Return the level of a long bracket opening at ``src[i]`` (``[==[``), or None."""
    if i >= len(src) or src[i] != "[":
        return None
    j = i + 1
    while j < len(src) and src[j] == "=":
        j += 1
    if j < len(src) and src[j] == "[":
        return j - i - 1
    return None


def _decode_quoted(src: str, i: int, quote: str):
    """Decode a quoted string starting after the opening quote.

    Returns (value, end_index, numeric_escape_count).
    """
    out: List[str] = []
    escapes = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == quote:
            return "".join(out), i + 1, escapes
        if c == "\n":
            # Unterminated string; stop at the line break like Lua would error.
            return "".join(out), i, escapes
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= n:
            break
        e = src[i]
        if e in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[e])
            i += 1
        elif e.isdigit():
            j = i
            while j < n and j - i < 3 and src[j].isdigit():
                j += 1
            code = int(src[i:j])
            out.append(chr(code) if code < 256 else "�")
            escapes += 1
            i = j
        elif e == "x" and i + 2 < n + 1:
            hexpart = src[i + 1 : i + 3]
            try:
                out.append(chr(int(hexpart, 16)))
                escapes += 1
                i += 3
            except ValueError:
                out.append("x")
                i += 1
        elif e == "u" and i + 1 < n and src[i + 1] == "{":
            end = src.find("}", i + 2)
            if end == -1:
                out.append("u")
                i += 1
                continue
            try:
                out.append(chr(int(src[i + 2 : end], 16)))
            except (ValueError, OverflowError):
                out.append("�")
            escapes += 1
            i = end + 1
        elif e == "z":
            i += 1
            while i < n and src[i] in " \t\r\n\f\v":
                i += 1
        else:
            out.append(e)
            i += 1
    return "".join(out), n, escapes


def tokenize(src: str) -> Iterator[Token]:
    i = 0
    n = len(src)
    line = 1
    line_start = 0

    def advance_lines(text: str, start: int):
        nonlocal line, line_start
        count = text.count("\n")
        if count:
            line += count
            line_start = start + text.rfind("\n") + 1

    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            line_start = i
            continue
        if c in " \t\r\f\v﻿":
            i += 1
            continue

        tline, tcol = line, i - line_start + 1

        # Comments
        if c == "-" and src.startswith("--", i):
            level = _long_bracket_level(src, i + 2)
            if level is not None:
                close = "]" + "=" * level + "]"
                end = src.find(close, i + 2)
                end = n if end == -1 else end + len(close)
            else:
                end = src.find("\n", i)
                end = n if end == -1 else end
            text = src[i:end]
            yield Token("comment", text, tline, tcol)
            advance_lines(text, i)
            i = end
            continue

        # Long strings
        if c == "[":
            level = _long_bracket_level(src, i)
            if level is not None:
                open_len = level + 2
                close = "]" + "=" * level + "]"
                end = src.find(close, i + open_len)
                body_end = n if end == -1 else end
                body = src[i + open_len : body_end]
                if body.startswith("\r\n"):
                    body = body[2:]
                elif body.startswith("\n"):
                    body = body[1:]
                stop = n if end == -1 else end + len(close)
                yield Token("string", body, tline, tcol)
                advance_lines(src[i:stop], i)
                i = stop
                continue

        # Quoted strings
        if c in "\"'`":
            value, end, escapes = _decode_quoted(src, i + 1, c)
            yield Token("string", value, tline, tcol, escapes)
            advance_lines(src[i:end], i)
            i = end
            continue

        # Numbers
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            j = i
            if src.startswith(("0x", "0X"), i):
                j = i + 2
                while j < n and (src[j] in "0123456789abcdefABCDEF_"):
                    j += 1
            elif src.startswith(("0b", "0B"), i):
                j = i + 2
                while j < n and src[j] in "01_":
                    j += 1
            else:
                while j < n and (src[j].isdigit() or src[j] in "._"):
                    j += 1
                if j < n and src[j] in "eE":
                    j += 1
                    if j < n and src[j] in "+-":
                        j += 1
                    while j < n and src[j].isdigit():
                        j += 1
            yield Token("number", src[i:j], tline, tcol)
            i = j
            continue

        # Names
        if c.isalpha() or c == "_":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            yield Token("name", src[i:j], tline, tcol)
            i = j
            continue

        # Operators
        for op in _OPS3:
            if src.startswith(op, i):
                break
        else:
            op = ""
        if not op:
            for cand in _OPS2:
                if src.startswith(cand, i):
                    op = cand
                    break
        if not op:
            op = c
        yield Token("op", op, tline, tcol)
        i += len(op)


def parse_number(text: str) -> Optional[float]:
    """Parse a Luau numeric literal. Returns None if it is not a valid number."""
    t = text.replace("_", "")
    try:
        if t[:2].lower() == "0x":
            return float(int(t[2:], 16))
        if t[:2].lower() == "0b":
            return float(int(t[2:], 2))
        return float(t)
    except (ValueError, OverflowError):
        return None
