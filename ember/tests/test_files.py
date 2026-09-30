import json
from pathlib import Path

import pytest

from ember import scan_paths
from ember.cli import main
from ember.lz4 import LZ4Error, decompress_block
from ember.rbxfile import RobloxFileError, read_binary, read_xml
from rbxm_builder import build_rbxm

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

TREE = [
    ("Model", "Tree", None, None),
    ("Part", "Trunk", 0, None),
    ("Script", "Weld", 1, "local w = 1" + " " * 140 + "require(99887766)"),
    ("LocalScript", "Sway", 0, "print('hi')"),
    ("ModuleScript", "​", 0, "return {}"),
]


@pytest.mark.parametrize("compress", [False, True])
def test_binary_rbxm_roundtrip(compress):
    if compress:
        pytest.importorskip("lz4")
    scripts = read_binary(build_rbxm(TREE, compress=compress))
    by_path = {s.path: s for s in scripts}
    assert set(by_path) == {"Tree.Trunk.Weld", "Tree.Sway", "Tree.​"}
    assert by_path["Tree.Trunk.Weld"].class_name == "Script"
    assert "require(99887766)" in by_path["Tree.Trunk.Weld"].source


def test_binary_scan_findings(tmp_path):
    (tmp_path / "tree.rbxm").write_bytes(build_rbxm(TREE))
    result = scan_paths([str(tmp_path)], base=str(tmp_path))
    found = {(f.unit.script.path, f.rule.id) for f in result.findings}
    assert ("Tree.Trunk.Weld", "EMB001") in found
    assert ("Tree.Trunk.Weld", "EMB008") in found
    assert ("Tree.Trunk.Weld", "EMB101") in found
    assert ("Tree.​", "EMB102") in found
    assert not any(path == "Tree.Sway" for path, _ in found)


def test_truncated_binary_is_an_error(tmp_path):
    data = build_rbxm(TREE)[:-40]
    with pytest.raises(RobloxFileError):
        read_binary(data)
    (tmp_path / "bad.rbxm").write_bytes(data)
    result = scan_paths([str(tmp_path)])
    assert result.errors and not result.findings


def test_lz4_rejects_garbage():
    with pytest.raises(LZ4Error):
        decompress_block(b"\xff\xff\xff", 100)


def test_lz4_overlapping_match():
    # literal "ab", then a 10-byte match at offset 2 -> "ababababababab"
    block = bytes([0x26]) + b"ab" + bytes([2, 0])
    assert decompress_block(block, 12) == b"ab" * 6


def test_xml_rejects_entities():
    with pytest.raises(RobloxFileError):
        read_xml(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><roblox>&a;</roblox>')


def test_example_model():
    scripts = read_xml((EXAMPLES / "infected_tree.rbxmx").read_bytes())
    assert [s.path for s in scripts] == ["Pine Tree.Trunk.Weld", "Pine Tree.Anti-Lag", "Pine Tree.LeafSway"]


def test_examples_scan():
    result = scan_paths([str(EXAMPLES)], base=str(EXAMPLES))
    files = {f.unit.file for f in result.findings}
    assert "clean.lua" not in files
    assert {"backdoor.lua", "infected_tree.rbxmx"} <= files
    assert not any(f.unit.script and f.unit.script.name == "LeafSway" for f in result.findings)


def test_cli_exit_codes(capsys):
    assert main(["scan", str(EXAMPLES / "clean.lua")]) == 0
    assert main(["scan", str(EXAMPLES / "backdoor.lua")]) == 1
    assert main(["scan", str(EXAMPLES / "backdoor.lua"), "--fail-on", "none"]) == 0
    capsys.readouterr()


def test_cli_json_and_sarif(tmp_path, capsys):
    out = tmp_path / "report.sarif"
    main(["scan", str(EXAMPLES), "--format", "sarif", "-o", str(out), "--fail-on", "none"])
    sarif = json.loads(out.read_text())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["results"]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert all(r["ruleId"] in rule_ids for r in run["results"])

    capsys.readouterr()
    main(["scan", str(EXAMPLES / "backdoor.lua"), "--format", "json", "--fail-on", "none"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["findings"] == len(data["findings"]) > 0


def test_cli_rejects_bad_arguments(capsys):
    with pytest.raises(SystemExit):
        main(["scan", "does-not-exist"])
    with pytest.raises(SystemExit):
        main(["scan", str(EXAMPLES), "--rules", "EMB999"])
    capsys.readouterr()
