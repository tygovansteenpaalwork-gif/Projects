from __future__ import annotations

import json
from itertools import groupby
from typing import Dict, List

from . import __version__
from .models import Finding, ScanResult, Severity
from .rules import RULES

REPO_URL = "https://github.com/tygovansteenpaalwork-gif/Projects/tree/main/ember"

_RESET = "\033[0m"
_STYLES = {
    "brand": "\033[1;38;5;202m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "file": "\033[1;38;5;252m",
    "code": "\033[38;5;245m",
    "ok": "\033[1;32m",
    Severity.CRITICAL: "\033[1;97;48;5;160m",
    Severity.HIGH: "\033[1;38;5;196m",
    Severity.MEDIUM: "\033[1;38;5;214m",
    Severity.LOW: "\033[1;38;5;45m",
    Severity.INFO: "\033[2m",
}


class _Painter:
    def __init__(self, color: bool):
        self.color = color

    def __call__(self, style, text: str) -> str:
        if not self.color:
            return text
        return f"{_STYLES[style]}{text}{_RESET}"


def _summary_counts(result: ScanResult) -> str:
    parts = [f"{result.count(s)} {s.label}" for s in sorted(Severity, reverse=True) if result.count(s)]
    return ", ".join(parts)


def render_text(result: ScanResult, color: bool = False) -> str:
    p = _Painter(color)
    out: List[str] = ["", f" {p('brand', 'ember')} {p('dim', f'v{__version__}  Roblox backdoor scanner')}", ""]

    for label, group in groupby(result.findings, key=lambda f: f.unit.label):
        items = list(group)
        out.append(f" {p('file', label)}")
        for f in items:
            badge = p(f.severity, f" {f.severity.name:<8} ")
            location = p("dim", f"L{f.line}:{f.col}" if f.line else "instance")
            out.append(f"   {badge} {p('bold', f.rule.id)}  {f.rule.title}  {location}")
            out.append(f"   {' ' * 10}  {f.message}")
            if f.snippet:
                gutter = p("dim", f"{f.line:>5} |")
                out.append(f"   {' ' * 4}{gutter} {p('code', f.snippet)}")
        out.append("")

    for err in result.errors:
        out.append(f" {p(Severity.MEDIUM, 'skipped')} {err.file}: {err.message}")
    if result.errors:
        out.append("")

    scripts = f"{result.units} script{'s' if result.units != 1 else ''}"
    files = f"{result.files} file{'s' if result.files != 1 else ''}"
    if result.findings:
        n = len(result.findings)
        verdict = p(result.max_severity(), f" {n} finding{'s' if n != 1 else ''} ")
        out.append(f" {verdict} in {scripts} across {files}  {p('dim', '(' + _summary_counts(result) + ')')}")
    else:
        out.append(f" {p('ok', 'clean')}  no findings in {scripts} across {files}")
    out.append("")
    return "\n".join(out)


def render_json(result: ScanResult) -> str:
    data = {
        "tool": {"name": "ember", "version": __version__},
        "summary": {
            "files": result.files,
            "scripts": result.units,
            "findings": len(result.findings),
            "by_severity": {s.label: result.count(s) for s in Severity},
        },
        "findings": [f.to_dict() for f in result.findings],
        "errors": [{"file": e.file, "message": e.message} for e in result.errors],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _sarif_result(f: Finding, rule_index: Dict[str, int]) -> dict:
    in_model = f.unit.script is not None
    text = f.message
    if in_model:
        text = f"{f.unit.script.path}: {f.message} (line {f.line} of the script)"
    result = {
        "ruleId": f.rule.id,
        "ruleIndex": rule_index[f.rule.id],
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.unit.file},
                    "region": {
                        "startLine": 1 if in_model else f.line,
                        "startColumn": 1 if in_model else f.col,
                    },
                }
            }
        ],
        "properties": {"security-severity": _SECURITY_SEVERITY[f.severity]},
    }
    if in_model:
        result["locations"][0]["logicalLocations"] = [
            {"fullyQualifiedName": f.unit.script.path, "kind": "object"}
        ]
    return result


def render_sarif(result: ScanResult) -> str:
    rules = list(RULES.values())
    rule_index = {r.id: i for i, r in enumerate(rules)}
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ember",
                        "version": __version__,
                        "informationUri": REPO_URL,
                        "rules": [
                            {
                                "id": r.id,
                                "name": r.name,
                                "shortDescription": {"text": r.title},
                                "fullDescription": {"text": r.description},
                                "help": {"text": r.description},
                                "defaultConfiguration": {"level": _SARIF_LEVEL[r.severity]},
                                "properties": {
                                    "tags": ["security", "roblox"],
                                    "security-severity": _SECURITY_SEVERITY[r.severity],
                                },
                            }
                            for r in rules
                        ],
                    }
                },
                "results": [_sarif_result(f, rule_index) for f in result.findings],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def render_rules(color: bool = False) -> str:
    p = _Painter(color)
    lines = [""]
    for r in RULES.values():
        lines.append(f" {p(r.severity, f' {r.severity.name:<8} ')} {p('bold', r.id)}  {r.name}")
        lines.append(f"            {r.title}: {r.description}")
        lines.append("")
    return "\n".join(lines)
