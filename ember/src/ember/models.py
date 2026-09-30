from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, text: str) -> "Severity":
        try:
            return cls[text.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity '{text}' (expected one of: {valid})") from None

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    title: str
    description: str


@dataclass
class ScriptInfo:
    """Instance metadata for scripts that came out of a model/place file."""

    class_name: str
    name: str
    path: str


@dataclass
class SourceUnit:
    """One piece of Luau source: a .lua file, or a script inside a model."""

    file: str
    source: str
    script: Optional[ScriptInfo] = None

    @property
    def label(self) -> str:
        if self.script:
            return f"{self.file} > {self.script.path}"
        return self.file


@dataclass
class Finding:
    rule: Rule
    severity: Severity
    message: str
    unit: SourceUnit
    line: int = 1
    col: int = 1
    snippet: str = ""

    def to_dict(self) -> dict:
        data = {
            "rule": self.rule.id,
            "name": self.rule.name,
            "severity": self.severity.label,
            "title": self.rule.title,
            "message": self.message,
            "file": self.unit.file,
            "line": self.line,
            "column": self.col,
            "snippet": self.snippet,
        }
        if self.unit.script:
            data["instance"] = {
                "class": self.unit.script.class_name,
                "name": self.unit.script.name,
                "path": self.unit.script.path,
            }
        return data


@dataclass
class ScanError:
    file: str
    message: str


@dataclass
class ScanResult:
    files: int = 0
    units: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def max_severity(self) -> Optional[Severity]:
        return max((f.severity for f in self.findings), default=None)
