from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Set

from .models import ScanError, ScanResult, ScriptInfo, SourceUnit
from .rbxfile import RobloxFileError, read_roblox_file
from .rules import run_rules

LUA_EXTENSIONS = {".lua", ".luau"}
ROBLOX_EXTENSIONS = {".rbxm", ".rbxmx", ".rbxl", ".rbxlx"}
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv"}
MAX_FILE_BYTES = 200 * 1024 * 1024


def iter_files(paths: Iterable[str]) -> Iterator[Path]:
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            yield path
            continue
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for name in sorted(files):
                p = Path(root, name)
                if p.suffix.lower() in LUA_EXTENSIONS | ROBLOX_EXTENSIONS:
                    yield p


def units_for_file(path: Path, display: str) -> List[SourceUnit]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise RobloxFileError(f"file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
    data = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix in ROBLOX_EXTENSIONS or suffix not in LUA_EXTENSIONS:
        scripts = read_roblox_file(data)
        if scripts is not None:
            return [
                SourceUnit(display, s.source, ScriptInfo(s.class_name, s.name, s.path))
                for s in scripts
            ]
        if suffix in ROBLOX_EXTENSIONS:
            raise RobloxFileError("not a valid Roblox model/place file")
    return [SourceUnit(display, data.decode("utf-8", "replace"))]


def scan_source(source: str, filename: str = "<memory>", rules: Optional[Set[str]] = None):
    """Scan a Luau source string and return the findings."""
    return run_rules(SourceUnit(filename, source), rules)


def scan_paths(paths: Iterable[str], rules: Optional[Set[str]] = None, base: Optional[str] = None) -> ScanResult:
    result = ScanResult()
    base_path = Path(base).resolve() if base else Path.cwd().resolve()
    for path in iter_files(paths):
        try:
            display = path.resolve().relative_to(base_path).as_posix()
        except ValueError:
            display = path.as_posix()
        result.files += 1
        try:
            units = units_for_file(path, display)
        except (OSError, RobloxFileError) as exc:
            result.errors.append(ScanError(display, str(exc)))
            continue
        for unit in units:
            result.units += 1
            result.findings.extend(run_rules(unit, rules))
    return result
