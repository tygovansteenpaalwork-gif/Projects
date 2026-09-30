from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .models import Severity
from .report import render_json, render_rules, render_sarif, render_text
from .rules import RULES
from .scanner import scan_paths


def _use_color(stream, mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ember",
        description="Find backdoors and malware in Roblox scripts, models and places.",
    )
    parser.add_argument("--version", action="version", version=f"ember {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan files or directories")
    scan.add_argument("paths", nargs="+", help=".lua/.luau/.rbxm/.rbxmx/.rbxl/.rbxlx files or directories")
    scan.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    scan.add_argument("--fail-on", default="high", metavar="SEVERITY",
                      help="exit with code 1 if a finding is at least this severe (default: high; 'none' to never fail)")
    scan.add_argument("--min-severity", default="low", metavar="SEVERITY",
                      help="hide findings below this severity (default: low)")
    scan.add_argument("--rules", metavar="IDS", help="only run these comma-separated rule IDs (e.g. EMB001,EMB003)")
    scan.add_argument("--color", choices=("auto", "always", "never"), default="auto")

    rules = sub.add_parser("rules", help="list all detection rules")
    rules.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        print(render_rules(_use_color(sys.stdout, args.color)))
        return 0
    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        min_severity = Severity.parse(args.min_severity)
        fail_on = None if args.fail_on.lower() == "none" else Severity.parse(args.fail_on)
    except ValueError as exc:
        parser.error(str(exc))

    enabled = None
    if args.rules:
        enabled = {r.strip().upper() for r in args.rules.split(",") if r.strip()}
        unknown = enabled - set(RULES)
        if unknown:
            parser.error(f"unknown rule id(s): {', '.join(sorted(unknown))}")

    missing = [p for p in args.paths if not os.path.exists(p)]
    if missing:
        parser.error(f"path not found: {', '.join(missing)}")

    result = scan_paths(args.paths, enabled)
    result.findings = [f for f in result.findings if f.severity >= min_severity]

    if args.format == "json":
        report = render_json(result)
    elif args.format == "sarif":
        report = render_sarif(result)
    else:
        stream = sys.stdout if not args.output else None
        report = render_text(result, color=stream is not None and _use_color(stream, args.color))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        if args.format != "text":
            print(render_text(result, color=_use_color(sys.stdout, args.color)))
    else:
        print(report)

    if fail_on is not None and any(f.severity >= fail_on for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
