"""Ember - find backdoors and malware in Roblox scripts, models and places."""

__version__ = "0.1.0"

from .models import Finding, Rule, ScanResult, Severity  # noqa: E402
from .scanner import scan_paths, scan_source  # noqa: E402

__all__ = ["Finding", "Rule", "ScanResult", "Severity", "scan_paths", "scan_source", "__version__"]
