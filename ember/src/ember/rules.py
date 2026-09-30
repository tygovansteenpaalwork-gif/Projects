"""Detection rules.

Every rule is a plain function that receives a :class:`Context` (one tokenized
script) and yields :class:`Finding` objects. Rules are registered with the
``@rule`` decorator, which also records their metadata for ``ember rules``,
JSON and SARIF output.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from .lexer import Token, parse_number, tokenize
from .models import Finding, Rule, Severity, SourceUnit

RuleFunc = Callable[["Context"], Iterable[Finding]]

RULES: Dict[str, Rule] = {}
_CHECKS: List[Tuple[Rule, RuleFunc]] = []


def rule(rule_id: str, name: str, severity: Severity, title: str, description: str):
    def register(func: RuleFunc) -> RuleFunc:
        meta = Rule(rule_id, name, severity, title, description)
        RULES[rule_id] = meta
        _CHECKS.append((meta, func))
        func.meta = meta  # type: ignore[attr-defined]
        return func

    return register


# --------------------------------------------------------------------------
# Shared vocabulary
# --------------------------------------------------------------------------

SENSITIVE_NAMES = {
    "require",
    "loadstring",
    "getfenv",
    "setfenv",
    "HttpGet",
    "HttpGetAsync",
    "GetAsync",
    "PostAsync",
    "RequestAsync",
    "LoadAsset",
    "LoadAssetVersion",
}
HIDDEN_SENSITIVE = SENSITIVE_NAMES | {"HttpService", "InsertService", "ServerScriptService"}
HTTP_NAMES = {"HttpGet", "HttpGetAsync", "GetAsync", "PostAsync", "RequestAsync"}

WEBHOOK_RE = re.compile(r"https?://(?:[\w-]+\.)?discord(?:app)?\.com/api/webhooks/", re.I)
REMOTE_HOST_RE = re.compile(
    r"(?:pastebin\.com/raw|raw\.githubusercontent\.com|gist\.githubusercontent\.com"
    r"|hastebin\.com/raw|rentry\.(?:co|org)/[^/\s]+/raw|paste\.ee/r/|glot\.io/snippets)",
    re.I,
)
OBFUSCATOR_SIGNATURES = [
    (re.compile(r"luraph", re.I), "Luraph"),
    (re.compile(r"iron\s*brew", re.I), "IronBrew"),
    (re.compile(r"moonsec", re.I), "MoonSec"),
    (re.compile(r"\bPSU\b|perfect\s+security", re.I), "PSU (Perfect Security)"),
    (re.compile(r"prometheus\s+obfuscator|obfuscated\s+(?:with|by|using)", re.I), "an obfuscator"),
    (re.compile(r"luaobfuscator\.com", re.I), "luaobfuscator.com"),
]
DISGUISE_NAMES = {
    name.lower()
    for name in (
        "Weld", "WeldConstraint", "Motor6D", "Snap", "Mesh", "SpecialMesh", "Decal", "Texture",
        "Sound", "TouchInterest", "TouchTransmitter", "ThumbnailCamera", "Configuration", "Fire",
        "Smoke", "Sparkles", "Attachment", "Animation", "Humanoid", "Camera", "PointLight",
        "SpotLight", "SurfaceLight", "Handle", "Part", "MeshPart", "Union", "BodyGyro",
        "BodyVelocity", "BodyPosition", "Value", "StringValue", "IntValue", "BoolValue",
        "ObjectValue", "NumberValue", "Script", "LocalScript", "ModuleScript",
    )
}
FAKE_AV_RE = re.compile(
    r"anti[\s_-]*(?:virus|lag|exploit|backdoor|hack|cheat)|virus|infect|vaccine|malware|cleaner",
    re.I,
)
INVISIBLE_CHARS = "​‌‍⁠﻿ ㅤᅟᅠ"

ESCAPE_RE = re.compile(r"\\\d{1,3}")
CONFUSABLE_RE = re.compile(r"\b(?=[lI1O0_]*[lI])[lI1O0_]{6,}\b")
PADDING_RE = re.compile(r"(?:^([ \t]{120,})|\S([ \t]{100,}))(?=[^ \t])")
SUPPRESS_RE = re.compile(r"ember-ignore(?!-file)(?:[ \t:]+((?:EMB\d{3}[ ,]*)+))?", re.I)


# --------------------------------------------------------------------------
# Constant folding for disguised asset IDs
# --------------------------------------------------------------------------


class _NotConstant(Exception):
    pass


class _NumberFolder:
    """Folds expressions like ``0x1F40 * 2 + tonumber("11")`` to a number."""

    def __init__(self, tokens: Sequence[Token], start: int, constants: Dict[str, float]):
        self.toks = tokens
        self.i = start
        self.constants = constants

    def _peek(self) -> Optional[Token]:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _take(self) -> Token:
        tok = self._peek()
        if tok is None:
            raise _NotConstant
        self.i += 1
        return tok

    def _expect_op(self, op: str) -> None:
        if not self._take().is_op(op):
            raise _NotConstant

    def expr(self) -> float:
        value = self.term()
        while True:
            tok = self._peek()
            if tok is not None and tok.is_op("+", "-"):
                self.i += 1
                rhs = self.term()
                value = value + rhs if tok.value == "+" else value - rhs
            else:
                return self._check(value)

    def term(self) -> float:
        value = self.unary()
        while True:
            tok = self._peek()
            if tok is None or not tok.is_op("*", "/", "%", "//"):
                return value
            self.i += 1
            rhs = self.unary()
            if tok.value == "*":
                value *= rhs
            elif rhs == 0:
                raise _NotConstant
            elif tok.value == "/":
                value /= rhs
            elif tok.value == "//":
                value = float(math.floor(value / rhs))
            else:
                value = value - math.floor(value / rhs) * rhs
            value = self._check(value)

    def unary(self) -> float:
        tok = self._peek()
        if tok is not None and tok.is_op("-"):
            self.i += 1
            return -self.unary()
        return self.power()

    def power(self) -> float:
        base = self.atom()
        tok = self._peek()
        if tok is not None and tok.is_op("^"):
            self.i += 1
            exponent = self.unary()
            if abs(exponent) > 64 or abs(base) > 1e9:
                raise _NotConstant
            return self._check(base ** exponent)
        return base

    def atom(self) -> float:
        tok = self._take()
        if tok.kind == "number":
            value = parse_number(tok.value)
            if value is None:
                raise _NotConstant
            return value
        if tok.is_op("("):
            value = self.expr()
            self._expect_op(")")
            return value
        if tok.is_name("tonumber"):
            self._expect_op("(")
            arg = self._take()
            if arg.kind == "string":
                base = 10
                if self._peek() is not None and self._peek().is_op(","):
                    self.i += 1
                    base_tok = self._take()
                    base = int(parse_number(base_tok.value) or 10) if base_tok.kind == "number" else 10
                value = _parse_numeric_string(arg.value, base)
            else:
                self.i -= 1
                value = self.expr()
            self._expect_op(")")
            return value
        if tok.kind == "name" and tok.value in self.constants:
            return self.constants[tok.value]
        raise _NotConstant

    @staticmethod
    def _check(value: float) -> float:
        if not math.isfinite(value) or abs(value) > 1e18:
            raise _NotConstant
        return value


def _parse_numeric_string(text: str, base: int = 10) -> float:
    text = text.strip()
    try:
        if base != 10:
            return float(int(text, base))
    except ValueError:
        raise _NotConstant from None
    value = parse_number(text)
    if value is None:
        raise _NotConstant
    return value


def fold_number(tokens: Sequence[Token], start: int, constants: Dict[str, float]) -> Optional[Tuple[float, int]]:
    """Try to fold a constant numeric expression. Returns (value, end_index)."""
    folder = _NumberFolder(tokens, start, constants)
    try:
        value = folder.expr()
    except (_NotConstant, RecursionError, OverflowError, ZeroDivisionError, ValueError):
        return None
    return value, folder.i


# --------------------------------------------------------------------------
# Context
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DerivedString:
    """A string value recovered from the source, however it was written."""

    value: str
    line: int
    col: int
    how: str  # literal | escaped | char | reverse | concat

    @property
    def hidden(self) -> bool:
        return self.how != "literal"


class Context:
    def __init__(self, unit: SourceUnit):
        self.unit = unit
        self.lines = unit.source.splitlines() or [""]
        all_tokens = list(tokenize(unit.source))
        self.comments = [t for t in all_tokens if t.kind == "comment"]
        self.tokens = [t for t in all_tokens if t.kind != "comment"]
        self.names: Set[str] = {t.value for t in self.tokens if t.kind == "name"}
        self.constants = self._numeric_constants()
        self.strings = self._derive_strings()

    # -- helpers -----------------------------------------------------------

    def tok(self, i: int) -> Optional[Token]:
        return self.tokens[i] if 0 <= i < len(self.tokens) else None

    def line_text(self, line: int) -> str:
        return self.lines[line - 1] if 1 <= line <= len(self.lines) else ""

    def snippet(self, line: int) -> str:
        text = re.sub(r"[ \t]{20,}", lambda m: f" <{len(m.group())} blanks> ", self.line_text(line))
        text = text.strip()
        return text if len(text) <= 120 else text[:117] + "..."

    def finding(self, rule_func: RuleFunc, message: str, line: int = 1, col: int = 1,
                severity: Optional[Severity] = None, snippet: bool = True) -> Finding:
        meta: Rule = rule_func.meta  # type: ignore[attr-defined]
        if not snippet:
            # Instance-level finding: it is about the object, not a source line.
            return Finding(meta, meta.severity if severity is None else severity, message, self.unit, 0, 0, "")
        return Finding(meta, meta.severity if severity is None else severity, message, self.unit, line, col, self.snippet(line))

    def is_call_name(self, i: int, *names: str) -> bool:
        """True if token i is a bare/field name in ``names`` (not a method call)."""
        t = self.tok(i)
        return t is not None and t.is_name(*names)

    # -- analysis ----------------------------------------------------------

    def _numeric_constants(self) -> Dict[str, float]:
        consts: Dict[str, float] = {}
        toks = self.tokens
        for i, t in enumerate(toks):
            nxt = self.tok(i + 1)
            if t.kind != "name" or nxt is None or not nxt.is_op("="):
                continue
            folded = fold_number(toks, i + 2, consts)
            if folded is None:
                continue
            value, end = folded
            after = self.tok(end)
            if after is not None and after.is_op("..", "(", ".", ":", "[", ","):
                continue
            consts[t.value] = value
        return consts

    def _derive_strings(self) -> List[DerivedString]:
        toks = self.tokens
        out: List[DerivedString] = []
        i = 0
        while i < len(toks):
            t = toks[i]

            if t.kind == "string":
                how = "escaped" if t.escapes >= max(3, len(t.value) // 2) else "literal"
                out.append(DerivedString(t.value, t.line, t.col, how))
                # "req" .. "uire" style concatenation of literals
                parts, j, escaped = [t.value], i, how == "escaped"
                while (self.tok(j + 1) is not None and self.tok(j + 1).is_op("..")
                       and self.tok(j + 2) is not None and self.tok(j + 2).kind == "string"):
                    parts.append(toks[j + 2].value)
                    escaped = escaped or toks[j + 2].escapes > 0
                    j += 2
                if len(parts) > 1:
                    out.append(DerivedString("".join(parts), t.line, t.col, "escaped" if escaped else "concat"))
                # ("gnirts"):reverse()  /  "gnirts":reverse()
                k = i + 1
                if self.tok(k) is not None and self.tok(k).is_op(")"):
                    k += 1
                if (self.tok(k) is not None and self.tok(k).is_op(":")
                        and self.tok(k + 1) is not None and self.tok(k + 1).is_name("reverse")):
                    out.append(DerivedString(t.value[::-1], t.line, t.col, "reverse"))

            elif t.is_name("string", "utf8") and self.tok(i + 1) is not None and self.tok(i + 1).is_op("."):
                fn = self.tok(i + 2)
                if fn is not None and fn.is_name("char") and self.tok(i + 3) is not None and self.tok(i + 3).is_op("("):
                    decoded = self._fold_char_args(i + 4)
                    if decoded:
                        out.append(DerivedString(decoded, t.line, t.col, "char"))
                elif (fn is not None and fn.is_name("reverse") and self.tok(i + 3) is not None
                      and self.tok(i + 3).is_op("(") and self.tok(i + 4) is not None
                      and self.tok(i + 4).kind == "string"):
                    out.append(DerivedString(toks[i + 4].value[::-1], t.line, t.col, "reverse"))
            i += 1
        return out

    def _fold_char_args(self, i: int) -> str:
        chars: List[str] = []
        while True:
            folded = fold_number(self.tokens, i, self.constants)
            if folded is None:
                return ""
            value, i = folded
            if not (0 <= value < 0x110000) or value != int(value):
                return ""
            chars.append(chr(int(value)))
            sep = self.tok(i)
            if sep is not None and sep.is_op(","):
                i += 1
                continue
            if sep is not None and sep.is_op(")"):
                return "".join(chars)
            return ""


# --------------------------------------------------------------------------
# Code rules
# --------------------------------------------------------------------------


def _describe_args(tokens: Sequence[Token]) -> str:
    text = " ".join(t.value if t.kind != "string" else repr(t.value) for t in tokens)
    return text if len(text) <= 40 else text[:37] + "..."


@rule(
    "EMB001", "remote-require", Severity.CRITICAL,
    "Remote module require",
    "require() called with a numeric asset ID downloads and runs a ModuleScript from the "
    "Roblox library at runtime. The code can be changed by its owner at any moment and is "
    "the most common free-model backdoor.",
)
def remote_require(ctx: Context) -> Iterator[Finding]:
    for i, t in enumerate(ctx.tokens):
        if not t.is_name("require"):
            continue
        prev, prev2 = ctx.tok(i - 1), ctx.tok(i - 2)
        nxt = ctx.tok(i + 1)
        if (prev is not None and prev.is_op("(") and prev2 is not None and prev2.is_name("pcall", "xpcall", "spawn")
                and nxt is not None and nxt.is_op(",")):
            # pcall(require, <id>) / task.spawn(require, <id>)
            folded = fold_number(ctx.tokens, i + 2, ctx.constants)
            if folded is not None and folded[0] > 0 and folded[0] == int(folded[0]):
                args = ctx.tokens[i + 2 : folded[1]]
                msg = f"{prev2.value}(require, {int(folded[0])}) loads a module from the Roblox library at runtime"
                if len(args) == 1 and args[0].kind == "name":
                    msg += f" (ID stored in `{args[0].value}`)"
                yield ctx.finding(remote_require, msg, t.line, t.col)
            continue
        if not (nxt and nxt.is_op("(")):
            continue
        folded = fold_number(ctx.tokens, i + 2, ctx.constants)
        if folded is None:
            continue
        value, end = folded
        if not (ctx.tok(end) and ctx.tok(end).is_op(")")) or value <= 0 or value != int(value):
            continue
        args = ctx.tokens[i + 2 : end]
        asset_id = int(value)
        msg = f"require({asset_id}) loads a module from the Roblox library at runtime"
        if len(args) == 1 and args[0].kind == "name":
            msg += f" (ID stored in `{args[0].value}`)"
        elif not (len(args) == 1 and args[0].kind == "number" and args[0].value.isdigit()):
            msg += f" (ID disguised as `{_describe_args(args)}`)"
        yield ctx.finding(remote_require, msg, t.line, t.col)


@rule(
    "EMB002", "remote-asset-load", Severity.HIGH,
    "InsertService asset load",
    "InsertService:LoadAsset() with a hard-coded ID pulls a model from the library at runtime; "
    "backdoors use it to fetch their payload after the game starts.",
)
def remote_asset_load(ctx: Context) -> Iterator[Finding]:
    for i, t in enumerate(ctx.tokens):
        if not t.is_name("LoadAsset", "LoadAssetVersion") or not (ctx.tok(i + 1) and ctx.tok(i + 1).is_op("(")):
            continue
        folded = fold_number(ctx.tokens, i + 2, ctx.constants)
        if folded is None or folded[0] <= 0:
            continue
        yield ctx.finding(remote_asset_load, f"{t.value}({int(folded[0])}) loads a remote model at runtime", t.line, t.col)


def _loadstring_sites(ctx: Context, include_hidden: bool = False) -> List[Tuple[int, int]]:
    """Positions where loadstring is referenced (optionally also via strings)."""
    sites = []
    for i, t in enumerate(ctx.tokens):
        if t.is_name("loadstring"):
            prev = ctx.tok(i - 1)
            if prev is None or not prev.is_op(":"):
                sites.append((t.line, t.col))
    if include_hidden:
        sites += [(s.line, s.col) for s in ctx.strings if s.value.strip() == "loadstring"]
    return sorted(set(sites))


def _has_remote_source(ctx: Context) -> bool:
    if ctx.names & HTTP_NAMES:
        return True
    return any(REMOTE_HOST_RE.search(s.value) or s.value.strip() in HTTP_NAMES for s in ctx.strings)


@rule(
    "EMB003", "remote-code-execution", Severity.CRITICAL,
    "Remote code execution",
    "loadstring() in a script that also performs HTTP requests: code is downloaded and executed, "
    "so whoever controls the URL controls your server.",
)
def remote_code_execution(ctx: Context) -> Iterator[Finding]:
    if not _has_remote_source(ctx):
        return
    for line, col in _loadstring_sites(ctx, include_hidden=True):
        yield ctx.finding(remote_code_execution, "loadstring() executes code fetched over HTTP", line, col)


@rule(
    "EMB004", "loadstring", Severity.HIGH,
    "Dynamic code execution",
    "loadstring() compiles and runs arbitrary strings. Legitimate games almost never need it, "
    "and backdoors pair it with remotes so an attacker can run any code on the server.",
)
def loadstring_use(ctx: Context) -> Iterator[Finding]:
    if _has_remote_source(ctx):
        return  # reported as EMB003
    for line, col in _loadstring_sites(ctx):
        yield ctx.finding(loadstring_use, "loadstring() runs arbitrary code strings", line, col)


@rule(
    "EMB005", "environment-access", Severity.MEDIUM,
    "Environment manipulation",
    "getfenv()/setfenv() let code look up globals by computed names, which obfuscated backdoors "
    "use to hide calls to require or loadstring.",
)
def environment_access(ctx: Context) -> Iterator[Finding]:
    for i, t in enumerate(ctx.tokens):
        if not t.is_name("getfenv", "setfenv"):
            continue
        prev = ctx.tok(i - 1)
        if prev is not None and prev.is_op(".", ":"):
            continue
        # getfenv()[...] or getfenv(0)[...] -> dynamic lookup, escalate
        j = i + 1
        dynamic = False
        if ctx.tok(j) and ctx.tok(j).is_op("("):
            depth = 0
            while ctx.tok(j) is not None:
                if ctx.tok(j).is_op("("):
                    depth += 1
                elif ctx.tok(j).is_op(")"):
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            dynamic = ctx.tok(j + 1) is not None and ctx.tok(j + 1).is_op("[")
        field = ctx.tok(j + 2) if ctx.tok(j + 1) is not None and ctx.tok(j + 1).is_op(".") else None
        if dynamic:
            yield ctx.finding(environment_access, f"{t.value}()[...] looks up a global by a computed name",
                              t.line, t.col, Severity.HIGH)
        elif field is not None and field.kind == "name":
            if field.value in SENSITIVE_NAMES:
                yield ctx.finding(environment_access, f"{t.value}().{field.value} reaches {field.value} indirectly",
                                  t.line, t.col, Severity.HIGH)
            else:
                # getfenv().expect in test runners and similar: harmless on its own.
                yield ctx.finding(environment_access, f"{t.value}().{field.value} reads from the environment",
                                  t.line, t.col, Severity.INFO)
        else:
            yield ctx.finding(environment_access, f"{t.value}() accesses the function environment", t.line, t.col)


@rule(
    "EMB006", "hidden-sensitive-name", Severity.HIGH,
    "Hidden sensitive identifier",
    "The name of a dangerous function or service (require, loadstring, HttpService, ...) is built "
    "from character codes, escapes, reversed text or string concatenation, or used as a dynamic "
    "index. Honest code has no reason to hide these names.",
)
def hidden_sensitive_name(ctx: Context) -> Iterator[Finding]:
    seen: Set[Tuple[int, str]] = set()
    for s in ctx.strings:
        name = s.value.strip()
        key = (s.line, name)
        if key in seen:
            continue
        if s.hidden and name in HIDDEN_SENSITIVE:
            seen.add(key)
            how = {
                "escaped": "escape sequences", "char": "string.char()", "reverse": "reversed text",
                "concat": "string concatenation",
            }[s.how]
            yield ctx.finding(hidden_sensitive_name, f"`{name}` is spelled out with {how}", s.line, s.col)
    for i, t in enumerate(ctx.tokens):
        if t.kind != "string" or t.value not in SENSITIVE_NAMES:
            continue
        prev, nxt = ctx.tok(i - 1), ctx.tok(i + 1)
        if prev is not None and prev.is_op("[") and nxt is not None and nxt.is_op("]"):
            if (t.line, t.value) not in seen:
                seen.add((t.line, t.value))
                yield ctx.finding(hidden_sensitive_name, f"`{t.value}` is looked up dynamically with [\"{t.value}\"]",
                                  t.line, t.col)


@rule(
    "EMB007", "encoded-string", Severity.MEDIUM,
    "Encoded string",
    "A long string is written as character codes or numeric escapes. Ember decodes it and shows "
    "the result so you can see what it is hiding.",
)
def encoded_string(ctx: Context) -> Iterator[Finding]:
    for s in ctx.strings:
        if s.how not in ("escaped", "char") or len(s.value) < 8:
            continue
        if s.value.strip() in HIDDEN_SENSITIVE:
            continue  # EMB006 already explains it
        readable = sum(32 <= ord(ch) < 127 for ch in s.value) / len(s.value)
        if readable < 0.9 or not any(ch.isalpha() for ch in s.value):
            continue  # binary data or non-Latin text, not hidden code
        preview = "".join(ch if ch.isprintable() else "." for ch in s.value)
        preview = preview if len(preview) <= 60 else preview[:57] + "..."
        yield ctx.finding(encoded_string, f'decodes to "{preview}"', s.line, s.col)


@rule(
    "EMB008", "offscreen-code", Severity.HIGH,
    "Code hidden by whitespace padding",
    "Code placed hundreds of columns to the right so it is invisible in the Studio editor "
    "unless you scroll sideways - a classic trick for hiding a require() at the end of a line.",
)
def offscreen_code(ctx: Context) -> Iterator[Finding]:
    for n, line in enumerate(ctx.lines, 1):
        m = PADDING_RE.search(line)
        if not m:
            continue
        hidden = line[m.end():].strip()
        if hidden.startswith("--"):
            continue
        pad = len(m.group(1) or m.group(2))
        shown = hidden if len(hidden) <= 50 else hidden[:47] + "..."
        yield ctx.finding(offscreen_code, f"`{shown}` is pushed {pad} columns off-screen", n, m.end() + 1)


def _entropy(text: str) -> float:
    counts = Counter(text)
    total = len(text)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


@rule(
    "EMB009", "obfuscated-blob", Severity.MEDIUM,
    "Obfuscated code blob",
    "Very long lines with random-looking content or huge numeric tables are typical of "
    "obfuscators and bytecode VMs. Obfuscated code in a free model is a red flag: you cannot "
    "review what it does.",
)
def obfuscated_blob(ctx: Context) -> Iterator[Finding]:
    hits: List[Tuple[int, str]] = []
    for n, line in enumerate(ctx.lines, 1):
        if len(line) < 1000 or line.lstrip().startswith("--"):
            continue
        kind = _blob_kind(line)
        if kind:
            hits.append((n, kind))
    if hits:
        n, kind = hits[0]
        more = f" (+{len(hits) - 1} more)" if len(hits) > 1 else ""
        size = len(ctx.line_text(n))
        yield ctx.finding(obfuscated_blob, f"{size:,}-character line of {kind}{more}", n, 1)


def _blob_kind(line: str) -> str:
    numeric = sum(ch.isdigit() or ch in ",{} " for ch in line) / len(line)
    if len(line) >= 2000 and numeric >= 0.8:
        return "numeric bytecode"
    if len(ESCAPE_RE.findall(line)) >= 150:
        return "escaped bytes"
    if len(CONFUSABLE_RE.findall(line)) >= 30:
        return "look-alike identifiers (IlIl1l...)"
    if _entropy(line) >= 5.3:
        return "high-entropy data"
    return ""


@rule(
    "EMB010", "obfuscator-signature", Severity.HIGH,
    "Known obfuscator",
    "The script carries the signature of a Lua obfuscator. Obfuscation is rarely used for honest "
    "free-model code and is standard practice for backdoors.",
)
def obfuscator_signature(ctx: Context) -> Iterator[Finding]:
    for n, line in enumerate(ctx.lines[:400], 1):
        for pattern, label in OBFUSCATOR_SIGNATURES:
            m = pattern.search(line)
            if m:
                yield ctx.finding(obfuscator_signature, f"signature of {label}", n, m.start() + 1)
                return


@rule(
    "EMB011", "discord-webhook", Severity.HIGH,
    "Discord webhook",
    "A Discord webhook URL. Backdoors use webhooks to report infected games, server IDs and "
    "player data back to the attacker.",
)
def discord_webhook(ctx: Context) -> Iterator[Finding]:
    seen: Set[int] = set()
    for s in ctx.strings:
        if s.line not in seen and WEBHOOK_RE.search(s.value):
            seen.add(s.line)
            extra = "" if s.how == "literal" else f" (hidden via {s.how})"
            yield ctx.finding(discord_webhook, f"sends data to a Discord webhook{extra}", s.line, s.col)


@rule(
    "EMB012", "remote-code-host", Severity.MEDIUM,
    "Paste/raw code host URL",
    "URL on a paste or raw-file host (pastebin, raw.githubusercontent, ...), commonly used to "
    "serve payloads that change after the model is published.",
)
def remote_code_host(ctx: Context) -> Iterator[Finding]:
    seen: Set[int] = set()
    for s in ctx.strings:
        m = REMOTE_HOST_RE.search(s.value)
        if m and s.line not in seen:
            seen.add(s.line)
            yield ctx.finding(remote_code_host, f"references {m.group(0)}", s.line, s.col)


# --------------------------------------------------------------------------
# Instance rules (scripts that came out of .rbxm / .rbxmx / place files)
# --------------------------------------------------------------------------


@rule(
    "EMB101", "disguised-script", Severity.MEDIUM,
    "Script disguised as another object",
    "The script is named after a non-script object (Weld, Mesh, ThumbnailCamera, ...) so it "
    "blends into the Explorer. Real welds and meshes are not scripts.",
)
def disguised_script(ctx: Context) -> Iterator[Finding]:
    info = ctx.unit.script
    if info and info.name.strip().lower() in DISGUISE_NAMES and info.name.strip().lower() != info.class_name.lower():
        yield ctx.finding(disguised_script, f"{info.class_name} is named \"{info.name}\"", snippet=False)


@rule(
    "EMB102", "invisible-name", Severity.MEDIUM,
    "Script with invisible name",
    "The script's name is empty or made of invisible characters so it is hard to spot in the "
    "Explorer.",
)
def invisible_name(ctx: Context) -> Iterator[Finding]:
    info = ctx.unit.script
    if info is None:
        return
    visible = "".join(ch for ch in info.name if ch not in INVISIBLE_CHARS and not ch.isspace())
    if not visible:
        yield ctx.finding(invisible_name, f"{info.class_name} has an invisible name ({len(info.name)} chars)", snippet=False)


@rule(
    "EMB103", "fake-antivirus", Severity.LOW,
    "Fake 'anti-virus' script name",
    "Names like 'Anti-Lag' or 'Virus Remover' are commonly used by malicious free-model scripts "
    "to look helpful. Review it before trusting it.",
)
def fake_antivirus(ctx: Context) -> Iterator[Finding]:
    info = ctx.unit.script
    if info and FAKE_AV_RE.search(info.name):
        yield ctx.finding(fake_antivirus, f"{info.class_name} is named \"{info.name}\"", snippet=False)


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------


def _suppressions(ctx: Context) -> Tuple[bool, Dict[int, Optional[Set[str]]]]:
    per_line: Dict[int, Optional[Set[str]]] = {}
    for c in ctx.comments:
        if "ember-ignore-file" in c.value.lower() and c.line <= 10:
            return True, {}
        m = SUPPRESS_RE.search(c.value)
        if not m:
            continue
        ids = set(re.findall(r"EMB\d{3}", (m.group(1) or "").upper())) or None
        existing = per_line.get(c.line, set())
        per_line[c.line] = None if ids is None or existing is None else existing | ids
    return False, per_line


def run_rules(unit: SourceUnit, enabled: Optional[Set[str]] = None) -> List[Finding]:
    ctx = Context(unit)
    skip_all, suppressed = _suppressions(ctx)
    if skip_all:
        return []
    findings: List[Finding] = []
    seen: Set[Tuple[str, int, int]] = set()
    for meta, check in _CHECKS:
        if enabled is not None and meta.id not in enabled:
            continue
        for f in check(ctx):
            key = (meta.id, f.line, f.col)
            if key in seen:
                continue
            seen.add(key)
            if f.line in suppressed:
                ids = suppressed[f.line]
                if ids is None or meta.id in ids:
                    continue
            findings.append(f)
    findings.sort(key=lambda f: (f.line, -f.severity, f.rule.id))
    return findings
