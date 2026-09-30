"""Readers for Roblox model and place files.

* Binary: ``.rbxm`` / ``.rbxl`` (``<roblox!`` header, LZ4 or ZSTD chunks)
* XML:    ``.rbxmx`` / ``.rbxlx``

Only what Ember needs is decoded: every instance's class, Name and parent,
plus the Source of scripts. No Roblox Studio required.
"""

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .lz4 import LZ4Error, decompress_block

SCRIPT_CLASSES = {"Script", "LocalScript", "ModuleScript"}
BINARY_MAGIC = b"<roblox!\x89\xff\r\n\x1a\n"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
MAX_CHUNK = 512 * 1024 * 1024
TYPE_STRING = 0x01


class RobloxFileError(ValueError):
    pass


@dataclass
class ScriptEntry:
    class_name: str
    name: str
    path: str
    source: str


class _Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise RobloxFileError("unexpected end of data")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.u32())

    def interleaved_i32(self, count: int) -> List[int]:
        raw = self.take(4 * count)
        out = []
        for i in range(count):
            v = (raw[i] << 24) | (raw[i + count] << 16) | (raw[i + 2 * count] << 8) | raw[i + 3 * count]
            out.append((v >> 1) ^ -(v & 1))
        return out

    def referents(self, count: int) -> List[int]:
        out, acc = [], 0
        for delta in self.interleaved_i32(count):
            acc += delta
            out.append(acc)
        return out


def _decompress(payload: bytes, size: int) -> bytes:
    if payload.startswith(ZSTD_MAGIC):
        try:
            import zstandard  # optional dependency
        except ImportError:
            raise RobloxFileError(
                "file uses ZSTD compression; install support with: pip install zstandard"
            ) from None
        try:
            return zstandard.ZstdDecompressor().decompress(payload, max_output_size=size)
        except zstandard.ZstdError as exc:
            raise RobloxFileError(f"corrupt ZSTD chunk: {exc}") from None
    try:
        return decompress_block(payload, size)
    except LZ4Error as exc:
        raise RobloxFileError(f"corrupt LZ4 chunk: {exc}") from None


def _iter_chunks(data: bytes):
    r = _Reader(data, len(BINARY_MAGIC))
    r.take(2 + 4 + 4 + 8)  # version, class count, instance count, reserved
    while r.pos < len(data):
        name = r.take(4)
        compressed, uncompressed, _reserved = struct.unpack("<III", r.take(12))
        if uncompressed > MAX_CHUNK or compressed > MAX_CHUNK:
            raise RobloxFileError("chunk too large")
        if compressed == 0:
            payload = r.take(uncompressed)
        else:
            payload = _decompress(r.take(compressed), uncompressed)
        if name == b"END\x00":
            return
        yield name, payload


def _build_paths(names: Dict[int, str], parents: Dict[int, int]) -> Dict[int, str]:
    paths: Dict[int, str] = {}

    def path_of(ref: int) -> str:
        if ref in paths:
            return paths[ref]
        chain, seen, cur = [], set(), ref
        while cur in names and cur not in seen:
            seen.add(cur)
            chain.append(names[cur])
            cur = parents.get(cur, -1)
        paths[ref] = ".".join(reversed(chain))
        return paths[ref]

    for ref in names:
        path_of(ref)
    return paths


def read_binary(data: bytes) -> List[ScriptEntry]:
    if not data.startswith(BINARY_MAGIC):
        raise RobloxFileError("not a binary Roblox file")

    classes: Dict[int, Tuple[str, List[int]]] = {}
    ref_class: Dict[int, str] = {}
    props: Dict[int, Dict[str, str]] = {}
    parents: Dict[int, int] = {}

    for name, payload in _iter_chunks(data):
        r = _Reader(payload)
        if name == b"INST":
            class_id = r.u32()
            class_name = r.string().decode("utf-8", "replace")
            r.u8()  # object format (service marker flag)
            count = r.u32()
            refs = r.referents(count)
            classes[class_id] = (class_name, refs)
            for ref in refs:
                ref_class[ref] = class_name
        elif name == b"PROP":
            class_id = r.u32()
            prop = r.string().decode("utf-8", "replace")
            type_id = r.u8()
            if prop not in ("Name", "Source") or type_id != TYPE_STRING or class_id not in classes:
                continue
            class_name, refs = classes[class_id]
            if prop == "Source" and class_name not in SCRIPT_CLASSES:
                continue
            for ref in refs:
                props.setdefault(ref, {})[prop] = r.string().decode("utf-8", "replace")
        elif name == b"PRNT":
            r.u8()
            count = r.u32()
            children = r.referents(count)
            for child, parent in zip(children, r.referents(count)):
                parents[child] = parent

    names = {ref: props.get(ref, {}).get("Name", cls) for ref, cls in ref_class.items()}
    paths = _build_paths(names, parents)
    return [
        ScriptEntry(cls, names[ref], paths[ref], props.get(ref, {}).get("Source", ""))
        for ref, cls in ref_class.items()
        if cls in SCRIPT_CLASSES
    ]


def read_xml(data: bytes) -> List[ScriptEntry]:
    head = data[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in data.lower():
        # Refuse DTDs outright: no entity expansion tricks from untrusted files.
        raise RobloxFileError("XML files with a DTD/entities are not accepted")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise RobloxFileError(f"invalid XML: {exc}") from None

    out: List[ScriptEntry] = []

    def walk(item: ET.Element, parent_path: str) -> None:
        class_name = item.get("class", "")
        name, source = class_name, None
        props = item.find("Properties")
        if props is not None:
            for prop in props:
                key = prop.get("name")
                if key == "Name":
                    name = prop.text or ""
                elif key == "Source":
                    source = prop.text or ""
        path = f"{parent_path}.{name}" if parent_path else name
        if class_name in SCRIPT_CLASSES:
            out.append(ScriptEntry(class_name, name, path, source or ""))
        for child in item.findall("Item"):
            walk(child, path)

    for top in root.findall("Item"):
        walk(top, "")
    return out


def read_roblox_file(data: bytes) -> Optional[List[ScriptEntry]]:
    """Return scripts in a Roblox file, or None if the data is not a Roblox file."""
    if data.startswith(BINARY_MAGIC):
        return read_binary(data)
    stripped = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped.startswith(b"<roblox") or stripped.startswith(b"<?xml"):
        return read_xml(data)
    return None
