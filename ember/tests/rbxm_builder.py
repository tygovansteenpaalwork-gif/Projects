"""Builds minimal binary .rbxm files for tests."""

import struct

MAGIC = b"<roblox!\x89\xff\r\n\x1a\n"


def _interleave(values):
    encoded = [((v << 1) ^ (v >> 31)) & 0xFFFFFFFF for v in values]
    out = bytearray()
    for shift in (24, 16, 8, 0):
        out += bytes((e >> shift) & 0xFF for e in encoded)
    return bytes(out)


def _referents(refs):
    deltas, prev = [], 0
    for r in refs:
        deltas.append(r - prev)
        prev = r
    return _interleave(deltas)


def _string(text):
    raw = text.encode("utf-8")
    return struct.pack("<I", len(raw)) + raw


def _chunk(name, payload, compress):
    if compress:
        import lz4.block

        packed = lz4.block.compress(payload, store_size=False)
        return name + struct.pack("<III", len(packed), len(payload), 0) + packed
    return name + struct.pack("<III", 0, len(payload), 0) + payload


def build_rbxm(instances, compress=False):
    """instances: list of (class_name, name, parent_index or None, source or None)."""
    by_class = {}
    for ref, (cls, _name, _parent, _src) in enumerate(instances):
        by_class.setdefault(cls, []).append(ref)

    chunks = []
    class_ids = {}
    for class_id, (cls, refs) in enumerate(by_class.items()):
        class_ids[cls] = class_id
        payload = struct.pack("<I", class_id) + _string(cls) + b"\x00" + struct.pack("<I", len(refs)) + _referents(refs)
        chunks.append(_chunk(b"INST", payload, compress))

    for cls, refs in by_class.items():
        names = b"".join(_string(instances[r][1]) for r in refs)
        chunks.append(_chunk(b"PROP", struct.pack("<I", class_ids[cls]) + _string("Name") + b"\x01" + names, compress))
        if cls in ("Script", "LocalScript", "ModuleScript"):
            sources = b"".join(_string(instances[r][3] or "") for r in refs)
            chunks.append(_chunk(b"PROP", struct.pack("<I", class_ids[cls]) + _string("Source") + b"\x01" + sources, compress))

    refs = list(range(len(instances)))
    parents = [-1 if inst[2] is None else inst[2] for inst in instances]
    prnt = b"\x00" + struct.pack("<I", len(refs)) + _referents(refs) + _referents(parents)
    chunks.append(_chunk(b"PRNT", prnt, compress))
    chunks.append(_chunk(b"END\x00", b"</roblox>", False))

    header = MAGIC + struct.pack("<HII", 0, len(by_class), len(instances)) + b"\x00" * 8
    return header + b"".join(chunks)
