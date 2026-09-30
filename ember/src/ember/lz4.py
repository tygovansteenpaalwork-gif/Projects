"""Pure-Python LZ4 block decompression (the format Roblox uses for binary chunks)."""

from __future__ import annotations


class LZ4Error(ValueError):
    pass


def decompress_block(src: bytes, uncompressed_size: int) -> bytes:
    dst = bytearray()
    i = 0
    n = len(src)
    try:
        while i < n:
            token = src[i]
            i += 1

            literal_len = token >> 4
            if literal_len == 15:
                while True:
                    extra = src[i]
                    i += 1
                    literal_len += extra
                    if extra != 255:
                        break
            if i + literal_len > n:
                raise LZ4Error("literal run past end of input")
            dst += src[i : i + literal_len]
            i += literal_len
            if i >= n:
                break  # last sequence has literals only

            offset = src[i] | (src[i + 1] << 8)
            i += 2
            if offset == 0 or offset > len(dst):
                raise LZ4Error("invalid match offset")

            match_len = token & 0x0F
            if match_len == 15:
                while True:
                    extra = src[i]
                    i += 1
                    match_len += extra
                    if extra != 255:
                        break
            match_len += 4

            start = len(dst) - offset
            if match_len <= offset:
                dst += dst[start : start + match_len]
            else:
                # Overlapping copy: repeat the window byte by byte.
                for k in range(match_len):
                    dst.append(dst[start + k])
            if len(dst) > uncompressed_size:
                raise LZ4Error("output larger than declared size")
    except IndexError:
        raise LZ4Error("truncated LZ4 block") from None

    if len(dst) != uncompressed_size:
        raise LZ4Error(f"expected {uncompressed_size} bytes, got {len(dst)}")
    return bytes(dst)
