"""LZO1X streams as some ALi bootloaders unpack their main code.

The M3801 bootloaders of the vic.wang builds (dump.bin, srt8115.BIN, the
Cabletech URZ0083Q / URZ0194S, the Strong Prima VIII) store the main code
chunk's payload as a 16-byte header -- little-endian compressed size,
uncompressed size, Adler-32 of the compressed bytes and Adler-32 of the
uncompressed bytes -- followed by an LZO1X stream (minilzo's
lzo1x_decompress, which the loader carries in MIPS32 code).

decompress() is a straight port of lzo1x_decompress_safe; compress() writes
a valid LZO1X stream with a simple greedy matcher (the loader only needs a
stream its decoder accepts, not the best ratio).  No third-party package is
used.
"""
from __future__ import annotations

import struct
import zlib


class LzoError(ValueError):
    pass


def decompress(src: bytes, out_len: int | None = None) -> bytes:
    """Decode an LZO1X stream (with its end-of-stream marker)."""
    ip = 0
    n = len(src)
    out = bytearray()

    def need(k):
        if ip + k > n:
            raise LzoError("input overrun")

    def copy_match(dist, length):
        start = len(out) - dist
        if start < 0:
            raise LzoError(f"match distance {dist} before the output start")
        for k in range(length):
            out.append(out[start + k])

    need(1)
    state = "loop"
    t = 0
    if src[0] > 17:
        t = src[0] - 17
        ip = 1
        if t < 4:
            state = "match_next"
        else:
            need(t)
            out += src[ip:ip + t]
            ip += t
            state = "first_literal_run"
    while True:
        if state == "loop":
            need(1)
            t = src[ip]
            ip += 1
            if t >= 16:
                state = "match"
                continue
            if t == 0:
                need(1)
                while src[ip] == 0:
                    t += 255
                    ip += 1
                    need(1)
                t += 15 + src[ip]
                ip += 1
            need(t + 3)
            out += src[ip:ip + t + 3]
            ip += t + 3
            state = "first_literal_run"
        if state == "first_literal_run":
            need(1)
            t = src[ip]
            ip += 1
            if t >= 16:
                state = "match"
            else:
                need(1)
                dist = 1 + 0x0800 + (t >> 2) + (src[ip] << 2)
                ip += 1
                copy_match(dist, 3)
                state = "match_done"
        if state == "match":
            if t >= 64:
                need(1)
                dist = 1 + ((t >> 2) & 7) + (src[ip] << 3)
                ip += 1
                length = (t >> 5) - 1 + 2
                copy_match(dist, length)
            elif t >= 32:
                t &= 31
                if t == 0:
                    need(1)
                    while src[ip] == 0:
                        t += 255
                        ip += 1
                        need(1)
                    t += 31 + src[ip]
                    ip += 1
                need(2)
                dist = 1 + (src[ip] >> 2) + (src[ip + 1] << 6)
                ip += 2
                copy_match(dist, t + 2)
            elif t >= 16:
                dist = (t & 8) << 11
                t &= 7
                if t == 0:
                    need(1)
                    while src[ip] == 0:
                        t += 255
                        ip += 1
                        need(1)
                    t += 7 + src[ip]
                    ip += 1
                need(2)
                dist += (src[ip] >> 2) + (src[ip + 1] << 6)
                ip += 2
                if dist == 0:
                    if ip != n and out_len is None:
                        pass
                    break                       # end of stream
                dist += 0x4000
                copy_match(dist, t + 2)
            else:
                need(1)
                dist = 1 + (t >> 2) + (src[ip] << 2)
                ip += 1
                copy_match(dist, 2)
            state = "match_done"
        if state == "match_done":
            t = src[ip - 2] & 3
            if t == 0:
                state = "loop"
                continue
            state = "match_next"
        if state == "match_next":
            need(t + 1)
            out += src[ip:ip + t]
            ip += t
            t = src[ip]
            ip += 1
            state = "match"
    if out_len is not None and len(out) != out_len:
        raise LzoError(f"decoded {len(out)} bytes, expected {out_len}")
    return bytes(out)


def _literal_run(data: bytes, first: bool) -> bytes:
    """One literal run of len(data) >= 4 bytes (the first instruction may use
    the 17 + n short form, any run the t == 0 extended form)."""
    count = len(data)
    if first and count <= 238:
        return bytes([17 + count]) + data
    if count <= 18:
        return bytes([count - 3]) + data
    rest = count - 3 - 15
    zeros, last = divmod(rest - 1, 255)
    return b"\x00" + b"\x00" * zeros + bytes([last + 1]) + data


def compress(data: bytes) -> bytes:
    """An LZO1X stream of `data` that lzo1x_decompress accepts.

    A greedy matcher (the last position of each 3-byte string) emits M3
    matches (distance up to 0x4000) and M4 matches (up to 0xBFFF), length >= 3.
    The format's rules: a run of 1-3 literals can only follow a match (it goes
    into that match's low offset bits) or open the stream; a longer run is its
    own instruction; the stream ends with the M4 distance-0 marker 11 00 00.
    """
    n = len(data)
    out = bytearray()
    table: dict[bytes, int] = {}
    first = True            # nothing emitted yet
    after_match = False     # the last instruction emitted is a match

    def emit_literals(run: bytes) -> None:
        nonlocal first, after_match
        if not run:
            return
        if len(run) <= 3:
            if after_match:
                out[-2] |= len(run)          # the previous match's trailing literal count
                out.extend(run)
            elif first:
                out.append(17 + len(run))   # a short first run (decoder: match_next)
                out.extend(run)
            else:                           # (cannot happen: literals only start after a match)
                raise AssertionError("a 1-3 byte literal run must follow a match")
        else:
            out.extend(_literal_run(run, first))
        first = False
        after_match = False

    def emit_match(dist: int, length: int) -> None:
        nonlocal first, after_match
        t = length - 2
        if dist <= 0x4000:                   # M3: 001LLLLL, then the 14-bit distance - 1
            d = dist - 1
            if t <= 31:
                out.append(0x20 | t)
            else:
                zeros, last = divmod(t - 31 - 1, 255)
                out.append(0x20)
                out.extend(b"\x00" * zeros)
                out.append(last + 1)
        else:                                # M4: 0001HLLL, then the distance - 0x4000
            d = dist - 0x4000
            hi = 8 if d >= 0x4000 else 0
            d &= 0x3FFF
            if t <= 7:
                out.append(0x10 | hi | t)
            else:
                zeros, last = divmod(t - 7 - 1, 255)
                out.append(0x10 | hi)
                out.extend(b"\x00" * zeros)
                out.append(last + 1)
        out.append((d & 63) << 2)
        out.append(d >> 6)
        first = False
        after_match = True

    i = 0
    lit_start = 0
    while i + 3 <= n:
        key = data[i:i + 3]
        cand = table.get(key)
        table[key] = i
        if cand is None or i - cand > 0xBFFF:
            i += 1
            continue
        length = 3
        limit = n - i
        while length < limit and data[cand + length] == data[i + length]:
            length += 1
        emit_literals(data[lit_start:i])
        emit_match(i - cand, length)
        for k in range(i + 1, min(i + length, n - 2)):
            table[data[k:k + 3]] = k
        i += length
        lit_start = i
    emit_literals(data[lit_start:])
    out.extend(b"\x11\x00\x00")
    return bytes(out)


HEADER = struct.Struct("<IIII")


def adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def pack_payload(application: bytes) -> bytes:
    """The vic.wang bootloaders' main code payload: header + LZO1X stream,
    zero-padded to a multiple of 4 bytes.  The loader copies the payload to
    (0x81E80000 - chunk length) and reads the header with word loads, so an
    unpadded odd length faults there (the stock images pad the same way:
    dump.bin's stream is 0x2FA6F9 bytes in a 0x2FA6FC-byte payload area)."""
    stream = compress(application)
    data = HEADER.pack(len(stream), len(application), adler32(stream), adler32(application)) + stream
    return data + b"\x00" * (-len(data) % 4)


def unpack_payload(payload: bytes) -> bytes:
    csize, usize, a_c, a_u = HEADER.unpack_from(payload, 0)
    stream = payload[16:16 + csize]
    if len(stream) != csize:
        raise LzoError("payload shorter than its compressed size")
    if adler32(stream) != a_c:
        raise LzoError("Adler-32 of the compressed stream does not match")
    out = decompress(stream, usize)
    if adler32(out) != a_u:
        raise LzoError("Adler-32 of the decompressed data does not match")
    return out
