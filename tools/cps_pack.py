#!/usr/bin/env python3
"""Pack a Capcom CPS-1 / CPS-1.5 / CPS-2 MAME .zip romset or raw ROM files into a
single-file .cps cartridge image understood by firmware/maciej_app/demo/cps.c.

Note: demo/cps.c also loads MAME CPS-1 and CPS-2 .zip romsets directly in RAM
without packing; this tool produces pre-interleaved single-file .cps images for
faster loading or custom homebrew builds.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import struct
import zipfile


def make_cps_header(
    *,
    cps_ver: int = 2,
    use_qsound: bool = True,
    p_size: int = 0,
    z_size: int = 0,
    snd_size: int = 0,
    gfx_size: int = 0,
    cpsb_id: int = 13,
    gfx_mapper: int = 0xFF,
    dip: tuple[int, int, int] = (0, 0, 0),
    scroll_off: tuple[int, int, int] = (0, 0, 0),
    cps2_key: tuple[int, int, int] | None = None,
    kabuki: tuple[int, int, int, int] | None = None,
    pre_unpacked_gfx: bool = False,
    m68k_16mhz: bool = False,
    title: str = "",
) -> bytes:
    magic = b"CPS2" if cps_ver == 2 else b"CPS1"
    flags = 0
    if use_qsound or cps_ver == 2:
        flags |= 1
    if cps2_key is not None:
        flags |= 2
    if kabuki is not None:
        flags |= 4
    if pre_unpacked_gfx:
        flags |= 8
    if m68k_16mhz or cps_ver == 2:
        flags |= 16

    k0, k1, k_up = cps2_key if cps2_key is not None else (0, 0, 0)
    ksw1, ksw2, kaddr, kxor = kabuki if kabuki is not None else (0, 0, 0, 0)
    kab_ax = ((kaddr & 0xFFFF) << 8) | (kxor & 0xFF)
    tbytes = title.encode("ascii", errors="replace")[:59].ljust(60, b"\x00")

    hdr = bytearray(256)
    hdr[0:4] = magic
    struct.pack_into("<5I", hdr, 0x04, flags, p_size, z_size, snd_size, gfx_size)
    hdr[0x18] = cpsb_id & 0xFF
    hdr[0x19] = gfx_mapper & 0xFF
    hdr[0x1A] = dip[0] & 0xFF
    hdr[0x1B] = dip[1] & 0xFF
    hdr[0x1C] = dip[2] & 0xFF
    struct.pack_into("<3I", hdr, 0x20, *scroll_off)
    struct.pack_into("<3I", hdr, 0x2C, k0, k1, k_up)
    struct.pack_into("<3I", hdr, 0x38, ksw1, ksw2, kab_ax)
    hdr[0x44:0x80] = tbytes
    return bytes(hdr)


def parse_cps2_key20(key20: bytes) -> tuple[int, int, int]:
    dec = [0] * 10
    for b in range(160):
        bit = (317 - b) % 160
        if (key20[bit // 8] >> ((bit ^ 7) % 8)) & 1:
            dec[b // 16] |= 0x8000 >> (b % 16)
    k0 = (dec[0] << 16) | dec[1]
    k1 = (dec[2] << 16) | dec[3]
    upper = 0x1000000 if dec[9] == 0xFFFF else ((((~dec[9] & 0x3FF) << 14) | 0x3FFF) + 1)
    return k0, k1, upper


def pack_cps2_zip(zip_path: Path, out_path: Path, title: str = "") -> None:
    with zipfile.ZipFile(zip_path, "r") as zf:
        by_num: dict[int, bytes] = {}
        key_bytes: bytes | None = None
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = Path(info.filename).name
            low = name.lower()
            if info.file_size == 20 and (low.endswith(".key") or low == "dl-1425.bin"):
                key_bytes = zf.read(info)
                continue
            if "." in low:
                ext = low.rsplit(".", 1)[1]
                if len(ext) >= 2 and ext[:2].isdigit() and "x" not in ext[2:]:
                    by_num[int(ext[:2])] = zf.read(info)

    p_rom = b"".join(by_num[n] for n in range(3, 11) if n in by_num)
    z_rom = b"".join(by_num[n] for n in range(1, 3) if n in by_num)
    s_chunks = []
    for n in (11, 12):
        if n in by_num:
            raw = bytearray(by_num[n])
            for i in range(0, len(raw) - 1, 2):
                raw[i], raw[i + 1] = raw[i + 1], raw[i]
            s_chunks.append(bytes(raw))
    snd_rom = b"".join(s_chunks)

    # Interleave CPS-2 graphics groups (13,15,14,16 and 17,19,18,20) into standard 4bpp planar C-ROM
    gfx_parts = []
    for grp in range(13, 30, 4):
        if grp not in by_num:
            break
        order = (grp, grp + 2, grp + 1, grp + 3)
        max_sz = max(len(by_num.get(r, b"")) for r in order)
        buf = bytearray(b"\xff" * (max_sz * 4))
        for k, r in enumerate(order):
            chip = by_num.get(r)
            if not chip:
                continue
            base_off = 4 if k >= 2 else 0
            plane_off = 2 if (k & 1) else 0
            blocks = len(chip) >> 19
            if blocks == 0:
                for pass_idx in range(2):
                    dst_base = pass_idx * (len(chip) * 2) + base_off + plane_off
                    for i in range(0, len(chip), 4):
                        si = i + pass_idx * 2
                        di = dst_base + (i // 4) * 8
                        if si + 1 < len(chip) and di + 1 < len(buf):
                            buf[di] = chip[si]
                            buf[di + 1] = chip[si + 1]
            else:
                for b in range(blocks):
                    sec = chip[b * 0x80000 : (b + 1) * 0x80000]
                    for pass_idx in range(2):
                        dst_base = (b * 2 + pass_idx) * 0x100000 + base_off + plane_off
                        for i in range(0, 0x80000, 4):
                            si = i + pass_idx * 2
                            di = dst_base + (i // 4) * 8
                            buf[di] = sec[si]
                            buf[di + 1] = sec[si + 1]
        gfx_parts.append(bytes(buf))
    gfx_rom = b"".join(gfx_parts)

    cps2_key = parse_cps2_key20(key_bytes) if key_bytes else None
    hdr = make_cps_header(
        cps_ver=2,
        use_qsound=True,
        p_size=len(p_rom),
        z_size=len(z_rom),
        snd_size=len(snd_rom),
        gfx_size=len(gfx_rom),
        cps2_key=cps2_key,
        title=title or zip_path.stem,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(hdr + p_rom + z_rom + snd_rom + gfx_rom)
    print(f"Packed {out_path} ({out_path.stat().st_size} bytes)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path, help="MAME CPS-2 .zip romset")
    ap.add_argument("-o", "--output", type=Path, required=True, help="Output .cps path")
    ap.add_argument("--title", default="", help="Optional game title")
    args = ap.parse_args()
    pack_cps2_zip(args.input, args.output, args.title)


if __name__ == "__main__":
    main()
