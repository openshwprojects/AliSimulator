#!/usr/bin/env python3
"""Pack a Sega System 16A / System 16B / OutRun MAME .zip romset or raw binary
sections into a single-file .s16 cartridge image for firmware/maciej_app/demo/s16.c.

Note: demo/s16.c also loads unencrypted MAME System 16A / 16B .zip romsets directly
in RAM; this tool produces fast single-file .s16 cartridges and handles custom or
homebrew 68000+Z80 System 16 builds.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import struct
import zipfile


def make_s16_header(
    *,
    board: str = "S16B",
    p_size: int = 0,
    c_size: int = 0,
    z_size: int = 0,
    pcm_size: int = 0,
    tile_size: int = 0,
    spr_size: int = 0,
    use_ym2151: bool = True,
    use_upd7759: bool = False,
    use_segapcm: bool = False,
    pre_tiles_4bpp: bool = False,
    use_road: bool = False,
    dip1: int = 0xFF,
    dip2: int = 0xFF,
    hw_cfg: int = 0,
    z80_mhz: int = 5,
    title: str = "",
) -> bytes:
    magic = board.encode("ascii")[:4].ljust(4, b"B")
    if magic not in (b"S16A", b"S16B", b"S16R"):
        raise ValueError(f"Unsupported board type: {board!r}")
    flags = 0
    if use_ym2151:
        flags |= 1
    if use_upd7759:
        flags |= 2
    if use_segapcm:
        flags |= 4
    if pre_tiles_4bpp:
        flags |= 8
    if use_road or magic == b"S16R":
        flags |= 16
    if c_size > 0:
        flags |= 32

    hdr = bytearray(256)
    hdr[0:4] = magic
    struct.pack_into("<7I", hdr, 0x04, flags, p_size, c_size, z_size, pcm_size, tile_size, spr_size)
    hdr[0x20] = dip1 & 0xFF
    hdr[0x21] = dip2 & 0xFF
    hdr[0x22] = hw_cfg & 0xFF
    hdr[0x23] = z80_mhz & 0xFF
    tbytes = title.encode("ascii", errors="replace")[:63].ljust(64, b"\x00")
    hdr[0x40:0x80] = tbytes
    return bytes(hdr)


def build_s16_image(
    *,
    board: str = "S16B",
    prog_rom: bytes,
    code_rom: bytes = b"",
    z80_rom: bytes = b"",
    pcm_rom: bytes = b"",
    tile_rom: bytes = b"",
    spr_rom: bytes = b"",
    use_ym2151: bool = True,
    use_upd7759: bool = False,
    use_segapcm: bool = False,
    pre_tiles_4bpp: bool = False,
    use_road: bool = False,
    dip1: int = 0xFF,
    dip2: int = 0xFF,
    hw_cfg: int = 0,
    z80_mhz: int = 5,
    title: str = "",
) -> bytes:
    if len(prog_rom) & 1:
        prog_rom += b"\x00"
    if len(code_rom) & 1:
        code_rom += b"\x00"
    if len(spr_rom) & 1:
        spr_rom += b"\x00"
    hdr = make_s16_header(
        board=board,
        p_size=len(prog_rom),
        c_size=len(code_rom),
        z_size=len(z80_rom),
        pcm_size=len(pcm_rom),
        tile_size=len(tile_rom),
        spr_size=len(spr_rom),
        use_ym2151=use_ym2151,
        use_upd7759=use_upd7759,
        use_segapcm=use_segapcm,
        pre_tiles_4bpp=pre_tiles_4bpp,
        use_road=use_road,
        dip1=dip1,
        dip2=dip2,
        hw_cfg=hw_cfg,
        z80_mhz=z80_mhz,
        title=title,
    )
    return hdr + prog_rom + code_rom + z80_rom + pcm_rom + tile_rom + spr_rom


def interleave_16bit_pair(even_rom: bytes, odd_rom: bytes) -> bytes:
    n = max(len(even_rom), len(odd_rom))
    out = bytearray(n * 2)
    out[0::2] = even_rom.ljust(n, b"\xff")
    out[1::2] = odd_rom.ljust(n, b"\xff")
    return bytes(out)


# Known MAME System 16A / 16B parent & unencrypted bootleg layouts
MAME_LAYOUTS: dict[str, dict] = {
    "shinobi": {
        "board": "S16A", "title": "Shinobi (System 16A)", "hw_cfg": 1, "upd7759": True,
        "cpu": [("epr-11287.a7", "epr-11286.a5"), ("opr-11291.a8", "opr-11290.a6")],
        "z80": ["epr-11288.b10"],
        "pcm": ["epr-11289.b11"],
        "tiles": ["opr-11226.a17", "opr-11225.a16", "opr-11224.a14"],
        "sprites": [("opr-11295.a11", "opr-11299.b15"), ("opr-11294.a10", "opr-11298.b14")],
    },
    "altbeast": {
        "board": "S16B", "title": "Altered Beast (System 16B)", "hw_cfg": 3, "upd7759": True,
        "cpu": [("epr-11678.a6", "epr-11677.a5"), ("opr-11680.a8", "opr-11679.a7")],
        "z80": ["epr-11681.b1"],
        "pcm": ["opr-11682.b4", "opr-11683.b5"],
        "tiles": [("opr-11669.a1", "opr-11668.a2"), ("opr-11671.a3", "opr-11670.a4"), ("opr-11673.a5", "opr-11672.a6")],
        "sprites": [("mpr-11674.b1", "mpr-11675.b3"), ("mpr-11676.b2", "mpr-11684.b4")],
    },
    "goldnaxe": {
        "board": "S16B", "title": "Golden Axe (System 16B)", "hw_cfg": 2, "upd7759": True,
        "cpu": [("epr-12545.a6", "epr-12544.a5"), ("mpr-12379.a8", "mpr-12378.a7")],
        "z80": ["epr-12390.b1"],
        "pcm": ["opr-12385.b4", "opr-12386.b5", "opr-12387.b6"],
        "tiles": [("mpr-12372.a1", "mpr-12373.a2"), ("mpr-12374.a3", "mpr-12375.a4"), ("mpr-12376.a5", "mpr-12377.a6")],
        "sprites": [("mpr-12380.b1", "mpr-12381.b2"), ("mpr-12382.b3", "mpr-12383.b4")],
    },
}


def pack_mame_zip(zip_path: Path, out_path: Path, title: str = "") -> None:
    stem = zip_path.stem.lower()
    with zipfile.ZipFile(zip_path, "r") as zf:
        files = {Path(i.filename).name.lower(): zf.read(i) for i in zf.infolist() if not i.is_dir()}

    if stem in MAME_LAYOUTS:
        spec = MAME_LAYOUTS[stem]
        prog = b"".join(interleave_16bit_pair(files[e], files[o]) for e, o in spec["cpu"] if e in files and o in files)
        z80 = b"".join(files[n] for n in spec["z80"] if n in files)
        pcm = b"".join(files[n] for n in spec["pcm"] if n in files)
        t_parts = []
        for item in spec["tiles"]:
            if isinstance(item, tuple):
                t_parts.append(interleave_16bit_pair(files[item[0]], files[item[1]]))
            elif item in files:
                t_parts.append(files[item])
        tiles = b"".join(t_parts)
        spr = b"".join(interleave_16bit_pair(files[e], files[o]) for e, o in spec["sprites"] if e in files and o in files)
        img = build_s16_image(
            board=spec["board"],
            prog_rom=prog,
            z80_rom=z80,
            pcm_rom=pcm,
            tile_rom=tiles,
            spr_rom=spr,
            use_upd7759=spec.get("upd7759", False),
            hw_cfg=spec.get("hw_cfg", 0),
            title=title or spec["title"],
        )
        out_path.write_bytes(img)
        return

    raise SystemExit(f"Unknown MAME zip set {stem!r}; pass explicit --prog/--tiles/--sprites sections.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Pack Sega System 16 (.s16) arcade cartridge")
    ap.add_argument("input", nargs="?", type=Path, help="Input MAME .zip romset")
    ap.add_argument("-o", "--output", type=Path, required=True, help="Output .s16 file")
    ap.add_argument("--board", default="S16B", choices=("S16A", "S16B", "S16R"))
    ap.add_argument("--title", default="")
    ap.add_argument("--prog", type=Path)
    ap.add_argument("--z80", type=Path)
    ap.add_argument("--pcm", type=Path)
    ap.add_argument("--tiles", type=Path)
    ap.add_argument("--sprites", type=Path)
    args = ap.parse_args()

    if args.input and args.input.suffix.lower() == ".zip":
        pack_mame_zip(args.input, args.output, args.title)
    elif args.prog:
        img = build_s16_image(
            board=args.board,
            prog_rom=args.prog.read_bytes(),
            z80_rom=args.z80.read_bytes() if args.z80 else b"",
            pcm_rom=args.pcm.read_bytes() if args.pcm else b"",
            tile_rom=args.tiles.read_bytes() if args.tiles else b"",
            spr_rom=args.sprites.read_bytes() if args.sprites else b"",
            use_upd7759=bool(args.pcm),
            use_segapcm=bool(args.pcm),
            title=args.title or args.output.stem,
        )
        args.output.write_bytes(img)
    else:
        ap.error("Provide either a MAME .zip or --prog <68k.bin>")


if __name__ == "__main__":
    main()
