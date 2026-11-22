#!/usr/bin/env python3
"""End-to-end AliSimulator verification for the 4 new v4 machine cores:
  1. ZX Spectrum 128K + Pentagon BetaDisk 128 (.z80 128K, .trd, .scl, .tap)
  2. MSX2 (Yamaha V9938 SCREEN 0..8, Blitter, YM2413, .mx2 & .dsk, C-BIOS & Built-in BIOS)
  3. Atari 520ST / 1040STFM (.st, .msa, $601A .prg, free GPLv2 EmuTOS 256K & Built-in TOS)
  4. Sega System 16A / 16B / OutRun-Road Arcade (.s16 & MAME .zip)
  5. TV File Explorer ('explorer') auto-detection & C64 vs Atari ST .prg disambiguation
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))

import fat_image                                                     # noqa: E402
import run_dump_maciej_demo_v4 as v4                                 # noqa: E402
from usb_host import VirtualKeyboard, VirtualStick                   # noqa: E402

GAMES = ROOT / "build/sample_games"


def unique_fb_colors(sim, x0=160, y0=60, x1=1120, y1=660, step=8):
    seen = set()
    for y in range(y0, y1, step):
        for x in range(x0, x1, step):
            seen.add(v4.fb_pixel(sim, x, y))
    return len(seen)


def unique_pic_colors(sim, w, h):
    raw = bytes(sim._ram_view[0x03D80000 : 0x03D80000 + w * h * 2])
    words = struct.unpack_from(f"<{w * h}H", raw)
    return len(set(words))


def parse_play_stats(out: str):
    m = re.search(
        r"(\d+) frames in [\d.]+ s; a frame took (\d+) us to run and (\d+) us to draw .*?picture CRC-32 ([0-9a-f]{8})",
        out,
    )
    if not m:
        return None
    return {
        "frames": int(m.group(1)),
        "run_us": int(m.group(2)),
        "draw_us": int(m.group(3)),
        "crc": m.group(4),
    }


def run(args):
    started = time.monotonic()
    image_path = v4.BIN / f"{v4.STEM}.bin"
    box = v4.Box(image_path, args.engine)
    boot = box.boot().decode("latin-1")
    v4.check("Version: v4" in boot, "v4 firmware boots via original bootloader")

    # Stick 1 (disk 2): games + open-source BIOSes (BSD C-BIOS MSX2 & GPLv2 EmuTOS 256K)
    files_bios = {
        # ZX Spectrum 128K + BetaDisk TR-DOS
        "ZX/SNAKE128.Z80": (GAMES / "zx/Speccy_Snake.z80").read_bytes(),
        "ZX/ABABOLDX.TRD": (GAMES / "zx/Sir_Ababol_DX_TRDOS.trd").read_bytes(),
        "ZX/PILOTATK.SCL": (GAMES / "zx/Pilot_Attack_TRDOS.scl").read_bytes(),
        "ZX/CHERIL.TAP":   (GAMES / "zx/Cheril_the_Goddess.tap").read_bytes(),
        # MSX2 with BSD C-BIOS MSX2
        "MSX2/cbios_main_msx2.rom": (GAMES / "msx2/cbios_main_msx2.rom").read_bytes(),
        "MSX2/cbios_sub.rom":       (GAMES / "msx2/cbios_sub.rom").read_bytes(),
        "MSX2/BATTLOT.DSK":         (GAMES / "msx2/Battlot_MSX2.dsk").read_bytes(),
        "MSX2/GALBLIT.MX2":         (GAMES / "msx2/Galactic_Blit_S8.mx2").read_bytes(),
        # Atari ST with free GPLv2 EmuTOS 1.4 256K
        "ATARIST/etos256uk.img":    (GAMES / "atarist/etos256uk.img").read_bytes(),
        "ATARIST/FROG.ST":          (GAMES / "atarist/Frank_the_Frog.st").read_bytes(),
        "ATARIST/DOTCHASE.MSA":     (GAMES / "atarist/Dot_Chase.msa").read_bytes(),
        # Sega System 16A / 16B / OutRun-Road Arcade
        "SYS16/OUTRUN.S16":         (GAMES / "sys16/OutRun_Horizon_S16R.s16").read_bytes(),
        "SYS16/OUTRUN.ZIP":         (GAMES / "sys16/outrun_hrz.zip").read_bytes(),
        "SYS16/SHINOBI.S16":        (GAMES / "sys16/Shinobi_Shadow_S16A.s16").read_bytes(),
        "SYS16/GOLDEN.S16":         (GAMES / "sys16/Golden_Blade_S16B.s16").read_bytes(),
    }
    # Stick 2 (disk 3): BIOS-free stick to verify clean-room built-in MSX2 BIOS & built-in Atari ST TOS
    files_nobios = {
        "MSX2/CAVIT.DSK":    (GAMES / "msx2/Cavit_MSX2.dsk").read_bytes(),
        "MSX2/PRISM.MX2":    (GAMES / "msx2/Prism_Breaker_S8.mx2").read_bytes(),
        "ATARIST/JUMP.PRG":  (GAMES / "atarist/Jump_Quest.prg").read_bytes(),
    }
    stick_bios   = VirtualStick(fat_image.build(files_bios, fat=16, size_mb=16, label="NEWCORES"), writable=True)
    stick_nobios = VirtualStick(fat_image.build(files_nobios, fat=16, size_mb=16, label="BUILTIN"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick_bios, "high")
    hub.plug(2, stick_nobios, "high")
    hub.plug(3, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(8.0)
    v4.check("disk 2:" in out_usb and "disk 3:" in out_usb,
             f"both USB sticks enumerated behind hub ({'disk 2:' in out_usb}, {'disk 3:' in out_usb})")

    # ---- 1. ZX Spectrum 128K + BetaDisk TR-DOS ---------------------------------
    for path, frames, min_cols, desc in (
        ("2:/ZX/SNAKE128.Z80", 25, 5, "ZX 128K .z80 v3 snapshot (Speccy Snake)"),
        ("2:/ZX/ABABOLDX.TRD", 50, 5, "ZX BetaDisk 128 .trd floppy (Sir Ababol DX)"),
        ("2:/ZX/PILOTATK.SCL", 50, 5, "ZX BetaDisk 128 .scl floppy (Pilot Attack)"),
        ("2:/ZX/CHERIL.TAP",   40, 5, "ZX fast-loaded .tap tape (Cheril the Goddess)"),
    ):
        out1 = box.command(f"zx -f {frames} {path}", timeout=120)
        st1 = parse_play_stats(out1)
        pcols = unique_pic_colors(box.sim, 320, 240)
        v4.check(
            st1 is not None and st1["frames"] == frames and pcols >= min_cols and st1["run_us"] < 20000,
            f"{desc}: {pcols} colors, {st1['run_us'] if st1 else -1} us/frame (< 20000 us 50 Hz budget), "
            f"CRC-32 {st1['crc'] if st1 else 'none'}",
        )
    # Deterministic replay check on .trd
    st_det = parse_play_stats(box.command("zx -f 30 2:/ZX/ABABOLDX.TRD", timeout=120))
    st_ref = parse_play_stats(box.command("zx -f 30 2:/ZX/ABABOLDX.TRD", timeout=120))
    v4.check(st_det is not None and st_ref is not None and st_det["crc"] == st_ref["crc"],
             f"ZX BetaDisk .trd execution is deterministic (CRC-32 {st_det['crc'] if st_det else '?'})")

    # ---- 2. MSX2 (V9938 + Blitter + YM2413 + C-BIOS & Built-in BIOS) ------------
    for path, frames, w, h, min_cols, want_sub, desc in (
        ("2:/MSX2/BATTLOT.DSK", 210, 256, 192, 5, "ROM: 2:/msx2/cbios_main_msx2.rom", "MSX2 .dsk with C-BIOS (Battlot)"),
        ("2:/MSX2/GALBLIT.MX2", 200, 256, 212, 5, "ROM: 2:/msx2/cbios_main_msx2.rom", "MSX2 SCREEN 8 + Blitter .mx2 with C-BIOS"),
        ("3:/MSX2/CAVIT.DSK",    60, 256, 192, 5, "built-in BIOS",                    "MSX2 .dsk with built-in BIOS (Cavit)"),
        ("3:/MSX2/PRISM.MX2",    30, 256, 212, 6, "built-in BIOS",                    "MSX2 SCREEN 8 + Blitter .mx2 with built-in BIOS"),
    ):
        out = box.command(f"msx2 -f {frames} {path}", timeout=180)
        st = parse_play_stats(out)
        pcols = unique_pic_colors(box.sim, w, h)
        v4.check(
            st is not None and want_sub.lower() in out.lower() and pcols >= min_cols and st["run_us"] < 16688,
            f"{desc}: {w}x{h}, {pcols} colors, {st['run_us'] if st else -1} us/frame (< 16688 us 60 Hz budget), "
            f"CRC-32 {st['crc'] if st else 'none'}",
        )

    # ---- 3. Atari 520ST / 1040STFM (EmuTOS 256K + Built-in TOS) -----------------
    # Note: Space (-k 85:02,92:00) dismisses EmuTOS 1.4's welcome screen immediately so AUTO/ boots right away
    for cmd, frames, min_cols, want_sub, desc in (
        ("atarist -f 220 -k 85:02,92:00 2:/ATARIST/FROG.ST",      220, 4, "etos256uk.img", "Atari ST .st floppy with EmuTOS 256K (Frank the Frog)"),
        ("atarist -f 220 -k 85:02,92:00 2:/ATARIST/DOTCHASE.MSA", 220, 8, "etos256uk.img", "Atari ST RLE .msa floppy with EmuTOS 256K (Dot Chase)"),
        ("atarist -f 60 3:/ATARIST/JUMP.PRG",                      60, 8, "built-in ROM",  "Atari ST GEMDOS .prg with built-in TOS (Jump Quest)"),
        ("atarist -f 40",                                          40, 2, "Desktop",       "Atari ST bare desktop boot ('atarist' with no file)"),
    ):
        out = box.command(cmd, timeout=240)
        st = parse_play_stats(out)
        pcols = unique_pic_colors(box.sim, 320, 200)
        v4.check(
            st is not None and st["frames"] == frames and want_sub.lower() in out.lower()
            and pcols >= min_cols and st["run_us"] < 19979,
            f"{desc}: {pcols} colors, {st['run_us'] if st else -1} us/frame (< 19979 us 50 Hz PAL budget), "
            f"CRC-32 {st['crc'] if st else 'none'}",
        )

    # ---- 4. Sega System 16A / 16B / OutRun-Road Arcade --------------------------
    crc_s16 = {}
    for key, path, min_cols, desc in (
        ("outrun_s16", "2:/SYS16/OUTRUN.S16",   8, "Sega OutRun/S16R .s16 (road + zoomed sprites + YM2151/PCM)"),
        ("outrun_zip", "2:/SYS16/OUTRUN.ZIP",   8, "Sega OutRun/S16R MAME .zip romset"),
        ("shinobi",    "2:/SYS16/SHINOBI.S16", 10, "Sega System 16A .s16 (Shinobi Shadow)"),
        ("golden",     "2:/SYS16/GOLDEN.S16",  10, "Sega System 16B .s16 (315-5195 mapper + shadow/highlight)"),
    ):
        out = box.command(f"sys16 -f 45 -k 10:08,20:00,30:01 {path}", timeout=180)
        st = parse_play_stats(out)
        pcols = unique_pic_colors(box.sim, 320, 224)
        crc_s16[key] = st["crc"] if st else None
        v4.check(
            st is not None and pcols >= min_cols and st["run_us"] < 16667,
            f"{desc}: {pcols} colors, {st['run_us'] if st else -1} us/frame (< 16667 us 60 Hz budget), "
            f"CRC-32 {st['crc'] if st else 'none'}",
        )
    v4.check(
        crc_s16["outrun_s16"] is not None and crc_s16["outrun_s16"] == crc_s16["outrun_zip"],
        f"sys16: .s16 and .zip produce identical picture CRC-32 ({crc_s16['outrun_s16']})",
    )

    # Live TV OSD pixel check on OutRun_Horizon_S16R.s16 (scaled 3x -> 960 x 672 on 1280 x 720 TV)
    out_live = box.keys(b"sys16 2:/SYS16/OUTRUN.S16\r", until=b"Esc ends", timeout=30)
    box.run(1.0)
    tv_cols = unique_fb_colors(box.sim)
    box.keys(b"\x03", timeout=10)
    v4.check("OutRun Horizon" in out_live and tv_cols >= 8,
             f"sys16 live TV OSD output shows multi-color arcade frame ({tv_cols} sampled TV colors)")

    # ---- 5. Explorer auto-dispatch (incl. $601A Atari ST .prg vs C64 .prg) ------
    box.t.pending.clear()
    box.t.write(b"explorer 3:/ATARIST\r")
    box.t.wait_for(b"brings the console back", 15)
    box.run(0.6)
    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}\r") + 2.0)   # Select JUMP.PRG and press Enter -> must launch Atari ST, not C64!
    uart_exp = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)      # Exit Atari ST back to explorer
    box.run(kbd.type("{ESC}") + 0.8)      # Exit explorer back to console
    v4.check(
        "Atari" in uart_exp and "kernal.rom" not in uart_exp,
        f"explorer disambiguates $601A .prg as Atari ST instead of C64 ({uart_exp.strip()[:80]!r})",
    )

    elapsed = round(time.monotonic() - started, 1)
    print(f"Completed in {elapsed} s", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("cpp", "unicorn"), default=os.environ.get("ALISIM_ENGINE", "cpp"))
    args = parser.parse_args()
    print("=== Testing New v4 Machine Cores (ZX 128K/TR-DOS, MSX2, Atari ST, Sega System 16) ===", flush=True)
    run(args)
    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} check(s) failed:")
        for f in v4.failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\n[PASS] ALL NEW MACHINE CORE CHECKS PASSED!")


if __name__ == "__main__":
    main()
