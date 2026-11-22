#!/usr/bin/env python3
"""End-to-end AliSimulator verification for CHIP-8 / SUPER-CHIP 1.1 / XO-CHIP ('chip8')."""
from __future__ import annotations

import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))

import fat_image  # noqa: E402
import run_dump_maciej_demo_v4 as v4  # noqa: E402
from usb_host import VirtualKeyboard, VirtualStick  # noqa: E402


def parse_perf(out: str):
    m = re.search(r"a frame took (\d+) us to run and (\d+) us to draw .*?; picture CRC-32 ([0-9a-f]{8})", out)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), m.group(3)


def unique_pic_colors(sim, w: int, h: int) -> int:
    pic_phys = 0x03D80000
    raw = bytes(sim.ram_buffer[pic_phys : pic_phys + w * h * 2])
    seen = set()
    for i in range(0, len(raw), 2):
        seen.add(raw[i] | (raw[i + 1] << 8))
    return len(seen)


def make_rpl_sav_rom() -> bytes:
    """Tiny XO-CHIP program that selects planes 1+2 (F301), draws 2-color sprite, and saves V0=0x42 to RPL (F075)."""
    return bytes([
        0xF3, 0x01,             # plane 3 (planes 1 & 2)
        0x60, 0x42,             # V0 = 0x42
        0xF0, 0x75,             # save V0 to RPL (.sav)
        0xA2, 0x10,             # I = 0x210
        0x61, 0x08,             # V1 = 8
        0x62, 0x08,             # V2 = 8
        0xD1, 0x22,             # draw 2-row 2-plane sprite -> 4 distinct colors (0, 1, 2, 3)!
        0x12, 0x0E,             # loop forever at 0x20E
        0xF0, 0x0F,             # plane 1 bytes
        0xFF, 0x00,             # plane 2 bytes
    ])


def main() -> int:
    engine = os.environ.get("ALISIM_ENGINE", "cpp")
    img = v4.BIN / f"{v4.STEM}.bin"
    print(f"Booting {img} on AliSimulator (engine={engine})...", flush=True)
    box = v4.Box(img, engine)
    boot = box.boot().decode("latin-1")
    v4.check("Version: v4" in boot, "v4 firmware booted via original bootloader")

    help_out = box.command("help")
    v4.check("\r\n  chip8 " in help_out, "help lists 'chip8'")

    sg = ROOT / "build/sample_games/chip8"
    files = {
        "CHIP8/LOGO.CH8":   (sg / "1-chip8-logo.ch8").read_bytes(),
        "CHIP8/CORAX.CH8":  (sg / "3-corax+.ch8").read_bytes(),
        "CHIP8/FLAGS.CH8":  (sg / "4-flags.ch8").read_bytes(),
        "CHIP8/DVN8.SC8":   (sg / "DVN8.sc8").read_bytes(),
        "CHIP8/PARTY.XO8":  (sg / "OctoPartyMix.xo8").read_bytes(),
        "CHIP8/RPLSAV.XO8": make_rpl_sav_rom(),
    }
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="CHIP8"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    for path, frames, min_cols, desc in (
        ("2:/CHIP8/LOGO.CH8",   25, 2, "Timendus 1-chip8-logo"),
        ("2:/CHIP8/CORAX.CH8",  40, 2, "Timendus 3-corax+ opcode suite"),
        ("2:/CHIP8/FLAGS.CH8",  50, 2, "Timendus 4-flags VF suite"),
        ("2:/CHIP8/DVN8.SC8",   30, 2, "DVN8 SUPER-CHIP 128x64"),
        ("2:/CHIP8/PARTY.XO8",  25, 3, "OctoPartyMix XO-CHIP multi-plane"),
        ("2:/CHIP8/RPLSAV.XO8",  5, 4, "XO-CHIP 4-color planes + RPL FX75 save"),
    ):
        out = box.command(f"chip8 -f {frames} {path}", timeout=90)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, 128, 64)
        v4.check(p is not None and cols >= min_cols and p[0] < 16667,
                 f"chip8 {desc}: colors={cols}, perf={p}")

    ls_out = box.command("ls 2:/CHIP8")
    v4.check("RPLSAV.XO8.sav" in ls_out, "FX75 RPL flags persisted to RPLSAV.XO8.sav")

    # Explorer .ch8/.sc8/.xo8 auto-launch
    box.t.pending.clear()
    box.t.write(b"explorer 2:/CHIP8\r")
    box.t.wait_for(b"brings the console back", 15)
    box.run(0.6)
    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}\r") + 1.5)
    uart_exp = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)
    box.run(kbd.type("{ESC}") + 0.8)
    v4.check("CHIP-8" in uart_exp or "SUPER-CHIP" in uart_exp or "XO-CHIP" in uart_exp,
             f"explorer auto-launches CHIP-8 program ({uart_exp.strip()[:80]!r})")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL CHIP-8 / SUPER-CHIP / XO-CHIP CHECKS PASSED!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
