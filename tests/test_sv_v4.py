#!/usr/bin/env python3
"""End-to-end AliSimulator verification for Watara Supervision ('sv')."""
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


def make_64k_banked_sv() -> bytes:
    """64 KB Supervision ROM that switches $2026 to bank 1 ($4000..$7FFF at $8000) and DMAs 4-shade pattern to VRAM."""
    rom = bytearray(0x10000)
    # Bank 1 ($4000..$7FFF): 256-byte 4-shade pattern at $8000 (file offset $4000)
    for i in range(256):
        rom[0x4000 + i] = ((i & 3) | (((i + 1) & 3) << 2) | (((i + 2) & 3) << 4) | (((i + 3) & 3) << 6)) & 0xFF
    # Fixed top bank ($C000..$FFFF, file offset $C000): reset code at $C000
    code = bytes([
        0x78,                   # SEI
        0xA9, 0xA0, 0x8D, 0x00, 0x20,  # LDA #$A0 (160); STA $2000 (XSIZE)
        0xA9, 0x20, 0x8D, 0x26, 0x20,  # LDA #$20 (bank 1); STA $2026
        0xA9, 0x00, 0x8D, 0x08, 0x20,  # DMA src = $8000
        0xA9, 0x80, 0x8D, 0x09, 0x20,
        0xA9, 0x00, 0x8D, 0x0A, 0x20,  # DMA dst = VRAM $0000, cpu2vram = 1 ($40)
        0xA9, 0x40, 0x8D, 0x0B, 0x20,
        0xA9, 0x10, 0x8D, 0x0C, 0x20,  # 16 * 16 = 256 bytes
        0xA9, 0x80, 0x8D, 0x0D, 0x20,  # Trigger GDMA!
        0x80, 0xFE,                    # BRA *
    ])
    rom[0xC000 : 0xC000 + len(code)] = code
    rom[0xFFFC] = 0x00
    rom[0xFFFD] = 0xC0
    return bytes(rom)


def main() -> int:
    engine = os.environ.get("ALISIM_ENGINE", "cpp")
    img = v4.BIN / f"{v4.STEM}.bin"
    print(f"Booting {img} on AliSimulator (engine={engine})...", flush=True)
    box = v4.Box(img, engine)
    boot = box.boot().decode("latin-1")
    v4.check("Version: v4" in boot, "v4 firmware booted via original bootloader")

    help_out = box.command("help")
    v4.check("\r\n  sv " in help_out, "help lists 'sv'")

    sg = ROOT / "build/sample_games/sv"
    files = {
        "SV/HOPMAN.SV":  (sg / "Hopman.sv").read_bytes(),
        "SV/MAZY2.SV":   (sg / "Mazy2.sv").read_bytes(),
        "SV/IMPETUS.SV": (sg / "Impetus.sv").read_bytes(),
        "SV/BANK64.SV":  make_64k_banked_sv(),
    }
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="SVTEST"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    for path, frames, min_cols, desc in (
        ("2:/SV/HOPMAN.SV",  30, 3, "Hopman (16 KB)"),
        ("2:/SV/MAZY2.SV",   30, 3, "Mazy2 (32 KB)"),
        ("2:/SV/IMPETUS.SV", 30, 3, "Impetus (32 KB)"),
        ("2:/SV/BANK64.SV",  10, 4, "Banked 64 KB + CPU->VRAM DMA"),
    ):
        out = box.command(f"sv -f {frames} {path}", timeout=90)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, 160, 160)
        v4.check(p is not None and cols >= min_cols and p[0] < 16384,
                 f"sv {desc}: colors={cols}, perf={p}")

    # Explorer .sv auto-launch
    box.t.pending.clear()
    box.t.write(b"explorer 2:/SV\r")
    box.t.wait_for(b"brings the console back", 15)
    box.run(0.6)
    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}\r") + 1.5)
    uart_exp = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)
    box.run(kbd.type("{ESC}") + 0.8)
    v4.check("Watara Supervision" in uart_exp,
             f"explorer auto-launches .sv cartridge ({uart_exp.strip()[:80]!r})")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL WATARA SUPERVISION CHECKS PASSED!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
