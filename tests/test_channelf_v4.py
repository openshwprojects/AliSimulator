#!/usr/bin/env python3
"""End-to-end AliSimulator verification for Fairchild Channel F / VES ('channelf')."""
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


def make_f2102_test_cart() -> bytes:
    """Synthetic Channel F cart testing HLE clrscrn ($00D0), HLE drawchar ($0679), and F2102 SRAM read/write."""
    code = bytearray(512)
    p = 0
    def emit(*bs):
        nonlocal p
        for b in bs:
            code[p] = b
            p += 1
    emit(0x55, 0x00)                # $0800: valid cart magic + pad -> entry at $0802
    emit(0x20, 0xC6, 0x53)          # LI $C6 (LtGray palette); LR 3, A
    emit(0x28, 0x00, 0xD0)          # PI $00D0 (clrscrn)
    # Write 1 bit to F2102 addr 0 (port $21=0, port $20=$09: bit3=1 data, bit0=1 write), then read back ($20=$00)
    emit(0x70, 0x27, 0x21)          # LIS 0; OUT $21
    emit(0x79, 0x27, 0x20)          # LIS 9; OUT $20 (write '1' to bit 0)
    emit(0x70, 0x27, 0x20)          # LIS 0; OUT $20 (read bit 0 -> port $24 bit 7 = 1!)
    emit(0x26, 0x24)                # IN $24 (A <- $80, negative -> W_SIGN == 0!)
    # Draw 'G' (0x0D) in RED ($80 -> col 2) if F2102 read bit7==1, else '0'
    emit(0x20, 0x8D, 0x50)          # LI $8D (Red 'G'); LR 0, A
    emit(0x20, 0x10, 0x51)          # LI 16; LR 1, A (X)
    emit(0x20, 0x10, 0x52)          # LI 16; LR 2, A (Y)
    emit(0x28, 0x06, 0x79)          # PI $0679 (drawchar_sys)
    # Also draw blue & green pixels directly via port strobes
    emit(0x20, 0x80, 0xB1)          # LI $80 (BLUE); OUTS 1
    emit(0x20, 0xDF, 0xB4)          # LI ~32; OUTS 4 (X=32)
    emit(0x20, 0xDF, 0xB5)          # LI ~32; OUTS 5 (Y=32)
    emit(0x20, 0x60, 0xB0)          # LI $60; OUTS 0 (RAM_WRT pulse)
    emit(0x20, 0x40, 0xB0)          # LI $40; OUTS 0
    emit(0x20, 0x00, 0xB1)          # LI $00 (GREEN); OUTS 1
    emit(0x20, 0xDE, 0xB4)          # LI ~33; OUTS 4 (X=33)
    emit(0x20, 0x60, 0xB0)          # LI $60; OUTS 0
    emit(0x20, 0x40, 0xB0)          # LI $40; OUTS 0
    loop_addr = 0x0800 + p
    emit(0x29, loop_addr >> 8, loop_addr & 0xFF)  # JMP loop
    return bytes(code)


def main() -> int:
    engine = os.environ.get("ALISIM_ENGINE", "cpp")
    img = v4.BIN / f"{v4.STEM}.bin"
    print(f"Booting {img} on AliSimulator (engine={engine})...", flush=True)
    box = v4.Box(img, engine)
    boot = box.boot().decode("latin-1")
    v4.check("Version: v4" in boot, "v4 firmware booted via original bootloader")

    help_out = box.command("help")
    v4.check("\r\n  channelf " in help_out, "help lists 'channelf'")

    sg = ROOT / "build/sample_games/channelf"
    files = {
        "CHF/BUFO.CHF":  (sg / "bufo.chf").read_bytes(),
        "CHF/QUEST.CHF": (sg / "quest.chf").read_bytes(),
        "CHF/DINO.CHF":  (sg / "retrodino.chf").read_bytes(),
        "CHF/WRDL.CHF":  (sg / "wrdl-f.chf").read_bytes(),
        "CHF/TENTS.CHF": (sg / "tents_and_trees.chf").read_bytes(),
        "CHF/SYNTH.CHF": make_f2102_test_cart(),
    }
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="CHF"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    for path, frames, min_cols, desc in (
        ("2:/CHF/SYNTH.CHF", 10, 4, "HLE clrscrn + drawchar + F2102 + 4-color VRAM"),
        ("2:/CHF/BUFO.CHF",  30, 3, "BUFO road-and-river homebrew"),
        ("2:/CHF/QUEST.CHF", 30, 2, "QUEST 4K JRPG homebrew"),
        ("2:/CHF/DINO.CHF",  30, 2, "RetroDino HLE delay+clrscrn"),
        ("2:/CHF/WRDL.CHF",  30, 2, "Wrdl-F 8K B&W title + Schach RAM"),
        ("2:/CHF/TENTS.CHF", 95, 2, "Tents & Trees intro song + title screen + Schach RAM"),
    ):
        out = box.command(f"channelf -f {frames} {path}", timeout=90)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, 102, 58)
        v4.check(p is not None and cols >= min_cols and p[0] < 16667,
                 f"channelf {desc}: colors={cols}, perf={p}")

    # Explorer .chf auto-launch
    box.t.pending.clear()
    box.t.write(b"explorer 2:/CHF\r")
    box.t.wait_for(b"brings the console back", 15)
    box.run(0.6)
    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}\r") + 1.5)
    uart_exp = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)
    box.run(kbd.type("{ESC}") + 0.8)
    v4.check("Fairchild Channel F" in uart_exp,
             f"explorer auto-launches Channel F cart ({uart_exp.strip()[:80]!r})")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL FAIRCHILD CHANNEL F CHECKS PASSED!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
