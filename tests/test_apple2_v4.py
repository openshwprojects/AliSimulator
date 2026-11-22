#!/usr/bin/env python3
"""End-to-end AliSimulator verification for Apple IIe Enhanced ('apple2')."""
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


def main() -> int:
    engine = os.environ.get("ALISIM_ENGINE", "cpp")
    img = v4.BIN / f"{v4.STEM}.bin"
    print(f"Booting {img} on AliSimulator (engine={engine})...", flush=True)
    box = v4.Box(img, engine)
    boot = box.boot().decode("latin-1")
    v4.check("Version: v4" in boot, "v4 firmware booted via original bootloader")

    help_out = box.command("help")
    v4.check("\r\n  apple2 " in help_out, "help lists 'apple2'")

    # 1. No-arg Applesoft BASIC boot
    out_bas = box.command("apple2 -f 45", timeout=90)
    p_bas = parse_perf(out_bas)
    cols_bas = unique_pic_colors(box.sim, 280, 192)
    v4.check(p_bas is not None and cols_bas >= 2,
             f"apple2 Applesoft BASIC boot: colors={cols_bas}, perf={p_bas}")

    sg = ROOT / "build/sample_games/apple2"
    files = {
        "APPLE2/HOPMAN.DSK":  (sg / "hopman.dsk").read_bytes(),
        "APPLE2/IMPETUS.DSK": (sg / "impetus.dsk").read_bytes(),
        "APPLE2/PRODOS.PO":   (sg / "ProDOS_2_4_3.po").read_bytes(),
    }
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="APPLE2"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    for path, extra, min_cols, desc in (
        ("2:/APPLE2/HOPMAN.DSK", "-f 380 -k 315:a:8", 4, "Hopman (140 KB Disk II NTSC Hi-Res)"),
        ("2:/APPLE2/PRODOS.PO",  "-f 280",            2, "ProDOS 2.4.3 (.po ProDOS order)"),
    ):
        out = box.command(f"apple2 {extra} {path}", timeout=140)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, 280, 192)
        v4.check(p is not None and cols >= min_cols and p[0] < 45000,
                 f"apple2 {desc}: colors={cols}, perf={p}")

    # Explorer 140 KB .dsk disambiguation auto-launch
    box.t.pending.clear()
    box.t.write(b"explorer 2:/APPLE2\r")
    box.t.wait_for(b"brings the console back", 15)
    box.run(0.6)
    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}\r") + 2.2)
    uart_exp = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)
    box.run(kbd.type("{ESC}") + 0.8)
    v4.check("Apple IIe Enhanced" in uart_exp,
             f"explorer auto-launches Apple IIe .dsk ({uart_exp.strip()[:80]!r})")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL APPLE IIE ENHANCED CHECKS PASSED!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
