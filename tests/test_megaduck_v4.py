#!/usr/bin/env python3
"""End-to-end AliSimulator verification for Mega Duck / Cougar Boy ('megaduck') + Game Boy ('gb') regression."""
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
    v4.check("\r\n  megaduck " in help_out, "help lists 'megaduck'")

    sg = ROOT / "build/sample_games/megaduck"
    files = {
        "GB/T.GB": v4.tiny_gb_cartridge(),
        "GB/C.GB": v4.tiny_gb_cartridge(True),
        "MEGADUCK/MAZY2.DUCK": (sg / "Mazy2.duck").read_bytes(),
        "MEGADUCK/CAVIT.DUCK": (sg / "Cavit.duck").read_bytes(),
        "MEGADUCK/WATERNET.DUCK": (sg / "waternet.duck").read_bytes(),
        "MEGADUCK/SUSHI.DUCK": (sg / "SushiNights.duck").read_bytes(),
    }
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="DUCK"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    # 1. Regression check on Game Boy DMG & CGB exact CRCs
    r_dmg = parse_perf(box.command("gb -f 60 2:/GB/T.GB", timeout=90))
    r_cgb = parse_perf(box.command("gb -f 60 2:/GB/C.GB", timeout=90))
    v4.check(r_dmg is not None and r_dmg[2] == "76250edf", f"gb DMG exact CRC-32 preserved ({r_dmg})")
    v4.check(r_cgb is not None and r_cgb[2] == "f31b3bd0", f"gb CGB exact CRC-32 preserved ({r_cgb})")

    # 2. Mega Duck non-16KB (11 KB Mazy2), 16 KB (Cavit), 32 KB (Waternet), 128 KB $0001-banked (SushiNights)
    for path, frames, min_cols, desc in (
        ("2:/MEGADUCK/MAZY2.DUCK",    18, 2, "Mazy2 (11 KB non-power-of-two)"),
        ("2:/MEGADUCK/CAVIT.DUCK",    18, 2, "Cavit (16 KB mirrored)"),
        ("2:/MEGADUCK/WATERNET.DUCK", 50, 3, "Waternet (32 KB flat)"),
        ("2:/MEGADUCK/SUSHI.DUCK",    60, 3, "SushiNights (128 KB $0001 banked)"),
    ):
        out = box.command(f"megaduck -f {frames} {path}", timeout=120)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, 160, 144)
        v4.check(p is not None and cols >= min_cols and p[0] < 25000,
                 f"megaduck {desc}: colors={cols}, perf={p}")

    # 3. Explorer .duck auto-launch
    box.t.pending.clear()
    box.t.write(b"explorer 2:/MEGADUCK\r")
    box.t.wait_for(b"brings the console back", 15)
    box.run(0.6)
    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}\r") + 1.5)
    uart_exp = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)
    box.run(kbd.type("{ESC}") + 0.8)
    v4.check("Mega Duck / Cougar Boy" in uart_exp,
             f"explorer auto-launches .duck cartridge ({uart_exp.strip()[:80]!r})")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL MEGADUCK & GAME BOY CHECKS PASSED!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
