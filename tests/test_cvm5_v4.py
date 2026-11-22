#!/usr/bin/env python3
"""End-to-end AliSimulator verification for VTech CreatiVision ('cv') & Sord M5 ('m5')."""
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
    v4.check("\r\n  cv " in help_out and "\r\n  m5 " in help_out, "help lists 'cv' and 'm5'")

    sg_cv = ROOT / "build/sample_games/cv"
    sg_m5 = ROOT / "build/sample_games/m5"
    files = {
        "CV/HOPMAN.CV":  (sg_cv / "hopman.cv").read_bytes(),
        "CV/IMPETUS.CV": (sg_cv / "impetus.cv").read_bytes(),
        "M5/HOPMAN.M5":  (sg_m5 / "hopman.m5").read_bytes(),
        "M5/OSOTOS.M5":  (sg_m5 / "osotos.m5").read_bytes(),
    }
    print("Building FAT16 image...", flush=True)
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="CVM5"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    print("Attaching USB hub...", flush=True)
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    for cmd_n, path, min_cols, desc in (
        ("cv", "2:/CV/HOPMAN.CV",  4, "CreatiVision Hopman (16 KB)"),
        ("cv", "2:/CV/IMPETUS.CV", 3, "CreatiVision Impetus (32 KB)"),
        ("m5", "2:/M5/HOPMAN.M5",  4, "Sord M5 Hopman (10 KB)"),
        ("m5", "2:/M5/OSOTOS.M5",  5, "Sord M5 Osotos (10 KB)"),
    ):
        out = box.command(f"{cmd_n} -f 70 -k 40:1 {path}", timeout=90)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, 256, 192)
        v4.check(p is not None and cols >= min_cols and p[0] < 45000,
                 f"{desc}: colors={cols}, perf={p}")

    # Explorer .cv and .m5 auto-launch
    for folder, marker in (("2:/CV", "VTech CreatiVision"), ("2:/M5", "Sord M5")):
        box.t.pending.clear()
        box.t.write(f"explorer {folder}\r".encode("ascii"))
        box.t.wait_for(b"brings the console back", 15)
        box.run(0.6)
        mark = len(box.t.received)
        box.run(kbd.type("{DOWN}\r") + 2.0)
        uart_exp = bytes(box.t.received[mark:]).decode("latin-1")
        box.run(kbd.type("{ESC}") + 0.8)
        box.run(kbd.type("{ESC}") + 0.8)
        v4.check(marker in uart_exp, f"explorer auto-launches {marker} ({uart_exp.strip()[:80]!r})")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL CREATIVISION & SORD M5 CHECKS PASSED!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
