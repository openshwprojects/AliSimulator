#!/usr/bin/env python3
"""End-to-end AliSimulator verification for Group 1 Classic Home Computers:
bbc (BBC Micro + Electron + Mode 7), ti99, oric, plus4, zx81, pc88, mz700, x1."""
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
    for c in ("bbc", "ti99", "oric", "plus4", "zx81", "pc88", "mz700", "x1"):
        v4.check(f"\r\n  {c} " in help_out, f"help lists '{c}'")

    sg = ROOT / "build/sample_games"
    files = {
        "bbc/hopman.uef":          (sg / "bbc/hopman.uef").read_bytes(),
        "bbc/hopman_el.uef":       (sg / "bbc/hopman_el.uef").read_bytes(),
        "bbc/mode7_star_raid.ssd": (sg / "bbc/mode7_star_raid.ssd").read_bytes(),
        "ti99/hopman.rpk":         (sg / "ti99/hopman.rpk").read_bytes(),
        "oric/hopman.tap":         (sg / "oric/hopman.tap").read_bytes(),
        "plus4/mazy2.tap":         (sg / "plus4/mazy2.tap").read_bytes(),
        "plus4/ted_121_prism.prg": (sg / "plus4/ted_121_prism.prg").read_bytes(),
        "zx81/hopman.p":           (sg / "zx81/hopman.p").read_bytes(),
        "pc88/hopman.d88":         (sg / "pc88/hopman.d88").read_bytes(),
        "mz700/hopman.mzt":        (sg / "mz700/hopman.mzt").read_bytes(),
        "x1/hopman.d88":           (sg / "x1/hopman.d88").read_bytes(),
    }
    print("Building FAT16 image (16 MB)...", flush=True)
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="GOALCOMP"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    cases = (
        ("bbc -f 15",                                       320, 256,   2, "BBC Micro Mode 7 BASIC"),
        ("bbc -f 90 -k 50:1 2:/bbc/hopman.uef",             320, 256,   4, "BBC Micro Hopman (.uef)"),
        ("bbc -f 95 -k 65:1 2:/bbc/hopman_el.uef",          320, 256,   4, "Acorn Electron Hopman (_el.uef)"),
        ("bbc -f 35 2:/bbc/mode7_star_raid.ssd",            320, 256,   4, "BBC Micro Mode 7 Star Raid (.ssd)"),
        ("ti99 -f 15",                                      256, 192,   2, "TI-99/4A TI BASIC"),
        ("ti99 -f 90 -k 45:1 2:/ti99/hopman.rpk",           256, 192,   5, "TI-99/4A Hopman (.rpk)"),
        ("oric -f 15",                                      240, 224,   2, "Oric Atmos BASIC"),
        ("oric -f 90 -k 45:1 2:/oric/hopman.tap",           240, 224,   4, "Oric Atmos Hopman (.tap)"),
        ("plus4 -f 15",                                     320, 200,   2, "Commodore Plus/4 BASIC V3.5"),
        ("plus4 -f 130 -k 40:1,50:0,60:80 2:/plus4/mazy2.tap", 320, 200, 5, "Commodore Plus/4 Mazy2 (.tap)"),
        ("plus4 -f 25 2:/plus4/ted_121_prism.prg",          320, 200, 100, "Commodore Plus/4 121-color TED (.prg)"),
        ("zx81 -f 15",                                      256, 192,   2, "Sinclair ZX81 16K BASIC"),
        ("zx81 -f 80 -k 40:1 2:/zx81/hopman.p",             256, 192,   2, "Sinclair ZX81 Hopman (.p)"),
        ("pc88 -f 15",                                      640, 200,   2, "NEC PC-8801 N88-BASIC"),
        ("pc88 -f 120 -k 85:1 2:/pc88/hopman.d88",          640, 200,   5, "NEC PC-8801 Hopman (.d88)"),
        ("mz700 -f 15",                                     320, 200,   2, "Sharp MZ-700 1Z-009A Monitor"),
        ("mz700 -f 80 -k 40:1 2:/mz700/hopman.mzt",         320, 200,   4, "Sharp MZ-700 Hopman (.mzt)"),
        ("x1 -f 15",                                        320, 200,   2, "Sharp X1 IPL/BASIC"),
        ("x1 -f 185 -k 125:1,126:1,127:1,128:1,129:1,130:1 2:/x1/hopman.d88", 320, 200, 5, "Sharp X1 Hopman (.d88)"),
    )

    for cmd_line, w, h, min_cols, desc in cases:
        print(f"Running: {cmd_line} ...", flush=True)
        out = box.command(cmd_line, timeout=180)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, w, h)
        v4.check(p is not None and cols >= min_cols, f"{desc}: colors={cols}, perf={p}")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL 8 CLASSIC HOME COMPUTERS PASSED ON ALISIMULATOR!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
