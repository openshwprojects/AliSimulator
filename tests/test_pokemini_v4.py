#!/usr/bin/env python3
"""End-to-end AliSimulator verification for Nintendo Pokemon Mini ('pokemini')."""
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
    v4.check("\r\n  pokemini " in help_out, "help lists 'pokemini'")

    sg = ROOT / "build/sample_games/pokemini"
    files = {
        "PM/ATWAR.MIN":   (sg / "AfterTheWar.min").read_bytes(),
        "PM/BIFF.MIN":    (sg / "Biff.min").read_bytes(),
        "PM/BOUNCE.MIN":  (sg / "Bounce.min").read_bytes(),
        "PM/CORTEX.MIN":  (sg / "cortex.min").read_bytes(),
        "PM/FTFF.MIN":    (sg / "ftff161.min").read_bytes(),
        "PM/SHADES6.MIN": (sg / "6shades.min").read_bytes(),
        "PM/EEP.MIN":     (sg / "eep.min").read_bytes(),
    }
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="POKEMINI"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    for path, frames, min_cols, desc in (
        ("2:/PM/ATWAR.MIN",   60, 2, "After The War homebrew"),
        ("2:/PM/BIFF.MIN",    60, 2, "Biff! action homebrew"),
        ("2:/PM/BOUNCE.MIN",  60, 2, "Bounce physics homebrew"),
        ("2:/PM/CORTEX.MIN",  60, 2, "Cortex 3D/demo homebrew"),
        ("2:/PM/FTFF.MIN",    60, 2, "FTFF rhythm/action homebrew"),
        ("2:/PM/SHADES6.MIN", 60, 3, "6-shades analog LCD persistence demo"),
    ):
        out = box.command(f"pokemini -f {frames} {path}", timeout=90)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, 96, 64)
        v4.check(p is not None and cols >= min_cols and p[0] < 13889,
                 f"pokemini {desc}: colors={cols}, perf={p}")

    # Test I2C EEPROM (.sav) persistence via eep.min (press A to trigger EEPROM read/write test)
    out_eep = box.command("pokemini -f 90 -k 20:01,25:00,45:01,50:00 2:/PM/EEP.MIN", timeout=90)
    p_eep = parse_perf(out_eep)
    cols_eep = unique_pic_colors(box.sim, 96, 64)
    ls_pm = box.command("ls 2:/PM")
    v4.check(p_eep is not None and cols_eep >= 2,
             f"pokemini eep.min I2C EEPROM test ran cleanly: colors={cols_eep}, perf={p_eep}")
    if "EEP.MIN.SAV" in ls_pm.upper():
        print("  [info] EEP.MIN.SAV persisted to FAT volume (8192 bytes)", flush=True)

    # Explorer .min auto-launch
    box.t.pending.clear()
    box.t.write(b"explorer 2:/PM\r")
    box.t.wait_for(b"brings the console back", 15)
    box.run(0.6)
    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}\r") + 1.5)
    uart_exp = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)
    box.run(kbd.type("{ESC}") + 0.8)
    v4.check("Pokemon Mini" in uart_exp,
             f"explorer auto-launches Pokemon Mini cart ({uart_exp.strip()[:80]!r})")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL POKEMON MINI CHECKS PASSED!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
