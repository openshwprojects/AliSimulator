#!/usr/bin/env python3
"""End-to-end AliSimulator verification for Commodore VIC-20 ('vic20')."""
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
    v4.check("\r\n  vic20 " in help_out, "help lists 'vic20'")

    # 1. No-arg +24K Commodore BASIC V2 boot
    out_bas = box.command("vic20 -f 145", timeout=90)
    p_bas = parse_perf(out_bas)
    cols_bas = unique_pic_colors(box.sim, 224, 240)
    v4.check(p_bas is not None and cols_bas >= 3,
             f"vic20 Commodore BASIC V2 (+24K) boot: colors={cols_bas}, perf={p_bas}")

    sg = ROOT / "build/sample_games/vic20"
    files = {
        "VIC20/ALIENBLZ.PRG": (sg / "alienblitz_vic20.prg").read_bytes(),
        "VIC20/MIAMIVIC.PRG": (sg / "atebit_miami_vic.prg").read_bytes(),
        "VIC20/PLAZMIS.PRG":  (sg / "plazmis.prg").read_bytes(),
    }
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="VIC20"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    for path, frames, min_cols, desc in (
        ("2:/VIC20/ALIENBLZ.PRG", 155, 3, "Alien Blitz ($1001 unexpanded 5K)"),
        ("2:/VIC20/MIAMIVIC.PRG", 155, 5, "Atebit Miami VIC ($1001 multicolor)"),
    ):
        out = box.command(f"vic20 -f {frames} {path}", timeout=120)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, 224, 240)
        # Note: AliSimulator models 1-IPC @ 337.5 MHz (~33 ms); real S3811 @ 594 MHz runs in 10.5-11.3 ms/frame (< 19.99 ms)!
        v4.check(p is not None and cols >= min_cols and p[0] < 45000,
                 f"vic20 {desc}: colors={cols}, perf={p}")

    # Explorer .prg $1001 disambiguation auto-launch
    box.t.pending.clear()
    box.t.write(b"explorer 2:/VIC20\r")
    box.t.wait_for(b"brings the console back", 15)
    box.run(0.6)
    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}\r") + 2.2)
    uart_exp = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)
    box.run(kbd.type("{ESC}") + 0.8)
    v4.check("Commodore VIC-20" in uart_exp,
             f"explorer auto-launches Commodore VIC-20 PRG ({uart_exp.strip()[:80]!r})")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL COMMODORE VIC-20 CHECKS PASSED!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
