#!/usr/bin/env python3
"""End-to-end AliSimulator verification for TRS-80 CoCo 1/2 ('coco') & Dragon 32/64 ('dragon')."""
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
    v4.check("\r\n  coco " in help_out and "\r\n  dragon " in help_out, "help lists 'coco' and 'dragon'")

    for cmd_n, label in (("coco", "CoCo NTSC BASIC"), ("dragon", "Dragon PAL BASIC")):
        out_b = box.command(f"{cmd_n} -f 30", timeout=60)
        p_b = parse_perf(out_b)
        cols_b = unique_pic_colors(box.sim, 320, 240)
        v4.check(p_b is not None and cols_b >= 3, f"{label} boot: colors={cols_b}, perf={p_b}")

    sg = ROOT / "build/sample_games/coco"
    files = {
        "COCO/HOPMAN.CCC": (sg / "hopman_pak.ccc").read_bytes(),
        "COCO/HOPMAN.BIN": (sg / "hopman_ml.bin").read_bytes(),
        "COCO/YEWDOW.CAS": (sg / "yewdow.cas").read_bytes(),
    }
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="COCO"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    for cmd_n, path, desc in (
        ("coco",   "2:/COCO/HOPMAN.CCC", "Hopman Program Pak (.ccc)"),
        ("coco",   "2:/COCO/HOPMAN.BIN", "Hopman Disk BASIC ML (.bin)"),
        ("coco",   "2:/COCO/YEWDOW.CAS", "Yewdow Cassette (.cas)"),
        ("dragon", "2:/COCO/YEWDOW.CAS", "Dragon 32/64 PAL Yewdow (.cas)"),
    ):
        out = box.command(f"{cmd_n} -f 90 -k 40:a:8 {path}", timeout=90)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, 320, 240)
        v4.check(p is not None and cols >= 4 and p[0] < 45000,
                 f"{cmd_n} {desc}: colors={cols}, perf={p}")

    # Explorer .ccc / .cas auto-launch
    box.t.pending.clear()
    box.t.write(b"explorer 2:/COCO\r")
    box.t.wait_for(b"brings the console back", 15)
    box.run(0.6)
    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}\r") + 2.0)
    uart_exp = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)
    box.run(kbd.type("{ESC}") + 0.8)
    v4.check("TRS-80 CoCo" in uart_exp,
             f"explorer auto-launches CoCo file ({uart_exp.strip()[:80]!r})")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL TRS-80 COCO & DRAGON 32/64 CHECKS PASSED!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
