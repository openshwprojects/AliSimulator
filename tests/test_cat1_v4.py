#!/usr/bin/env python3
"""End-to-end AliSimulator verification for Category 1 cartridge consoles:
pv1000, astro, arcadia, vc4000, studio2, scv, vb."""
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
    for c in ("pv1000", "astro", "arcadia", "vc4000", "studio2", "scv", "vb"):
        v4.check(f"\r\n  {c} " in help_out, f"help lists '{c}'")

    sg = ROOT / "build/sample_games"
    files = {
        "pv1000/hopman.pv":         (sg / "pv1000/hopman.pv").read_bytes(),
        "astro/astro_invaders.ast": (sg / "astro/astro_invaders.ast").read_bytes(),
        "arcadia/alien_raid.a2k":   (sg / "arcadia/alien_raid.a2k").read_bytes(),
        "vc4000/grand_prix.vc4":    (sg / "vc4000/grand_prix.vc4").read_bytes(),
        "studio2/star_dodger.st2":  (sg / "studio2/star_dodger.st2").read_bytes(),
        "scv/hopman.scv":           (sg / "scv/hopman.scv").read_bytes(),
        "vb/red_horizon_3d.vb":     (sg / "vb/red_horizon_3d.vb").read_bytes(),
    }
    print("Building FAT16 image (16 MB)...", flush=True)
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="CAT1CON"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    cases = (
        ("pv1000 -f 60 -k 30:8 2:/pv1000/hopman.pv",       256, 192, 4, "Casio PV-1000 Hopman"),
        ("astro -f 45",                                    320, 204, 3, "Bally Astrocade built-in Star Blaster"),
        ("astro -f 60 2:/astro/astro_invaders.ast",        320, 204, 4, "Bally Astrocade Astro Invaders"),
        ("arcadia -f 45 2:/arcadia/alien_raid.a2k",        160, 208, 4, "Emerson Arcadia 2001 Alien Raid"),
        ("vc4000 -f 45 2:/vc4000/grand_prix.vc4",          192, 224, 3, "Interton VC 4000 Grand Prix"),
        ("studio2 -f 45",                                  256, 128, 2, "RCA Studio II built-in COSMAC Interceptor"),
        ("studio2 -f 45 2:/studio2/star_dodger.st2",       256, 128, 2, "RCA Studio II Star Dodger"),
        ("scv -f 45 -k 22:1 2:/scv/hopman.scv",            192, 222, 4, "Epoch SCV Hopman"),
        ("vb -f 30 2:/vb/red_horizon_3d.vb",               384, 224, 3, "Virtual Boy Red Horizon 3D (Red/Black)"),
        ("vb -m 1 -f 30 2:/vb/red_horizon_3d.vb",          384, 224, 8, "Virtual Boy Red Horizon 3D (3D Anaglyph)"),
    )

    for cmd_line, w, h, min_cols, desc in cases:
        print(f"Running: {cmd_line} ...", flush=True)
        out = box.command(cmd_line, timeout=120)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, w, h)
        v4.check(p is not None and cols >= min_cols, f"{desc}: colors={cols}, perf={p}")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL CATEGORY 1 CARTRIDGE CONSOLES PASSED ON ALISIMULATOR!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
