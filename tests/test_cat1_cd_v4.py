#!/usr/bin/env python3
"""End-to-end AliSimulator verification for SuperGrafx ('sgx'), PC Engine CD ('pcecd'),
and Sega CD / Mega-CD ('segacd'), including .sav BRAM persistence and explorer .cue signature routing."""
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
    for c in ("sgx", "pcecd", "segacd"):
        v4.check(f"\r\n  {c} " in help_out, f"help lists '{c}'")

    sg = ROOT / "build/sample_games"
    files = {
        "sgx/sgx_starblade.sgx":    (sg / "sgx/sgx_starblade.sgx").read_bytes(),
        "pcecd/cyber_cd.cue":       (sg / "pcecd/cyber_cd.cue").read_bytes(),
        "pcecd/cyber_cd.bin":       (sg / "pcecd/cyber_cd.bin").read_bytes(),
        "segacd/sonic_warp_cd.cue": (sg / "segacd/sonic_warp_cd.cue").read_bytes(),
        "segacd/sonic_warp_cd.bin": (sg / "segacd/sonic_warp_cd.bin").read_bytes(),
        "DISC/cyber_cd.cue":        (sg / "pcecd/cyber_cd.cue").read_bytes(),
        "DISC/cyber_cd.bin":        (sg / "pcecd/cyber_cd.bin").read_bytes(),
        "DISC/sonic_warp_cd.cue":   (sg / "segacd/sonic_warp_cd.cue").read_bytes(),
        "DISC/sonic_warp_cd.bin":   (sg / "segacd/sonic_warp_cd.bin").read_bytes(),
    }
    print("Building FAT16 image (16 MB)...", flush=True)
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="CAT1CD"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    cases = (
        ("sgx -f 45 2:/sgx/sgx_starblade.sgx",       256, 240, 12, "NEC SuperGrafx Starblade"),
        ("pcecd -f 70 2:/pcecd/cyber_cd.cue",        256, 240,  8, "PC Engine CD Cyber CD (SysCard 3.0 + AC 2MB)"),
        ("segacd -f 75 2:/segacd/sonic_warp_cd.cue", 256, 224,  8, "Sega CD Sonic Warp 3D (Dual-68k + Stamp ASIC)"),
    )

    for cmd_line, w, h, min_cols, desc in cases:
        print(f"Running: {cmd_line} ...", flush=True)
        out = box.command(cmd_line, timeout=120)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, w, h)
        v4.check(p is not None and cols >= min_cols, f"{desc}: colors={cols}, perf={p}")

    ls_scd = box.command("ls 2:/segacd")
    v4.check("sonic_warp_cd.cue.sav" in ls_scd and "8192" in ls_scd,
             f"Sega CD 8 KB BRAM .sav persisted ({ls_scd.strip()[:100]!r})")

    # Explorer signature-based auto-launch for .cue in neutral DISC/ folder
    box.t.pending.clear()
    box.t.write(b"explorer 2:/DISC\r")
    box.t.wait_for(b"brings the console back", 15)
    box.run(0.6)
    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}{DOWN}\r") + 2.5)
    uart_pce = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)
    v4.check("PC Engine CD" in uart_pce or "Arcade Card" in uart_pce,
             f"explorer signature-routes cyber_cd.cue -> pcecd_play ({uart_pce.strip()[:90]!r})")

    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}{DOWN}\r") + 2.5)
    uart_scd = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)
    box.run(kbd.type("{ESC}") + 0.8)
    v4.check("Sega CD" in uart_scd or "SONIC WARP" in uart_scd,
             f"explorer signature-routes sonic_warp_cd.cue -> segacd_play ({uart_scd.strip()[:90]!r})")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL SUPERGRAFX, PCE-CD & SEGA CD CHECKS PASSED ON ALISIMULATOR!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
