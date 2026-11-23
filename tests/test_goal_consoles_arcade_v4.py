#!/usr/bin/env python3
"""End-to-end AliSimulator verification for Group 2 & Group 3:
fds + NES expansion audio (VRC6/VRC7/N163), s32x, cd32, cps2, and arcade."""
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


def unique_nes_colors(sim, w: int, h: int) -> int:
    pic_phys = 0x03D80000
    raw = bytes(sim.ram_buffer[pic_phys : pic_phys + w * h])
    return len(set(raw))


def main() -> int:
    engine = os.environ.get("ALISIM_ENGINE", "cpp")
    img = v4.BIN / f"{v4.STEM}.bin"
    print(f"Booting {img} on AliSimulator (engine={engine})...", flush=True)
    box = v4.Box(img, engine)
    boot = box.boot().decode("latin-1")
    v4.check("Version: v4" in boot, "v4 firmware booted via original bootloader")

    help_out = box.command("help")
    for c in ("fds", "nes", "s32x", "cd32", "cps2", "arcade"):
        v4.check(f"\r\n  {c} " in help_out, f"help lists '{c}'")

    sg = ROOT / "build/sample_games"
    files = {
        "fds/disk_quest_2side.fds":    (sg / "fds/disk_quest_2side.fds").read_bytes(),
        "fds/vrc6_castle_synth.nes":   (sg / "fds/vrc6_castle_synth.nes").read_bytes(),
        "fds/vrc7_cosmic_fm.nes":      (sg / "fds/vrc7_cosmic_fm.nes").read_bytes(),
        "fds/n163_wavetable_raid.nes": (sg / "fds/n163_wavetable_raid.nes").read_bytes(),
        "s32x/star_viper_32x.32x":     (sg / "s32x/star_viper_32x.32x").read_bytes(),
        "s32x/prism_direct15.32x":     (sg / "s32x/prism_direct15.32x").read_bytes(),
        "cd32/akiko_citadel_3d.cue":   (sg / "cd32/akiko_citadel_3d.cue").read_bytes(),
        "cd32/akiko_citadel_3d.bin":   (sg / "cd32/akiko_citadel_3d.bin").read_bytes(),
        "DISC/akiko_citadel_3d.cue":   (sg / "cd32/akiko_citadel_3d.cue").read_bytes(),
        "DISC/akiko_citadel_3d.bin":   (sg / "cd32/akiko_citadel_3d.bin").read_bytes(),
        "cps2/cyber_brawl_cps2.zip":   (sg / "cps2/cyber_brawl_cps2.zip").read_bytes(),
        "cps2/qsound_xor_arena.zip":   (sg / "cps2/qsound_xor_arena.zip").read_bytes(),
        "arcade/maze_chomp.zip":       (sg / "arcade/maze_chomp.zip").read_bytes(),
        "arcade/galactic_swarm.zip":   (sg / "arcade/galactic_swarm.zip").read_bytes(),
        "arcade/river_frog.zip":       (sg / "arcade/river_frog.zip").read_bytes(),
        "arcade/barrel_kong.zip":      (sg / "arcade/barrel_kong.zip").read_bytes(),
    }
    print("Building FAT16 image (16 MB)...", flush=True)
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="GOAL32ARC"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, "USB stick + keyboard enumerated behind hub")

    nes_cases = (
        ("fds -f 45 -k 20:400 2:/fds/disk_quest_2side.fds",  6, "FDS 2-Side Disk + RP2C33 FM"),
        ("nes -f 35 2:/fds/vrc6_castle_synth.nes",           8, "NES Konami VRC6 (Mapper 24)"),
        ("nes -f 35 2:/fds/vrc7_cosmic_fm.nes",              8, "NES Konami VRC7 FM (Mapper 85)"),
        ("nes -f 35 2:/fds/n163_wavetable_raid.nes",         8, "NES Namco 163 Wavetable (Mapper 19)"),
    )
    for cmd_line, min_cols, desc in nes_cases:
        print(f"Running: {cmd_line} ...", flush=True)
        out = box.command(cmd_line, timeout=180)
        p = parse_perf(out)
        cols = unique_nes_colors(box.sim, 256, 240)
        v4.check(p is not None and cols >= min_cols, f"{desc}: colors={cols}, perf={p}")

    rgb15_cases = (
        ("s32x -f 25 2:/s32x/star_viper_32x.32x",      320, 224, 180, "Sega 32X Star Viper (Dual SH-2 256-col)"),
        ("s32x -f 25 2:/s32x/prism_direct15.32x",      320, 224,  30, "Sega 32X Prism (Dual SH-2 Direct15)"),
        ("cd32 -f 25 2:/cd32/akiko_citadel_3d.cue",    352, 272, 200, "Amiga CD32 Akiko C2P 256-color"),
        ("cps2 -f 30 2:/cps2/cyber_brawl_cps2.zip",    384, 224,  15, "Capcom CPS-2 (.key Feistel + QSound)"),
        ("cps2 -f 30 2:/cps2/qsound_xor_arena.zip",    384, 224,  15, "Capcom CPS-2 (.03x XOR + QSound)"),
        ("arcade -f 25",                               224, 288,   4, "Golden-Age Arcade Built-in Maze Chomp"),
        ("arcade -f 30 2:/arcade/maze_chomp.zip",      224, 288,   5, "Arcade Namco Pac-Man WSG (.zip)"),
        ("arcade -f 30 2:/arcade/galactic_swarm.zip",  224, 256,  12, "Arcade Namco Galaxian Starfield (.zip)"),
        ("arcade -f 30 2:/arcade/river_frog.zip",      224, 256,   6, "Arcade Konami Frogger Dual-Z80 (.zip)"),
        ("arcade -f 30 2:/arcade/barrel_kong.zip",     224, 256,   6, "Arcade Nintendo Donkey Kong (.zip)"),
    )
    for cmd_line, w, h, min_cols, desc in rgb15_cases:
        print(f"Running: {cmd_line} ...", flush=True)
        out = box.command(cmd_line, timeout=180)
        p = parse_perf(out)
        cols = unique_pic_colors(box.sim, w, h)
        v4.check(p is not None and cols >= min_cols, f"{desc}: colors={cols}, perf={p}")

    ls_cd32 = box.command("ls 2:/cd32")
    v4.check("akiko_citadel_3d.cue.sav" in ls_cd32 and "1024" in ls_cd32,
             f"Amiga CD32 1 KB NVRAM .sav persisted ({ls_cd32.strip()[:100]!r})")

    # Explorer ISO-9660 PVD signature auto-routing in neutral DISC/ folder
    box.t.pending.clear()
    box.t.write(b"explorer 2:/DISC\r")
    box.t.wait_for(b"brings the console back", 15)
    box.run(0.6)
    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}{DOWN}\r") + 3.0)
    uart_cd32 = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)
    box.run(kbd.type("{ESC}") + 0.8)
    v4.check("Amiga CD32" in uart_cd32 or "AKIKO CITADEL" in uart_cd32,
             f"explorer signature-routes akiko_citadel_3d.cue -> cd32_play ({uart_cd32.strip()[:90]!r})")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL CONSOLE ADD-ONS, 32-BIT HEAVYWEIGHTS & ARCADE BOARDS PASSED ON ALISIMULATOR!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
