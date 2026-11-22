#!/usr/bin/env python3
"""End-to-end AliSimulator verification for Atari 800XL / 130XE ('atari8') & Atari 5200 ('a5200'):
boots the full MIPS32 v4 firmware image inside AliSimulator, attaches a writable FAT16 virtual USB
stick + VirtualKeyboard behind a USB hub, and verifies:
  1. Bare 'atari8' -> Altirra 8K BASIC Ready screen + live TV OSD colors
  2. Multi-segment .xex (Scorch 56 KB DLI game) & 16 KB .rom (Aerial) & 1 MB .car (FloB)
  3. Bootable .atr floppy disk read + sector writeback (.atr.sav created on USB stick!)
  4. Atari 5200 32 KB (Impetus) & 16 KB (Cavit) .a52 cartridges
  5. TV File Explorer ('explorer') disambiguation of $FFFF Atari .com vs MS-DOS .com
"""
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
    for i in range(0, len(raw), 16):
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
    v4.check("\r\n  atari8 " in help_out and "\r\n  a5200 " in help_out, "help lists 'atari8' and 'a5200'")

    sg_a8 = ROOT / "build/sample_games/atari8"
    sg_52 = ROOT / "build/sample_games/a5200"

    # Tiny bootable .atr that writes sector 2 via SIOV ($E459) to verify .sav persistence!
    atr_wr = bytearray(16 + 720 * 128)
    pars = (720 * 128) >> 4
    atr_wr[0:6] = bytes([0x96, 0x02, pars & 0xFF, pars >> 8, 128, 0])
    boot1 = bytes([
        0x00, 0x01, 0x00, 0x07, 0x06, 0x07,
        0xA9, 0x10, 0x85, 0x0A, 0xA9, 0x07, 0x85, 0x0B, 0x18, 0x60,
        0xA9, 0x31, 0x8D, 0x00, 0x03,
        0xA9, 0x01, 0x8D, 0x01, 0x03,
        0xA9, 0x57, 0x8D, 0x02, 0x03,
        0xA9, 0x80, 0x8D, 0x03, 0x03,
        0xA9, 0x00, 0x8D, 0x04, 0x03,
        0xA9, 0x07, 0x8D, 0x05, 0x03,
        0xA9, 0x80, 0x8D, 0x08, 0x03,
        0xA9, 0x00, 0x8D, 0x09, 0x03,
        0xA9, 0x02, 0x8D, 0x0A, 0x03,
        0xA9, 0x00, 0x8D, 0x0B, 0x03,
        0x20, 0x59, 0xE4,
        0xA9, 0x94, 0x8D, 0xC8, 0x02,
        0x4C, 0x45, 0x07,
    ])
    atr_wr[16 : 16 + len(boot1)] = boot1

    files = {
        "ATARI8/SCORCH.XEX": (sg_a8 / "scorch.xex").read_bytes(),
        "ATARI8/AERIAL.ROM": (sg_a8 / "aerial.rom").read_bytes(),
        "ATARI8/FLOB.CAR":   (sg_a8 / "flob.car").read_bytes(),
        "ATARI8/SAVE.ATR":   bytes(atr_wr),
        "COMTEST/ADEMO.COM": (sg_a8 / "dts.xex").read_bytes(),  # $FFFF Atari .com executable!
        "A5200/IMPETUS.A52": (sg_52 / "impetus.a52").read_bytes(),
        "A5200/CAVIT.A52":   (sg_52 / "cavit.a52").read_bytes(),
    }
    stick = VirtualStick(fat_image.build(files, fat=16, size_mb=16, label="ATARI"), writable=True)
    kbd = VirtualKeyboard()
    hub = v4.VirtualHub(4)
    hub.plug(1, stick, "high")
    hub.plug(2, kbd, "full")
    box.usb.attach("high", hub)
    out_usb = box.run(6.5)
    v4.check("disk 2:" in out_usb, f"USB stick + keyboard enumerated behind hub ({'disk 2:' in out_usb})")

    # 1. Bare 'atari8' -> Altirra 8K BASIC Ready screen
    r_bas = box.command("atari8 -f 45", timeout=90)
    p_bas = parse_perf(r_bas)
    c_bas = unique_pic_colors(box.sim, 336, 240)
    v4.check(p_bas is not None and "Altirra 8K BASIC" in r_bas and c_bas >= 2 and p_bas[0] < 20033,
             f"atari8 bare BASIC boots cleanly (colors={c_bas}, perf={p_bas})")

    # 2. Scorch .xex (56 KB multi-segment DLI game with 50+ color sky gradient!)
    r_sc = box.command("atari8 -f 70 2:/ATARI8/SCORCH.XEX", timeout=120)
    p_sc = parse_perf(r_sc)
    c_sc = unique_pic_colors(box.sim, 336, 240)
    v4.check(p_sc is not None and "Atari 130XE" in r_sc and c_sc >= 8 and p_sc[0] < 20033,
             f"atari8 scorch.xex runs within 50 Hz PAL budget (colors={c_sc}, perf={p_sc})")

    # 3. Aerial 16 KB XL/XE .rom cartridge + FloB 1 MB Atarimax .car cartridge
    r_rom = box.command("atari8 -f 45 2:/ATARI8/AERIAL.ROM", timeout=90)
    p_rom = parse_perf(r_rom)
    c_rom = unique_pic_colors(box.sim, 336, 240)
    v4.check(p_rom is not None and c_rom >= 2 and p_rom[0] < 20033,
             f"atari8 aerial.rom runs within 50 Hz PAL budget (colors={c_rom}, perf={p_rom})")

    r_car = box.command("atari8 -f 55 2:/ATARI8/FLOB.CAR", timeout=120)
    p_car = parse_perf(r_car)
    c_car = unique_pic_colors(box.sim, 336, 240)
    v4.check(p_car is not None and "CART ROM" in r_car and c_car >= 2 and p_car[0] < 20033,
             f"atari8 flob.car (1 MB Atarimax) runs cleanly (colors={c_car}, perf={p_car})")

    # 4. Bootable .atr + sector writeback (.sav)
    r_atr = box.command("atari8 -f 35 2:/ATARI8/SAVE.ATR", timeout=90)
    ls_out = box.command("ls 2:/ATARI8")
    v4.check("SAVE.ATR.sav" in ls_out and "SD .atr floppy disk" in r_atr,
             "atari8 .atr sector write creates SAVE.ATR.sav on USB disk")

    # 5. Atari 5200 32 KB (impetus.a52) & 16 KB (cavit.a52)
    r_52a = box.command("a5200 -f 148 -k 138:8 2:/A5200/IMPETUS.A52", timeout=120)
    p_52a = parse_perf(r_52a)
    c_52a = unique_pic_colors(box.sim, 336, 240)
    v4.check(p_52a is not None and "Atari 5200 SuperSystem -- 32 KB" in r_52a and c_52a >= 2 and p_52a[0] < 16707,
             f"a5200 impetus.a52 (32K) runs within 60 Hz NTSC budget (colors={c_52a}, perf={p_52a})")

    r_52b = box.command("a5200 -f 148 -k 138:8 2:/A5200/CAVIT.A52", timeout=120)
    p_52b = parse_perf(r_52b)
    c_52b = unique_pic_colors(box.sim, 336, 240)
    v4.check(p_52b is not None and "Atari 5200 SuperSystem -- 16 KB" in r_52b and c_52b >= 3 and p_52b[0] < 16707,
             f"a5200 cavit.a52 (16K) runs within 60 Hz NTSC budget (colors={c_52b}, perf={p_52b})")

    # 6. Explorer $FFFF .com disambiguation (2:/COMTEST/ADEMO.COM -> atari8, NOT dos!)
    box.t.pending.clear()
    box.t.write(b"explorer 2:/COMTEST\r")
    box.t.wait_for(b"brings the console back", 15)
    box.run(0.6)
    mark = len(box.t.received)
    box.run(kbd.type("{DOWN}\r") + 2.0)   # Row 0 = "..", Row 1 = ADEMO.COM -> Enter launches atari8!
    uart_exp = bytes(box.t.received[mark:]).decode("latin-1")
    box.run(kbd.type("{ESC}") + 0.8)      # Exit atari8 back to explorer
    box.run(kbd.type("{ESC}") + 0.8)      # Exit explorer back to console
    v4.check("Atari 130XE" in uart_exp and "binary executable (.xex)" in uart_exp,
             f"explorer routes $FFFF .com file to atari8 instead of dos ({uart_exp.strip()[:90]!r})")

    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} failure(s):", flush=True)
        for f in v4.failures:
            print(f"  - {f}")
        return 1
    print("\n[PASS] ALL ATARI 800XL/130XE & ATARI 5200 ALISIMULATOR CHECKS PASSED!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
