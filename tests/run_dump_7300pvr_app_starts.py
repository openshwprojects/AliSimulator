#!/usr/bin/env python3
"""
The Opticum 7300 PVR CI2CX 4 MB SPI flash dump (firmware 1.0.78, ALi M3329E,
chips/m3329.py) auto-selects chip ID 0x3329 and SPI flash mode, boots its
3329EA 1.1.2 bootloader ("APP  init ok"), unpacks its 3.94 MB LZMA maincode to
SDRAM ("Starting mcas v.1.0 compiled Sep  4 2009"), decodes its boot logo via
M3329E's VideoEngine at 0xB8013200 (IC line 12), renders its OSD via GE_M36 at
0xB800E000 into OSD_S36 regions in the 0x00800000 SDRAM segment, and drives its
8-character 14-segment PT6312 VFD on GPIO 3 (CLK) / 2 (DIO) / 4 (STB) through
"  BOOT  " -> "   ON   " -> "--------" -> "1PLUS1  ".
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "OPTICUM 7300 PVR/7300PVR.bin"
LIMIT = 60_000_000
SLICE = 2_500_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Opticum 7300 PVR CI2CX 1.0.78 (M3329E) boots into its application ===")
uart = []
seen_panels = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
panel, _keys, panel_desc = make_panel(DUMP, log_handler=lambda m: None)
panel.dump_enabled = False


def on_uart(c):
    ch = c if isinstance(c, str) else chr(c)
    uart.append(ch)
    if len(uart) <= 1200 and ch.isascii():
        sys.stdout.write(ch)
        sys.stdout.flush()


sim.setGpioHandler(panel.on_gpio_write)
sim.setUartHandler(on_uart)
sim.loadFile(DUMP)
chip_id = int.from_bytes(sim.peek(0xB8000002, 2), "little")

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    txt = panel.get_display_text()
    if txt.strip() and (not seen_panels or seen_panels[-1] != txt):
        seen_panels.append(txt)
    if txt == "1PLUS1  " and sim.ge_ops >= 5:
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
print(f"\nStopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), panel history {seen_panels}")
text = "".join(uart)

check(type(sim.chip).__name__ == "M3329" and chip_id == 0x3329,
      f"detected as M3329 with M3329E chip ID 0x3329 (got {type(sim.chip).__name__}, 0x{chip_id:04X})")
check(sim.flash_device is None,
      f"SPI flash detected by bootloader SF_INS stores (flash_device={sim.flash_device})")
for expected in ("APP  init ok", "dmx_m33_start", "Starting mcas v.1.0"):
    check(expected in text, f"{expected!r} printed on UART")
check(sim.chip.video_engine.pictures >= 1,
      f"M3329E VideoEngine at 0xB8013200 decoded boot logo ({sim.chip.video_engine.pictures} picture(s))")
check(sim.ge_ops >= 5,
      f"M3329E GE_M36 at 0xB800E000 executed OSD blits ({sim.ge_ops} command(s))")
check("  BOOT  " in seen_panels and "1PLUS1  " in seen_panels,
      f"PT6312 14-seg VFD ({panel_desc}) showed '  BOOT  ' -> '1PLUS1  ' (got {seen_panels})")
ok_frame = sim.chip.remote_frame("OK")
check(ok_frame is not None, f"remote key OK resolved from Libcore key table ({ok_frame})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Opticum 7300 PVR CI2CX 1.0.78 (M3329E) boots into its application")
