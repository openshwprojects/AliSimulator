#!/usr/bin/env python3
"""
The Opticum 4000A / Globo 7010A 2 MB parallel-NOR flash dump (maincode
2008-03-19, ALi M3329C / M3101, chips/m3329.py) boots from parallel NOR flash
at 0xAFC00000 with chip ID 0x3101, unpacks its LZMA maincode(AV) into SDRAM
("APP  init ok", "main emu init", "max_key_db_count = 442"), enters its saved
standby clock "1737" on its 74HC164 4-digit panel (GPIO 16..21), and on IR
POWER updates parallel NOR flash, resets VPO_M3327, soft-reboots to channel
"OOO1", and renders its 720x576 8 bpp CLUT OSD in direct-framebuffer mode.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import numpy as np

import gma_capture
from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "OPTICUM 4000A/DumpFlash Opticum4000a(Globo7xxx)4,5w.bin"
LIMIT = 300_000_000
SLICE = 2_500_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Opticum 4000A / Globo 7010A (M3329 parallel NOR) boots and wakes from standby ===")
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

woke = False
t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    txt = panel.get_display_text()
    if txt.strip() and (not seen_panels or seen_panels[-1] != txt):
        seen_panels.append(txt)
    if not woke and txt == "1737":
        woke = True
        sim.press_key("POWER")
    if woke and txt == "OOO1":
        osd_ctrl = int.from_bytes(sim.peek(0xB80041A0, 4), "little")
        osd_stride = int.from_bytes(sim.peek(0xB80041A8, 4), "little")
        if (osd_ctrl & 1) and osd_stride == 0x02D00240:
            break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
print(f"\nStopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), panel history {seen_panels}")
text = "".join(uart)

check(type(sim.chip).__name__ == "M3329" and chip_id == 0x3101,
      f"detected as M3329 with chip ID 0x3101 (got {type(sim.chip).__name__}, 0x{chip_id:04X})")
check(sim.flash_device is not None,
      f"parallel NOR flash attached at 0xAFC00000 (flash_device={type(sim.flash_device).__name__ if sim.flash_device else None})")
for expected in ("APP  init ok", "main emu init", "TPSKeyDB Initing... 0", "max_key_db_count = 442"):
    check(expected in text, f"{expected!r} printed on UART")
check(" ON " in seen_panels and "1737" in seen_panels and "OOO1" in seen_panels,
      f"front panel ({panel_desc}) showed standby '1737' then woke to 'OOO1' (got {seen_panels})")
check(sim.chip.video_output.resets >= 1,
      f"VPO_M3327 reset on soft reboot (resets={sim.chip.video_output.resets})")
regions = gma_capture.m3327_regions(np.frombuffer(sim._ram_view, np.uint8), sim.peek(0xB8000000, 0x10000))
check(len(regions) == 1 and regions[0][1]["header"] is None and regions[0][1]["width"] == 720 and regions[0][1]["height"] == 576,
      f"OSD_M3327_0 configured 720x576 direct framebuffer ({regions})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Opticum 4000A / Globo 7010A (M3329 parallel NOR) boots and wakes from standby")
