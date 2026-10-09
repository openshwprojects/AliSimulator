"""
Signal regression for the Globo STB HD N3 (slow, about 4 minutes): boots
"Ali_3801_Globo_DVBT_dump SPI 4mb.bin" with sim.set_signal(True) -- its
sidecar's tuner, a Rafael R820T at I2C 0x1A (tuners.py), on the I2C bus, and
the M3801's internal demodulator reporting lock (chips/m3801.py).  The
application tunes its last channel at start: the R820T driver's filter
calibration and PLL check see the chip calibrated and locked at the first
try, the demodulator's get_lock() (register 0x1D bit 5) reports lock, so
after the channel banner ("41. WP", which times out) the screen stays clear:
no red "Brak sygnału" (no signal) box, which the same boot without a signal
draws at about 900 GE commands (run_dump_globo_capture_screen.py's expected
screen).  There is no transport stream behind the lock, so the picture is
black.  The final screen goes to the report.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

import numpy as np

import gma_capture
import report_artifacts
from simulator import AliMipsSimulator, flash_size_for

DUMP = "Ali_3801_Globo_DVBT_dump SPI 4mb.bin"
BANNER_OPS = 590                # the channel banner is drawn by then
END = 240_000_000               # well past the point the no-signal box appears without a signal

print(f"=== Signal regression: {DUMP} with a tuner and demodulator lock ===")
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(lambda c: None)
sim.loadFile(DUMP)
tuner, demod = sim.set_signal(True)
print(f"tuner model: {type(tuner).__name__ if tuner else None}, demodulator modelled: {demod}")
start = time.time()
banner_seen = False
while sim.instruction_count < END:
    sim.run(max_instructions=sim.instruction_count + 5_000_000)
    banner_seen |= sim.ge_ops >= BANNER_OPS
rgb = sim.capture_screen()
out = report_artifacts.path("globo_signal_screen.png")
gma_capture.save_png(out, rgb)
report_artifacts.image(out, f"screen at {sim.instruction_count:,} instructions with a signal: "
                            f"{sim.ge_ops} GE commands")
red = int(((rgb[:, :, 0] > 200) & (rgb[:, :, 1] < 60) & (rgb[:, :, 2] < 60)).sum())
print(f"{time.time() - start:.0f}s, {sim.instruction_count:,} instructions, {sim.ge_ops} GE commands, "
      f"R820T reads by length {dict(tuner.reads) if tuner else '-'}, demodulator lock reads {sim.chip.demod.lock_reads}")

ok = True


def check(cond, msg):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    ok &= bool(cond)


check(type(tuner).__name__ == "R820T", "set_signal attached the sidecar's tuner, an R820T")
check(tuner is not None and tuner.reads[5] >= 1, "the R820T driver ran its filter calibration (5-byte status reads)")
check(tuner is not None and tuner.reads[3] >= 1 and tuner.regs[0x12] & 0xE0 != 0x60,
      "the driver checked the PLL and found it locked (it never raised the VCO current, register 0x12)")
check(sim.chip.demod.lock_reads > 0, f"the demodulator's lock register was read ({sim.chip.demod.lock_reads} times)")
check(banner_seen, f"the channel banner was drawn ({BANNER_OPS}+ GE commands)")
check(red == 0, f"no red \"Brak sygnału\" box on the screen ({red} red pixels)")
print(f"\n[{'PASS' if ok else 'FAIL'}] Globo STB HD N3 with a signal ({time.time() - start:.0f} s)")
sys.exit(0 if ok else 1)
