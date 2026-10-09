#!/usr/bin/env python3
"""A remote-control key reaches the Opticum Blue R265 Lite firmware: the M3821 application
configures the same M6303 IR controller (0xB8018100, interrupt line 19) as the M3801 boxes,
press_key() finds its key table in RAM, and its interrupt handler drains the run-length
FIFO and acknowledges the controller.  (That a key moves the home menu's highlight is
checked by the slow run_dump_r265lite_capture_screen.py.)
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

from simulator import AliMipsSimulator

DUMP = "T2GEN265_1.1.5-2022-08-01.abs"
BOOT_INSTRUCTIONS = 40_000_000          # the application has configured its IR controller by then (fast-mode estimate)
AFTER_KEY_INSTRUCTIONS = 10_000_000

print(f"=== Regression Test: {DUMP}: a MENU key reaches the firmware ===")
sim = AliMipsSimulator(log_handler=lambda msg: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.loadFile(DUMP)
start = time.time()
sim.run(max_instructions=BOOT_INSTRUCTIONS)
print(f"booted in {time.time() - start:.1f}s")

address, command = sim.press_key("MENU")
print(f"MENU = NEC 0x{address:02X} / 0x{command:02X} from the application's key table")
sim.run(max_instructions=sim.instruction_count + AFTER_KEY_INSTRUCTIONS)

checks = [
    ("the frame was received by the IR controller", sim.ir_keys_sent == 1),
    ("the firmware drained the run-length FIFO", not sim._irc_fifo),
    ("the firmware acknowledged the controller's interrupt", sim._irc_status == 0),
]
ok = True
for what, hit in checks:
    print(f"  [{'PASS' if hit else 'FAIL'}] {what}")
    ok &= hit
print(f"\n[{'PASS' if ok else 'FAIL'}] a remote key reaches the R265 Lite firmware ({time.time() - start:.1f}s)")
sys.exit(0 if ok else 1)
