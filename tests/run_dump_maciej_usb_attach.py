#!/usr/bin/env python3
"""
dump_maciej's own USB host driver against the USB model (usb_host.py): boot
the original firmware, plug the model's high-speed mass-storage stick into
the emulated port (0xB8032000, interrupt-controller line 29) and watch the
SDK's hc_s3602 / hcd_s3602 code do what it does with a real stick: enable
its interrupts, debounce, drive a bus reset, and enumerate the device over
endpoint 0 -- SET_ADDRESS(1), GET_DESCRIPTOR(device) 8 and 18 bytes,
GET_DESCRIPTOR(configuration) 9 and 32 bytes, SET_CONFIGURATION(1) -- then
the mass-storage class's GET MAX LUN, and set up its first bulk-only
command: a 31-byte CBW through the DMA engine (+0x50.. +0x60), where the
model ends (bulk transfers are not modelled).  So the port's and endpoint
0's registers mean what the original driver expects.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for   # noqa: E402

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}", flush=True)
    if not ok:
        failures.append(text)


print("=== dump_maciej's USB driver: a USB stick plugged into the emulated port ===")
t0 = time.time()
sim = AliMipsSimulator(rom_size=flash_size_for("dump_maciej.bin"), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
uart = bytearray()
sim.setUartHandler(lambda ch: uart.extend(ch.encode("latin-1")))
sim.loadFile("dump_maciej.bin")
usb = sim.attach_usb_host()
sim.run(max_instructions=sim.instruction_count + 10 ** 11, max_vtime=70)
check(b"Application version" in uart, "the original application started")
init = [(o, v) for _t, o, _s, v in usb.writes]
check((0x34, 0x90) in init and (0x1E, 0x0F) in init, "its driver set the controller to host mode and enabled interrupts")
mark = len(usb.writes)
usb.attach("high")
sim.run(max_instructions=sim.instruction_count + 10 ** 11, max_vtime=sim._vtime() + 15)
after = usb.writes[mark:]
check(any(o == 0x10 and v & 0x20 for t, o, s, v in after), "the driver drives a bus reset after the stick appears")
check("bus reset done" in [e for _t, e in usb.events], "the model completes the reset")
setups = [p.hex(" ") for _t, p in usb.setups]
want = ["00 05 01 00 00 00 00 00", "80 06 00 01 00 00 08 00", "80 06 00 01 00 00 12 00",
        "80 06 00 02 00 00 09 00", "80 06 00 02 00 00 20 00"]
check(setups[:5] == want, "enumeration: SET_ADDRESS(1), GET_DESCRIPTOR(device) 8 / 18, (configuration) 9 / 32 bytes")
check("00 09 01 00 00 00 00 00" in setups, "SET_CONFIGURATION(1)")
check(setups and setups[-1] == "a1 fe 00 00 00 00 01 00", "then the mass-storage class's GET MAX LUN")
check(any(o == 0x58 and v == 0x1F for t, o, s, v in after) and any(o == 0x60 and v & 1 for t, o, s, v in after),
      "and its first bulk-only command: a 31-byte CBW through the DMA engine (not modelled further)")
print(f"\n{time.time() - t0:.1f} s")
if failures:
    print(f"[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("[PASS] the original driver enumerates the model's USB stick")
