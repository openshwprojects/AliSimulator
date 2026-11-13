"""
Test: the C++ core's native UART transmit log (sim.uart_tx_native, the
DR_UART_TX rule) changes nothing but when the host sees the bytes.

  same     - booting dump.bin for 3 s of emulation time with the log on and
             off: the same UART bytes, the same instruction count and time
             (each logged store is charged like the Python handler it
             replaces)
  bulk     - with uart_bulk_callback the bytes arrive as bytes objects, in
             order, the same stream again
  burst    - a bootloader 'dump' streams 600 KB through the log: what the
             host receives is the flash, byte for byte
"""
import os
import struct
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

from engine_check import CPP, not_applicable           # noqa: E402

if not CPP:
    not_applicable("the C++ core's transmit log (Unicorn calls the UART handler per byte)")

from simulator import AliMipsSimulator, flash_size_for  # noqa: E402

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


def boot(native, bulk=False, vtime=3.0):
    sim = AliMipsSimulator(rom_size=flash_size_for("dump.bin"), log_handler=lambda m: None, engine="cpp")
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    sim.uart_tx_native = native
    out = bytearray()
    chunks = []
    sim.setUartHandler(lambda ch: out.extend(ch.encode("latin-1")))
    if bulk:
        def take(data):
            chunks.append(data)
            out.extend(data)
        sim.uart_bulk_callback = take
    sim.loadFile("dump.bin")
    sim.run(max_instructions=sim.instruction_count + 10 ** 11, max_vtime=vtime)
    return sim, bytes(out), chunks


print("=== C++ core: native UART transmit log ===")
off_sim, off_out, _ = boot(False)
on_sim, on_out, _ = boot(True)
check(len(off_out) > 40 and off_out == on_out, f"the same {len(off_out)} UART bytes with the log on and off")
check(off_sim.instruction_count == on_sim.instruction_count and off_sim._vtime() == on_sim._vtime(),
      f"the same instruction count ({on_sim.instruction_count}) and emulation time")
bulk_sim, bulk_out, chunks = boot(True, bulk=True)
check(bulk_out == off_out and chunks and all(isinstance(c, bytes) for c in chunks),
      f"uart_bulk_callback: the same bytes in {len(chunks)} hand-over(s)")

# a burst: capture the bootloader, ask for its dump, compare the first 600 KB with the flash
sys.path.insert(0, os.path.join(ROOT, "tools"))
from pathlib import Path                                   # noqa: E402
import bootloader_flash_survey as survey                   # noqa: E402

path = Path(ROOT) / "dumps" / "dump.bin"
rom = flash_size_for(str(path))
sim, wire = survey._new_sim(path, rom, deadline=1e18)       # (uart_tx_native on, bulk callback)
cap = survey.capture(wire)
hs = survey.handshake(wire)
check(cap["captured"] and hs["protocol"] == "classic", "the bootloader is captured and answers the handshake")
wire.write(b"dump\r")
echo = wire.read(5, 2.0)
size = struct.unpack(">I", wire.read(4, 2.0))[0]
wire.write(b"O")
data = bytearray()
while len(data) < 600_000:
    part = wire.read(600_000 - len(data), 60.0)
    if not part:
        break
    data += part
check(echo == b"dump\r" and size == rom and bytes(data) == bytes(sim.rom_image[:len(data)]),
      f"'dump' streams the flash through the log: {len(data)} bytes as in the flash")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] the native transmit log is transparent")
