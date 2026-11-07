#!/usr/bin/env python3
"""
The Ferguson Ariva 102E firmware V1.27B3 (an M3606-class dual-CPU satellite
receiver with smartcard slot: chips/m3602.py with chip ID 0x3603) runs its
bootloader ("HS17", version 37017-01047) up to the point where the board's
security IC at I2C 0x62 (bit-banged on SCL = GPIO 44, SDA = GPIO 43) decrypts
the first 1 KB (64 x 16-byte blocks, each protected by CRC-16/BUYPASS) of the
maincode chunk at 0x20080.

The bootloader prints "APP  init!", sends the parked SEE to its boot stub at
0xA1E90C60, updates its 3-wire PT6964 front panel (STB = GPIO 39, CLK = 38,
DIO = 40), unpacks the SEE's program, exchanges 64 decryption requests with
I2C 0x62, calls LzmaDecode() to unpack maincode to 0x80000200, and jumps to
0x80000200.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from unicorn.mips_const import UC_MIPS_REG_PC

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for, resolve_dump

DUMP = "FERGUSON ARIVA 102E/A102E_20150324_V1.27B3.abs"
LIMIT = 30_000_000
SLICE = 5_000_000
MAIN_ENTRY = 0x80000200
SECURITY_IC = 0x62
MAINCODE_DATA = 0x20080
BLOCKS = 64
SEE_BOOT = "[SEE] started at 0xA1E90C60: its boot code parked"

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


def crc16_buypass(data):
    """CRC-16/BUYPASS: polynomial 0x8005, initial 0, MSB first, no final XOR."""
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x8005) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


class SecurityIcStandIn:
    """Acknowledges every byte at its address, records the write transactions
    and answers reads with zeros."""

    def __init__(self):
        self.writes = []
        self.read_bytes = 0

    def write(self, data):
        self.writes.append(bytes(data))
        return True

    def read(self, n):
        self.read_bytes += n
        return bytes(n)


print(f"=== Ferguson Ariva 102E ({DUMP}): bootloader up to security IC decryption ===")
image = open(resolve_dump(DUMP), "rb").read()
log = []
uart = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=log.append)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
panel, _keys, panel_desc = make_panel(DUMP, log_handler=lambda m: None)
panel.dump_enabled = False
sim.setGpioHandler(panel.on_gpio_write)
sim.loadFile(DUMP)
ic = SecurityIcStandIn()
sim.i2c_devices[SECURITY_IC] = ic
sim.addBreakpoint(MAIN_ENTRY)
print(f"front panel: {panel_desc}")

check(type(sim.chip).__name__ == "M3602" and sim.chip.chip_id == 0x3603,
      f"runs as the M3602 family with chip ID 0x3603 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check(any(type(d).__name__ == "GpioI2cBus" for d in sim.gpio_devices),
      "the sidecar's gpioI2c bus (SCL 44 / SDA 43) is attached")

while sim.instruction_count < LIMIT and (sim.mu.reg_read(UC_MIPS_REG_PC) & ~1) != MAIN_ENTRY:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    if sim.instruction_count <= before:
        break
pc = sim.mu.reg_read(UC_MIPS_REG_PC)
print(f"stopped after {sim.instruction_count / 1e6:.1f} M instructions at PC 0x{pc:08X}")
text = "".join(uart)

check("APP  init!" in text, "the bootloader prints \"APP  init!\"")
check(any(m.startswith(SEE_BOOT) for m in log), "it sends the parked SEE to its boot code at 0xA1E90C60, which parks it again")
check(panel.frame_count > 0 and any(panel.ram), f"it writes its PT6964 front panel ({panel.frame_count} frames, "
      f"RAM {' '.join(f'{b:02x}' for b in panel.ram[:8])})")

requests = [w for w in ic.writes if len(w) == 26 and w[0] == 0x37]
check(len(requests) == BLOCKS, f"it sends {BLOCKS} decryption requests to the security IC at 0x{SECURITY_IC:02X} "
      f"(got {len(requests)}, {len(ic.writes)} writes, {ic.read_bytes} bytes read back)")
fixed = {w[1:8] for w in requests}
check(len(fixed) == 1, f"every request carries the same 7 bytes after the command ({' / '.join(f.hex() for f in fixed)})")
blocks_ok = all(w[8:24] == image[MAINCODE_DATA + 16 * i:MAINCODE_DATA + 16 * (i + 1)] for i, w in enumerate(requests))
check(bool(requests) and blocks_ok, f"request i carries the main code's encrypted bytes at 0x{MAINCODE_DATA:X} + 16 i "
      "(the first 1 KB of the chunk, in order)")
crc_ok = all(int.from_bytes(w[24:26], "big") == crc16_buypass(w[:24]) for w in requests)
check(bool(requests) and crc_ok, "each request ends in the CRC-16/BUYPASS of its first 24 bytes")

check(len(sim.lzma_decodes) == 1, f"the bootloader then calls LzmaDecode() once (got {len(sim.lzma_decodes)})")
if sim.lzma_decodes:
    _entry, src, dst, size = sim.lzma_decodes[0]
    check(dst == 0x80000200, f"to unpack the main code to its entry 0x80000200 (output 0x{dst:08X}, input 0x{src:08X})")
    check(size == 0, f"which yields nothing without the security IC's plaintext ({size} bytes)")
entry = bytes(sim.mu.mem_read(MAIN_ENTRY, 64))
check((pc & ~1) == MAIN_ENTRY and not any(entry),
      f"and jumps to 0x{MAIN_ENTRY:08X}, where the RAM is empty (stopped at 0x{pc:08X}: a breakpoint)")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] the Ariva 102E's bootloader reaches the security IC's decryption of its main code")
