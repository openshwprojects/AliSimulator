#!/usr/bin/env python3
"""
The Ferguson Ariva 153 Combo firmware V1.28B3 (an M3503 / M3516 dual-CPU combo
receiver: chips/m3503.py with chip word 0x35030001) runs its XIP cache-as-RAM
bootloader ("HSJU", version "39015-01047") up to the point where the board's
security IC has to decrypt the first 1 KB of the main code.

The bootloader runs from the flash window with its initial stack in
cache-as-RAM (0x8FFF8000..0x8FFFFFFF), jumps to its RAM copy at 0x80C985C4,
writes " On " to its FD650K front panel (I2C on SCL = GPIO 135, SDA = GPIO
134), unpacks the LZO1X-compressed seecode chunk (2,976,604 bytes at
0x81202000 via lzo1x_decompress_safe at 0x80C86348), and sends the parked SEE
to its boot stub at 0xA0C938F8, which copies the SEE program to 0xA6000200
(entry 0x86001000), sets the started flag and parks again.  Then it sends the
first 1 KB of the maincode chunk (0x30080), 16 bytes at a time, over a
bit-banged I2C bus (SCL = GPIO 7, SDA = GPIO 8: the sidecar's gpioI2c) to the
security IC at 0x62: each 26-byte request is 0xA2, seven fixed bytes
(42 29 14 e6 fa 9f 15), 16 encrypted bytes and a CRC-16/BUYPASS of the 24
bytes before it; 26 bytes are read back per block.  Without the real chip's
plaintext, LzmaDecode() at 0x80C9B780 unpacks 0 bytes to 0x80000200 and the
bootloader jumps to an empty 0x80000200.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from uc_const import UC_MIPS_REG_PC

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for, resolve_dump

DUMP = "A153Combo_20150320_V1.28B3.abs"
LIMIT = 25_000_000
SLICE = 5_000_000
MAIN_ENTRY = 0x80000200
SECURITY_IC = 0x62
MAINCODE_DATA = 0x30080
BLOCKS = 64
SEE_BOOT = "[SEE] started at 0xA0C938F8: its boot code parked"

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
    and answers reads with zeros (the real chip's answers are not known)."""

    def __init__(self):
        self.writes = []
        self.read_bytes = 0

    def write(self, data):
        self.writes.append(bytes(data))
        return True

    def read(self, n):
        self.read_bytes += n
        return bytes(n)


print(f"=== Ferguson Ariva 153 Combo ({DUMP}): the bootloader up to the security IC's decryption ===")
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

check(type(sim.chip).__name__ == "M3503" and sim.chip.chip_id == 0x3503,
      f"runs as the M3503 family with chip ID 0x3503 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check(any(type(d).__name__ == "GpioI2cBus" for d in sim.gpio_devices),
      "the sidecar's gpioI2c bus (SCL 7 / SDA 8) is attached")

while sim.instruction_count < LIMIT and (sim.mu.reg_read(UC_MIPS_REG_PC) & ~1) != MAIN_ENTRY:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    if sim.instruction_count <= before:
        break
pc = sim.mu.reg_read(UC_MIPS_REG_PC)
print(f"stopped after {sim.instruction_count / 1e6:.1f} M instructions at PC 0x{pc:08X}")

check(any(m.startswith("[CAR] the bootloader runs from RAM") for m in log),
      "the XIP bootloader switches from cache-as-RAM to its RAM copy at 0x80C985C4")
check(panel.get_display_text() == " On ",
      f"it writes \" On \" to its FD650K front panel on GPIO 135 / 134 (got {panel.get_display_text()!r})")
check(any(m.startswith(SEE_BOOT) for m in log),
      "it sends the parked SEE to its boot stub at 0xA0C938F8, which copies seecode and parks again")
see_entry = bytes(sim.mu.mem_read(0x86001000, 16))
check(see_entry[:4] == bytes.fromhex("00800840"),
      f"the SEE's unpacked program sits at 0x86001000 ({see_entry[:8].hex()})")

# the decryption requests: 0xA2, 7 fixed bytes (422914e6fa9f15), 16 bytes of maincode, CRC-16/BUYPASS
requests = [w for w in ic.writes if len(w) == 26 and w[0] == 0xA2]
check(len(requests) == BLOCKS, f"it sends {BLOCKS} decryption requests to the security IC at 0x{SECURITY_IC:02X} "
      f"(got {len(requests)}, {len(ic.writes)} writes, {ic.read_bytes} bytes read back)")
fixed = {w[1:8] for w in requests}
check(fixed == {bytes.fromhex("422914e6fa9f15")},
      f"every request carries the 7-byte header 422914e6fa9f15 ({' / '.join(f.hex() for f in fixed)})")
blocks_ok = all(w[8:24] == image[MAINCODE_DATA + 16 * i:MAINCODE_DATA + 16 * (i + 1)] for i, w in enumerate(requests))
check(bool(requests) and blocks_ok, f"request i carries the main code's encrypted bytes at 0x{MAINCODE_DATA:X} + 16 i "
      "(the first 1 KB of the chunk, in order)")
crc_ok = all(int.from_bytes(w[24:26], "big") == crc16_buypass(w[:24]) for w in requests)
check(bool(requests) and crc_ok, "each request ends in the CRC-16/BUYPASS of its first 24 bytes")

# LZO1X decode of seecode + LzmaDecode() of the empty maincode buffer
lzo_decs = getattr(sim, "lzo1x_decodes", [])
check(len(lzo_decs) == 1 and len(sim.lzma_decodes) == 1,
      f"the bootloader runs LZO1X (seecode) and LzmaDecode (maincode) (got {len(lzo_decs)} LZO1X, {len(sim.lzma_decodes)} LZMA)")
if lzo_decs and sim.lzma_decodes:
    _e0, src0, dst0, size0 = lzo_decs[0]
    check(dst0 == 0x81202000 and size0 == 2976604,
          f"LZO1X unpacks 2,976,604 bytes of seecode to 0x81202000 (got {size0} bytes at 0x{dst0:08X})")
    _e1, src1, dst1, size1 = sim.lzma_decodes[0]
    check(dst1 == 0x80000200 and size1 == 0,
          f"LzmaDecode() to 0x80000200 yields 0 bytes without the security IC's plaintext (got {size1} bytes at 0x{dst1:08X})")
entry = bytes(sim.mu.mem_read(MAIN_ENTRY, 64))
check((pc & ~1) == MAIN_ENTRY and not any(entry),
      f"and jumps to 0x{MAIN_ENTRY:08X}, where the RAM is empty (stopped at 0x{pc:08X}: a breakpoint)")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] the Ariva 153 Combo's bootloader unpacks seecode, drives its FD650K panel, and reaches the security IC's decryption")
