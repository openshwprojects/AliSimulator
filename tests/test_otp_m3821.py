"""
Fast check of the M3821 family's OTP controller model (chips/m3821.Otp at
0xB8042000), no firmware run: the Ferguson T750i image's OTP reads blank (its
sidecar gives no device.otp), and the driver's sequences work as the
firmware's OTP driver uses them -- a burn (+04 = the byte address, +08 = the
byte, +0C |= 1) sets bits in the byte and reports done, a read (+04, +0C |=
0x100) puts the word at the address into +18, and the command's start bits
read back clear.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from simulator import AliMipsSimulator, flash_size_for, resolve_dump

ok = True


def check(cond, msg):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    ok &= bool(cond)


def write(sim, offset, value, size=4):
    """A guest store to the OTP block: the model's write hook, then the memory."""
    address = 0xB8042000 + offset
    stored = value
    for h in sim._mmio_wr.get(address & 0xFFFFFF, []):
        r = h(sim.mu, 0, address, size, value, None)
        if r is not None:
            stored = r
    sim.mu.mem_write(address, stored.to_bytes(size, 'little'))


def read(sim, offset, size=4):
    return int.from_bytes(sim.mu.mem_read(0xB8042000 + offset, size), 'little')


def read_word(sim, address):
    write(sim, 0x04, address)
    write(sim, 0x0C, read(sim, 0x0C) | 0x100)
    return read(sim, 0x18)


print("=== Test: the M3821's OTP controller model ===")
dump = "Ferguson_T750i_V1.20B2_18092019.abs"
sim = AliMipsSimulator(rom_size=flash_size_for(resolve_dump(dump)), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setUartHandler(lambda c: None)
sim.loadFile(dump)
otp = getattr(sim.chip, "otp", None)
check(otp is not None and not any(otp.data), "the T750i's chip (an M3821) has a blank OTP")
check(read_word(sim, 0x1C0) == 0 and read(sim, 0x0C) & 0x101 == 0,
      "a read of its signature's first word (0x1C0) gets 0, and the start bit clears")
for byte in (0x5A, 0x81):
    write(sim, 0x04, 0x1C1)
    write(sim, 0x08, byte, 1)
    write(sim, 0x0C, read(sim, 0x0C) | 1)
check(otp.data[0x1C1] == 0xDB and otp.burns == 2 and read(sim, 0x14) & 1 == 0,
      "two burns of 0x1C1 set its bits (0x5A | 0x81 = 0xDB) and report done")
check(read_word(sim, 0x1C0) == 0xDB00 and read(sim, 0x10) & 0x101 == 0,
      "the word read back holds the burnt byte (0x0000DB00); nothing reads busy")
print(f"\n[{'PASS' if ok else 'FAIL'}] M3821 OTP controller")
sys.exit(0 if ok else 1)
