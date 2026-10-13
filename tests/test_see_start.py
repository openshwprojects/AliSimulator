#!/usr/bin/env python3
"""
The SEE co-processor (src/chips/see.py) on a simulator with the M3602 family
installed, without firmware.

The start handshake, driven by register writes the way the URZ0086's
bootloader makes them, with run_program cleared: park the SEE (0x200 =
0xB8000280), let it run (0x220 bits 9 and 1), clear the started flag, send
it to boot code in RAM -- which copies a block, writes 0xB8000280 to 0x200,
sets the flag and jumps back to the park loop -- then send it to a program
that does not park.  Checks that the boot code runs on the SEE's own
instance and leaves exactly its effects after the main CPU's start store (at
its next look at the SEE's registers, or at the end of its slice), that the
program is not run, and that 0x200 writes are mailbox data after that.  Then
the handshake once more with the start store replayed (re-executed after an
asynchronous stop at it): the replay lands before the SEE runs -- the slice
that stopped on the store does not start it either --, so the boot code's
0xB8000280 stays in 0x200.

The doorbells in both register layouts (the M3602's chip ID: ring +0x36,
acknowledge +0x37 bits 3 / 2; the M3503's: ring +0x37 bits 3 / 2,
acknowledge +0x37 bits 7 / 6, a plain byte store that keeps the CPU's own
rings).

The SEE's program on the second core (run_program, the default): a small
program that writes RAM, reads its EBase CPU number, rings the main CPU and
idles in `b .`, while the main CPU runs slices of its own; then the main
CPU's acknowledge ends the ring.  And the random number generator the SEE's
program reads (see.Trng): a new result per start.
"""
import os
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_SP

from chips import see as see_mod
from chips.m3503 import M3503
from chips.m3602 import M3602
from simulator import AliMipsSimulator

failures = 0


def check(ok, text):
    global failures
    failures += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")


def asm(*words):
    return struct.pack(f"<{len(words)}I", *words)


print("=== Test: the SEE start handshake (chips/see.py) ===")
check(see_mod.parks(asm(0x3C09B800, 0x35290280, 0x01200008, 0)), "parks(): lui t1, 0xB800 / ori t1, t1, 0x280 is boot code that parks")
check(not see_mod.parks(asm(0x3C09B800, 0x35290284, 0x01200008, 0)), "parks(): another register address is not")
check(not see_mod.parks(asm(*([0] * 16))), "parks(): nops are not")

sim = AliMipsSimulator(log_handler=lambda m: None)
sim._switch_family(M3602)
see = sim.chip.see
check(see.run_program, "the SEE's program runs on the second core by default")
see.run_program = False                 # (the handshake: the program is not run)

# The SEE's boot code at 0x81000000: copy 4 words 0x81100000 -> 0x81200000, then park (as the
# URZ0086's trampoline does: 0x200 = 0xB8000280, 0x20C |= 1, jr 0xB8000280)
boot = asm(0x3C058110, 0x3C048120, 0x24060004,                  # a1 = src, a0 = dst, a2 = 4 words
           0x8CA20000, 0xAC820000, 0x24A50004, 0x24840004,      # loop: lw v0,(a1); sw v0,(a0); a1+=4; a0+=4
           0x24C6FFFF, 0x14C0FFFA, 0x00000000,                  #       a2--; bnez a2, loop
           0x3C08B800, 0x3C09B800, 0x35290280, 0xAD090200,      # 0x200 = 0xB8000280
           0x9109020C, 0x35290001, 0xA109020C,                  # 0x20C |= 1
           0x3C09B800, 0x35290280, 0x01200008, 0x00000000)      # jr 0xB8000280
sim.mu.mem_write(0x81000000, boot)
sim.mu.mem_write(0x81100000, asm(0x11111111, 0x22222222, 0x33333333, 0x44444444))
program = asm(*([0] * 64))                                      # the SEE's own program: no park
sim.mu.mem_write(0x81300000, program)


def write(offset, value, size=4):
    """A store by the main CPU to the system register block (as _mmio_write delivers it)."""
    sim._mmio_write(sim.mu, offset, size, value, None)


def word(offset):
    return int.from_bytes(sim.peek(0xB8000000 + offset, 4), "little")


def byte(offset):
    return sim.peek(0xB8000000 + offset, 1)[0]


def look():
    """The main CPU's next look at the SEE's registers: a read of the started flag."""
    return sim._mmio_read(sim.mu, 0x20C, 1, None)


def slice_end():
    """The end of one of the main CPU's slices: run() calls its slice services."""
    for service in sim.slice_services:
        service()


def handshake(target):
    """The bootloader's start of the SEE: park it (0x200 = 0xB8000280), let it run (0x220 bits 9
    and 1), clear the started flag, send it to `target`."""
    write(0x200, see_mod.PARK)
    write(0x220, word(0x220) | 0x202)
    write(0x20C, word(0x20C) & ~1, 4)
    write(0x200, target)


def reset_see():
    """0x220 bit 1 cleared: the SEE held in reset."""
    write(0x220, word(0x220) & ~0x02, 1)


write(0x200, 0xB8000280)
check(see.state == "reset", "the SEE starts out in reset")
write(0x220, word(0x220) | 0x202)
check(see.state == "parked", "0x220 bit 1 set with 0x200 = 0xB8000280: the SEE runs and parks")
write(0x20C, word(0x20C) & ~1, 4)
write(0x200, 0xA1000000)
check(see.starts == [] and word(0x200) == 0xA1000000, "0x200 = the boot code: the main CPU's store lands first")
flag = look()
check(see.starts == [(0xA1000000, "parked")], f"the main CPU's next look runs the boot code, which parks ({see.starts})")
check(flag & 1 == 1, "that read already sees the started flag the boot code set")
check(word(0x200) == 0xB8000280, "the boot code wrote 0xB8000280 back to 0x200")
check(sim.peek(0x81200000, 16) == asm(0x11111111, 0x22222222, 0x33333333, 0x44444444),
      "the boot code's copy landed in the shared RAM")
check(see.state == "parked", "the SEE is parked again")
write(0x200, 0xA1300000)
look()
check(see.state == "running" and see.starts[-1][0] == 0xA1300000 and "not run" in see.starts[-1][1],
      f"0x200 = a program that does not park: not run, the SEE counts as running ({see.starts[-1]})")
n = len(see.starts)
write(0x200, 0x18)
check(len(see.starts) == n, "0x200 writes while the SEE runs its program are mailbox data, not starts")
reset_see()
check(see.state == "reset", "0x220 bit 1 cleared: the SEE is in reset")

# The handshake again, the main CPU's slice ending before its next look: the SEE starts then
handshake(0xA1000000)
n = len(see.starts)
slice_end()
check(see.starts[n:] == [(0xA1000000, "parked")] and word(0x20C) & 1 and word(0x200) == 0xB8000280,
      f"the end of the main CPU's slice runs the boot code too ({see.starts[n:]})")
reset_see()

# The handshake again, with an asynchronous stop that leaves the PC on the start store: the
# simulator runs that store again on resume (a replay, simulator._dev_note), which must land
# before the SEE runs -- run in the replay's handler, or at the end of the slice that stopped
# on the store, the boot code's 0xB8000280 was overwritten with the start address by the store
# landing after it
handshake(0xA1000000)
n = len(see.starts)
key = (sim.mu.reg_read(UC_MIPS_REG_PC), sim.mu.reg_read(UC_MIPS_REG_SP))
sim._dev_replays[key] = sim._dev_last[0:3]      # what the emu_start wrapper records at such a stop
slice_end()
check(len(see.starts) == n, "the slice that stopped on the start store ends: no start yet, the store runs again first")
write(0x200, 0xA1000000)                        # the replay
check(len(see.starts) == n and word(0x200) == 0xA1000000,
      "a replayed start store lands again before the SEE runs (no start yet)")
look()
check(see.starts[n:] == [(0xA1000000, "parked")] and word(0x200) == 0xB8000280,
      f"the next look runs the boot code once, and its 0xB8000280 stays in 0x200 ({see.starts[n:]}, "
      f"0x{word(0x200):08X})")
reset_see()

# The doorbells, the M3602's layout: the SEE rings in its +0x36 byte, the main CPU acknowledges
# with bit 3 / 2 of its own +0x37 byte (stores the simulator delivers like the main CPU's)
print("\n--- the doorbells (see.Doorbells) ---")
sim.poke(0xB800003F, b"\xC0")                   # the main CPU's doorbell lines 63 / 62 enabled
sim.poke(0xB804003F, b"\xC0")                   # the SEE's
sim.doorbell_in = see_mod.Doorbells.ring(0x3602, see_mod.SEE_IC)
write(0x40036, 0x80, 1)                         # the SEE rings channel 1
check(sim.doorbell_in == (0x40036, 0) and sim._doorbell_ip3(),
      "chip 0x3602: the SEE's ring in 0xB8040036 bit 7 interrupts the main CPU (IP3)")
write(0x37, 0x08, 1)                            # the main CPU acknowledges channel 1
check(byte(0x40036) == 0 and byte(0x37) == 0 and not sim._doorbell_ip3(),
      "chip 0x3602: 0xB8000037 bit 3 ends the ring and does not stay set "
      f"(0x{byte(0x40036):02X}, 0x{byte(0x37):02X})")
write(0x37, 0x08, 1)                            # once more, nothing rung
check(see.doorbells.taken == {"main": [1, 0], "SEE": [0, 0]},
      f"the acknowledge that ended a ring counts a call the main CPU took, the other none ({see.doorbells.taken})")
sim.doorbell_in = None

# The SEE's own program on the second core (run_program): it writes a marker and its EBase to
# RAM, rings the main CPU and idles; the main CPU runs a `b .` of its own meanwhile
print("\n--- the SEE's program on the second core (see.SeeCore) ---")
see.run_program = True
sim.mu.mem_write(0x81400000, asm(0x3C088150,                    # lui t0, 0x8150
                                 0x240905EE, 0xAD090000,        # 0x81500000 = 0x5EE
                                 0x400A7801, 0xAD0A0004,        # 0x81500004 = EBase (mfc0 t2, $15, 1)
                                 0x3C0BB804, 0x240C0080,        # 0xB8040036 = 0x80: ring channel 1
                                 0xA16C0036,
                                 0x1000FFFF, 0x00000000))       # b .
sim.mu.mem_write(0x81600000, asm(0x1000FFFF, 0x00000000))       # the main CPU's b .
handshake(0x81400000)
slice_end()
check(see.core is not None and see.starts[-1] == (0x81400000, "run on the SEE core"),
      f"a program that does not park: the second core runs it ({see.starts[-1]})")
sim.mu.reg_write(UC_MIPS_REG_PC, 0x81600000)
sim.run(max_instructions=sim.instruction_count + 400_000)
core = see.core.core if see.core else None
marker, ebase = struct.unpack("<2I", bytes(sim.peek(0x81500000, 8)))
check(marker == 0x5EE, f"the SEE's stores land in the shared RAM (0x{marker:X})")
check(ebase == 0x80000001, f"the SEE reads its CPU number 1 in EBase (0x{ebase:08X})")
check(core is not None and core.i2c_devices is sim.i2c_devices,
      "the SEE core's I2C masters reach the first core's devices (one bus, the board's chips on it)")
check(core is not None and core.mu.reg_read(UC_MIPS_REG_PC) == 0x81400020,
      f"the SEE idles in its b . (PC 0x{core.mu.reg_read(UC_MIPS_REG_PC) if core else 0:08X})")
check(sim.doorbell_in == (0x40036, 0) and byte(0x40036) == 0x80 and sim._doorbell_ip3(),
      "the SEE's ring interrupts the main CPU")
write(0x37, 0x08, 1)
check(byte(0x40036) == 0 and not sim._doorbell_ip3(), "the main CPU's acknowledge ends it")
write(0x36, 0x40, 1)                            # the main CPU rings channel 2
check(core is not None and core._doorbell_ip3(), "the main CPU's ring interrupts the SEE")
core._mmio_write(core.mu, 0x40037, 1, 0x04, None)       # the SEE acknowledges channel 2
check(byte(0x36) == 0 and not core._doorbell_ip3(), "the SEE's acknowledge ends it")
check(see.doorbells.taken == {"main": [2, 0], "SEE": [0, 1]},
      f"both cores' acknowledges count: the main CPU took 2 calls, the SEE 1 answer ({see.doorbells.taken})")
seecore = see.core
reset_see()
check(see.core is None and sim.doorbell_in is None and seecore.service not in sim.slice_services,
      "0x220 bit 1 cleared: the second core stops (no turns, no rings)")

# The random number generator (see.Trng) the SEE's TRNG task keeps a FIFO of, which drops a
# result equal to one of the last five: each start must give a new one
print("\n--- the random number generator (see.Trng) ---")
results = []
for _ in range(3):
    write(see_mod.TRNG, byte(see_mod.TRNG) | 1, 1)                  # start: +0 bit 0
    results.append(bytes(sim.peek(0xB8000000 + see_mod.TRNG + 8, 8)))
check(len(set(results)) == 3 and b"\0" * 8 not in results, f"each start gives a new 64-bit result ({results[0].hex()} ...)")
check(byte(see_mod.TRNG) & 1 == 0 and byte(see_mod.TRNG + 4) & 1 == 0, "the start bit clears itself, busy (+4 bit 0) reads 0")

# The newer chips' layout (the M3503): ring +0x37 bits 3 / 2, acknowledge +0x37 bits 7 / 6 -- a
# plain byte store, which must keep the acknowledging CPU's own rings
print("\n--- the doorbells of the newer chips (M3503) ---")
see.reset()
sim._switch_family(M3503)
write(0x40037, 0x08, 1)                         # the SEE rings channel 1
write(0x37, 0x04, 1)                            # the main CPU rings channel 2
check(byte(0x40037) == 0x08 and byte(0x37) == 0x04, "chip 0x3503: the rings land in the +0x37 bytes")
sim.doorbell_in = see_mod.Doorbells.ring(0x3503, see_mod.SEE_IC)
check(sim.doorbell_in == (0x40037, 4) and sim._doorbell_ip3(), "the SEE's ring interrupts the main CPU")
write(0x37, 0x80, 1)                            # the main CPU acknowledges channel 1: sb 0x80
check(byte(0x40037) == 0 and not sim._doorbell_ip3(), "0x80 in 0xB8000037 ends the SEE's ring")
check(byte(0x37) == 0x04, f"the main CPU's own ring stays, the acknowledge bit is not stored (0x{byte(0x37):02X})")
write(0x40037, 0x40, 1)                         # the SEE acknowledges channel 2
check(byte(0x37) == 0 and byte(0x40037) == 0, "0x40 in 0xB8040037 ends the main CPU's ring")
check(sim.chip.see.doorbells.taken == {"main": [1, 0], "SEE": [0, 1]},
      f"the messages taken ({sim.chip.see.doorbells.taken})")
sim.doorbell_in = None

print(f"\n[{'PASS' if not failures else 'FAIL'}] SEE start handshake, doorbells and second core")
sys.exit(1 if failures else 0)
