#!/usr/bin/env python3
"""
The SEE co-processor's start handshake (src/chips/see.py) on a simulator with
the M3602 family installed, driven by register writes the way the URZ0086's
bootloader makes them (no firmware): park the SEE (0x200 = 0xB8000280), let
it run (0x220 bits 9 and 1), clear the started flag, send it to boot code in
RAM -- which copies a block, writes 0xB8000280 to 0x200, sets the flag and
jumps back to the park loop -- then send it to a program that does not park.
Checks that the boot code runs on the SEE's own instance and leaves exactly
its effects after the main CPU's start store (at its next look at the SEE's
registers), that the program is not run, and that 0x200 writes are mailbox
data after that.
"""
import os
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from chips import see as see_mod
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
sim.chip = M3602(sim)
sim.chip.install()
see = sim.chip.see

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


write(0x200, 0xB8000280)
check(see.state == "reset", "the SEE starts out in reset")
write(0x220, word(0x220) | 0x202)
check(see.state == "parked", "0x220 bit 1 set with 0x200 = 0xB8000280: the SEE runs and parks")
write(0x20C, word(0x20C) & ~1, 4)
write(0x200, 0xA1000000)
check(see.starts == [] and word(0x200) == 0xA1000000, "0x200 = the boot code: the main CPU's store lands first")
flag = sim._mmio_read(sim.mu, 0x20C, 1, None)
check(see.starts == [(0xA1000000, "parked")], f"the main CPU's next look runs the boot code, which parks ({see.starts})")
check(flag & 1 == 1, "that read already sees the started flag the boot code set")
check(word(0x200) == 0xB8000280, "the boot code wrote 0xB8000280 back to 0x200")
check(sim.peek(0x81200000, 16) == asm(0x11111111, 0x22222222, 0x33333333, 0x44444444),
      "the boot code's copy landed in the shared RAM")
check(see.state == "parked", "the SEE is parked again")
write(0x200, 0xA1300000)
sim._mmio_read(sim.mu, 0x20C, 1, None)
check(see.state == "running" and see.starts[-1][0] == 0xA1300000 and "not run" in see.starts[-1][1],
      f"0x200 = a program that does not park: not run, the SEE counts as running ({see.starts[-1]})")
n = len(see.starts)
write(0x200, 0x18)
check(len(see.starts) == n, "0x200 writes while the SEE runs its program are mailbox data, not starts")
write(0x220, word(0x220) & ~0x02, 1)
check(see.state == "reset", "0x220 bit 1 cleared: the SEE is in reset")

print(f"\n[{'PASS' if not failures else 'FAIL'}] SEE start handshake")
sys.exit(1 if failures else 0)
