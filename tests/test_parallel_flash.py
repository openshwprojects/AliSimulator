#!/usr/bin/env python3
"""
The parallel NOR flash (parallel_flash.py, the M3329 board's MX29LV400B) and
the simulator's fix for stores to the flash window in branch delay slots.

Without firmware: the command state machine -- autoselect IDs in byte mode,
F0 back to the array, program (bits only clear), sector erase on the bottom
boot block layout, chip erase, unlock bypass, a broken sequence starting over.
Then MIPS code in RAM on a simulator, in fast and exact mode: the M3329
driver's probe (reset, the unlock cycles and 90 at 0xAAA / 0x555, the ID
word read back, reset stored in the delay slot of a taken branch) must read
the IDs and run the branch target's first instruction once -- Unicorn 2.1.4
runs it twice unless the simulator clears the branch flags
(simulator._device_access); the same for an SPI-flash simulator's store in a
delay slot, taken and not taken.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from unicorn.mips_const import UC_MIPS_REG_A1, UC_MIPS_REG_PC, UC_MIPS_REG_V0, UC_MIPS_REG_V1

from parallel_flash import MX29LV400B, ParallelNorFlash
from simulator import AliMipsSimulator

failures = 0


def check(ok, text):
    global failures
    failures += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")


class Sim:
    """What ParallelNorFlash uses of the simulator: the image, program / erase, the buffer."""
    def __init__(self, size=0x80000):
        self.rom_image = bytearray(range(256)) * (size // 256)
        self.buffer = bytearray(self.rom_image)
        self.flash_device = None

    def _flash_program(self, off, byte):
        self.rom_image[off] &= byte

    def _flash_erase(self, start, length):
        self.rom_image[start:start + length] = b"\xFF" * length
        self.buffer[start:start + length] = b"\xFF" * length

    def _rom_write(self, off, data):
        self.buffer[off:off + len(data)] = data


def commands(flash, *cycles):
    for offset, byte in cycles:
        flash.write(offset, byte)


UNLOCK = ((0xAAA, 0xAA), (0x555, 0x55))


def test_state_machine():
    print("Command state machine (MX29LV400B, byte mode):")
    sim = Sim()
    flash = ParallelNorFlash(sim, **MX29LV400B)
    check(flash.read(0, 4) == bytes([0, 1, 2, 3]), "reads the array at power-on")
    commands(flash, *UNLOCK, (0xAAA, 0x90))
    check(flash.read(0, 4) == bytes([0xC2, 0xC2, 0xBA, 0xBA]), "autoselect: manufacturer at word 0, device at word 1")
    check(flash.read(0x100, 4) == bytes([0xC2, 0xC2, 0xBA, 0xBA]) and flash.read(0x1C, 4) == bytes(4),
          "autoselect decodes address bits 0..6 of the word address (0x100: IDs, 0x1C: 0)")
    check(sim.buffer[0x200:0x204] == bytes([0xC2, 0xC2, 0xBA, 0xBA]), "the windows' buffer shows the ID pattern")
    commands(flash, (0, 0xF0))
    check(flash.read(0, 4) == bytes([0, 1, 2, 3]) and sim.buffer[0x200:0x204] == bytes([0, 1, 2, 3]),
          "F0 reads the array again (and the buffer holds it)")
    commands(flash, *UNLOCK, (0xAAA, 0xA0), (0x10, 0x0F))
    check(sim.rom_image[0x10] == 0x10 & 0x0F, "program clears bits only (0x10 & 0x0F)")
    commands(flash, *UNLOCK, (0xAAA, 0x80), *UNLOCK, (0x5123, 0x30))
    erased = sim.rom_image[0x4000:0x6000] == b"\xFF" * 0x2000
    check(erased and sim.rom_image[0x3FFF] == 0xFF - 0 and sim.rom_image[0x6000] == 0x00,
          "sector erase at 0x5123 erases the 8 KB sector 0x4000..0x5FFF only")
    commands(flash, *UNLOCK, (0xAAA, 0x55), (0x20, 0x00))
    check(sim.rom_image[0x20] == 0x20, "a broken sequence (AA 55 55) starts over: the next byte is no program data")
    commands(flash, *UNLOCK, (0xAAA, 0x20), (0, 0xA0), (0x30, 0x01), (0, 0xA0), (0x31, 0x02), (0, 0x90), (0, 0x00))
    check(sim.rom_image[0x30] == 0x30 & 0x01 and sim.rom_image[0x31] == 0x31 & 0x02 and not flash.bypass,
          "unlock bypass: A0 + data programs without unlock cycles, 90 00 leaves it")
    commands(flash, *UNLOCK, (0xAAA, 0x80), *UNLOCK, (0xAAA, 0x10))
    check(sim.rom_image == b"\xFF" * len(sim.rom_image), "chip erase")
    check(flash.commands == {'autoselect': 1, 'reset': 1, 'program': 3, 'erase sector': 1, 'bypass': 1,
                             'erase chip': 1}, f"command counts {flash.commands}")


# The M3329 driver's probe (0xA002E0D4), reduced: a1 = the array word, v0 = the word in autoselect mode;
# the branch over `move v0, zero` is taken when they differ, the reset stored in its delay slot
PROBE = bytes.fromhex(
    "c0af013c"   # lui   at, 0xafc0
    "aa000824"   # addiu t0, zero, 0xaa
    "55000924"   # addiu t1, zero, 0x55
    "90000a24"   # addiu t2, zero, 0x90
    "f0000b24"   # addiu t3, zero, 0xf0
    "00002ba0"   # sb    t3, 0(at)            reset
    "0000258c"   # lw    a1, 0(at)            the array
    "aa0a28a0"   # sb    t0, 0xaaa(at)
    "550529a0"   # sb    t1, 0x555(at)
    "aa0a2aa0"   # sb    t2, 0xaaa(at)        autoselect
    "0000228c"   # lw    v0, 0(at)            the IDs
    "0200a214"   # bne   a1, v0, +2           (taken)
    "00002ba0"   # sb    t3, 0(at)            reset, in the delay slot
    "21100000"   # move  v0, zero             (skipped)
    "01006324"   # target: addiu v1, v1, 1    (must run once)
    "ffff0010"   # b     .
    "00000000")


def run_code(sim, code, end):
    sim.mu.mem_write(0x80001000, code)
    sim.mu.reg_write(UC_MIPS_REG_PC, 0x80001000)
    for _ in range(50):
        if sim.mu.reg_read(UC_MIPS_REG_PC) == end:
            break
        sim.run(max_instructions=sim.instruction_count + 50)


def test_probe(exact):
    print(f"The M3329's flash probe on a simulator ({'exact' if exact else 'fast'} mode):")
    sim = AliMipsSimulator(rom_size=0x80000, log_handler=lambda m: None)
    sim.hook_every_instruction = exact
    sim.rom_image = bytearray(range(256)) * 0x800
    sim._rom_write(0, bytes(sim.rom_image))
    flash = ParallelNorFlash(sim, **MX29LV400B)
    flash.connect()
    run_code(sim, PROBE, 0x8000103C)
    a1, v0, v1 = (sim.mu.reg_read(r) for r in (UC_MIPS_REG_A1, UC_MIPS_REG_V0, UC_MIPS_REG_V1))
    # (the reset store lands in the window and is reverted at the next instruction in exact
    # mode, at the next flash store or slice end in fast mode: there the load right after it
    # sees its byte)
    check(a1 == 0x03020100 or (not exact and a1 == 0x030201F0), f"the array word before autoselect (0x{a1:08X})")
    check(v0 == 0xBABAC2C2, f"the ID word in autoselect mode (0x{v0:08X})")
    check(v1 == 1, f"the branch target's first instruction ran once ({v1}; Unicorn alone: 2)")
    check(not flash.autoselect and sim.peek(0xAFC00000, 4) == bytes([0, 1, 2, 3]),
          "the reset in the delay slot ended autoselect: the window shows the array")
    check(sim.ds_flag_fixes == 1, f"the simulator cleared the stale branch flags once ({sim.ds_flag_fixes})")


def test_spi_delay_slot(exact, taken):
    print(f"A store to an SPI flash's window in a delay slot ({'exact' if exact else 'fast'} mode, "
          f"branch {'taken' if taken else 'not taken'}):")
    sim = AliMipsSimulator(rom_size=0x80000, log_handler=lambda m: None)
    sim.hook_every_instruction = exact
    code = bytes.fromhex(
        "c0af013c"   # lui   at, 0xafc0
        "f0000b24"   # addiu t3, zero, 0xf0
        + ("01000524" if taken else "00000524") +   # addiu a1, zero, 1 / 0
        "0200a014"   # bne   a1, zero, +2
        "00002ba0"   # sb    t3, 0(at)            (delay slot)
        "01006324"   # addiu v1, v1, 1            (fall-through only)
        "01004224"   # target: addiu v0, v0, 1
        "10004224"   # addiu v0, v0, 0x10
        "ffff0010"   # b .
        "00000000")
    run_code(sim, code, 0x80001020)
    v0, v1 = sim.mu.reg_read(UC_MIPS_REG_V0), sim.mu.reg_read(UC_MIPS_REG_V1)
    check((v0, v1) == (0x11, 0 if taken else 1), f"v0 0x{v0:X} v1 {v1}: every instruction ran once")


test_state_machine()
for exact in (False, True):
    test_probe(exact)
for exact in (False, True):
    for taken in (True, False):
        test_spi_delay_slot(exact, taken)
print("RESULT:", "FAIL" if failures else "PASS")
sys.exit(1 if failures else 0)
