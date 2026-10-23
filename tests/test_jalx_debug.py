"""
Test JALX execution and mode switching: dump.bin's bootloader, once it has
copied its code from the ROM to RAM (see test_boot_dump_copies_to_ram.py),
has a JALX at 0x81E8E1B8 that calls the MIPS16 code at 0x81E84280.  Stepping
it (sim.step) must report the JALX, the switch from MIPS32 to MIPS16 and the
callee's address; the next step is the callee's first MIPS16 instruction.
(Before the copy the RAM there is zero, so the test boots to 0xAFC007F4 first.)
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from simulator import AliMipsSimulator
from unicorn import UcError
from unicorn.mips_const import UC_MIPS_REG_PC

COPY_DONE = 0xAFC007F4      # the bootloader past its ROM-to-RAM copy
JALX_AT = 0x81E8E1B8        # jalx 0x81E84280
CALLEE = 0x81E84280         # MIPS16: save 0x38,ra,s0-s5


def boot_to(sim, stop_addr, max_steps=1000000):
    """Run the bootloader until it reaches stop_addr (the loop of
    test_boot_dump_copies_to_ram.py)."""
    end_addr = sim.base_addr + sim.rom_size
    sim.stop_instr = stop_addr
    cur_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    steps = 0
    while cur_pc != stop_addr and cur_pc < end_addr and steps < max_steps:
        sim.apply_manual_fixes()
        sim.invalidate_jit(cur_pc)
        try:
            sim.mu.emu_start(sim.start_pc(cur_pc), end_addr)   # bit 0 = current ISA mode
        except UcError:
            pass
        cur_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
        steps += 1
    return cur_pc


def main():
    print("Testing JALX execution...")

    # Create simulator
    sim = AliMipsSimulator()
    sim.loadFile("dump.bin")

    print(f"Booting until 0x{COPY_DONE:08X} (the code copied to RAM)...")
    pc = boot_to(sim, COPY_DONE)
    checks = [(pc == COPY_DONE, f"the bootloader reaches 0x{COPY_DONE:08X} (stopped at 0x{pc:08X})")]

    # Set PC to the JALX instruction at 0x81E8E1B8
    sim.mu.reg_write(UC_MIPS_REG_PC, JALX_AT)

    print(f"Initial PC: 0x{sim.mu.reg_read(UC_MIPS_REG_PC):08X}")
    print(f"Initial mode: {sim.isa_mode.value}")
    print()

    # Execute one step (should execute JALX)
    print("Executing first step (JALX)...")
    result = sim.step()

    print(f"\nResult:")
    print(f"  Instruction: {result.instruction} {result.operands}")
    print(f"  Mode before: {result.mode_before}")
    print(f"  Mode after: {result.mode_after}")
    print(f"  Mode switched: {result.mode_switched}")
    print(f"  Next PC: 0x{result.next_pc:08X}")
    print(f"  Current mode: {sim.isa_mode.value}")
    print()
    checks += [(result.instruction == "jalx", f"the instruction at 0x{JALX_AT:08X} is a JALX ({result.instruction})"),
               (str(result.mode_before) == "mips32" and str(result.mode_after) == "mips16" and result.mode_switched,
                f"the step switches from MIPS32 to MIPS16 ({result.mode_before} -> {result.mode_after}, "
                f"switched: {result.mode_switched})"),
               (result.next_pc == CALLEE, f"the next PC is the callee 0x{CALLEE:08X} (0x{result.next_pc:08X})"),
               (sim.isa_mode.value == "mips16", f"the simulator tracks the MIPS16 mode ({sim.isa_mode.value})")]

    # Execute next step (should be MIPS16)
    print("Executing second step (should be MIPS16)...")
    result2 = sim.step()

    print(f"\nResult:")
    print(f"  Instruction: {result2.instruction} {result2.operands}")
    print(f"  Mode before: {result2.mode_before}")
    print(f"  Next PC: 0x{result2.next_pc:08X}")
    checks += [(str(result2.mode_before) == "mips16" and result2.instruction == "save",
                f"the second step is the callee's MIPS16 'save' ({result2.mode_before}: {result2.instruction})"),
               (result2.next_pc == CALLEE + 2, f"a 16-bit instruction: the next PC is 0x{CALLEE + 2:08X} "
                                               f"(0x{result2.next_pc:08X})")]

    print()
    ok = True
    for good, text in checks:
        print(f"[{'PASS' if good else 'FAIL'}] {text}")
        ok &= bool(good)
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
