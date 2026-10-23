import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
sys.stdout.reconfigure(line_buffering=True)

from simulator import AliMipsSimulator
from unicorn.mips_const import *


def main():
    print("Creating simulator...")
    sim = AliMipsSimulator()
    print("Loading dump.bin...")
    sim.loadFile("dump.bin")
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    print(f"Initial PC: 0x{pc:08X}")

    # Try run() - which uses emu_start without count limit
    # This should handle the spin loop differently 
    print("\nRunning with run() for max 50000 instructions...")
    sim.run(max_instructions=50000)
    pc_after = sim.mu.reg_read(UC_MIPS_REG_PC)
    print(f"PC after run: 0x{pc_after:08X}")
    print(f"Instructions executed: {sim.instruction_count}")

    # run() stops at its instruction limit, with the bootloader still in the
    # ROM window (it loops on the flash at this point: the count is exact)
    rom_end = sim.base_addr + sim.rom_size
    checks = [(sim.instruction_count == 50000, f"run() stops at its limit of 50000 instructions ({sim.instruction_count})"),
              (pc_after != pc and sim.base_addr <= pc_after < rom_end,
               f"the bootloader ran on in the ROM window (0x{pc:08X} -> 0x{pc_after:08X})")]
    ok = True
    for good, text in checks:
        print(f"[{'PASS' if good else 'FAIL'}] {text}")
        ok &= bool(good)

    print("\nDone.")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()


