"""
The SEE co-processor's start handshake.  The dual-CPU ALi chips (the M3606
of the Cabletech URZ0086 / Kruger&Matz KM0186, the T750i's M3821, the C3505)
have a second MIPS core, the SEE, which runs its own program from the main
CPU's DDR.  The main CPU starts it through three system registers:

  * 0xB8000220 bit 1: the SEE runs (set) or is held in reset (clear);
  * 0xB8000200: where the SEE goes -- while it holds 0xB8000280 the SEE
    waits in an on-chip loop at that address, and when the main CPU writes
    another address the parked SEE jumps there;
  * 0xB800020C bit 0: the started flag, which the main CPU clears before it
    starts the SEE and then waits for the SEE's code to set.

The URZ0086's bootloader writes 0xB8000280 to 0x200, sets 0x220 bits 9 and 1
(the SEE runs and parks), clears the flag, writes the address of the SEE's
boot code to 0x200 and waits for the flag.  That boot code -- a trampoline
in the bootloader's RAM copy -- copies the SEE's program to where it runs,
writes 0xB8000280 to 0x200 again, sets the flag and jumps back to the park
loop.  Once the SEE runs its own program the main CPU uses 0x200 for its
mailbox messages instead.

The simulator has one CPU, so SeeStart runs such boot code itself when the
parked SEE is sent to it: on a second Unicorn instance that shares the RAM
and the register block (its stores land in the same registers, without
device side effects), from the start address until it reaches the park
loop -- after the main CPU's start store has landed, at its next access to
the SEE's registers (its wait for the flag at the latest).  The copy and
the flag are then the boot code's own doing.  Only boot code that parks the
SEE is run -- code that loads 0xB8000280 near its start; the SEE's own
program, started the same way later, is not: the SEE then counts as
running, so a firmware that waits for that program's answers waits on.
"""
import ctypes
import struct

from unicorn import UC_ARCH_MIPS, UC_MODE_LITTLE_ENDIAN, UC_MODE_MIPS32, UC_PROT_ALL, Uc, UcError
from unicorn.mips_const import UC_CPU_MIPS32_24KF, UC_MIPS_REG_PC

START, FLAG, CONTROL = 0x200, 0x20C, 0x220     # offsets in the register block 0xB8000000
RUN_BIT = 0x02                                  # 0xB8000220: the SEE runs
PARK = 0xB8000280                               # the on-chip loop the SEE waits in
MMIO_PHYS = 0x18000000
SCAN = 0x200                                    # bytes of boot code searched for PARK
LIMIT = 50_000_000                              # instructions: a backstop, the copy takes far fewer


def parks(code):
    """Whether boot code (bytes) loads PARK into a register near its start:
    lui rX, 0xB800 followed within four instructions by ori rX, rX, 0x0280."""
    words = struct.unpack(f"<{len(code) // 4}I", code[:len(code) // 4 * 4])
    for i, w in enumerate(words):
        if w >> 26 == 0x0F and w & 0xFFFF == PARK >> 16:
            reg = (w >> 16) & 31
            for v in words[i + 1:i + 5]:
                if v >> 26 == 0x0D and (v >> 21) & 31 == reg and (v >> 16) & 31 == reg and v & 0xFFFF == PARK & 0xFFFF:
                    return True
    return False


class SeeStart:
    def __init__(self, sim):
        self.sim = sim
        self.state = "reset"        # "reset", "parked" (at PARK), "starting" (pending) or "running" (its program)
        self.pending = None         # a start address the SEE goes to once the main CPU's store landed
        self.cpu = None             # the SEE's Unicorn instance, made at its first start
        self.starts = []            # (start address, what happened) per start
        sim._mmio_on('w', self._write_start, START, START + 3)
        sim._mmio_on('w', self._write_control, CONTROL, CONTROL + 3)
        # the main CPU's next look at the SEE's registers comes after the SEE ran
        sim._mmio_on('r', self._access, START, FLAG + 3)
        sim._mmio_on('r', self._access, CONTROL, CONTROL + 3)
        sim._mmio_on('w', self._access, FLAG, FLAG + 3)

    def _access(self, uc, access, address, size, value, user_data):
        if self.pending is not None:
            address, self.pending = self.pending, None
            self.start(address)

    def _word(self, offset):
        return int.from_bytes(self.sim.mmio_buffer[offset:offset + 4], 'little')

    @staticmethod
    def _after(old, address, base, size, value):
        """A register word as a store of `size` bytes at `address` leaves it."""
        shift = 8 * ((address & 0xFFFFFF) - base)
        mask = ((1 << (8 * size)) - 1) << shift
        return (old & ~mask) | ((value << shift) & mask)

    # (the write handlers run before the store lands: the registers still hold the old
    # values.  A store the simulator re-executes after a stop at it is not a second start.)
    def _write_control(self, uc, access, address, size, value, user_data):
        self._access(uc, access, address, size, value, user_data)
        old = self._word(CONTROL)
        new = self._after(old, address, CONTROL, size, value)
        if not new & RUN_BIT:
            self.state = "reset"
        elif not old & RUN_BIT:
            target = self._word(START)
            if target == PARK:
                self.state = "parked"
            elif self.sim._dev_replay_of(uc, 'see_run', address, value) is None:
                self.sim._dev_note(uc, 'see_run', address, value)
                self.state, self.pending = "starting", target

    def _write_start(self, uc, access, address, size, value, user_data):
        self._access(uc, access, address, size, value, user_data)
        target = self._after(self._word(START), address, START, size, value)
        if self.state != "parked" or target == PARK or (address & 3) + size != 4:
            return
        if self.sim._dev_replay_of(uc, 'see_start', address, value) is not None:
            return
        self.sim._dev_note(uc, 'see_start', address, value)
        self.state, self.pending = "starting", target

    def start(self, address):
        """The SEE goes to `address`: run it if it is boot code that parks the SEE."""
        sim = self.sim
        try:
            code = bytes(sim.mu.mem_read(address & ~3, SCAN))
        except UcError:
            code = b""
        if not parks(code):
            self.state = "running"
            self.starts.append((address, "not run (the SEE's own program)"))
            sim.log(f"[SEE] started at 0x{address:08X}: not boot code that parks the SEE -- the SEE's "
                    f"program is not run")
            return
        if self.cpu is None:
            cpu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
            cpu.ctl_set_cpu_model(UC_CPU_MIPS32_24KF)
            cpu.mem_map_ptr(0, sim.ram_size, UC_PROT_ALL, ctypes.addressof(sim.ram_buffer))
            cpu.mem_map_ptr(MMIO_PHYS, ctypes.sizeof(sim.mmio_buffer), UC_PROT_ALL, ctypes.addressof(sim.mmio_buffer))
            self.cpu = cpu
        try:
            self.cpu.emu_start(address, PARK, count=LIMIT)
            pc = self.cpu.reg_read(UC_MIPS_REG_PC)
            what = "parked" if pc == PARK else f"stopped at 0x{pc:08X} without parking"
        except UcError as e:
            what = f"stopped: {e}"
        self.state = "parked" if what == "parked" else "running"
        self.starts.append((address, what))
        sim.log(f"[SEE] started at 0x{address:08X}: its boot code {what}"
                f" (started flag {'set' if self._word(FLAG) & 1 else 'clear'})")
