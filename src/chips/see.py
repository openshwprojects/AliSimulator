"""
The SEE co-processor: its start handshake, its program on a second core,
the doorbells between the two.  The dual-CPU ALi chips (the M3606 of the
Cabletech URZ0086 / Kruger&Matz KM0186 and the Opticum X110TS, the Globo
HD-XS2's M3503, the T750i's M3821, the T760i's C3505) have a second MIPS
core, the SEE, which runs its own program from the main CPU's DDR -- the
audio / video decoders' and the display's drivers, which the main CPU's
drivers call.  The main CPU starts it through three system registers:

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

SeeStart runs such boot code itself when the parked SEE is sent to it: on a
light Unicorn instance that shares the RAM and the register block (its
stores land in the same registers, without device side effects), from the
start address until it reaches the park loop -- after the main CPU's start
store has landed, at its next access to the SEE's registers or the end of
its slice, whichever comes first.  The copy and the flag are then the boot
code's own doing.  Only boot code that parks the SEE is run that way -- code
that loads 0xB8000280 near its start.  The SEE's own program, started the
same way later, runs on a second simulated core (SeeCore) -- unless
run_program is cleared: then it is not run, the SEE only counts as running,
and a firmware that waits for that program's answers waits on.

The two programs talk through the SDK's remote calls (dual_new.o): a
message goes in chunks through two buffers at the start of the shared
memory, a quarter of it each (the URZ0086: 0x40 bytes at 0xA7DFFF00 main CPU
-> SEE and 0xA7DFFF40 SEE -> main CPU; the T750i: 0x80 bytes at 0xA7FFFE00
and 0xA7FFFE80), each chunk's length through a mailbox register (0xB8000200
/ 204: the main CPU's calls / answers, 0xB8040200 / 204: the SEE's), which
the receiver overwrites with 0xFFFFFFFF once it has taken the chunk, and a
message's first chunk rings the receiver's doorbell (Doorbells).
"""
import ctypes
import random
import struct

from unicorn import UC_ARCH_MIPS, UC_MODE_LITTLE_ENDIAN, UC_MODE_MIPS32, UC_PROT_ALL, Uc, UcError
from unicorn.mips_const import UC_CPU_MIPS32_24KF, UC_MIPS_REG_PC

from .base import ChipFamily

START, FLAG, CONTROL = 0x200, 0x20C, 0x220     # offsets in the register block 0xB8000000
MAIN_IC, SEE_IC = 0x00030, 0x40030              # the CPUs' interrupt controllers (0xB8000030 / 0xB8040030)
SEE_CPU_NUM = 1                                 # the SEE's EBase CPU number (the main CPU's is 0)
OLD_DOORBELL_CHIPS = (0x3602, 0x3603, 0x3281)   # chip IDs whose SDK rings in the +0x36 byte (Doorbells)
TRNG = 0x34400                                  # the random number generator (0xB8034400, Trng)
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


class SeeCoreFamily(ChipFamily):
    """The chip family of a second core (simulator.AliMipsSimulator made with
    share_memory_with): no chip of its own -- the first core's family has the
    chip ID and the devices --, only the code the core runs besides the first
    32 MB of RAM, for its CP0 instruction scans (code_ranges)."""
    name = "SEE"

    def __init__(self, sim):
        super().__init__(sim)
        self.ranges = []            # [(address, length)]

    def install(self):
        pass

    def code_ranges(self):
        return list(self.ranges)

    @property
    def ve_status(self):
        """The first core's family's: the video engine is the chip's (the SEE
        runs the video decoder's driver)."""
        return self.sim._shared.chip.ve_status


class Doorbells:
    """The doorbells between the two CPUs (the SDK's dual_new.o).  A CPU rings
    the other on channel 1 (its calls) or 2 (its answers): the other CPU's OS
    IRQ 0x47 / 0x46, interrupt controller lines 63 / 62, which interrupt it
    while enabled (simulator._doorbell_ip3; each core's doorbell_in is where
    the other rings) and which its dispatcher finds in the ring byte, until
    the receiver acknowledges.  Rings and acknowledges are the top bytes of
    each CPU's interrupt status word +0x34 -- the main CPU's block
    0xB8000030, the SEE's 0xB8040030 --, in one of two layouts, which the
    SDK picks by the chip ID (0xB8000002):
      * 0x3602 / 0x3603 / 0x3281 (the newer SDK's chip codes 0x10047 /
        0x10049; the M3602's older SDK knows only this layout): the ringer
        sets bit 7 / 6 of its +0x36 byte, the receiver acknowledges by
        setting bit 3 / 2 of its own +0x37 byte -- the SEE writes 0xB8040037
        for the main CPU's ring;
      * the newer chips (0x3701 / 0x3503 / 0x3821 / 0x3505, chip codes
        0x1004A on):
        the ringer sets bit 3 / 2 of its +0x37 byte, the receiver
        acknowledges by storing bit 7 / 6 to its own +0x37 byte.
    An acknowledge bit never stays set (a later read-modify-write of the
    byte must not acknowledge again), and in the newer layout a store does
    not clear the CPU's own rings -- its acknowledge is a plain byte store,
    which would take a ring of its own with it: the ring bits are set by
    writing 1 and cleared by the other CPU's acknowledge.  The registers are
    the shared register block, so both cores' handlers have them (wire).

    A message's first chunk rings its receiver, so the acknowledges that end
    a ring count the messages each CPU took: taken["SEE"] / taken["main"],
    [calls, answers]."""

    def __init__(self):
        self.taken = {"main": [0, 0], "SEE": [0, 0]}

    @staticmethod
    def chip_id(uc):
        """The chip ID the SDK picks the layout by (0xB8000002)."""
        return int.from_bytes(uc.mem_read(0xB8000002, 2), 'little')

    @staticmethod
    def ring(chip_id, block):
        """Where the CPU whose interrupt controller is at `block` rings: its
        ring byte's offset in the device window and the shift that puts
        channel 1 / 2 at bits 7 / 6."""
        return (block + 6, 0) if chip_id in OLD_DOORBELL_CHIPS else (block + 7, 4)

    def wire(self, core):
        """Among a core's device register handlers: stores that cover a +0x37 byte."""
        for block in (MAIN_IC, SEE_IC):
            core._mmio_on('w', self._write, block + 4, block + 7)

    def _write(self, uc, access, address, size, value, user_data):
        offset = address & 0xFFFFFF
        reg = (offset & ~3) + 3                     # the +0x37 byte
        if offset + size <= reg:
            return None                             # (the store ends before it)
        shift = 8 * (reg - offset)
        b = (value >> shift) & 0xFF
        receiver, other = ("main", SEE_IC) if reg - 7 == MAIN_IC else ("SEE", MAIN_IC)
        ring, ring_shift = self.ring(self.chip_id(uc), other)
        if ring_shift:                              # (the newer layout: acknowledges in bits 7 / 6)
            acks = (b >> 4) & 0x0C
            b = (b & ~0xCC) | ((uc.mem_read(0xB8000000 + reg, 1)[0] | b) & 0x0C)
        else:                                       # (acknowledges in bits 3 / 2)
            acks = (b << 4) & 0xC0
            b &= ~0x0C
        if acks:
            ring += 0xB8000000
            rung = uc.mem_read(ring, 1)[0]
            ended = (rung & acks) << ring_shift     # channel 1 / 2 at bits 7 / 6
            self.taken[receiver][0] += bool(ended & 0x80)
            self.taken[receiver][1] += bool(ended & 0x40)
            uc.mem_write(ring, bytes([rung & ~acks & 0xFF]))
        return (value & ~(0xFF << shift)) | ((b & 0xFF) << shift)


class Trng:
    """The chip's random number generator, 0xB8034400 on these chips (the
    newer SDK has it at 0xB803A400 on the M3281 and a later M3603
    revision): setting bit 0 of +0 starts it, bit 0 of +4 reads busy (never
    here), +8 / +0xC hold the 64-bit result.  The SEE's TRNG task
    (LLD_TRNG_M36F) keeps a FIFO of 0x80 results and drops a result equal to
    one of the last five: with the registers as plain memory every result
    was the same, the FIFO never filled and the task never slept -- the
    T760i's SEE then ran nothing else once its interrupts were off, ~190 M
    instructions in.  The results come from a seeded generator, the same
    sequence every run; the start bit clears itself."""

    def __init__(self):
        self.random = random.Random(0x5EE)

    def wire(self, core):
        core._mmio_on('w', self._write, TRNG, TRNG)

    def _write(self, uc, access, address, size, value, user_data):
        if not value & 1:
            return None
        uc.mem_write(0xB8000000 + TRNG + 8, self.random.getrandbits(64).to_bytes(8, 'little'))
        return value & ~1


class SeeCore:
    """The SEE's own program on a second simulated core: an AliMipsSimulator
    sharing the first one's RAM, flash and device registers (its stores land
    in the same registers), with its own CP0 state and timer, the CPU number
    SEE_CPU_NUM in EBase -- the exception vector both cores share
    (0x80000180) sends a core other than 0 through g_see_exception_handler to
    the handler the SEE's start-up stored in the shared memory's last word --
    and its own interrupt controller at 0xB8040030 (status 30 / 34, enables
    38 / 3C; boot_see.o's _start clears it); the main CPU's doorbell
    interrupts it, its doorbell the main CPU (Doorbells).  It starts at
    `address`, its program's entry, and runs as a slice service of the first
    core: after each of that core's slices it runs until its emulation time
    catches up with that core's (service) -- two cores on one clock, each
    core's Count following its own emulation time.  (A turn of so many
    instructions did not work: fast-mode counts are estimates, and with the
    SEE's rate estimated low a million-instruction turn took minutes.)  While
    the SEE's idle task waits for an interrupt in its `b .` the time skips to
    the next one (simulator.idle_skip).  Its code is scanned for CP0
    instructions from the entry's page on, CODE bytes, and in the shared
    vector page.  What it writes to the UART goes where the first core's
    output goes: the two CPUs share the chip's UART."""
    CODE = 0x400000

    def __init__(self, sim, address, wire):
        from simulator import AliMipsSimulator          # (simulator imports chips)
        self.main = sim
        self.core = AliMipsSimulator(share_memory_with=sim, cpu_num=SEE_CPU_NUM, ic_base=SEE_IC,
                                     log_handler=self._log)
        self.core.setSPIDump(False)
        self.core.setUartHandler(lambda ch: sim._uart_log(ord(ch)))
        self.core.idle_skip = True
        page = 0x80000000 | (address & 0x1FFFF000)
        self.core.chip.ranges = [(page, self.CODE), (0x80000000, 0x1000)]
        self.core._rescan_all()
        self.core.mu.reg_write(UC_MIPS_REG_PC, address)
        self.core.max_instructions = 0                  # (no instruction limit: turns are emulation time)
        wire(self.core)                                 # (the models both cores share: SeeStart._wire)
        chip = Doorbells.chip_id(sim.mu)
        sim.doorbell_in, self.core.doorbell_in = Doorbells.ring(chip, SEE_IC), Doorbells.ring(chip, MAIN_IC)
        self._t0 = (sim._vtime(), self.core._vtime())
        sim.slice_services.append(self.service)

    def stop(self):
        """The SEE held in reset: no more turns, no more rings."""
        if self.service in self.main.slice_services:
            self.main.slice_services.remove(self.service)
        self.main.doorbell_in = None

    def _log(self, msg):
        if not msg.startswith("Starting emulation"):
            self.main.log(f"[SEE core] {msg}")

    def service(self):
        """Between the first core's slices: the SEE's turn, until its emulation
        time since it started catches up with the first core's.  (A turn can
        run over -- a slice lasts min_slice_us at least, and an asynchronous
        stop comes up to async_stop_margin_us late --, so the SEE waits out
        what it ran ahead: given each slice's length as a turn of its own, it
        ran 1 s while the main CPU's start-up ran 80 ms.)"""
        main_t0, see_t0 = self._t0
        target = see_t0 + (self.main._vtime() - main_t0)
        if self.core._vtime() < target:
            self.core.run(max_vtime=target)


class SeeStart:
    def __init__(self, sim):
        self.sim = sim
        self.state = "reset"        # "reset", "parked" (at PARK), "starting" (pending) or "running" (its program)
        self.pending = None         # a start address the SEE goes to once the main CPU's store landed
        self.cpu = None             # the SEE's Unicorn instance, made at its first start
        self.starts = []            # (start address, what happened) per start
        self.run_program = True     # run the SEE's own program on a second core (SeeCore) when it is started
        self.core = None            # that core
        sim._mmio_on('w', self._write_start, START, START + 3)
        sim._mmio_on('w', self._write_control, CONTROL, CONTROL + 3)
        # the main CPU's next look at the SEE's registers comes after the SEE ran,
        # and so does the end of its slice: the real SEE starts at once.  (Waiting
        # for the next look only, the URZ0086's SEE program -- started by the
        # bootloader at ~30 M instructions -- started when the application next
        # read 0x200, at ~50 M, just before its first remote call, which found
        # none of the SEE's server tasks ready yet: SDBBP in its mailbox_hsr.)
        self._looking = False
        self._watch(True)
        sim.slice_services.append(self._start_at_slice_end)
        self.doorbells = Doorbells()    # (its taken: the messages each CPU took from the other)
        self.trng = Trng()
        self._wire(sim)

    def _watch(self, on):
        """The main CPU's looks at the SEE's registers (its reads of 0x200..0x20F and
        0x220, its stores to the flag) start a pending start: watched while the SEE
        is in reset or parked.  While the SEE runs its program those registers are
        the mailboxes the main CPU polls, and no start can be pending."""
        if on == self._looking:
            return
        self._looking = on
        change = self.sim._mmio_on if on else self.sim._mmio_off
        change('r', self._access, START, FLAG + 3)
        change('r', self._access, CONTROL, CONTROL + 3)
        change('w', self._access, FLAG, FLAG + 3)

    def _wire(self, core):
        """The device models both cores' stores reach: the doorbells and the
        random number generator the SEE's program keeps a FIFO of -- and, on
        the second core, the family's own engines the SEE's drivers feed too
        (ChipFamily.core_devices: the M36xx's DMA engine)."""
        self.doorbells.wire(core)
        self.trng.wire(core)
        if core is not self.sim:
            for device in getattr(self.sim.chip, 'core_devices', ()):
                device.wire(core)

    def reset(self):
        """The SEE back in reset (the simulator loads an image again)."""
        self.state, self.pending = "reset", None
        self._watch(True)
        self._stop_core()
        for counts in self.doorbells.taken.values():
            counts[:] = [0, 0]

    def _stop_core(self):
        if self.core is not None:
            self.core.stop()
            self.core = None

    def _access(self, uc, access, address, size, value, user_data):
        self._start_pending()

    def _start_at_slice_end(self):
        """Between the main CPU's slices: a pending start -- unless the store
        that made it is still to run again (the slice stopped on it, see
        _pend; an interrupt taken at the boundary can come first).  Its
        replay lands the start address in 0x200 once more, so started before
        it the SEE's boot code had its 0xB8000280 overwritten: the Globo
        HD-XS2's application then saw no parked SEE and skipped starting the
        SEE's program, its first mailbox word taken for the start."""
        if self.pending is not None and \
                not any(rp[0] in ('see_start', 'see_run') for rp in self.sim._dev_replays.values()):
            self._start_pending()

    def _start_pending(self):
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
    # values.  A store that makes a start is noted (_pend): one the simulator re-executes
    # after a stop at it is not a second start, and it lands again before the SEE runs --
    # the start it made waits for the next access.  Run in the replay's handler, the SEE's
    # boot code wrote 0xB8000280 back to 0x200 just before the replayed store put the
    # start address there again -- and the Globo HD-XS2's application, which starts the
    # SEE's program only while 0x200 reads 0xB8000280 (0x80016DE8), then skipped it, its
    # first mailbox word taken for the start.)
    def _pend(self, uc, kind, address, value, target):
        """The SEE goes to `target` once this store has landed."""
        self.sim._dev_note(uc, kind, address, value)
        self.state, self.pending = "starting", target

    def _write_control(self, uc, access, address, size, value, user_data):
        if self.sim._dev_replay_of(uc, 'see_run', address, value) is not None:
            return
        self._access(uc, access, address, size, value, user_data)
        old = self._word(CONTROL)
        new = self._after(old, address, CONTROL, size, value)
        if not new & RUN_BIT:
            self.state = "reset"
            self._stop_core()
            self._watch(True)
        elif not old & RUN_BIT:
            target = self._word(START)
            if target == PARK:
                self.state = "parked"
            else:
                self._pend(uc, 'see_run', address, value, target)

    def _write_start(self, uc, access, address, size, value, user_data):
        if self.sim._dev_replay_of(uc, 'see_start', address, value) is not None:
            return
        self._access(uc, access, address, size, value, user_data)
        target = self._after(self._word(START), address, START, size, value)
        if self.state == "parked" and target != PARK and (address & 3) + size == 4:
            self._pend(uc, 'see_start', address, value, target)

    def start(self, address):
        """The SEE goes to `address`: run it if it is boot code that parks the
        SEE (_boot), else start its program on the second core (run_program)."""
        sim = self.sim
        try:
            code = bytes(sim.mu.mem_read(address & ~3, SCAN))
        except UcError:
            code = b""
        if parks(code):
            what = self._boot(address)
            told = f"its boot code {what} (started flag {'set' if self._word(FLAG) & 1 else 'clear'})"
        elif self.run_program and self.core is None:
            self.cpu = None
            self.core = SeeCore(sim, address, self._wire)
            what, told = "run on the SEE core", "the SEE's program runs on the second core"
        else:
            what = "not run (the SEE's own program)"
            told = "not boot code that parks the SEE -- the SEE's program is not run"
        self.state = "parked" if what == "parked" else "running"
        self._watch(self.state != "running" or self.core is None)
        self.starts.append((address, what))
        sim.log(f"[SEE] started at 0x{address:08X}: {told}")

    def _boot(self, address):
        """Boot code on the SEE's light Unicorn instance, from `address` until
        it reaches the park loop: what happened."""
        sim = self.sim
        if self.cpu is None:
            if sim.engine == "cpp":             # (the C++ core: its Unicorn-like API)
                import cpp_core
                cpu = cpp_core.CppUc()
            else:
                cpu = sim._new_mips_uc()
            cpu.mem_map_ptr(0, sim.ram_size, UC_PROT_ALL, ctypes.addressof(sim.ram_buffer))
            cpu.mem_map_ptr(MMIO_PHYS, ctypes.sizeof(sim.mmio_buffer), UC_PROT_ALL, ctypes.addressof(sim.mmio_buffer))
            self.cpu = cpu
        try:
            self.cpu.emu_start(address, PARK, count=LIMIT)
        except UcError as e:
            return f"stopped: {e}"
        pc = self.cpu.reg_read(UC_MIPS_REG_PC)
        return "parked" if pc == PARK else f"stopped at 0x{pc:08X} without parking"
