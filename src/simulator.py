from unicorn import *
from unicorn.mips_const import *
from capstone import *
import sys
import os
import re
import threading
import time
try:
    import numpy as _np          # fast CP0-site scans; optional
except ImportError:              # pragma: no cover
    _np = None
from enum import Enum
from dataclasses import dataclass
from typing import Optional
from mips16_decoder import MIPS16Decoder
from tm1650_decoder import GPIO_DO_OFFSETS, GPIO_EXTRA_DO_OFFSETS
import chips

class ISAMode(Enum):
    """ISA mode enumeration"""
    MIPS32 = 'mips32'
    MIPS16 = 'mips16'


@dataclass
class StepResult:
    """Result of a single step execution"""
    address: int
    instruction: str
    operands: str
    next_pc: int
    mode_before: str
    mode_after: str
    is_branch: bool = False
    is_call: bool = False
    is_return: bool = False
    mode_switched: bool = False
    instruction_size: int = 4


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the repository
DUMPS_DIR = os.path.join(ROOT_DIR, "dumps")                               # the firmware images


def resolve_dump(path):
    """The file a dump name refers to: the path as given when it exists, else
    the same name under dumps/ (directly or in one of its sub-folders), where
    the firmware images live.  Tests, tools and the GUIs name a dump by its
    file name ("dump.bin", "STRONG PRIMA VIII/GD25Q32B_20190128_141501.BIN")
    and run from any directory.  An unknown name comes back unchanged, so the
    open() error names it."""
    if os.path.exists(path):
        return path
    candidate = os.path.join(DUMPS_DIR, path)
    if os.path.exists(candidate):
        return candidate
    base = os.path.basename(path)
    for folder, _dirs, files in os.walk(DUMPS_DIR):
        if base in files:
            return os.path.join(folder, base)
    return path


def flash_size_for(path):
    """The rom_size a dump file needs: its size rounded up to a power of two,
    at least 4 MB.  A short tail is ignored (dump_maciej.bin is 4 MB plus the
    4-byte CRC its bootloader's 'dump' command appends), so 4 MB dumps stay
    4 MB and an 8 MB image (the Ferguson Ariva T650i's) gets 8 MB."""
    size = max(os.path.getsize(resolve_dump(path)) - 0x10000, 1)
    return max(0x400000, 1 << (size - 1).bit_length())


class AliMipsSimulator:
    def __init__(self, rom_size=4*1024*1024, ram_size=128*1024*1024, log_handler=None,
                 share_memory_with=None, cpu_num=0, ic_base=0x30):
        """A simulated ALi chip with one MIPS core.  The second core of a
        dual-CPU chip (the SEE, chips/see.py) is another instance made with
        share_memory_with=<the first>: the same RAM, flash and device-register
        buffers seen by its own Unicorn CPU, with its own CP0 state, timer and
        interrupt controller -- cpu_num, its CP0 EBase CPU number (the shared
        exception vector tells the cores apart by it), and ic_base, the offset
        of its interrupt controller's status / enable words in the device
        window (the first core's at 0xB8000030, the SEE's at 0xB8040030)."""
        if share_memory_with is not None:
            rom_size, ram_size = share_memory_with.rom_size, share_memory_with.ram_size
        # The flash is mirrored inside the 16MB windows (see _flash_offset): a
        # power of two up to 16 MB (a 4 MB or smaller part repeats every
        # rom_size bytes, a larger one is laid out in 4 MB segments).
        if rom_size <= 0 or (rom_size & (rom_size - 1)) or rom_size > 0x01000000:
            raise ValueError(f"rom_size must be a power of two of at most 16 MB, got {rom_size:#x}")
        self.rom_size = rom_size
        self.ram_size = ram_size
        self._shared = share_memory_with
        self.ic_base = ic_base
        self._ic = 0xB8000000 + ic_base     # its status words (+0 / +4) and enables (+8 / +0xC), no side effects
        self._ic_en = self._ic + 8          # (the enables: elsewhere on older chips, set_ic_layout)
        self.base_addr = 0xAFC00000
        self.mu = None
        self.md = None
        self.uart_callback = None
        self.spi_callback = None
        self.gpio_callback = None
        self.gpio_devices = []          # the board's other chips on GPIO pins (attach_gpio_devices)
        self._gpio_dbg_seen = set()
        self._spi_dump_enabled = True
        self.log_callback = log_handler

        self.instruction_count = 0
        self.visit_counts = {}
        self.instruction_sizes = {}
        self.instruction_isa = {}        # address -> True if executed as MIPS16 (exact mode only)
        self.trace_instructions = False
        self._stop_instr = None
        self.break_on_printf = False
        self.max_instructions = 10000000
        self.is_syncing = False
        self.prev_executed_pc = None
        self.current_executed_pc = None
        
        # ISA mode (MIPS32 / MIPS16e).  Unicorn executes MIPS16e natively; the
        # mode is tracked exactly, see the "ISA mode tracking" section below.
        self._isa_mode_fallback = ISAMode.MIPS32
        
        # Call stack tracking for step_out
        self.call_stack = []
        
        # Debug flag - only log after MIPS16 mode entered
        self.debug_enabled = False
        
        # Breakpoints
        self.breakpoints = set()
        self.is_stepping = False
        self.pc_history = []
        self.history_size = 50

        # Simulated CP0 registers — Unicorn doesn't reliably expose these.
        # Count (reg 9): hardware cycle counter, incremented every instruction
        # Status (reg 12): IE, EXL, IM bits — controls interrupt enable
        # Cause (reg 13): IP bits — pending interrupt lines
        # EPC (reg 14): saved PC on exception entry
        self.cp0_count = 0
        self.cp0_compare = 0
        self.cp0_status = 0x10400000  # Must match Unicorn's initial CP0 Status
        self.cp0_cause = 0            # stored Cause bits; MFC0 reads _cause_value() (adds TI/IP7, IP3)
        self.cp0_epc = 0
        self.cp0_ebase = 0x80000000 | (cpu_num & 0x3FF)   # EBase (reg 15 sel 1): the exception vectors
                                                            # while Status.BEV = 0, and the CPU number

        # CP0 timer (Count == Compare -> Cause.TI / IP7), see "CP0 timer" below.
        self._timer_enabled = True    # property timer_enabled
        self.timer_irq_count = 0      # timer interrupts delivered
        self._ti = False              # Cause.TI latched (IP7 pending) until Compare is written
        self._timer_armed = False     # no timer events before the first MTC0 Compare
        self._timer_anchor = 0        # Count value up to which Compare crossings were checked
        self._timer_next_icount = 0   # exact mode: instruction_count of the next crossing check
        self._count_observed = None   # last Count value the guest read or wrote
        self._uart_ip3 = False        # IP3 asserted by a delivered UART interrupt until ERET
        self._ic_lines = 0            # interrupt-controller inputs driven by modelled devices (see _ic_set_line)
        self.doorbell_in = None       # where the other CPU of a dual-CPU chip rings this one (see _doorbell_ip3)
        self.ic_irq_count = 0         # IP3 interrupts taken for those lines and doorbells
        self._ge_status = 0           # graphics engine interrupt status (+8, see _hook_ge_write)
        self.ge_ops = 0               # graphics engine commands completed
        self.ge_render = True         # execute GE commands (draw into RAM) with the ge_m36f model
        self.ge = None                # ge_m36f.GeM36F instance (created on the first command)
        from collections import deque
        self._irc_fifo = deque()      # IR controller run-length FIFO (see ir_send_nec)
        self._irc_status = 0          # IR controller interrupt status (+7)
        self.irc_base = 0x18100       # its registers (device-window offset) and interrupt line:
        self.irc_line = self._IC_IRC  # the M3329 has the same controller at 0x1100 on line 7
        self._irc_frames = deque()    # NEC frames waiting to be received (any thread may append)
        self.slice_services = []      # called between slices (emulation thread): device models that feed data
        self.signal_frequencies = None  # set_signal(frequencies=...): where a signal is (None: everywhere)
        self._irc_last_vt = -1e9      # emulation time the last frame was received
        self._ir_key_table = None     # {vkey: ir16} found in RAM by press_key()
        self.ir_coding = "nec"        # how that table maps to NEC frames (ir_remote.IR_CODINGS)
        self.ir_keys_sent = 0         # IR frames delivered to the firmware
        self._in_run = False          # inside run(): hooks may stop the slice to deliver an IRQ
        self._run_tid = None          # thread running run()
        self._external_stop = False   # emu_stop() from another thread during run(): return
        self._eret_logged = 0
        self._dev_last = None         # last non-idempotent device access in this emu_start (see _dev_note)
        self._dev_cb_depth = 0        # > 0 while a device access callback runs
        self._dev_replays = {}        # (pc, sp) -> access a stop left the PC on (its re-execution is a replay)
        self._ds_dev_warned = set()   # PCs of device accesses in delay slots already warned about
        self._ds_flags_stale = False  # such an access left the branch flags set (_device_access)
        self.ds_flag_fixes = 0        # ... cleared that many times

        # UART Receive simulation
        from collections import deque
        self._uart_rx_queue = deque()  # Queued bytes for UART receive
        self._pending_uart_irq = False
        self._uart_irq_delivered = False
        self._uart_irq_arm_after = 0  # Deliver IRQ only after this icount
        self._uart_irq_retries = 0
        self._step_count = 0  # Hook-based step counter for precise single-stepping

        # ---- ISA mode tracking state (see _hook_code / is_mips16_mode) ----
        self._hflags_off = None      # byte offset of CPUMIPSState.hflags in a saved context
        self._ctx = None             # reusable UcContext for fast hflags reads
        self._hflags_view = None     # ctypes view onto hflags inside self._ctx
        self._cur_m16 = False        # ISA mode of the instruction currently executing
        self._mode_resync_in = 0     # re-read exact mode from hflags after N more instructions
        self._next_in_delay_slot = False  # next hooked instruction is a branch delay slot
        self._stop_reason = None     # why _hook_code called emu_stop() (None = external stop)
        self.verify_isa_mode = False # debug: cross-check tracked mode against hflags every insn
        self.isa_mode_mismatches = 0
        self._delay_slot_skips = 0   # CP0 emulations skipped because insn sat in a delay slot

        # ---- Execution modes ----
        # Fast mode (default): Unicorn runs natively in batches of `batch_size`
        # instructions; Python is only involved through small ranged hooks:
        #   * CP0 instruction sites (MFC0/MTC0/ERET of Count, Compare, Status,
        #     Cause, EPC) found by scanning memory for their encodings,
        #   * breakpoints / stop address,
        #   * "virgin" RAM chunks executed for the first time (trigger a rescan
        #     for new CP0 sites, e.g. after the bootloader copied code to RAM).
        # Full-hook mode (hook_every_instruction=True, or when tracing /
        # verifying): the exact per-instruction _hook_code hook is installed
        # instead; used by the GUI for instruction history and by tests.
        self.hook_every_instruction = False
        # Fast mode runs Unicorn in wall-clock slices (batch_timeout_us) without
        # an instruction count: Unicorn's count mechanism calls a helper on
        # every instruction that walks the whole hook list, which with a few
        # hundred site hooks costs more than the instruction itself.  The
        # instruction count is then *estimated* from the measured rate; exact
        # (count-based) slices are used only close to an instruction limit or
        # an interrupt arming point, and for single steps.
        # Counted slices are only used before the first wall-clock slice of a
        # simulator instance (small exact budgets such as run(60000), and the
        # initial rate calibration): Unicorn flushes its whole translation
        # cache whenever the count hook is added or removed, and counted
        # slices with hundreds of site hooks have been observed to stall for
        # minutes in later phases of the firmware.
        self.batch_size = 200_000            # instructions per exact slice
        self.batch_timeout_us = 100_000      # wall time per estimated slice
        self.exact_count_threshold = 300_000
        self.calibration_slices = 2          # counted slices used to measure the rate at start
        self._insn_rate = 1e6                # instructions / second (measured by the first counted slices)
        self._counted_slices = 0
        self._timeout_slices = 0
        self.count_hz = 100_000_000          # CP0 Count rate in fast mode (emulation time based)
        # Fast-mode Count follows "emulation time": wall time spent inside
        # emu_start() only, so host work between slices (rescans, hook syncs,
        # TB flushes) does not make Count jump past the firmware's deadlines.
        # The clock is the emulation thread's CPU time ('thread', see
        # thread_clock.py): a host stall (the thread preempted) does not
        # advance Count.  'wall' uses time.perf_counter().
        self.count_clock = 'thread'
        self._clk = time.perf_counter        # clock of the current emulation thread
        self._clk_key = None                 # (native thread id, count_clock) it was made for
        self._clk_cache = None               # one clock reading per CP0 hook
        self._in_cp0_hook = False            # (taken at the hook's first use of the time)
        self._vt_accum = 0.0                 # emulation seconds of finished emu_start() calls
        self._vt_slice_t0 = None             # clock at the start of the running call
        self._vt_stop_t = None               # clock when a stop was requested in this call
        self._count_t0 = 0.0                 # emulation time at which Count was cp0_count
        # Fast-mode slices end at a deadline set by a re-armable stopper (see
        # slice_stopper.py): 'auto' (native on 64-bit Windows, else a Python
        # thread), 'native', 'python', or 'unicorn' (emu_start(timeout=), whose
        # granularity on Windows is 15-150 ms).
        self.slice_stopper = 'auto'
        self._stopper = None
        self._stopper_made = None            # slice_stopper value the current _stopper was made for
        self.min_slice_us = 200              # shortest fast-mode slice
        # Slice deadlines are enforced synchronously by every hooked CP0
        # instruction; the asynchronous stopper only fires this much later, as
        # a backstop for code without CP0 instructions (an idle `b .` loop).
        # Unicorn skips all code hooks while an asynchronous stop is pending
        # (and in a delay slot does not even exit first), so a CP0 instruction
        # reached then would run natively (mfc0 Count -> 0, eret -> ErrorEPC).
        self.async_stop_margin_us = 1000
        # While EXL is set (exception entry / exit, context switches: CP0-dense
        # code where a native ERET / MFC0 EPC would be fatal) the backstop
        # waits much longer; that code ends in a hooked ERET within ~1 ms.
        self.async_stop_margin_exl_us = 50_000
        self._slice_armed_exl = False
        self._slice_deadline = None          # perf_counter() at which hooked CP0 code ends the slice
        self.native_cp0_repairs = 0          # native MTC0 Status seen after an asynchronous stop
        # Fast mode: a hooked CP0 instruction costs ~10 us of host time (~50 us
        # before), which Count sees.  A tick handler can take longer than a short
        # timer period, and every ERET would find the next tick due: the
        # interrupted code would never run again.  After an ERET the guest runs
        # at least this long before the next timer/software interrupt.
        self.irq_min_gap_us = 200
        self._last_eret_vt = -1e9            # emulation time of the last ERET
        self._slice_cap_end = None           # emulation time at which the running slice must end
        self._slice_planned_end = None       # ... and at which it is planned to end (timer)
        self._slice_armed_end = None         # ... and at which the stopper is armed now
        self._slice_uses_stopper = False
        self._step_full_hook = False         # _exec_one(): force the exact hook for one step
        self.rescan_interval = 1_000_000     # periodic RAM rescan for new CP0 sites (instructions)
        self._rom_sites = set()
        self._rom_sites_dirty = True
        self._rom_sites_hooked = False       # the flash's sites are in _cp0_site_hooks
        self._vector_page = None             # (page, its bytes) when the tick's vector page was last scanned
        self._delay_slot_words = {}          # word before a CP0 site -> it has a delay slot
        self._code_hook_h = None
        self._cp0_site_hooks = {}            # address -> hook handle
        self._bp_hooks = {}                  # address -> hook handle
        self._virgin_hooks = {}              # chunk base -> hook handle
        self._idle_loops = {}                # idle loop address -> hook handle (idle_skip)
        self.idle_skipped = 0.0              # emulation time idle_skip moved on (seconds)
        self.busy_pending = 0.0              # emulation time still owed for work done in Python
        self._lzma_hooks = {}                # LzmaDecode() entry -> hook handle (_hook_lzma)
        self.lzma_decodes = []               # (entry, input, output address, output size) per decode
        self._run_max_vtime = None           # run()'s max_vtime, for _hook_idle_loop
        self._rescan_due = False
        self._last_rescan_icount = -1
        self._tb_flush_needed = False
        # CP0 Count: value `cp0_count` as of instruction `_count_icount`, plus
        # 2 ticks per instruction since then (real MIPS: Count += 1 every 2 cycles)
        # and a small step per read so polling loops progress inside a batch.
        self._count_icount = 0
        self._count_reads = 0

        # SPI Flash Controller emulation (matches flash_raw_sl_c.c)
        # Hardware registers:
        #   SF_INS (+0x98) = command/instruction register
        #   SF_FMT (+0x99) = format register (which SPI bus phases are active)
        #   SF_DUM (+0x9A) = dummy/data register
        #   SF_CFG (+0x9B) = configuration register
        # SF_FMT bit flags:
        #   0x01 SF_HIT_DATA  - data phase active
        #   0x02 SF_HIT_DUMM  - dummy cycle active
        #   0x04 SF_HIT_ADDR  - address phase active
        #   0x08 SF_HIT_CODE  - command/opcode phase active
        #   0x40 SF_CONT_RD   - continuous read mode
        #   0x80 SF_CONT_WR   - continuous write mode
        # Winbond W25Qxx; the capacity byte follows the flash size (0x16 = 4 MB W25Q32,
        # 0x17 = 8 MB W25Q64), both in the drivers' device tables
        self._spi_jedec_id = [0xEF, 0x40, self.rom_size.bit_length() - 1]
        self._spi_ins = 0x03       # SF_INS: current SPI command (default: normal read)
        self._spi_fmt = 0x0D       # SF_FMT: default = HIT_CODE|HIT_ADDR|HIT_DATA (normal read)
        self._spi_dum = 0x00       # SF_DUM: dummy/data register
        self._spi_cfg = 0x00       # SF_CFG: config register
        self._spi_stream = None    # a chip family's byte-stream mode of the flash window (chips/m3821.py)
        self._spi_status = 0x00    # Flash status register (bit0=WIP, bits[5:2]=BP)
        self._spi_wel = False      # Write Enable Latch
        self._spi_response = []    # queued response bytes for memory-mapped reads
        self._spi_resp_idx = 0     # current read index into response
        self._last_flash_read_page = -1  # for throttled flash read logging

        # Pristine flash contents.  Guest stores into the memory-mapped flash
        # window (SPI command triggers, page-program data) and the SPI response
        # bytes injected by the read hooks all land in the ROM buffer; they are
        # undone by _rom_restore() right after the access, so the ROM image only
        # changes through emulated flash program/erase commands.
        self.rom_image = bytearray(self.rom_size)
        self._rom_dirty = []       # [(offset, size)] ROM ranges to restore

        # Last hooked instruction (size / address), kept for diagnostics.
        self._last_hook_size = 0
        self._last_hook_addr = 0

        self._init_unicorn()
        self._init_capstone()
        # The chip family (chips/): its chip ID, boot flow and devices on top of
        # the common ones; loadFile() switches to the family of the image it
        # loads (_switch_family), which starts again from the common devices.
        # A second core is no chip of its own: the first core's flash image and
        # family devices stay theirs (its stub family only names its code).
        self._common_devices = self._device_tables()
        if self._shared is not None:
            self.rom_image = self._shared.rom_image
            self.chip = chips.see.SeeCoreFamily(self)
        else:
            self.chip = chips.M3801(self)
            self.chip.install()


        self.gpr_map = [
            UC_MIPS_REG_ZERO, UC_MIPS_REG_AT, UC_MIPS_REG_V0, UC_MIPS_REG_V1,
            UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3,
            UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2, UC_MIPS_REG_T3,
            UC_MIPS_REG_T4, UC_MIPS_REG_T5, UC_MIPS_REG_T6, UC_MIPS_REG_T7,
            UC_MIPS_REG_S0, UC_MIPS_REG_S1, UC_MIPS_REG_S2, UC_MIPS_REG_S3,
            UC_MIPS_REG_S4, UC_MIPS_REG_S5, UC_MIPS_REG_S6, UC_MIPS_REG_S7,
            UC_MIPS_REG_T8, UC_MIPS_REG_T9, UC_MIPS_REG_K0, UC_MIPS_REG_K1,
            UC_MIPS_REG_GP, UC_MIPS_REG_SP, UC_MIPS_REG_FP, UC_MIPS_REG_RA
        ]
        self._calibrate_gpr_view()

    def _init_unicorn(self):
        # Initialize Unicorn (MIPS32 + Little Endian)
        self.mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        # Set MIPS32R2 CPU model (24Kf) to match ALI hardware
        self.mu.ctl_set_cpu_model(UC_CPU_MIPS32_24KF)
        
        import ctypes
        
        # No UC_HOOK_MEM_READ / UC_HOOK_MEM_WRITE hooks in normal operation:
        # while one such hook exists, whatever its range, Unicorn translates
        # every load (store) to its slow path, which scans the whole hook list
        # per access (decided per translation block when it is translated).
        # With the ~60 device hooks this used to have, RAM loads / stores ran
        # ~3x slower (dump_maciej's LZMA bootloader: ~200 s of emulation
        # instead of ~64 s).  Instead the device registers are an mmio_map
        # region (Python is called only for accesses to it), the flash window
        # is write-protected (stores to it fault into a hook), and the flash
        # read hook exists only around SPI command mode (see
        # _update_flash_read_hooks).
        # Memory hooks and protection faults report physical addresses, and
        # the guest only ever reaches the physical mappings (kseg0 / kseg1
        # translate to physical; kuseg is mapped 1:1 under the forced ERL),
        # so the 0x8.../0x9.../0xA.../0xB... mappings below are views for
        # Python (mem_read(0xB8000030), mem_write(base_addr, ...)).

        # Shared ROM Buffer (Usually 4MB dumped flash)
        self.rom_buffer = self._buffer('rom_buffer', self.rom_size)

        # Map ROM aliases to the same buffer
        # Ali SoCs commonly map flash repeatedly within a 16MB window
        self.log(f"Mapping Shared ROM mirrors in 16MB window for Phys, KSEG0, KSEG1")
        # 0x0F000000 is the ALi flash window (KSEG0 0x8F..., KSEG1 0xAF...).
        # 0x1F000000 (KSEG1 0xBF...) holds the MIPS reset/BEV exception vectors
        # (0xBFC00000 / 0xBFC00380) which the chip also decodes to the flash.
        # The physical windows the guest uses are read-only: a store to them
        # (an SPI command trigger / page program data) faults into
        # _hook_flash_write_prot, which emulates it and lets it land.
        # A flash larger than 4 MB shows its 4 MB segments below the
        # 0x..C00000 slot (see _flash_offset), so each slot maps its segment.
        slot = min(self.rom_size, 0x400000)
        for offset in range(0, 0x01000000, slot):
            for phys in (0x0F000000, 0x1F000000):
                for seg in (0x00000000, 0x80000000, 0xA0000000):
                    base = seg + phys + offset
                    try:
                        self._map_flash_mirror(base, slot)
                    except Exception as e:
                        self.log(f"Warning: Failed to map ROM mirror at {hex(base)}: {e}")
        
        # Shared RAM Buffer (128MB as per device spec)
        self.ram_buffer = self._buffer('ram_buffer', self.ram_size)
        ram_ptr = ctypes.addressof(self.ram_buffer)
        
        # Map RAM aliases to same buffer
        self.log(f"Mapping Shared RAM at 0x80000000, 0xA0000000, 0x00000000")
        self.mu.mem_map_ptr(0x80000000, self.ram_size, UC_PROT_ALL, ram_ptr)
        self.mu.mem_map_ptr(0xA0000000, self.ram_size, UC_PROT_ALL, ram_ptr)
        self.mu.mem_map_ptr(0x00000000, self.ram_size, UC_PROT_ALL, ram_ptr)
        self._init_fast_access()
        # kuseg 1:1 through a wired TLB entry and the guest's own native Status,
        # or (without it) the forced ERL (see native_status)
        self.force_erl = not (self.native_status and self._setup_kuseg_tlb())
        self._site_words = self._CP0_WORDS - ({0x40006000} if not self.force_erl else set())
        self._site_word_array = None if _np is None else _np.array(sorted(self._site_words), dtype=_np.uint32)

        # Map MMIO: one shared register buffer.  The guest reaches it at the
        # physical 0x18000000 (from any segment), an mmio_map region whose
        # callbacks dispatch to the device handlers registered with _mmio_on
        # and otherwise read / write the buffer like RAM.  0x98000000 /
        # 0xB8000000 map the same buffer for Python (no side effects).
        MMIO_SIZE = 0x01000000
        self.mmio_buffer = self._buffer('mmio_buffer', MMIO_SIZE)
        mmio_ptr = ctypes.addressof(self.mmio_buffer)
        self._mmio_rd = {}          # offset -> [handler]: reads starting at that offset
        self._mmio_wr = {}          # offset -> [handler]: writes starting at that offset
        for base, name in [(0x98000000, "KSEG0 view"), (0xB8000000, "KSEG1 view")]:
            try:
                self.mu.mem_map_ptr(base, MMIO_SIZE, UC_PROT_ALL, mmio_ptr)
                self.log(f"Mapped {name} of the peripherals at {hex(base)} (shared)")
            except UcError as e:
                self.log(f"Warning: {name} at {hex(base)} - {e}")
        self.mu.mmio_map(0x18000000, MMIO_SIZE, self._mmio_read, None, self._mmio_write, None)

        # Set UART LSR (THR empty) so the firmware's putc does not wait
        self.mu.mem_write(0xB8018305, b'\x20')
        # (the chip ID at 0xB8000002 is the chip family's: chips/)

        # Hooks
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_FETCH_PROT | UC_HOOK_MEM_READ_PROT,
                         self._hook_mem_invalid)
        self.mu.hook_add(UC_HOOK_MEM_WRITE_PROT, self._hook_flash_write_prot)

        # Device registers (offsets in the 0x18000000 window, any segment)
        # UART: THR writes (TX), LSR / URBR / UIIR reads (RX simulation)
        self._mmio_on('w', self._hook_uart_write, 0x18300, 0x18305)
        self._mmio_on('r', self._hook_uart_read, 0x18300, 0x18309)
        # GPIO DO and DIR writes for I2C / panel decoding, DI reads loop DO back
        for gpio_off in self._GPIO_DO_OFFSETS:  # 0x054, 0x0D4, 0x0F4, 0x354, 0x454 and 0x0E8
            self._mmio_on('w', self._hook_gpio_write, gpio_off, gpio_off + 7)
        for di_off in self._GPIO_DI_TO_DO:      # DO - 4
            self._mmio_on('r', self._hook_gpio_di_read, di_off, di_off + 3)
        # Device operations the applications start and then poll for completion
        # (see _hook_selfcomplete_read): PMU 0x18018D02, VCAP 0x1800F04B
        for reg in self._SELF_COMPLETING:
            self._mmio_on('r', self._hook_selfcomplete_read, reg & ~3, reg)
        # Video engine status words the decoder driver checks after a VE reset
        for reg in self._VE_STATUS_REGS:
            self._mmio_on('r', self._hook_ve_status_read, reg, reg + 3)
        # The chip ID word (0xB8000000, ChipFamily.write_chip_id) is read-only
        self._mmio_on('w', self._hook_chip_id_store, 0x0000, 0x0003)
        # Graphics engine command / interrupt status (_hook_ge_write) and the
        # interrupt controller status the modelled lines show up in
        self._mmio_on('w', self._hook_ge_write, 0xA004, 0xA00B)
        self._mmio_on('r', self._hook_ge_read, 0xA008, 0xA00B)
        self._mmio_on('r', self._hook_ic_status_read, self.ic_base, self.ic_base + 7)
        # Ethernet MAC ("ETHERNET_MAC_0", 0xB802C000; the Ferguson Ariva T650i's
        # network driver): bit 3 of +0 is a software reset the driver sets and
        # polls until the MAC clears it (_hook_mac_reset_read); +0x7C starts an
        # MDIO (PHY management) access and +0x82 returns its data
        # (_hook_mac_mdio_read)
        self._mmio_on('r', self._hook_mac_reset_read, 0x2C000, 0x2C000)
        self._mmio_on('r', self._hook_mac_mdio_read, 0x2C07C, 0x2C07F)
        # IR receiver controller: FIFO count +1, interrupt status +7, RLC data +8
        self._mmio_on('r', self._hook_irc_read, 0x18101, 0x18101)
        self._mmio_on('r', self._hook_irc_read, 0x18107, 0x18108)
        self._mmio_on('w', self._hook_irc_write, 0x18107, 0x18107)
        # SPI flash controller: both register bases, 0xB8000098 (default) and
        # 0xB802E098 (M3329E rev>=5), each SF_INS(+0x98), SF_FMT(+0x99),
        # SF_DUM(+0x9A), SF_CFG(+0x9B)
        for base in (0x00098, 0x2E098):
            self._mmio_on('w', self._hook_spi_write, base, base + 3)
            self._mmio_on('r', self._hook_spi_read, base, base + 3)
        # The hardware I2C masters the tuner / EEPROM drivers use (i2c_scb.py):
        # the slaves are sim.i2c_devices, none answers unless sim.i2c_ack_all
        # (a second core's are the first one's: one bus, the board's chips on it)
        import i2c_scb
        self.i2c_devices = self._shared.i2c_devices if self._shared else {}
        self.i2c_ack_all = False
        self._demod_address = None          # where attach_demod put the loaded board's demodulator
        self.i2c_masters = [i2c_scb.I2cMaster(self, base, f"SCB{i}") for i, base in enumerate(self.I2C_SCB_BASES)]

        # SPI flash memory-mapped data (SYS_FLASH_BASE_ADDR, the physical
        # 0x0F000000 / 0x1F000000 windows; the firmware uses both 0xAFC00000
        # and 0x0FC00000).  Stores fault into _hook_flash_write_prot; the read
        # hook is only installed around SPI command mode (or with
        # setSPIDump(True, flash_reads=True)), see _update_flash_read_hooks.
        self._flash_windows = [0x0F000000, 0x1F000000]
        # A chip family's own flash device takes the stores to them instead (a
        # parallel flash: parallel_flash.py)
        self.flash_device = None
        self._flash_read_hooks = []
        self._flash_hooks_pending = False
        self._spi_cmd_vt = -1e9               # emulation time of the last SPI command mode
        self._spi_dump_flash_reads = False
        self.flash_hook_changes = 0           # flash read hook installs / removals (each flushes the TBs)
        self._mmio_observers = []             # add_mmio_hook() callbacks
        self._update_flash_read_hooks()

        # Jumps to address 0 (NULL function pointers, end of a test program)
        # stop emulation instead of executing RAM as code.
        self.mu.hook_add(UC_HOOK_CODE, self._hook_null_jump, begin=0, end=3)
        # 0x80000200..0x80000FFF: a code hook while it holds the SDK's zero
        # padding (_update_short_block_hook)
        self._short_block_hook = None

        # The per-instruction hook (_hook_code) and the fast-mode hooks are
        # installed on demand by _sync_hooks() (see run()).
        # Intercept emu_stop() so run() can tell a stop requested by user code
        # or the GUI from a batch that simply ran its instruction count.
        raw_emu_stop = self.mu.emu_stop
        def _timed_emu_stop():
            # Emulation time (Count) ends when a stop is requested: what follows
            # (the requesting hook's rescan, Unicorn's shutdown) is host work.
            # Only on the emulation thread: another thread's reading of its clock
            # would be stale (and could even belong to the previous slice).
            if self._vt_slice_t0 is not None and self._vt_stop_t is None and                     self._clk_key is not None and threading.get_native_id() == self._clk_key[0]:
                self._vt_stop_t = self._clk()
            raw_emu_stop()
        self._orig_emu_stop = _timed_emu_stop
        def _emu_stop_wrapper():
            if self._stop_reason is None:
                self._stop_reason = 'external'
            if self._in_run and threading.get_ident() != self._run_tid:
                self._external_stop = True  # a pause from another thread (GUI): run() returns
            elif self._dev_cb_depth == 0 and self._vt_slice_t0 is not None and \
                    self._clk_key is not None and threading.get_native_id() == self._clk_key[0]:
                # Requested on the emulation thread outside a device access (a
                # code hook: breakpoint, GUI / user pause): the CPU stops before
                # the next instruction, nothing is rewound (see _dev_note).
                self._dev_last = None
            self._orig_emu_stop()
        self.mu.emu_stop = _emu_stop_wrapper
        # Account the time spent inside every emu_start() (run(), single steps
        # and test scripts that call it directly) as emulation time for Count.
        self._orig_emu_start = self.mu.emu_start
        def _emu_start_wrapper(*args, **kwargs):
            # Flash read hook changes happen here, never while the CPU runs
            if self._flash_hooks_pending or (self._flash_read_hooks and not self._flash_hooks_wanted()):
                self._apply_flash_hooks()
            self._setup_clock()
            self._vt_stop_t = None
            self._dev_last = None
            self._vt_slice_t0 = self._clk()
            try:
                return self._orig_emu_start(*args, **kwargs)
            finally:
                if self._ds_flags_stale:
                    self._clear_branch_flags()
                end = self._clk()
                if self._vt_stop_t is not None:
                    end = min(end, self._vt_stop_t)
                self._vt_accum += max(0.0, end - self._vt_slice_t0)
                self._vt_slice_t0 = self._vt_stop_t = None
                # An asynchronous stop (stopper, timeout, GUI pause; not a counted
                # run or a hook's own stop) that left the PC on the last device
                # access: that instruction runs again on resume (see _dev_note).
                # (A counted run that simply ran out stops before an instruction:
                # no replay.  An explicit emu_stop() is 'external' in any run.)
                # ('flashhooks': requested inside an SF_INS store, which then
                # re-executes like after an asynchronous stop)
                count = kwargs.get('count', args[3] if len(args) > 3 else 0)
                last = self._dev_last
                if last is not None and (self._stop_reason in ('external', 'flashhooks') or
                                         (self._stop_reason is None and not count)):
                    try:
                        # Rewound onto the access, not stopped before a later pass
                        # of it: the instruction at the (exact) stop PC is a load /
                        # store of that address, it lies in the translation block
                        # the access ran in, and the registers are unchanged (a
                        # load's destination is written only after the exit
                        # check).  The access itself cannot tell its PC: in an
                        # mmio_map callback Unicorn's PC is the start of the
                        # translation block (last[4]).
                        pc = self.mu.reg_read(UC_MIPS_REG_PC)
                        if (last[3] is None or self._gpr_snapshot() == last[3]) and \
                                self._phys(self._insn_mem_address(pc)) == self._phys(last[1]) and \
                                (pc == last[4] if last[5] else self._same_block(last[4], pc)):
                            if len(self._dev_replays) >= 16:      # stale entries: drop the oldest
                                self._dev_replays.pop(next(iter(self._dev_replays)))
                            # keyed by (PC, SP): an interrupt handler or another task
                            # running the same code must not take this entry.  On
                            # resume the rewound instruction starts a translation
                            # block, so its access sees this PC (_dev_replay_of).
                            key = (pc, self.mu.reg_read(UC_MIPS_REG_SP))
                            self._dev_replays[key] = last[0:3]
                    except UcError:
                        pass
        self.mu.emu_start = _emu_start_wrapper

        # CP0 Status configuration
        try:
            status = 0x10400000 # CU0=1, BEV=1
            self._write_native_status(self.mu, status)
            self.log(f"Set CP0 Status = 0x{status:08X}")
        except Exception as e:
            self.log(f"Warning: Could not set CP0 Status: {e}")

        self._calibrate_hflags()

    # The firmwares address peripherals and the flash window through kuseg
    # (0x18000058, 0x0FC00000) as if it were identity mapped.  QEMU maps kuseg
    # 1:1 only while Status.ERL is set, so the simulator forced ERL into the
    # native Status (force_erl) -- and had to emulate every MFC0 / MTC0 Status,
    # whose native result would show it: in the RTOS's interrupt disable and
    # enable alone, half of all the hooked CP0 instructions.  With native_status
    # a wired TLB entry -- two 256 MB pages, physical 0x00000000 and
    # 0x10000000, uncached, global -- maps kuseg's lower 512 MB 1:1 instead
    # (none of the firmwares writes the TLB) and the native Status is the
    # guest's own: MFC0 Status runs natively (it is not a CP0 site), the hook
    # of MTC0 Status only follows the write unless the slice must end there
    # (_emulate_cop0), and the run loop takes the native Status over at each
    # slice boundary.  An ERET that runs natively (its hook skipped under an
    # asynchronous stop) goes to the native EPC, which nothing writes, 0:
    # run() redoes it (as it did with ErrorEPC under the forced ERL).
    native_status = True

    def _setup_kuseg_tlb(self):
        """Install the wired TLB entry that maps kuseg 1:1 (a stub run once on
        a scratch page) and check it: a kuseg load with ERL clear reads RAM.
        False if that cannot be done (the forced ERL stays)."""
        import struct
        page = 0x0EFFF000                   # (physical; above the RAM, below the flash window)
        if self.ram_size > page:
            return False
        mu = self.mu

        def li(v):
            return [0x3C080000 | (v >> 16), 0x35080000 | (v & 0xFFFF)]        # lui / ori t0

        def mtc0(rd):
            return 0x40880000 | rd << 11                                     # mtc0 t0, rd

        def entry_lo(pa):
            return ((pa >> 12) << 6) | (2 << 3) | 0x7                        # PFN, uncached, D, V, G

        install = (li(0x1FFFE000) + [mtc0(5)] + li(0) + [mtc0(10)] + li(entry_lo(0)) + [mtc0(2)] +
                   li(entry_lo(0x10000000)) + [mtc0(3)] + li(0) + [mtc0(0)] + li(1) + [mtc0(6)] +
                   [0x42000002, 0])                                          # tlbwi
        check = [0x3C090000, 0x8D2A0000, 0]                                  # lui t1, 0; lw t2, 0(t1)
        saved = [mu.reg_read(r) for r in (UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2, UC_MIPS_REG_PC)]
        ok = False
        try:
            mu.mem_map(page, 0x1000)
            for code, status in ((install, 0x10400004), (check, 0x10400000)):
                mu.mem_write(page, struct.pack(f"<{len(code)}I", *code))
                mu.ctl_flush_tb()
                mu.reg_write(UC_MIPS_REG_CP0_STATUS, status)
                mu.emu_start(0x80000000 | page, (0x80000000 | page) + 4 * len(code), count=len(code))
            ok = mu.reg_read(UC_MIPS_REG_T2) == int.from_bytes(self._ram_view[0:4], 'little')
        except UcError as e:
            self.log(f"Warning: the kuseg TLB entry could not be set up ({e}); forcing Status.ERL")
        finally:
            try:
                mu.mem_unmap(page, 0x1000)
            except UcError:
                pass
            mu.ctl_flush_tb()
            for r, v in zip((UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2, UC_MIPS_REG_PC), saved):
                mu.reg_write(r, v)
        return ok

    def _buffer(self, name, size):
        """A memory buffer the Unicorn mappings point into: a second core's is the
        first core's (share_memory_with)."""
        import ctypes
        return getattr(self._shared, name) if self._shared else ctypes.create_string_buffer(size)

    def _init_fast_access(self):
        """What the fast-mode CP0 hooks read and write many times a second goes
        around the Unicorn binding, whose reg_read / reg_write / mem_read build
        ctypes objects per call (2.6-3.5 us each, against ~1 us for the C call):
        _reg_read / _reg_write call uc_reg_read / uc_reg_write with one
        preallocated value (GPRs, PC and CP0 Status: 32-bit registers), and
        _ram_words views the RAM buffer that kuseg, KSEG0 and KSEG1 map, as
        little-endian words (None on a big-endian host)."""
        import ctypes
        mu = self.mu
        try:
            lib = sys.modules[type(mu).__module__].uclib
            uch, val = mu._uch, ctypes.c_uint64()
            ref, c_write, c_read = ctypes.byref(val), lib.uc_reg_write, lib.uc_reg_read

            def reg_write(reg, value):
                val.value = value
                err = c_write(uch, reg, ref)
                if err:
                    raise UcError(err)

            def reg_read(reg):
                err = c_read(uch, reg, ref)
                if err:
                    raise UcError(err)
                return val.value & 0xFFFFFFFF

            self._reg_write, self._reg_read = reg_write, reg_read
        except Exception:                    # another binding: its own calls
            self._reg_write, self._reg_read = mu.reg_write, mu.reg_read
        self._ram_view = memoryview(self.ram_buffer).cast('B')
        self._ram_words = self._ram_view.cast('I') if sys.byteorder == 'little' else None

    def _init_capstone(self):
        self.md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)

    def setLogHandler(self, handler):
        self.log_callback = handler

    def setUartHandler(self, handler):
        self.uart_callback = handler

    def setUartReceiveData(self, data_bytes, delay_instructions=500000, force_immediate=False):
        """Queue bytes for UART receive simulation.

        When the firmware's UART ISR runs, it reads UIIR, LSR, and URBR.
        Our read hook serves bytes from this queue.  Also arms interrupt
        delivery so the ISR gets invoked via the MIPS exception vector.

        Args:
            data_bytes: bytes to queue for UART receive
            delay_instructions: wait this many instructions before delivering
                               the first interrupt (default 500K, so TDS2 has
                               registered the UART ISR via OS_RegisterISR)
            force_immediate: if True, deliver IRQ at exactly delay_instructions
                            regardless of CP0 Status IE/EXL (for testing)
        """
        self._uart_rx_queue.extend(data_bytes)
        if len(self._uart_rx_queue) > 0:
            self._pending_uart_irq = True
            self._uart_irq_delivered = False
            self._uart_irq_arm_after = self.instruction_count + delay_instructions
            self._uart_irq_retries = 0
            self._uart_irq_force = force_immediate
        self.log(f"[UART RX] Queued {len(data_bytes)} bytes, IRQ armed after {delay_instructions} instructions{' (FORCED)' if force_immediate else ''}")

    def setSpiHandler(self, handler):
        self.spi_callback = handler

    def setSPIDump(self, enabled, flash_reads=False):
        """Enable or disable SPI dump logging (SPI commands, responses, flash
        program / erase).  flash_reads=True also logs normal-mode flash reads
        (once per 64 KB sector); that keeps a Unicorn memory hook installed,
        which slows every load of the emulation down (see _init_unicorn)."""
        self._spi_dump_enabled = enabled
        self._spi_dump_flash_reads = bool(enabled and flash_reads)
        if self._rom_dirty:
            self._rom_restore()
        self._update_flash_read_hooks()

    # The flash-window read hook (_hook_spi_flash_read) serves the SPI command
    # responses.  It is a Unicorn memory hook, so while it exists every guest
    # load takes Unicorn's slow path, and Unicorn decides that per translation
    # block when the block is translated.  Therefore:
    #  * it is only added / removed between emu_start() calls, and then the
    #    translation cache is flushed so that every block sees the change
    #    (added from a device callback while the CPU ran, the rest of the
    #    running block still read the flash window without it; that version
    #    also crashed Unicorn natively in 7-30% of the boots, together with the
    #    response bytes written into the read-only flash mapping, see
    #    _rom_inject);
    #  * when the guest enters SPI command mode without the hook, the emulation
    #    stops right at that SF_INS store (a stop requested inside a device
    #    access takes effect before the next instruction; the store is
    #    re-executed on resume and recognised as a replay), and the next
    #    emu_start() installs the hook before the guest reads the response;
    #  * leaving command mode stops at that SF_INS store too, and the next
    #    emu_start() removes the hook (and flushes): with the hook installed,
    #    every flash-window load (also in normal read mode) goes through it,
    #    which is slow and exposes the delay-slot bug (_device_access).  The
    #    two stops and flushes per command phase cost less than keeping it
    #    through sparse commands (dump.bin / Prima decompression: idle 0 s ~
    #    0.05 s, both ~20% faster than 0.5 s), but dense command sequences
    #    (dump.bin's application reads its flash database byte by byte, ~750k
    #    commands) run 5x faster when the hook stays through them: it is kept
    #    for flash_hook_idle_s of emulation time after command mode ends.
    flash_hook_idle_s = 0.05

    def _flash_hooks_wanted(self):
        return (not self._spi_is_passthrough()) or self._spi_dump_flash_reads

    def _update_flash_read_hooks(self):
        """The SPI controller mode or the logging setting changed."""
        wanted = self._flash_hooks_wanted()
        if wanted:
            self._spi_cmd_vt = self._vtime()
        if wanted == bool(self._flash_read_hooks):
            self._flash_hooks_pending = False
        elif self._vt_slice_t0 is None:               # not emulating: change it now
            self._apply_flash_hooks(force=True)
        elif wanted or self.flash_hook_idle_s <= 0:   # emulating: at the next emu_start()
            self._flash_hooks_pending = True
            if not self.is_stepping:                   # (a single step ends after this instruction)
                if self._stop_reason is None:
                    self._stop_reason = 'flashhooks'
                self._orig_emu_stop()
        # (else: no longer wanted; _apply_flash_hooks removes it after the idle time)

    def _apply_flash_hooks(self, force=False):
        """Between emu_start() calls: install the flash read hook if wanted;
        remove it if not, after flash_hook_idle_s without command mode (at
        once with force)."""
        self._flash_hooks_pending = False
        wanted = self._flash_hooks_wanted()
        if wanted and not self._flash_read_hooks:
            for flash_base in self._flash_windows:
                self._flash_read_hooks.append(self.mu.hook_add(
                    UC_HOOK_MEM_READ, self._hook_spi_flash_read,
                    begin=flash_base, end=flash_base + 0x00FFFFFF))
            self.flash_hook_changes += 1
            self._flush_tb()
        elif self._flash_read_hooks and not wanted and \
                (force or self._vtime() - self._spi_cmd_vt >= self.flash_hook_idle_s):
            for h in self._flash_read_hooks:
                self.mu.hook_del(h)
            self._flash_read_hooks = []
            self.flash_hook_changes += 1
            self._flush_tb()

    def _hook_null_jump(self, uc, address, size, user_data):
        if self.is_stepping:
            return
        self._stop_reason = 'null'
        uc.emu_stop()

    # The SDK's application images are loaded at 0x80000200, and some start with
    # 0xE00 zero bytes before their first code (the Ferguson T750i / T760i
    # applications).  Unicorn 2.1.4 crashes translating that run of ~900 NOPs
    # as one unhooked block, so while the range holds such a run it executes
    # under a code hook that does nothing (_hook_short_blocks); the exception
    # vectors below it stay unhooked.  Code there runs unhooked: a Python call
    # per instruction made the URZ0086's start-up (its BSS clear) take 1.7 s of
    # emulation time instead of 25 ms, and the SEE's program, which its
    # bootloader starts just before, ran all that time.
    _PADDING = (0x80000200, 0x80000FFF)
    _PADDING_WORDS = 128                # a run of zero words this long is padding, not code

    def _update_short_block_hook(self):
        """At a full CP0 site scan: hook the padding range while it holds a long
        run of zero words, unhook it otherwise."""
        lo, hi = self._PADDING
        padded = bytes(4 * self._PADDING_WORDS) in self.mu.mem_read(lo, hi + 1 - lo)
        if padded and self._short_block_hook is None:
            self._short_block_hook = self.mu.hook_add(UC_HOOK_CODE, self._hook_short_blocks, begin=lo, end=hi)
            self._tb_flush_needed = True
        elif not padded and self._short_block_hook is not None:
            self.mu.hook_del(self._short_block_hook)
            self._short_block_hook = None
            self._tb_flush_needed = True

    def _hook_short_blocks(self, uc, address, size, user_data):
        """Nothing: being hooked keeps Unicorn's translation blocks short there
        (_update_short_block_hook)."""

    def setGpioHandler(self, handler):
        """Set the callback for GPIO pin changes, handler(address, size,
        value): called for every write of a GPIO bank's DO or DIR register
        with the bank's pin levels (_hook_gpio_write).  If the handler is a
        bound method of an object with di_override(di_offset, value), the
        object also answers the firmware's reads of the pins it drives
        (_hook_gpio_di_read)."""
        self.gpio_callback = handler

    def setI2CDump(self, enabled):
        """Enable or disable I2C/GPIO trace logging. TM1650 results always shown."""
        if self.gpio_callback and hasattr(self.gpio_callback, '__self__'):
            self.gpio_callback.__self__.dump_enabled = enabled

    def addBreakpoint(self, address):
        self.breakpoints.add(address)
        self.log(f"Breakpoint added at 0x{address:08X}")
        self._sync_hooks_if_ready()

    def removeBreakpoint(self, address):
        if address in self.breakpoints:
            self.breakpoints.remove(address)
            self.log(f"Breakpoint removed at 0x{address:08X}")
            self._sync_hooks_if_ready()

    @property
    def stop_instr(self):
        """Address at which emulation stops (like a one-off breakpoint)."""
        return self._stop_instr

    @stop_instr.setter
    def stop_instr(self, value):
        self._stop_instr = value
        self._sync_hooks_if_ready()

    def _sync_hooks_if_ready(self):
        """Keep the fast-mode hooks in step with breakpoints/stop_instr for
        scripts that drive sim.mu.emu_start() directly instead of run()."""
        if self.mu is not None and self.rom_image is not None and getattr(self, '_virgin_hooks', None) is not None:
            try:
                self._sync_hooks()
            except Exception as e:
                self.log(f"Warning: hook sync failed: {e}")

    def log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
        else:
            print(msg)

    def _uart_log(self, value):
        if self.uart_callback:
            # Pass the character code directly, let the handler decide format
            self.uart_callback(chr(value & 0xFF))
        else:
            try:
                print(bytes([value & 0xFF]).decode('ascii', errors='replace'), end='', flush=True)
            except:
                pass

    # SPI command name lookup for readable log output
    _SPI_CMD_NAMES = {
        0x03: "Read", 0x0B: "Fast Read", 0x9F: "JEDEC Read ID",
        0x05: "Read Status", 0xAB: "Release Power Down",
        0x90: "Read Mfr/Dev ID", 0x06: "WREN", 0x04: "WRDI",
        0x01: "Write Status", 0x02: "Page Program", 0xAD: "AAI Program",
        0x3B: "Dual Read", 0x6B: "Quad Read", 0xBB: "Dual I/O Read", 0xEB: "Quad I/O Read",
        0x32: "Quad Page Program",
        0x20: "Sector Erase 4K", 0x52: "Block Erase 32K",
        0xD8: "Block Erase 64K", 0xC7: "Chip Erase", 0x60: "Chip Erase",
    }

    def _spi_log(self, msg):
        if not self._spi_dump_enabled:
            return
        if self.spi_callback:
            self.spi_callback(msg)
        else:
            print(f"[SPI] {msg}", flush=True)

    def loadFile(self, filename):
        filename = resolve_dump(filename)
        self.dump_path = filename
        self.log(f"Loading {filename}...")
        import ir_remote
        self.ir_coding = ir_remote.coding_for(filename)
        with open(filename, "rb") as f:
            code = f.read()
        
        if len(code) > self.rom_size:
            # Reallocation would break the multiple mem_map_ptr calls we did in _init_unicorn,
            # so for now we'll issue a strong warning and truncate if needed.
            # In a real environment, the ROM dump shouldn't exceed the configured ROM size.
            self.log(f"Warning: File size (0x{len(code):X}) exceeds rom_size (0x{self.rom_size:X}). Truncating!")
            code = code[:self.rom_size]
        
        # Keep the pristine image (padded with erased flash) and load it into the
        # shared ROM buffer; every mirror sees it.
        self.rom_image = bytearray(code) + bytearray(b'\xFF' * (self.rom_size - len(code)))
        self._rom_dirty = []
        self._rom_write(0, bytes(self.rom_image))
        # SPI flash controller back to its power-on state (normal read mode)
        self._spi_ins, self._spi_fmt, self._spi_dum, self._spi_cfg = 0x03, 0x0D, 0x00, 0x00
        self._spi_status, self._spi_wel = 0x00, False
        self._spi_response, self._spi_resp_idx, self._last_flash_read_page = [], 0, -1
        self._update_flash_read_hooks()

        # A dual-CPU chip's SEE back in reset: a SEE core running the last image's program stops
        if self.chip.see is not None:
            self.chip.see.reset()
        # The image's chip family: its boot flow, and its devices if it differs
        # from the current one (chips/; the class itself: an M3503 is an M3602
        # and a C3505 an M3821 to isinstance, but their chip IDs and devices differ)
        family = chips.detect(self.rom_image)
        if type(self.chip) is not family:
            self._switch_family(family)
        else:
            self.chip.write_chip_id()       # (this image's board may read another chip ID)
        self.attach_demod()                 # (the board's external demodulator, when its sidecar names one)
        self.attach_gpio_devices()          # (its bit-banged I2C bus, pulled-up inputs)

        # Re-initialize globals if re-running
        self.instruction_count = 0
        self._count_icount = 0
        self._count_t0 = self._vtime()
        # CP0 timer back to its reset state (no Compare written yet)
        self._ti = False
        self._timer_armed = False
        self._timer_anchor = self._cp0_count_now()
        self._timer_next_icount = 0
        self._count_observed = None
        self._uart_ip3 = False
        while self._ic_lines:                   # (also clears their 0xB8000030 / 34 bits)
            self._ic_set_line((self._ic_lines & -self._ic_lines).bit_length() - 1, False)
        self._ge_status = 0
        self._irc_fifo.clear()
        self._irc_status = 0
        self._irc_frames.clear()
        self._irc_last_vt = -1e9
        self._ir_key_table = None
        self.ir_keys_sent = 0
        for master in self.i2c_masters:
            master.reset()
        self.timer_irq_count = self.ic_irq_count = self.ge_ops = 0
        self.busy_pending = 0.0
        self.lzma_decodes = []
        self._last_eret_vt = -1e9
        self._dev_replays = {}
        self.visit_counts = {}
        self.last_lui_addr = None
        self._rescan_all()
        # The reset state: the PC, after whatever the chip's boot ROM does first
        self.chip.start()

    def _rescan_all(self):
        """Fast mode: scan the flash, the RAM and the family's code ranges for
        CP0 instruction sites again, and install the hooks now -- some test
        scripts drive sim.mu.emu_start() directly instead of run(), and still
        need CP0 emulation."""
        self._rescan_due = True
        self._rom_sites_dirty = True
        self._sync_hooks()

    def _device_tables(self):
        """Copies of the device register handlers (reads, writes) and the slice
        services: taken before the first chip family installs its devices, they
        are the common devices'."""
        return ({off: list(h) for off, h in self._mmio_rd.items()},
                {off: list(h) for off, h in self._mmio_wr.items()},
                list(self.slice_services))

    def _switch_family(self, family):
        """Replace the chip family by `family` (a chips/ class): the current one
        gives back what its install() changed besides its devices
        (ChipFamily.uninstall: memory it mapped, hooks, attributes of the
        simulator), the device handlers and slice services go back to the
        common ones, then the new family installs its own.  Without that, a
        simulator -- which starts as the M3801 -- kept the M3801's
        demodulator, demultiplexer and RTC handlers under every other family."""
        self.chip.uninstall()
        reads, writes, services = self._common_devices
        self._mmio_rd = {off: list(h) for off, h in reads.items()}
        self._mmio_wr = {off: list(h) for off, h in writes.items()}
        self.slice_services[:] = services
        self.chip = family(self)
        self.chip.install()

    def _map_flash_mirror(self, base, size):
        """Map the flash window's mirror over base .. base + size - 1 (base: an
        address of the 0x0F000000 / 0x1F000000 windows in any segment, the
        range inside one 4 MB slot): read-only at the physical address, its
        bytes the flash's at _flash_offset(base).  _init_unicorn() maps the
        windows with it, and a chip family that put memory of its own there
        gives it back with it."""
        import ctypes
        perms = (UC_PROT_READ | UC_PROT_EXEC) if base < 0x80000000 else UC_PROT_ALL
        self.mu.mem_map_ptr(base, size, perms, ctypes.addressof(self.rom_buffer) + self._flash_offset(base))

    def loadFileTruncated(self, filename, max_bytes):
        """Load a ROM file but keep only the first max_bytes.
        
        The rest of ROM is filled with 0xFF (erased flash state).
        Useful for testing bootloader behavior when main app chunks
        are missing or corrupted.
        """
        self.loadFile(filename)
        if max_bytes < self.rom_size:
            pad = b'\xFF' * (self.rom_size - max_bytes)
            self.rom_image[max_bytes:] = pad
            self._rom_write(max_bytes, pad)
            self._rescan_all()
            self.log(f"Truncated ROM to {max_bytes // 1024}KB (rest filled with 0xFF)")

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        access_types = {
            16: "READ", 17: "WRITE", 18: "FETCH",
            19: "READ_UNMAPPED", 20: "WRITE_UNMAPPED", 21: "FETCH_UNMAPPED",
            22: "WRITE_PROT", 23: "READ_PROT", 24: "FETCH_PROT",
        }
        pc = uc.reg_read(UC_MIPS_REG_PC)
        atype = access_types.get(access, f"UNKNOWN({access})")
        
        # Always print to stderr so crash details are never lost
        import sys as _sys
        print(f"\n[!] INVALID MEMORY ACCESS", file=_sys.stderr, flush=True)
        print(f"    Type: {atype}", file=_sys.stderr, flush=True)
        print(f"    Address: 0x{address:08X}", file=_sys.stderr, flush=True)
        print(f"    Size: {size}", file=_sys.stderr, flush=True)
        print(f"    PC: 0x{pc:08X}", file=_sys.stderr, flush=True)
        
        try:
            print(f"    Instruction bytes: {uc.mem_read(pc, 4).hex()}", file=_sys.stderr, flush=True)
        except:
            pass
        
        # Dump all GPRs for debugging
        gpr_names = [
            "zero","at","v0","v1","a0","a1","a2","a3",
            "t0","t1","t2","t3","t4","t5","t6","t7",
            "s0","s1","s2","s3","s4","s5","s6","s7",
            "t8","t9","k0","k1","gp","sp","fp","ra"
        ]
        print(f"    --- Register Dump ---", file=_sys.stderr, flush=True)
        for i, name in enumerate(gpr_names):
            val = uc.reg_read(self.gpr_map[i])
            print(f"    {name:4s} = 0x{val:08X}", file=_sys.stderr, flush=True)
        
        # Disassemble instruction at PC
        try:
            code = uc.mem_read(pc, 4)
            print(f"    --- Instruction at PC ---", file=_sys.stderr, flush=True)
            print(f"    Bytes: {' '.join(f'{b:02x}' for b in code)}", file=_sys.stderr, flush=True)
            for i in self.md.disasm(bytes(code), pc):
                print(f"    {i.mnemonic}\t{i.op_str}", file=_sys.stderr, flush=True)
        except Exception as e:
            print(f"    (could not disasm: {e})", file=_sys.stderr, flush=True)
        
        # Also send to log handler
        if address == 0 and access in [18, 21]:  # FETCH or FETCH_UNMAPPED
            self.log(f"\n[!] STOPPED: Jump to NULL (0x0) detected!")
        else:
            self.log(f"\n[!] INVALID MEMORY ACCESS")
            self.log(f"    Type: {atype}")
            self.log(f"    Address: 0x{address:08X}")
        self.log(f"    Size: {size}")
        self.log(f"    PC: 0x{pc:08X}")
        return False

    # ------------------------------------------------------------------
    # Replay-safe device side effects
    # ------------------------------------------------------------------
    # An asynchronous stop (the slice stopper, Unicorn's timeout, a GUI pause)
    # is noticed by Unicorn right after a load / store and rewinds the PC to
    # that instruction, which then runs again -- memory hook included -- on
    # resume.  For RAM that is harmless; for device registers whose access has
    # a side effect it duplicated UART TX characters, lost UART RX bytes and
    # skipped SPI response bytes.  Those hooks record their access
    # (_dev_note); if the emu_start() wrapper sees an asynchronous stop that
    # left the PC on that very instruction, the re-execution is recognised
    # (_dev_replay_of) and serves / skips the same data.  A stop noticed just
    # *before* a later pass of the same instruction (a GUI pause, the start of
    # a translation block) must not count: the access keeps a register
    # fingerprint, a rewind leaves the registers unchanged, and any other
    # hooked instruction / device access in between clears the record.
    # Pending replays are kept per (PC, SP), so an interrupt handler or another
    # task running the same putc / getc in between does not take them.

    def _device_access(self, uc, hooked=False):
        """Start of every device handler.  A new device access proves the
        noted one completed (see _dev_note).  An access that reached us
        through a Unicorn memory hook / protection fault (hooked=True: the
        flash window) in a branch delay slot meets a Unicorn 2.1.4 bug: the
        branch flags of hflags stay set after it, so the next translation
        block -- at the branch's target -- runs as the delay slot of a branch
        to that target, and its first instruction runs twice (the M3329's
        flash probe, whose target is another branch: PC 0 in the end).  So
        the emulation stops there (before that block: the branch has
        completed) and the emu_start() wrapper clears the flags
        (_clear_branch_flags).  mmio_map accesses (the device registers) do
        not have that bug -- unless a Unicorn memory hook (a debugging
        script's) covers the device window too, which is not checked."""
        self._dev_last = None
        if hooked and self._hflags_off is not None:
            self.mu.context_update(self._ctx)
            if self._hflags_view.value & self._HFLAG_BMASK:
                pc = uc.reg_read(UC_MIPS_REG_PC)
                if pc not in self._ds_dev_warned and len(self._ds_dev_warned) < 16:
                    self._ds_dev_warned.add(pc)
                    self.log(f"[DSLOT] device access in a branch delay slot at 0x{pc:08X}: stopping "
                             f"after the branch to clear its flags (Unicorn 2.1.4 would run its target twice)")
                self._ds_flags_stale = True
                if not self.is_stepping:            # (a single step ends after the branch anyway)
                    if self._stop_reason is None:
                        self._stop_reason = 'dslot'
                    self._orig_emu_stop()

    def _clear_branch_flags(self):
        """After an emu_start() that stopped for a hooked access in a delay
        slot (_device_access): the branch has completed, clear its flags."""
        self._ds_flags_stale = False
        self.mu.context_update(self._ctx)
        if self._hflags_view.value & self._HFLAG_BMASK:
            self._hflags_view.value &= ~self._HFLAG_BMASK
            self.mu.context_restore(self._ctx)
            self.ds_flag_fixes += 1

    def _dev_note(self, uc, kind, address, data, exact=None):
        """Record a device access with a side effect (see the section comment).
        Its PC is exact in exact mode and for accesses through a Unicorn memory
        hook (exact=True: the flash window); in an mmio_map callback in fast
        mode it is the start of the translation block."""
        if exact is None:
            exact = self._code_hook_h is not None
        self._dev_last = (kind, address, data, self._gpr_snapshot(), uc.reg_read(UC_MIPS_REG_PC), exact)

    def _same_block(self, start, pc):
        """True if pc can lie in the translation block that starts at `start`:
        straight-line code from start to pc, or pc is the delay slot of the
        branch that ends it (in exact mode start is the access itself).  Tells
        a rewound access from a stop just before another instruction that
        repeats it (a later block)."""
        if start is None:
            return False
        start &= ~1
        # a translation block never crosses a 4 KB page
        if not 0 <= pc - start < 0x1000 or (start ^ pc) & ~0xFFF:
            return False
        m16 = self.is_mips16_mode()
        sites = self._cp0_site_hooks
        a = start
        try:
            while a < pc:
                if m16:
                    op = int.from_bytes(self.mu.mem_read(a, 2), 'little') >> 11
                    size = 4 if op in (0x1E, 0x03) else 2                # EXTEND / JAL(X)
                    insn = bytes(self.mu.mem_read(a, size))
                    hw = insn[0] | (insn[1] << 8)
                    ends = (self._insn_has_delay_slot(insn, size, True)
                            or self._m16_pc_relative_branch(insn, size)
                            or (size == 2 and op == 0x1D and (hw & 0x1F) in (0, 1, 5)))  # J(AL)R(C), SDBBP, BREAK
                else:
                    size = 4
                    insn = bytes(self.mu.mem_read(a, 4))
                    w = int.from_bytes(insn, 'little')
                    ends = (self._insn_has_delay_slot(insn, 4, False)
                            or a in sites                                  # hooked CP0 site: the hook moves the PC
                            or w in (0x42000018, 0x4200001F)               # ERET, DERET
                            or (w & 0xFE00003F) == 0x42000020              # WAIT
                            or (w & 0xFFE0FFDF) == 0x41606000              # DI / EI
                            or ((w >> 26) == 1 and ((w >> 16) & 0x1F) == 0x1F)    # SYNCI
                            or ((w >> 26) == 0 and (w & 0x3F) in (0x0C, 0x0D)))  # SYSCALL / BREAK
                if ends:
                    return pc == a + size and self._insn_has_delay_slot(insn, size, m16)
                a += size
            return a == pc
        except UcError:
            return False

    @staticmethod
    def _phys(address):
        """Physical address of a kseg0 / kseg1 / (ERL) kuseg address; None stays None."""
        if address is None:
            return None
        return address & 0x1FFFFFFF if 0x80000000 <= address < 0xC0000000 else address

    # MIPS32 load / store opcodes: lb lh lwl lw lbu lhu lwr sb sh swl sw swr ll sc
    _M32_MEM_OPS = frozenset((0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x28, 0x29, 0x2A, 0x2B, 0x2E,
                              0x30, 0x38))
    # MIPS16e: major opcode -> (offset scale, base register: None = rx, 29 = sp)
    _M16_MEM_OPS = {0x10: (1, None), 0x11: (2, None), 0x12: (4, 29), 0x13: (4, None),
                    0x14: (1, None), 0x15: (2, None), 0x18: (1, None), 0x19: (2, None),
                    0x1A: (4, 29), 0x1B: (4, None)}
    _M16_REGS = (16, 17, 2, 3, 4, 5, 6, 7)

    def _insn_mem_address(self, pc):
        """Effective address of the load / store at pc in the current ISA mode
        (with the current registers), or None if it is not one."""
        try:
            if self.is_mips16_mode():
                hw = int.from_bytes(self.mu.mem_read(pc, 2), 'little')
                ext = None
                if hw >> 11 == 0x1E:                        # EXTEND prefix
                    ext = hw
                    hw = int.from_bytes(self.mu.mem_read(pc + 2, 2), 'little')
                op = hw >> 11
                if op == 0x0C and (hw >> 8) & 7 == 2:       # SWRASP: sw ra, imm8*4(sp)
                    scale, base, imm = 4, 29, hw & 0xFF
                elif op in self._M16_MEM_OPS:
                    scale, base = self._M16_MEM_OPS[op]
                    if base is None:
                        base, imm = self._M16_REGS[(hw >> 8) & 7], hw & 0x1F
                    else:
                        imm = hw & 0xFF
                else:
                    return None
                if ext is not None:                         # 16-bit signed, unscaled
                    off = ((ext & 0x1F) << 11) | (((ext >> 5) & 0x3F) << 5) | (hw & 0x1F)
                    off -= (off & 0x8000) << 1
                else:
                    off = imm * scale
            else:
                w = int.from_bytes(self.mu.mem_read(pc, 4), 'little')
                if w >> 26 not in self._M32_MEM_OPS:
                    return None
                base, off = (w >> 21) & 31, w & 0xFFFF
                off -= (off & 0x8000) << 1
            return (self.mu.reg_read(self.gpr_map[base]) + off) & 0xFFFFFFFF
        except UcError:
            return None

    def _dev_replay_of(self, uc, kind, address, data=None):
        """(kind, address, data) of the first execution if this access is its
        replay, else None (and then recorded as a new access by the caller)."""
        if not self._dev_replays:
            return None
        pc = uc.reg_read(UC_MIPS_REG_PC)
        rp = self._dev_replays.pop((pc, uc.reg_read(UC_MIPS_REG_SP)), None)
        if rp is None or rp[0] != kind or rp[1] != address or (data is not None and rp[2] != data):
            return None                     # not pending here, or re-executed with other data
        self._dev_note(uc, kind, address, rp[2])    # a stop during the replay is a replay again
        return rp

    # ------------------------------------------------------------------
    # Device register window (mmio_map at the physical 0x18000000)
    # ------------------------------------------------------------------
    def _mmio_on(self, kind, handler, begin, end):
        """Call handler(uc, access, address, size, value, user_data) -- the
        signature of a Unicorn memory hook -- for every read ('r') / write
        ('w') of the device window that starts at an offset in begin..end
        (offsets in the 16 MB window; any segment's address is accepted).  It
        runs before the access, like a memory hook: a read handler can put the
        value to be read into the register (via the 0xB8000000 view it is
        given as `address`), a write handler sees the register before the
        store lands -- and can return the value that lands instead, for
        registers whose bits do not simply take what is stored."""
        table = self._mmio_rd if kind == 'r' else self._mmio_wr
        for off in range(begin & 0xFFFFFF, (end & 0xFFFFFF) + 1):
            table.setdefault(off, []).append(handler)

    @staticmethod
    def _mmio_offset(address):
        """Offset in the 16 MB device window of a physical / kseg0 / kseg1
        address of it (0x18xxxxxx, 0x98xxxxxx, 0xB8xxxxxx), or of a bare offset."""
        if address < 0x01000000:
            return address
        if (address & 0x1FFFFFFF) >> 24 == 0x18 and (address < 0x20000000 or address >= 0x80000000):
            return address & 0x00FFFFFF
        raise ValueError(f"0x{address:08X} is not in the device window (0x18000000-0x18FFFFFF)")

    def add_mmio_hook(self, kind, callback, begin, end):
        """Observe the guest's device register accesses: kind 'read' or
        'write'; accesses that START in begin..end (any segment's addresses of
        the 0x18000000 window, e.g. 0xB800A000..0xB800A0FF).  callback has the
        Unicorn memory hook signature (uc, access, address, size, value,
        user_data) with `address` in the side-effect-free 0xB8000000 view; a
        write observer runs before the store with the value written, a read
        observer after the device model updated the register, with the value
        the guest reads.  Use this instead of mu.hook_add(UC_HOOK_MEM_READ /
        WRITE), which slows every RAM access of the emulation down.  Caveats:
        in fast mode uc.reg_read(PC) inside it is the start of the translation
        block, not the accessing instruction; an access that re-executes after
        a stop at it (an asynchronous stop, see _dev_note, or the stop at an
        SF_INS store that installs the flash read hook) is seen again.
        Returns a handle for remove_mmio_hook()."""
        if kind not in ('read', 'write'):
            raise ValueError(f"kind must be 'read' or 'write', not {kind!r}")
        lo, hi = self._mmio_offset(begin), self._mmio_offset(end)
        if lo > hi:
            raise ValueError("begin > end")
        handle = (kind == 'write', lo, hi, callback)
        self._mmio_observers.append(handle)
        return handle

    def remove_mmio_hook(self, handle):
        self._mmio_observers.remove(handle)

    def _mmio_observe(self, uc, write, offset, size, value):
        address = 0xB8000000 | offset
        for w, lo, hi, cb in list(self._mmio_observers):
            if w == write and lo <= offset <= hi:
                cb(uc, UC_MEM_WRITE if write else UC_MEM_READ, address, size, value, None)

    def _mmio_read(self, uc, offset, size, user_data):
        self._dev_last = None           # (a new device access: the noted one completed)
        self._dev_cb_depth += 1
        try:
            handlers = self._mmio_rd.get(offset)
            if handlers:
                address = 0xB8000000 | offset
                for h in handlers:
                    h(uc, UC_MEM_READ, address, size, 0, None)
            value = int.from_bytes(self.mmio_buffer[offset:offset + size], 'little')
            if self._mmio_observers:
                self._mmio_observe(uc, False, offset, size, value)
            return value
        finally:
            self._dev_cb_depth -= 1

    def _mmio_write(self, uc, offset, size, value, user_data):
        value &= (1 << (8 * size)) - 1
        self._dev_last = None
        self._dev_cb_depth += 1
        try:
            if self._mmio_observers:
                self._mmio_observe(uc, True, offset, size, value)
            handlers = self._mmio_wr.get(offset)
            if handlers:
                address = 0xB8000000 | offset
                for h in handlers:
                    stored = h(uc, UC_MEM_WRITE, address, size, value, None)
                    if stored is not None:
                        value = stored
            self.mmio_buffer[offset:offset + size] = value.to_bytes(size, 'little')
        finally:
            self._dev_cb_depth -= 1

    # Python-side memory access without device side effects: a mem_read /
    # mem_write of the physical device window 0x18xxxxxx goes through the
    # mmio_map callbacks (reading URBR pops a UART RX byte, writing THR prints
    # a character, ...); peek / poke use the 0xB8000000 view of it instead.
    @staticmethod
    def _quiet_address(address):
        return address + 0xA0000000 if 0x18000000 <= address < 0x19000000 else address

    def peek(self, address, size):
        """Read guest memory (any mapped address) without device side effects."""
        return self.mu.mem_read(self._quiet_address(address), size)

    def poke(self, address, data):
        """Write guest memory (any mapped address) without device side effects."""
        self.mu.mem_write(self._quiet_address(address), bytes(data))

    def _hook_flash_write_prot(self, uc, access, address, size, value, user_data):
        """A store to the read-only flash window: emulate it (SPI command
        trigger, page program, see _hook_spi_flash_write) and let it land (it
        is reverted before the firmware can read it back: at the next
        instruction in exact mode; in fast mode at the next SPI register write,
        flash hook, CP0 hook or slice end).  Anything else is invalid."""
        if any(w <= address < w + 0x01000000 for w in self._flash_windows):
            self._dev_cb_depth += 1
            try:
                (self.flash_device.store if self.flash_device else self._hook_spi_flash_write)(
                    uc, access, address, size, value, user_data)
            finally:
                self._dev_cb_depth -= 1
            return True
        return self._hook_mem_invalid(uc, access, address, size, value, user_data)

    def _hook_uart_write(self, uc, access, address, size, value, user_data):
        self._device_access(uc)
        # the UART's block (0xB8018300; the M3329's 0xB8001300, chips/m3329.py) is
        # 16-byte aligned: a store to its +0 is THR, in any segment's view
        if (address & 0xF) == 0:
            if self._dev_replay_of(uc, 'thr', address, value) is None:
                self._uart_log(value)
                self._dev_note(uc, 'thr', address, value)
            # Set LSR bit 5 (0x20 = Transmitter Holding Register Empty)
            # so firmware's uart_write_char doesn't timeout and retry 3x.
            # LSR is at UART base + 5 (SCI_16550_ULSR = 5).
            lsr_addr = (address & ~0xF) | 5
            uc.mem_write(lsr_addr, b'\x20')

    def _hook_uart_read(self, uc, access, address, size, value, user_data):
        """Handle reads from UART registers for RX simulation.

        16550 UART registers at base 0xB8018300:
          +0 URBR  — Receive Buffer Register (read: get received byte)
          +2 UIIR  — Interrupt Identification Register
          +5 ULSR  — Line Status Register (bit0=DataReady, bit5=THRE)
        """
        self._device_access(uc)
        reg_offset = (address & 0xF)  # offset within UART block
        if reg_offset == 5:  # ULSR — Line Status Register
            lsr = 0x20  # bit5 = THRE always set
            if len(self._uart_rx_queue) > 0:
                lsr |= 0x01  # bit0 = Data Ready
            uc.mem_write(address, bytes([lsr]))
        elif reg_offset == 0:  # URBR — Receive Buffer Register
            rp = self._dev_replay_of(uc, 'urbr', address)
            if rp is not None:
                uc.mem_write(address, bytes([rp[2]]))     # the same byte again, nothing popped
            elif len(self._uart_rx_queue) > 0:
                byte_val = self._uart_rx_queue.popleft()
                uc.mem_write(address, bytes([byte_val]))
                self._dev_note(uc, 'urbr', address, byte_val)
                self.log(f"[UART RX] Read byte 0x{byte_val:02X} ('{chr(byte_val)}'), {len(self._uart_rx_queue)} remaining")
                # Re-trigger interrupt if more data available
                if len(self._uart_rx_queue) > 0:
                    self._pending_uart_irq = True
                    self._uart_irq_delivered = False
        elif reg_offset == 2:  # UIIR — Interrupt Identification Register
            if len(self._uart_rx_queue) > 0:
                # bit0=0 means interrupt pending, bits[3:1]=010 = Received Data Available
                uc.mem_write(address, bytes([0x04]))
            else:
                # bit0=1 means no interrupt pending
                uc.mem_write(address, bytes([0x01]))

    # The GPIO banks (tm1650_decoder.GPIO_DO_OFFSETS and _EXTRA_ give each bank's DO register; its DI
    # register is DO - 4, its DIR register DO + 4): DO and DIR writes go to the panel decoder as the
    # bank's pin levels, a DI read returns the DO value (pin loopback) for the output bits
    _GPIO_DO_OFFSETS = set(GPIO_DO_OFFSETS) | set(GPIO_EXTRA_DO_OFFSETS)
    _GPIO_DI_TO_DO = {do - 4: do for do in _GPIO_DO_OFFSETS}
    _GPIO_DI_TO_DIR = {do - 4: do + 4 for do in _GPIO_DO_OFFSETS}

    def _hook_gpio_write(self, uc, access, address, size, value, user_data):
        """A write of a GPIO bank's DO or DIR register: the GPIO handler gets
        the bank's pin levels as they are after it, `address` the bank's DO
        register -- an output pin at its DO bit, an input pin high (the
        bus's pull-up; the decoder adds what its chip pulls low).  Drivers
        that bit-bang a bus open-drain keep DO 0 and switch the direction
        (the Opticum Blue R265 Lite's application, tm1650_decoder.py).  The
        board's other chips on GPIO pins (gpio_devices) get the same."""
        self._device_access(uc)
        if not self.gpio_callback and not self.gpio_devices:
            return
        base = address & ~3
        shift = (address & 3) * 8
        mask = ((1 << (size * 8)) - 1) << shift
        word = int.from_bytes(uc.mem_read(base, 4), 'little') & ~mask | ((value << shift) & mask)
        if (base & 0xFFF) in self._GPIO_DO_OFFSETS:
            do_addr, do_val, dir_val = base, word, int.from_bytes(uc.mem_read(base + 4, 4), 'little')
        else:
            do_addr, dir_val = base - 4, word
            do_val = int.from_bytes(uc.mem_read(do_addr, 4), 'little')
        levels = (do_val & dir_val | ~dir_val) & 0xFFFFFFFF
        if self.gpio_callback:
            self.gpio_callback(do_addr, 4, levels)
        for device in self.gpio_devices:
            device.on_gpio_write(do_addr, 4, levels)

    def _hook_gpio_di_read(self, uc, access, address, size, value, user_data):
        """GPIO DI→DO loopback with DIR-aware ACK simulation.
        
        For each bit:
        - If DIR bit = 1 (output): return the DO value (master is driving)
        - If DIR bit = 0 (input):  return 0 (simulate slave pulling low = ACK)

        This makes I2C START succeed (SDA=output, DI returns 1) while also
        making ACK succeed (SDA=input after SET_SDA_IN, DI returns 0).  The
        panel decoder answers for the input pins of its own chip instead
        (di_override): a TM1650's idle bus reads high, its SDA low only while
        it acknowledges or sends a 0 bit -- and so do the board's other chips
        on GPIO pins (gpio_devices: a bit-banged I2C bus, pulled-up inputs).
        """
        self._device_access(uc)
        di_offset = address & 0xFFF
        do_offset = self._GPIO_DI_TO_DO.get(di_offset)
        dir_offset = self._GPIO_DI_TO_DIR.get(di_offset)
        if do_offset is not None and dir_offset is not None:
            mmio_base = address & 0xFFFFF000
            try:
                do_data = uc.mem_read(mmio_base + do_offset, 4)
                do_val = int.from_bytes(do_data, 'little')
                dir_data = uc.mem_read(mmio_base + dir_offset, 4)
                dir_val = int.from_bytes(dir_data, 'little')
                # Output bits (DIR=1): return DO value
                # Input bits (DIR=0): return 0 (simulated slave response),
                # unless the GPIO handler's object drives a line (the TM1650
                # decoder answers key reads on SDA: di_override)
                di_val = do_val & dir_val
                override = getattr(getattr(self.gpio_callback, '__self__', None), 'di_override', None)
                if override is not None:
                    di_val = override(di_offset, di_val)
                for device in self.gpio_devices:
                    di_val = device.di_override(di_offset, di_val)
                di_val = di_val & ~dir_val | (do_val & dir_val)
                uc.mem_write(address & ~3, di_val.to_bytes(4, 'little'))
            except:
                pass

    # Status bytes (offset in the MMIO window) of device operations that
    # complete at once: {offset: (start bit, done bits to set, bits to clear)}.
    #  * PMU (pmu_m36, 0xB8018D00): the application init sets bit 0x80 of
    #    +2 and polls bit 0x20 with udelay(2000), up to 36,848 times (6-7
    #    minutes in the simulator; the failure is then ignored).  The 13-bit
    #    calibration value read afterwards (+1, +2[4:0]) is only used on
    #    another chip revision and stays 0.
    #  * VCAP_M36F (0xB800F000), opened by the video output: the driver sets
    #    bit 0 of +0x4B and spins, without a timeout, until the hardware clears
    #    it again.
    #  * The M36xx's DMA controller (dma_s3601, 0xB800F200), which the SEE's
    #    video output opens (the URZ0086's vpo_open): dma_dma_start sets bit 0
    #    of +0x4B the same way (bit 2 stops it, bit 7 reads busy).
    _SELF_COMPLETING = {
        0x18D02: (0x80, 0x20, 0x00),
        0x0F04B: (None, 0x00, 0x01),
        0x0F24B: (None, 0x00, 0x01),
    }

    def _hook_selfcomplete_read(self, uc, access, address, size, value, user_data):
        """Reads of a self-completing status byte see the operation finished
        (idempotent, so a replayed load after an asynchronous stop is harmless)."""
        self._device_access(uc)
        for reg, (start, done, clear) in self._SELF_COMPLETING.items():
            target = (address & ~0x00FFFFFF) | reg
            if address <= target < address + size:
                b = uc.mem_read(target, 1)[0]
                if start is None or b & start:
                    uc.mem_write(target, bytes([(b | done) & ~clear & 0xFF]))

    # Video engine (the video decoder's hardware, registers at 0xB8004200).
    # When the application starts playing a channel, the decoder driver resets
    # the VE (vdec_reset_ve_hw: 0xB8000060, 0xB8000028 bit 1) and then checks
    # the VE status word (+0x28, or +0x88 on another chip revision) for its
    # busy / event bits 8-25 (masks 0x036FFF00 / 0x017FFF00); if any is set it
    # takes the firmware's fatal path 0x8000070C, which reboots into the
    # bootloader.  The register is RAM here and held the 0x318 the driver wrote
    # at init, so dump.bin rebooted two minutes after its first screen and
    # started over.  With no VE events to report those bits read clear -- on
    # the chips whose VE has them there (ChipFamily.ve_status: not the M36xx,
    # whose decoder keeps its bit offset at +0x28).
    _VE_STATUS_REGS = (0x4228, 0x4288)
    _VE_STATUS_MASK = 0x037FFF00

    def _hook_ve_status_read(self, uc, access, address, size, value, user_data):
        self._device_access(uc)
        if not self.chip.ve_status:
            return
        word = address & ~3
        v = int.from_bytes(uc.mem_read(word, 4), 'little')
        if v & self._VE_STATUS_MASK:
            uc.mem_write(word, (v & ~self._VE_STATUS_MASK).to_bytes(4, 'little'))

    @staticmethod
    def _hook_chip_id_store(uc, access, address, size, value, user_data):
        """A store to the chip ID word leaves it as it is (the chip's ID, its
        variant bits).  The Cabletech URZ0083's bootloader pulses bit 31 of
        it (0xB6020000, 0x36020000, ... 0xB6020000): kept, the application
        read its chip as 0xB602, which its chip table does not know, and its
        display driver's attach rebooted it every ~38 M instructions."""
        return int.from_bytes(uc.mem_read(address, size), 'little')

    def _hook_mac_reset_read(self, uc, access, address, size, value, user_data):
        """ETHERNET_MAC_0 +0 (0xB802C000): the software-reset bit 3 reads back
        clear -- the reset completes at once (nothing else of the MAC is
        modelled).  Without it the T650i's network driver spun on the bit
        forever and its task starved the UI."""
        self._device_access(uc)
        a = address & ~3
        b = uc.mem_read(a, 1)[0]
        if b & 0x08:
            uc.mem_write(a, bytes([b & 0xF7]))

    def _hook_mac_mdio_read(self, uc, access, address, size, value, user_data):
        """ETHERNET_MAC_0 +0x7C (0xB802C07C): the driver writes PHY address
        (bits 21-25), register (bits 16-20) and 0x88000000 (bit 31 busy / go,
        bit 27 read), polls until bit 31 clears -- giving up after 1000 ms of
        firmware time and taking 0xFFFF -- and reads the data from +0x82.  No
        PHY is modelled: the access completes at once and reads 0xFFFF, which
        is what an MDIO bus without a PHY returns (it idles high) and what the
        driver's timeout path used, so the firmware ends up in the same state,
        without waiting a second for every PHY register it probes."""
        self._device_access(uc)
        a = 0xB802C07C
        v = int.from_bytes(uc.mem_read(a, 4), 'little')
        if v & 0x80000000:
            uc.mem_write(a, (v & 0x7FFFFFFF).to_bytes(4, 'little'))
            if v & 0x08000000:                       # a read: the data a bus without a PHY gives
                uc.mem_write(0xB802C082, b'\xFF\xFF')

    # Graphics engine (GE_M36F, registers at 0xB800A000).  A command written to
    # +4 is executed at once by the ge_m36f model (it draws into RAM, see
    # ge_m36f.py; ge_render = False only completes it) and sets its bit in the
    # interrupt status +8 (write 1 to clear), which drives interrupt-controller
    # line 4.  The driver's ISR acks +8 and wakes the drawing task through an
    # event flag; without the interrupt every operation ended in its timeout
    # (0.5-6 s) and a GE reset, so the UI took minutes to come up.
    _GE_DONE = {1: 0x4, 2: 0x1, 3: 0x2}     # command -> status bit (the flag bit its caller waits for)
    _IC_GE = 4                               # interrupt-controller line (0xB8000030 bit 4)

    def _hook_ge_write(self, uc, access, address, size, value, user_data):
        self._device_access(uc)
        off = address & 0xFFF
        if off == 0x004:
            done = self._GE_DONE.get(value & 0xFFFFFFFF, 0)
            # (a store rewound by an asynchronous stop must not complete twice)
            if done and self._dev_replay_of(uc, 'ge', address, value) is None:
                self._dev_note(uc, 'ge', address, value)
                self.ge_ops += 1
                if self.ge_render:
                    self._ge_execute(value & 0xFFFFFFFF)
                self._ge_status |= done
                self._ic_set_line(self._IC_GE, True)
        elif off == 0x008:
            self._ge_status &= ~value
            if not self._ge_status:
                self._ic_set_line(self._IC_GE, False)

    def _ge_execute(self, command):
        """Run GE command 1 (the live registers), 2 / 3 (the HQ / LQ command
        list between its start and end pointers) on the RAM image."""
        if _np is None:
            return
        if self.ge is None:
            import ge_m36f
            ram = _np.frombuffer(self.ram_buffer, dtype=_np.uint8, count=self.ram_size)
            self.ge = ge_m36f.GeM36F(ram, log=self.log)
        regs = _np.frombuffer(bytes(self.mmio_buffer[0xA000:0xA100]), dtype='<u4').tolist()
        if command == 1:
            self.ge.run_io(regs)
            return
        o = 0x10 if command == 2 else 0x18
        start, end = regs[o >> 2] & 0x1FFFFFFF, regs[(o >> 2) + 1] & 0x1FFFFFFF
        if start <= end < start + 0x400000 and end + 4 <= self.ram_size:
            self.ge.run_list(self.ge.ram[start:end + 4].view('<u4').tolist(), regs)

    def capture_screen(self, path=None, screen=(1280, 720)):
        """What the TV would show of the OSD: the enabled GMA display layers
        (registers 0xB8006300 / 0xB8006304: enable, first region head in RAM)
        composited over black (see gma_capture.py), drawn into RAM by the GE
        model.  Returns an RGB uint8 array (height, width, 3) and writes a PNG
        if path is given.  Needs numpy (and Pillow or zlib for the PNG)."""
        import gma_capture
        ram = _np.frombuffer(self.ram_buffer, dtype=_np.uint8, count=self.ram_size)
        osd = getattr(self.chip, "osd", None)          # (the M3329's OSD layers: their palettes)
        rgb, _ = gma_capture.capture(ram, bytes(self.mmio_buffer[0:0x10000]), screen,
                                     m3327_palettes=osd.palettes if osd is not None else None)
        if path:
            gma_capture.save_png(path, rgb)
        return rgb

    def _hook_ge_read(self, uc, access, address, size, value, user_data):
        self._device_access(uc)
        uc.mem_write((address & ~0xFFF) | 0x008, self._ge_status.to_bytes(4, 'little'))

    # IR receiver (M6303 IRC, registers at 0xB8018100, see ir_remote.py).  A
    # frame from ir_send_nec() is put into the run-length FIFO at once and
    # signalled as the idle timeout (status bit 1): the firmware's ISR
    # (irc_m6303irc_lsr) reads the FIFO count (+1) and drains the bytes (+8)
    # -- on that interrupt it also schedules its decoder -- and acknowledges
    # the status by writing it back (+7, write 1 to clear).  The status drives
    # interrupt-controller line 19 (OS IRQ 27) while enabled in IER (+6).
    _IC_IRC = 19
    IR_FRAME_GAP_S = 0.25            # emulation time between two frames (NEC repeats every 108 ms)
    I2C_SCB_BASES = (0x18200, 0x18700, 0x18B00)  # the hardware I2C masters (i2c_scb.py; the M3801's
                                                 # SCB0 / SCB1 and the M3821's), window offsets

    def _hook_irc_read(self, uc, access, address, size, value, user_data):
        self._device_access(uc)
        off = address & 0xFFF                   # (0x1xx at either base, irc_base)
        if off == 0x101:                                     # FIFO byte count
            uc.mem_write(address, bytes([min(len(self._irc_fifo), 0x7F)]))
        elif off == 0x107:                                   # interrupt status
            uc.mem_write(address, bytes([self._irc_status]))
        elif off == 0x108:                                   # RLC data: pops the FIFO
            rp = self._dev_replay_of(uc, 'irc', address)
            if rp is not None:
                uc.mem_write(address, bytes([rp[2]]))
            elif self._irc_fifo:
                b = self._irc_fifo.popleft()
                uc.mem_write(address, bytes([b]))
                self._dev_note(uc, 'irc', address, b)

    def _hook_irc_write(self, uc, access, address, size, value, user_data):
        self._device_access(uc)
        self._irc_status &= ~value & 0xFF
        self._irc_update_line()

    def _irc_update_line(self):
        ier = self.mu.mem_read(0xB8000000 + self.irc_base + 6, 1)[0]
        self._ic_set_line(self.irc_line, bool(self._irc_status & ier & 3))

    def _irc_service(self):
        """Between slices (emulation thread): receive the next queued IR frame
        once the previous one was taken and IR_FRAME_GAP_S has passed."""
        if not self._irc_frames or self._irc_fifo or self._irc_status:
            return
        if self._vtime() - self._irc_last_vt < self.IR_FRAME_GAP_S:
            return
        if not self.mu.mem_read(0xB8000000 + self.irc_base, 1)[0] & 0x80:   # IRCCFG: controller enabled
            return
        rlc, label = self._irc_frames.popleft()
        self._irc_fifo.extend(rlc)
        self._irc_status |= 0x02
        self._irc_last_vt = self._vtime()
        self.ir_keys_sent += 1
        self.log(f"[IR] {label}: {len(rlc)} RLC bytes")
        self._irc_update_line()

    def ir_send_nec(self, address, command, label=None, address_hi=None):
        """Queue an NEC remote-control frame (address, command bytes; address_hi
        for an extended-NEC second address byte instead of ~address) for the
        IR receiver.  Thread-safe: it is received at the next slice boundary
        of run(), at least IR_FRAME_GAP_S of emulation time after the previous
        frame and only while the firmware has the controller enabled."""
        import ir_remote
        self._irc_frames.append((ir_remote.nec_rlc(address, command, address_hi),
                                 label or f"NEC 0x{address:02X}/0x{command:02X}"))

    def attach_tuner(self, chip=None, address=None):
        """Put a tuner chip model (tuners.py) on the I2C bus: `chip` (a key of
        tuners.MODELS) at the 7-bit `address`, or by default the one the loaded
        dump's sidecar names (device.tunerModel, dump_catalog.py).  The driver
        then sees a tuner that takes its settings and locks.  Returns the model
        (None when the dump names none)."""
        import tuners
        if chip is None:
            import dump_catalog
            info = dump_catalog.load(self.dump_path) if getattr(self, "dump_path", None) else None
            model = (info or {}).get("device", {}).get("tunerModel")
            if not model:
                return None
            chip = model["chip"]
            address = model["address"] if address is None else address
            config = {k: model[c] for k, c in (("xtal_hz", "xtalHz"), ("if_hz", "ifHz")) if c in model}
        elif address is None:
            raise ValueError("attach_tuner: give the tuner's 7-bit I2C address with its chip")
        else:
            config = {}
        device = tuners.make(chip, **config)
        self.i2c_devices[address] = device
        self.log(f"[I2C] tuner model {chip} at 0x{address:02X}")
        return device

    def attach_demod(self):
        """Put the loaded board's external demodulator (demods.py: its
        sidecar's device.demodModel) on the I2C bus, in place of the one
        the previous image's board had; loadFile calls it.  Returns the
        model, or None when the board names none."""
        import demods
        import dump_catalog
        if self._demod_address is not None:
            self.i2c_devices.pop(self._demod_address, None)
            self._demod_address = None
        given = dump_catalog.demod_model(self.dump_path) if getattr(self, "dump_path", None) else None
        if given is None:
            return None
        chip, address = given
        self.i2c_devices[address] = device = demods.make(chip)
        self._demod_address = address
        self.log(f"[I2C] demodulator model {chip} at 0x{address:02X}")
        return device

    def attach_gpio_devices(self):
        """Put the loaded board's other chips on GPIO pins in place of the
        previous board's (loadFile calls it): the I2C bus its firmware
        bit-bangs to its tuner or other chips (its sidecar's device.gpioI2c,
        gpio_i2c.py; the slaves are sim.i2c_devices, as on the hardware
        masters) and the input pins its board pulls up (device.gpioPullUps:
        they read high, gpio_keys.GpioKeys that nobody presses).  Returns
        the list, sim.gpio_devices."""
        import dump_catalog
        from gpio_i2c import GpioI2cBus
        from gpio_keys import GpioKeys
        self.gpio_devices = []
        path = getattr(self, "dump_path", None)
        if not path:
            return self.gpio_devices
        bus = dump_catalog.gpio_i2c(path)
        if bus:
            self.gpio_devices.append(GpioI2cBus(self, *bus))
            self.log(f"[I2C] bit-banged bus on GPIO {bus[0]} (SCL) / {bus[1]} (SDA)")
        pull_ups = dump_catalog.gpio_pull_ups(path)
        if pull_ups:
            self.gpio_devices.append(GpioKeys(pull_ups))
        return self.gpio_devices

    def tuner(self):
        """The tuner model on the I2C bus (tuners.py), or None."""
        import tuners
        return next((d for d in self.i2c_devices.values() if tuners.is_tuner(d)), None)

    def tuner_info(self):
        """What the tuner is tuned to, one line (tuners.describe), or None
        without a tuner model."""
        import tuners
        return tuners.describe(self.tuner())

    def set_signal(self, on=True, frequencies=None):
        """A receivable channel: the dump's tuner model on the I2C bus
        (attach_tuner) and the chip family's demodulator reporting lock
        (chips/m3801.py, chips/m3821.py) -- on every frequency, or with
        `frequencies` (Hz) only while the tuner model is tuned to one of them
        (tuned_to_signal), as an antenna receives a few multiplexes: a channel
        search then finds those and nothing elsewhere.  There is no transport
        stream behind it (attach_mux), so the firmware finds a locked channel
        with nothing in it.  Returns (tuner model or None, demodulator
        modelled)."""
        tuner = self.tuner()
        if on and tuner is None:
            tuner = self.attach_tuner()
        self.signal_frequencies = None if frequencies is None else tuple(frequencies)
        demod = self.chip.set_signal(on)
        if not demod:
            self.log(f"[NIM] {self.chip.name}: no demodulator model, the firmware sees no lock")
        return tuner, demod

    SIGNAL_TOLERANCE_HZ = 1_000_000     # a terrestrial channel raster is 7 or 8 MHz

    def tuned_to_signal(self):
        """Whether the tuner sits on a frequency with a signal: any frequency
        unless set_signal() named some; then the tuner model must be tuned
        within SIGNAL_TOLERANCE_HZ of one of them (not while it calibrates)."""
        if self.signal_frequencies is None:
            return True
        tuner = self.tuner()
        f = tuner.frequency() if tuner is not None else None
        if not f or f.get("calibrating"):
            return False
        return any(abs(f["rf_hz"] - hz) <= self.SIGNAL_TOLERANCE_HZ for hz in self.signal_frequencies)

    def attach_mux(self, mux=None):
        """Put a transport stream behind the locked channel: the chip family's
        demultiplexer model (dmx_m36.Demux, chips/m3801.py and m3602.py) feeds
        the tables of `mux` (a transport_stream.Mux; by default one service,
        "AliSimulator TV") to the firmware's PID filters, so a channel change
        finds its PAT / PMT / SDT instead of waiting for them.  Usually with
        set_signal(True).  Returns the demultiplexer model, or None when the
        family has none."""
        dmx = getattr(self.chip, "dmx", None)
        if dmx is None:
            self.log(f"[DMX] {self.chip.name}: no demultiplexer model")
            return None
        if mux is None:
            import transport_stream
            mux = transport_stream.Mux()
        dmx.mux = mux
        if dmx.service not in self.slice_services:
            self.slice_services.append(dmx.service)
        self.log(f"[DMX] transport stream attached: {', '.join(s.name for s in mux.services)}")
        return dmx

    def dmx_info(self):
        """What the demultiplexer model is doing, one line, or None without one."""
        dmx = getattr(self.chip, "dmx", None)
        return dmx.describe() if dmx is not None else None

    def press_key(self, key):
        """Press a remote-control key: a name of ir_remote.VKEYS ('UP', 'DOWN',
        'OK', 'MENU', 'EXIT', '0'..'9', ...) or a virtual key number.  The NEC
        code is looked up in the UI's own key table, found in RAM the first
        time (so only after the application has started).  Returns the
        (address, command) sent.  A chip family whose firmware keeps another
        kind of table (the M3329's) gives the frame itself: remote_frame()."""
        import ir_remote
        frame = self.chip.remote_frame(key) if hasattr(self.chip, "remote_frame") else None
        if frame is not None:
            address, command, address_hi = frame
            self.ir_send_nec(address, command, label=f"key {key}", address_hi=address_hi)
            return address, command
        vkey = ir_remote.VKEYS[key.upper()] if isinstance(key, str) else int(key)
        if not self._ir_key_table:
            ram = _np.frombuffer(self.ram_buffer, dtype=_np.uint8, count=self.ram_size)
            self._ir_key_table = ir_remote.find_key_table(ram)
            if not self._ir_key_table:
                raise RuntimeError("no remote key table in RAM (has the application started?)")
        if vkey not in self._ir_key_table and isinstance(key, str):
            # the firmware may number this key differently (ir_remote.VKEY_FALLBACKS)
            vkey = next((v for v in ir_remote.VKEY_FALLBACKS.get(key.upper(), ())
                         if v in self._ir_key_table), vkey)
        if vkey not in self._ir_key_table:
            raise KeyError(f"key {key!r} (vkey {vkey}) is not in the firmware's key table")
        # the frame bytes a table code stands for depend on the firmware's SDK
        # generation (ir_remote.IR_CODINGS; set from the dump's name by loadFile)
        address, command, address_hi = ir_remote.frame_from_ir16(self._ir_key_table[vkey], self.ir_coding)
        if address_hi is None:
            self.ir_send_nec(address, command, label=f"key {key}")
        else:
            self.ir_send_nec(address, command, label=f"key {key}", address_hi=address_hi)
        return address, command

    def _hook_ic_status_read(self, uc, access, address, size, value, user_data):
        """Interrupt-controller status (0xB8000030 / 34; the SEE's at 0xB8040030 /
        34, ic_base) shows the asserted lines (a write-back acknowledge does not
        clear a line its device still drives)."""
        if self._ic_lines:
            for word in (0, 1):
                bits = (self._ic_lines >> (32 * word)) & self._M32
                if bits:
                    a = self._ic + 4 * word
                    v = int.from_bytes(uc.mem_read(a, 4), 'little')
                    uc.mem_write(a, (v | bits).to_bytes(4, 'little'))

    def _ic_set_line(self, line, on):
        """Drive an interrupt-controller input of a modelled device (a level):
        its status bit (0xB8000030 / 34, at ic_base) follows it, and while it
        is asserted and enabled (0xB8000038 / 3C) the CPU sees IP3."""
        bit = 1 << line
        was = self._ic_lines
        self._ic_lines = (was | bit) if on else (was & ~bit)
        addr = self._ic + 4 * (line // 32)
        b = 1 << (line % 32)
        cur = int.from_bytes(self.mu.mem_read(addr, 4), 'little')
        self.mu.mem_write(addr, ((cur | b) if on else (cur & ~b)).to_bytes(4, 'little'))
        if on and not was & bit:
            self._irq_soon()

    def _ic_ip3(self):
        """IP3 from the interrupt controller: a modelled line asserted and
        enabled, or the other CPU's doorbell (_doorbell_ip3)."""
        if self._ic_lines and self._ic_lines & int.from_bytes(self.mu.mem_read(self._ic_en, 8), 'little'):
            return True
        return self._doorbell_ip3()

    def set_ic_layout(self, status, enable):
        """Where an older chip's interrupt controller keeps its status and
        enable words (device-window offsets; the M3329's 0x38 and 0x3C, which
        take lines 0..31 only): the modelled devices' lines go there.  A chip
        family calls it from install() (and with 0x30, 0x38 from uninstall())."""
        self._ic = 0xB8000000 + status
        self._ic_en = 0xB8000000 + enable
        if status != self.ic_base:
            self._mmio_on('r', self._hook_ic_status_read, status, status + 3)

    def _doorbell_ip3(self):
        """The other CPU of a dual-CPU chip rings this one (chips/see.py
        Doorbells): its channel 1 / 2 ring bits (doorbell_in: their byte's
        offset in the device window and the shift that puts them at bits 7 /
        6) are this CPU's OS IRQ 0x47 / 0x46, interrupt controller lines 63 /
        62, which assert IP3 while their enable bits (31 / 30 of the second
        enable word) are set -- the SDK's OS_RegisterISR sets them --, but do
        not show in the status words: the dispatcher reads the ring byte
        itself, and takes an IP3 without status for a ring."""
        if self.doorbell_in is None:
            return False
        offset, shift = self.doorbell_in
        return bool((self.mmio_buffer[offset][0] << shift) & self.mmio_buffer[self.ic_base + 0xF][0] & 0xC0)

    def _irq_soon(self):
        """A device raised an interrupt from a memory hook.  Fast mode, inside a
        slice: end the slice at the next hooked CP0 instruction (or by the
        asynchronous backstop) so that run() delivers it.  Not emu_stop() here:
        Unicorn would finish the translation block first and skip the CP0
        hooks in it (see async_stop_margin_us).  Exact mode delivers it at the
        next instruction anyway."""
        if self._in_run and self._code_hook_h is None and self._slice_cap_end is not None:
            if self._slice_uses_stopper:
                self._arm_deadline(0.0)
                self._slice_armed_end = self._vtime()
            else:
                self._slice_deadline = time.perf_counter()

    def _hook_spi_write(self, uc, access, address, size, value, user_data):
        """Handle writes to SPI flash controller registers.

        Matches the hardware register interface from flash_raw_sl_c.c:
          SF_INS (+0x98) — SPI command/instruction
          SF_FMT (+0x99) — format (which bus phases are active)
          SF_DUM (+0x9A) — dummy/data register
          SF_CFG (+0x9B) — configuration
        The firmware also writes INS+FMT together with one 16-bit store, so
        every byte of the access is dispatched to its own register.
        """
        self._device_access(uc)
        if self._dev_replay_of(uc, 'spi_reg', address, value) is not None:
            return      # the same store again after a stop at it (e.g. to install the flash read hook)
        self._dev_note(uc, 'spi_reg', address, value)
        for i in range(size):
            reg = (address + i) & 0xF
            byte = (value >> (8 * i)) & 0xFF
            if reg == 0x8:
                self._spi_write_ins(uc, byte)
            elif reg == 0x9:
                self._spi_write_fmt(byte)
            elif reg == 0xA:
                self._spi_dum = byte
            elif reg == 0xB:
                self._spi_cfg = byte

    def _spi_write_ins(self, uc, cmd):
        """SF_INS written: latch the SPI command and queue its response bytes."""
        if self._rom_dirty:
            self._rom_restore()          # response bytes must not survive into normal read mode
        self._spi_ins = cmd
        self._last_flash_read_page = -1  # Reset so next passthrough read always logs
        self._update_flash_read_hooks()
        cmd_name = self._SPI_CMD_NAMES.get(cmd, "Unknown")
        pc = uc.reg_read(UC_MIPS_REG_PC)
        # (fast mode: inside a device access Unicorn's PC is the translation block start)
        where = f"PC=0x{pc:08X}" if self._code_hook_h is not None else f"block at 0x{pc:08X}"
        self._spi_log(f"CMD 0x{cmd:02X} ({cmd_name}) [{where}]")
        self._spi_resp_idx = 0
        self._spi_response = self._spi_command_response(cmd)
        if cmd in (0x06, 0x04):     # Write Enable / Disable
            self._spi_set_wel(cmd == 0x06)

    def _spi_set_wel(self, on):
        """The part's write-enable latch (status bit 1): set by WREN, cleared by
        WRDI and by every command it enabled (WRSR, erase, page program)."""
        self._spi_wel = on
        self._spi_status = (self._spi_status | 0x02) if on else (self._spi_status & ~0x02)

    def _spi_command_response(self, cmd):
        """The bytes the part answers a command with (the ID and status reads);
        WRSR / reads / program / erase have none."""
        if cmd == 0x9F:      # JEDEC Read ID: 3 bytes, padded to 4 for word reads
            return list(self._spi_jedec_id) + [0x00]
        if cmd == 0x05:      # Read Status Register: bit0=WIP, bit1=WEL, bits[5:2]=BP
            return [self._spi_status]
        if cmd == 0xAB:      # Release from Deep Power Down / Read Electronic ID
            # A real part clocks its electronic ID out after the 3 dummy bytes,
            # repeatedly: one below the JEDEC capacity byte (W25Q32 / MX25L3205
            # 0x15, W25Q64 / MX25L6405 0x16).  The ALi drivers read it without
            # a dummy phase and match byte 3 ("0x15, 56 /*MX25L3205*/", "0x16,
            # 56 /*MX25L6405D*/"); the newer tables also know 4 MB parts by
            # the JEDEC capacity byte ("0x16, 16"), the Ferguson T50's 2009
            # bootloader only by this read -- with 0x00 there it attached no
            # flash device and rebooted.
            res = (self._spi_jedec_id[2] - 1) & 0xFF
            return [res, res, res, res]
        if cmd == 0x90:      # Read Manufacturer/Device ID
            return [self._spi_jedec_id[0], self._spi_jedec_id[2],
                    self._spi_jedec_id[0], self._spi_jedec_id[2]]
        return []

    def _spi_response_bytes(self, size):
        """The next `size` bytes the part clocks out for a flash-window load:
        the stream's while a chip family's byte-stream mode is on, else what is
        left of the last SF_INS command's response, then 0x00 (idle, not busy)."""
        stream = self._spi_stream
        if stream is not None and stream.active:
            return stream.read(size)
        resp = bytearray(size)
        for i in range(size):
            if self._spi_resp_idx < len(self._spi_response):
                resp[i] = self._spi_response[self._spi_resp_idx]
                self._spi_resp_idx += 1
        return bytes(resp)

    def _spi_write_fmt(self, value):
        self._spi_fmt = value
        flags = []
        if value & 0x01: flags.append("DATA")
        if value & 0x02: flags.append("DUMM")
        if value & 0x04: flags.append("ADDR")
        if value & 0x08: flags.append("CODE")
        if value & 0x40: flags.append("CONT_RD")
        if value & 0x80: flags.append("CONT_WR")
        self._spi_log(f"  FMT 0x{value:02X} [{' | '.join(flags)}]")

    def _hook_spi_read(self, uc, access, address, size, value, user_data):
        """Handle reads from SPI flash controller registers.

        Firmware does volatile readback of registers it just wrote
        (e.g. write SF_INS then read SF_INS back). Return the stored values.
        """
        self._device_access(uc)
        regs = {0x8: self._spi_ins, 0x9: self._spi_fmt, 0xA: self._spi_dum, 0xB: self._spi_cfg}
        for i in range(size):
            reg = (address + i) & 0xF
            if reg in regs:
                uc.mem_write(address + i, bytes([regs[reg] & 0xFF]))

    def _spi_is_passthrough(self):
        """Check if SPI controller is in normal flash read mode (passthrough).
        
        In normal read mode, reads from SYS_FLASH_BASE_ADDR return actual
        flash content. The controller is in passthrough when:
          SF_INS = 0x03 (Read), 0x0B (Fast Read) or a dual / quad read

        Note: SF_HIT_ADDR may or may not be set. In CONT_RD mode the firmware
        sets FMT=0x0D (DATA|ADDR|CODE) for the first read, then FMT=0x09
        (DATA|CODE) for sequential reads without address phase.

        The dual and quad reads (0x3B, 0x6B, 0xBB, 0xEB) deliver the same
        bytes, only faster: the M3601E / M3606 bootloaders switch to the quad
        I/O read 0xEB under the chip ID 0x3603 (the Cabletech URZ0083's and
        URZ0086's), and their chunk headers read as zeros while only 0x03 /
        0x0B counted -- "malloc size: 0, please check the application!".

        A chip family's byte-stream mode (chips/m3821.py) takes the window
        over while it is on, whatever SF_INS says.
        """
        stream = self._spi_stream
        return self._spi_ins in self._SPI_READS and not (stream is not None and stream.active)

    _SPI_READS = (0x03, 0x0B, 0x3B, 0x6B, 0xBB, 0xEB)

    def _flash_offset(self, address):
        """Offset into the flash image for any mirror of the memory-mapped flash.

        The 16 MB windows (physical 0x0F000000 / 0x1F000000) show flash offset
        0 at their 0x..C00000 slot (SYS_FLASH_BASE_ADDR 0xAFC00000, the reset
        vector 0xBFC00000); a part larger than 4 MB shows its 4 MB segment n
        at 0x..C00000 - n * 4 MB -- the SDK's flash driver reaches offset o at
        SYS_FLASH_BASE_ADDR - (o & 0xC00000) + (o & 0x3FFFFF) ("M3329E and
        M3202 SFlash addr mapping in 8M or 16M", flash_raw_sl_c.c).  For 4 MB
        and smaller parts this is the address modulo rom_size."""
        rel = address & 0x00FFFFFF
        seg = (0xC00000 - (rel & 0xC00000)) >> 22
        return ((seg << 22) | (rel & 0x3FFFFF)) % self.rom_size

    def _rom_write(self, off, data):
        """Write bytes at flash offset off into the shared ROM buffer through the
        writable KSEG1 view of its segment (wrapping at the end of the flash
        like the next mirror does); see _flash_offset for the layout."""
        mv = memoryview(bytes(data))
        pos = 0
        while pos < len(mv):
            o = (off + pos) % self.rom_size
            n = min(len(mv) - pos, 0x400000 - (o & 0x3FFFFF), self.rom_size - o)
            self.mu.mem_write(0xAFC00000 - (o & 0xC00000) + (o & 0x3FFFFF), bytes(mv[pos:pos + n]))
            pos += n

    def _rom_restore(self):
        """Undo transient writes to the memory-mapped flash window (see rom_image;
        a parallel flash in autoselect mode shows its IDs there instead)."""
        for off, size in self._rom_dirty:
            end = min(off + size, self.rom_size)
            if self.flash_device is None:
                self._rom_write(off, self.rom_image[off:end])
            else:
                self._rom_write(off, self.flash_device.read(off, end - off))
        self._rom_dirty.clear()

    def _flash_program(self, off, byte):
        """Program one byte: flash can only clear bits until the sector is erased."""
        if off < self.rom_size:
            self.rom_image[off] &= byte
            self._rom_sites_dirty = True

    def _flash_erase(self, start, length):
        start = min(start, self.rom_size)
        length = min(length, self.rom_size - start)
        self.rom_image[start:start + length] = b'\xFF' * length
        self._rom_write(start, b'\xFF' * length)
        self._rom_sites_dirty = True

    def _rom_inject(self, uc, address, off, data):
        """Put transient bytes (SPI responses) into the flash window for the
        load at `address`, always through the writable 0xAFC00000 view of the
        ROM buffer.  A Python write to the guest's read-only flash mapping
        makes Unicorn toggle its protection, and doing that from a hook while
        the CPU runs crashed Unicorn natively ('access violation reading
        0xAFC00000' in 1 of 30 Prima boots; 0 of 105 since).  Reverted by _rom_restore."""
        self._rom_write(off, data)              # (a load across the end of a mirror reads the next one)

    def _hook_spi_flash_read(self, uc, access, address, size, value, user_data):
        self._dev_cb_depth += 1
        try:
            self._spi_flash_read(uc, address, size)
        finally:
            self._dev_cb_depth -= 1

    def _spi_flash_read(self, uc, address, size):
        """Handle reads from the memory-mapped flash region (SYS_FLASH_BASE_ADDR).

        When the SPI controller is in command mode (not passthrough), reads
        from the flash address space return SPI response data instead of
        flash content. This implements the hardware behavior where:

          write_uint8(SF_FMT, SF_HIT_CODE | SF_HIT_DATA);  // command mode
          write_uint8(SF_INS, 0x9F);                         // JEDEC Read ID
          result = *(volatile UINT32 *)SYS_FLASH_BASE_ADDR;  // read response

        The response bytes are placed in the ROM buffer for this one load and
        restored from rom_image before the next flash-window load (and at the
        next instruction in exact mode), so they never leak into the flash
        contents the firmware reads later.
        """
        if self._rom_dirty:
            self._rom_restore()          # undo the previous transient bytes before this load
        off = self._flash_offset(address)
        if self._spi_is_passthrough():
            self._dev_last = None        # (a plain flash read: no side effect, nothing to replay)
            # Log flash read offset (throttled: only when 64KB sector changes)
            sector = off >> 16
            if self._spi_dump_flash_reads and self._last_flash_read_page != sector:
                self._last_flash_read_page = sector
                self._spi_log(f"  FLASH READ @ 0x{off:06X} (sector {sector})")
            return  # Normal read mode — let ROM content pass through

        # Command mode — inject SPI response data
        self._device_access(uc, hooked=True)
        rp = self._dev_replay_of(uc, 'spi', address)
        if rp is not None and len(rp[2]) == size:
            self._rom_inject(uc, address, off, rp[2])   # replay: the same response bytes again
            self._rom_dirty.append((off, size))
            return
        resp = self._spi_response_bytes(size)
        self._rom_inject(uc, address, off, resp)
        self._rom_dirty.append((off, size))
        self._dev_note(uc, 'spi', address, resp, exact=True)    # (memory hook: exact PC)
        if self._spi_response:
            self._spi_log(f"  RESP [{size}B]: {' '.join(f'{b:02X}' for b in resp)}")

    def _hook_spi_flash_write(self, uc, access, address, size, value, user_data):
        """Handle writes to the memory-mapped flash region (SYS_FLASH_BASE_ADDR).

        Memory-mapped writes trigger SPI command execution:
          - WREN/WRDI (cmd 0x06/0x04): trigger via write to any flash address
          - WRSR (cmd 0x01): the write data is the new status register value
          - Erase (cmd 0x20/0x52/0xD8/0xC7/0x60): erase the sector containing
            the address (or the whole chip)
          - Page Program (cmd 0x02) / AAI (0xAD): program the data bytes

        The guest's store itself is reverted later (see _hook_flash_write_prot);
        only the emulated program/erase changes rom_image.
        """
        self._device_access(uc, hooked=True)
        if self._rom_dirty:
            self._rom_restore()
        off = self._flash_offset(address)
        self._rom_dirty.append((off, size))
        if self._spi_is_passthrough():
            return  # Normal mode — a write to the flash window has no effect

        data = value.to_bytes(size, 'little')
        stream = self._spi_stream
        if stream is not None and stream.active:
            # the bytes go out to the part (once: a stop at this store replays it)
            if self._dev_replay_of(uc, 'spi_stream', address, data) is None:
                self._dev_note(uc, 'spi_stream', address, data, exact=True)
                stream.write(data)
            return
        self._spi_execute(self._spi_ins, off, data)

    def _spi_execute(self, cmd, off, data):
        """Carry out a command that changes the part: WREN / WRDI, WRSR (the
        status is data[0]), an erase of the block at flash offset off (or of
        the chip), a page program / AAI of data at off."""
        cmd_name = self._SPI_CMD_NAMES.get(cmd, f"0x{cmd:02X}")
        if cmd in (0x06, 0x04):     # WREN / WRDI — trigger
            self._spi_set_wel(cmd == 0x06)
            self._spi_log(f"  EXEC {cmd_name}")
        elif cmd == 0x01:    # WRSR — write status register
            if self._spi_wel and data:
                self._spi_status = data[0]
                self._spi_set_wel(False)
                self._spi_log(f"  EXEC {cmd_name} = 0x{data[0]:02X}")
        elif cmd in (0xC7, 0x60, 0xD8, 0x52, 0x20):   # erase
            if not self._spi_wel:
                self._spi_log(f"  EXEC {cmd_name} without WEL (applied anyway)")
            if cmd in (0xC7, 0x60):
                self._flash_erase(0, self.rom_size)
                self._spi_log(f"  EXEC {cmd_name}")
            else:
                blk = {0xD8: 0x10000, 0x52: 0x8000, 0x20: 0x1000}[cmd]
                self._flash_erase(off & ~(blk - 1), blk)
                self._spi_log(f"  EXEC {cmd_name} @ flash[0x{off & ~(blk - 1):06X}]")
            self._spi_set_wel(False)
        elif cmd in (0x02, 0x32, 0xAD):                  # page program (quad: 0x32) / AAI
            if not self._spi_wel:
                self._spi_log(f"  EXEC {cmd_name} without WEL (applied anyway)")
            for i, byte in enumerate(data):
                self._flash_program(off + i, byte)
            shown = f"0x{int.from_bytes(data, 'little'):0{2 * len(data)}X}" if len(data) <= 4 else f"{len(data)} bytes"
            self._spi_log(f"  EXEC {cmd_name} @ flash[0x{off:06X}] = {shown}")
            if cmd != 0xAD:
                self._spi_set_wel(False)

    # ------------------------------------------------------------------
    # ISA mode tracking (MIPS32 vs MIPS16e)
    #
    # Unicorn (QEMU) executes MIPS16e natively -- the 24Kf model carries
    # ASE_MIPS16 -- and keeps the current mode in bit MIPS_HFLAG_M16 (0x400)
    # of env->hflags.  The API only lets us *set* that bit (low bit of the PC
    # passed to emu_start()/reg_write()), it never reports it back: reg_read(PC)
    # is always even.  The hflags word is however part of the blob returned by
    # context_save(), so we locate it once (_calibrate_hflags) and read it
    # directly whenever the exact mode is needed: at every emu_start() and
    # after every mode-changing jump (JALX / JR / JALR / JRC / JALRC / ERET).
    #
    # Rules that follow from experiments with Unicorn 2.1.4:
    #  * reg_write(PC, x) inside a code hook makes execution continue at x
    #    (the hooked instruction is skipped) -- no emu_stop() needed.  The
    #    low bit of x selects the ISA mode of the target.
    #  * A PC write from a branch *delay slot* is ignored (the branch wins),
    #    so nothing is emulated manually there.
    #  * A 2-byte hook size means MIPS16; a 4-byte one is MIPS32 or a MIPS16
    #    EXTEND/JAL/JALX -- the tracked mode disambiguates.
    # ------------------------------------------------------------------
    HFLAG_M16 = 0x400

    def _calibrate_hflags(self):
        """Find CPUMIPSState.hflags inside Unicorn's context blob (see above)."""
        import struct, ctypes
        cands = []
        ctx = None
        try:
            probe = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
            probe.ctl_set_cpu_model(UC_CPU_MIPS32_24KF)
            probe.mem_map(0x1000, 0x1000)
            probe.mem_write(0x1000, struct.pack('<2H', 0x6500, 0x6500))   # MIPS16: nop ; nop
            probe.mem_write(0x1100, struct.pack('<2I', 0, 0))             # MIPS32: nop ; nop
            probe.emu_start(0x1000 | 1, 0x2000, count=1)
            blob16 = bytes(probe.context_save())
            probe.emu_start(0x1100, 0x2000, count=1)
            blob32 = bytes(probe.context_save())
            for off in range(0, min(len(blob16), len(blob32)) - 3, 4):
                w16 = struct.unpack_from('<I', blob16, off)[0]
                w32 = struct.unpack_from('<I', blob32, off)[0]
                if (w16 ^ w32) == self.HFLAG_M16 and (w16 & self.HFLAG_M16):
                    cands.append(off)
            ctx = self.mu.context_save()
            if ctx.size != len(blob16):
                cands = []
        except Exception as e:
            self.log(f"Warning: hflags calibration failed: {e}")
            cands = []
        if len(cands) != 1 or ctx is None:
            self.log(f"Warning: could not locate hflags in Unicorn context (candidates={cands}); "
                     f"falling back to address-based ISA mode heuristics")
            self._hflags_off = None
            return
        self._hflags_off = cands[0]
        self._ctx = ctx
        base = ctypes.cast(ctx.context, ctypes.c_void_p).value
        self._hflags_view = ctypes.c_uint32.from_address(base + self._hflags_off)
        # Make sure context_update works with this binding before relying on it.
        self.mu.context_update(self._ctx)
        self.log(f"ISA mode tracking: hflags at context offset {self._hflags_off}")

    def _calibrate_gpr_view(self):
        """Find the 32 GPRs inside the context blob, for cheap register
        fingerprints (_gpr_snapshot: one context_update instead of 32
        reg_reads).  Called once the GPR map exists."""
        import struct, ctypes
        self._gpr_view = None
        if self._ctx is None:
            return
        try:
            vals = [0x5A5A0000 | (i << 8) | 0xA5 for i in range(1, 32)]
            for i, v in enumerate(vals, 1):
                self.mu.reg_write(self.gpr_map[i], v)
            self.mu.context_update(self._ctx)
            blob = ctypes.string_at(self._ctx.context, self._ctx.size)
            off = blob.find(struct.pack('<31I', *vals))
            for i in range(1, 32):
                self.mu.reg_write(self.gpr_map[i], 0)
            if off >= 4:
                base = ctypes.cast(self._ctx.context, ctypes.c_void_p).value
                self._gpr_view = (ctypes.c_char * 128).from_address(base + off - 4)
        except Exception as e:
            self.log(f"Warning: GPR fingerprint calibration failed: {e}")

    def _gpr_snapshot(self):
        """The 32 GPRs as bytes (None if not calibrated)."""
        if self._gpr_view is None:
            return None
        self.mu.context_update(self._ctx)
        return self._gpr_view.raw

    def get_hflags(self):
        """Current QEMU hflags word, or None if calibration failed."""
        if self._hflags_off is None:
            return None
        self.mu.context_update(self._ctx)
        return self._hflags_view.value

    def is_mips16_mode(self, pc=None):
        """Exact ISA mode of the CPU right now (valid inside hooks and after
        emu_start returns).  Without hflags calibration falls back to the
        address heuristic for pc (or the current PC)."""
        hf = self.get_hflags()
        if hf is None:
            if pc is None:
                pc = self.mu.reg_read(UC_MIPS_REG_PC)
            return self.is_mips16_addr(pc)
        return bool(hf & self.HFLAG_M16)

    @property
    def isa_mode(self):
        if self._hflags_off is not None:
            return ISAMode.MIPS16 if self.is_mips16_mode() else ISAMode.MIPS32
        return self._isa_mode_fallback

    @isa_mode.setter
    def isa_mode(self, value):
        """Force the ISA mode of the instruction at the current PC (Unicorn takes
        the mode from bit 0 of the PC, so the PC is rewritten with that bit)."""
        self._isa_mode_fallback = value
        if self.mu is not None:
            pc = self.mu.reg_read(UC_MIPS_REG_PC) & ~1
            self.mu.reg_write(UC_MIPS_REG_PC, pc | (1 if value == ISAMode.MIPS16 else 0))
            self._cur_m16 = (value == ISAMode.MIPS16)

    def start_pc(self, pc):
        """PC value to hand to mu.emu_start(): the current ISA mode in bit 0.

        Scripts that call sim.mu.emu_start() directly must use this instead of
        a plain reg_read(PC) (which is always even and would restart MIPS16
        code as MIPS32)."""
        return self._start_pc(pc)

    def _start_pc(self, pc):
        """PC value to hand to emu_start(): resets the tracker and encodes the ISA mode in bit 0."""
        hf = self.get_hflags() if self._hflags_off is not None else None
        if hf is not None:
            m16 = self.is_mips16_mode()
        else:
            m16 = self.is_mips16_addr(pc)
        self._cur_m16 = m16
        self._isa_mode_fallback = ISAMode.MIPS16 if m16 else ISAMode.MIPS32
        # An asynchronous stop can leave the CPU between a branch and its delay
        # slot (the translation block ended at a page boundary): the first
        # instruction then runs as the delay slot, so nothing may be injected there.
        in_ds = bool(hf is not None and hf & self._HFLAG_BMASK)
        self._next_in_delay_slot = in_ds
        self._mode_resync_in = 2 if in_ds else 0   # the branch may switch the ISA mode
        return (pc & ~1) | (1 if m16 else 0)

    # MIPS32 primary opcodes whose instruction has a branch delay slot
    _M32_DELAY_SLOT_OPCODES = frozenset({2, 3, 4, 5, 6, 7, 0x14, 0x15, 0x16, 0x17, 0x1D})
    _M32_REGIMM_BRANCH_RT = frozenset({0, 1, 2, 3, 0x10, 0x11, 0x12, 0x13})

    @classmethod
    def _insn_has_delay_slot(cls, insn, size, m16):
        if m16:
            hw = insn[0] | (insn[1] << 8)
            op = hw >> 11
            if op == 0x03:                                    # JAL / JALX
                return True
            if op == 0x1D and (hw & 0x1F) == 0:               # RR JR/JALR family
                return ((hw >> 5) & 7) in (0, 1, 2)           # JR rx / JR ra / JALR (not JRC/JALRC)
            return False
        w = int.from_bytes(insn, 'little')
        op = w >> 26
        if op in cls._M32_DELAY_SLOT_OPCODES:
            return True
        if op == 0:
            return (w & 0x3F) in (8, 9)                       # JR / JALR
        if op == 1:
            return ((w >> 16) & 0x1F) in cls._M32_REGIMM_BRANCH_RT
        if op in (0x11, 0x12):                                # BC1x / BC2x
            return ((w >> 21) & 0x1F) == 8
        return False

    @staticmethod
    def _insn_may_switch_mode(insn, size, m16):
        """True for instructions after which the ISA mode may differ (target taken from a register or JALX)."""
        if m16:
            hw = insn[0] | (insn[1] << 8)
            op = hw >> 11
            if op == 0x03:
                return bool(hw & 0x0400)                      # JALX (x bit); JAL stays MIPS16
            return op == 0x1D and (hw & 0x1F) == 0            # JR / JALR / JRC / JALRC
        w = int.from_bytes(insn, 'little')
        op = w >> 26
        if op == 0x1D:                                        # JALX
            return True
        return op == 0 and (w & 0x3F) in (8, 9)               # JR / JALR

    @staticmethod
    def _m16_pc_relative_branch(insn, size):
        """MIPS16 B / BEQZ / BNEZ / BTEQZ / BTNEZ (plain or EXTENDed).  These
        have no delay slot and Unicorn completes them inside the instruction:
        a reg_write(PC) from a code hook before one of them raises an
        'Unhandled CPU exception' or is ignored, so no interrupt may be
        injected there (verified with Unicorn 2.1.4)."""
        hw = insn[0] | (insn[1] << 8)
        if size == 4:
            if (hw >> 11) != 0x1E:                            # JAL / JALX: redirect works
                return False
            hw = insn[2] | (insn[3] << 8)                     # instruction after EXTEND
        op = hw >> 11
        return op in (0x02, 0x04, 0x05) or (op == 0x0C and ((hw >> 8) & 7) in (0, 1))

    def _hook_code(self, uc, address, size, user_data):
        # The previous instruction completed: its device access (if any) can no
        # longer be rewound by a stop (see _dev_note).
        self._dev_last = None
        # Undo transient writes into the flash window made by the previous instruction.
        if self._rom_dirty:
            self._rom_restore()

        # (CP0 Count is derived from instruction_count, see _cp0_count_now.)

        # Hook-based single-stepping: stop before the 2nd instruction (see step()).
        # If that instruction is a branch delay slot Unicorn executes it anyway,
        # so it is still tracked/emulated below and the stop is issued at the end.
        insn = uc.mem_read(address, size)
        # MIPS16 JRC / JALRC complete their jump inside the same instruction, so
        # neither a PC redirect nor an emu_stop() request takes effect before them.
        compact_jump = (size == 2 and (insn[1] >> 3) == 0x1D and (insn[0] & 0x1F) == 0
                        and ((insn[0] >> 5) & 7) in (4, 5, 6))
        stop_after = False
        if self.is_stepping:
            self._step_count += 1
            if self._step_count > 1:
                self._stop_reason = 'step'
                if not self._next_in_delay_slot and not compact_jump:
                    uc.emu_stop()
                    return
                stop_after = True

        in_delay_slot = self._next_in_delay_slot

        # ---- ISA mode of this instruction ----
        m16 = self._cur_m16
        if self._mode_resync_in:
            self._mode_resync_in -= 1
            if self._mode_resync_in == 0:
                m16 = self.is_mips16_mode(address)
        if size == 2:
            m16 = True                                        # only MIPS16 has 2-byte instructions
        elif m16 and (insn[1] >> 3) not in (0x1E, 0x03):
            m16 = self.is_mips16_mode(address)                # 4-byte MIPS16 must be EXTEND or JAL/JALX
        if self.verify_isa_mode and self._hflags_off is not None:
            exact = self.is_mips16_mode()
            if exact != m16:
                self.isa_mode_mismatches += 1
                self.log(f"[ISA] tracked {'MIPS16' if m16 else 'MIPS32'} but CPU is "
                         f"{'MIPS16' if exact else 'MIPS32'} at 0x{address:08X} (size {size})")
                m16 = exact
        self._cur_m16 = m16
        self._next_in_delay_slot = self._insn_has_delay_slot(insn, size, m16)
        if self._insn_may_switch_mode(insn, size, m16):
            self._mode_resync_in = 2 if self._next_in_delay_slot else 1

        # ---- Bookkeeping: history, visit counts, trace ----
        self._last_hook_size = size
        self._last_hook_addr = address
        self.prev_executed_pc = self.current_executed_pc
        self.current_executed_pc = address

        self.pc_history.append(address)
        if len(self.pc_history) > self.history_size:
            self.pc_history.pop(0)

        if address not in self.visit_counts:
            self.visit_counts[address] = 0
        self.visit_counts[address] += 1
        self.instruction_sizes[address] = size
        self.instruction_isa[address] = m16

        if self.trace_instructions:
            try:
                loop_str = f" [LOOP {self.visit_counts[address]}]" if self.visit_counts[address] > 1 else ""
                bytes_str = ' '.join(f'{b:02x}' for b in insn)
                if m16:
                    mnemonic, operands = MIPS16Decoder.decode(bytes(insn), address)
                    self.log(f"0x{address:08X}: {bytes_str:<15} {mnemonic}\t{operands}{loop_str}")
                else:
                    for i in self.md.disasm(bytes(insn), address):
                        self.log(f"0x{i.address:08X}: {bytes_str:<15} {i.mnemonic}\t{i.op_str}{loop_str}")
            except Exception:
                pass

        # ---- Breakpoints / stop address (checked before the instruction runs) ----
        if not self.is_stepping:
            if self.stop_instr is not None and address == self.stop_instr:
                self.log(f"\n[STOP] Reached stop address: 0x{address:08X}")
                self._stop_reason = 'stop_instr'
                uc.emu_stop()
                return
            if address in self.breakpoints:
                self.log(f"\n[BREAKPOINT] Hit at 0x{address:08X}")
                self._stop_reason = 'breakpoint'
                uc.emu_stop()
                return

        # ---- Interrupt injection (UART receive, CP0 timer, software) ----
        # Delivered by redirecting the PC to the exception vector (MIPS32) before
        # this instruction runs.  Never during a single step (like a debugger's
        # "step without interrupts": a step off a breakpoint must execute the
        # instruction; the interrupt is taken by the next run()), nor in a delay
        # slot (Unicorn ignores the PC write there).  On a MIPS16 compact jump or
        # PC-relative branch Unicorn ignores (or faults on) a PC write from a
        # hook, so the slice is stopped right after the branch and run() delivers.
        irq_stop = False
        if self._pending_uart_irq and not self._uart_irq_delivered and not in_delay_slot \
                and not self.is_stepping and self.instruction_count >= self._uart_irq_arm_after:
            ie = self.cp0_status & 0x01
            exl = self.cp0_status & 0x02
            force = getattr(self, '_uart_irq_force', False)
            if force or (ie and not exl):
                if compact_jump or (m16 and self._m16_pc_relative_branch(insn, size)):
                    irq_stop = True
                else:
                    exc_vector = self._enter_uart_irq(uc, address | (1 if m16 else 0))
                    self._cur_m16 = False
                    self._mode_resync_in = 0
                    self._next_in_delay_slot = False
                    uc.reg_write(UC_MIPS_REG_PC, exc_vector)   # even -> MIPS32
                    return

        # Count advances 2 per instruction here, so the next Compare crossing
        # is a known instruction count.
        if self.instruction_count >= self._timer_next_icount:
            self._timer_update()
        if (self._ti or self.cp0_cause & 0x300 or self._ic_ip3()) and not in_delay_slot \
                and not self.is_stepping and self._irq_deliverable():
            if compact_jump or (m16 and self._m16_pc_relative_branch(insn, size)):
                irq_stop = True
            else:
                exc_vector = self._enter_interrupt(uc, address | (1 if m16 else 0))
                self._cur_m16 = False
                self._mode_resync_in = 0
                self._next_in_delay_slot = False
                uc.reg_write(UC_MIPS_REG_PC, exc_vector)
                return

        # ---- CP0 emulation (MIPS32 COP0 opcode 0x10: MFC0 / MTC0 / ERET) ----
        if size == 4 and not m16 and (insn[3] >> 2) == 0x10:
            self._emulate_cop0(uc, address, int.from_bytes(insn, 'little'), in_delay_slot)

        self.instruction_count += 1
        if stop_after:
            uc.emu_stop()
        elif irq_stop:
            self._stop_reason = 'irq'       # takes effect after the branch; run() delivers
            uc.emu_stop()
        elif self.max_instructions and not self.is_stepping and self.instruction_count >= self.max_instructions:
            self._stop_reason = 'max_instructions'
            uc.emu_stop()

    def _emulate_cop0(self, uc, address, w, in_delay_slot):
        """Emulate MFC0/MTC0 of Count, Status, Cause, EPC and EBase and ERET with
        the simulated CP0 state.  Returns True if the PC was redirected past the
        instruction (i.e. Unicorn will not execute it)."""
        rs = (w >> 21) & 0x1F
        rt = (w >> 16) & 0x1F
        rd = (w >> 11) & 0x1F
        sel = w & 0x7
        funct = w & 0x3F
        if rs == 0x00:                      # MFC0 rt, rd
            val = self._cp0_read(rd, sel)
            if val is None:
                return False                # other registers: let Unicorn handle
            if in_delay_slot:
                self._delay_slot_skips += 1
                return False
            self._reg_write(self.gpr_map[rt], val & 0xFFFFFFFF)
            self._reg_write(UC_MIPS_REG_PC, address + 4)
            return True
        if rs == 0x04:                      # MTC0 rt, rd
            if rd == 12 and not self.force_erl and not in_delay_slot and self._code_hook_h is None:
                return self._follow_status_write(uc, address, rt)
            resched = self._cp0_write(uc, rd, sel, self._reg_read(self.gpr_map[rt]) & 0xFFFFFFFF)
            if resched is None:
                return False
            if in_delay_slot:
                self._delay_slot_skips += 1  # shadow updated; native MTC0 still executes
                if resched:
                    self._reschedule_slice() # a stop here takes effect after the branch
                return False
            self._reg_write(UC_MIPS_REG_PC, address + 4 * self._repeated(address, w))
            if resched:
                self._reschedule_slice()
            return True
        if rs == 0x10 and funct == 0x18:    # ERET
            if in_delay_slot:
                return False
            target = self._eret(uc)
            self._reg_write(UC_MIPS_REG_PC, target)   # bit 0 selects the ISA mode
            self._reschedule_slice()
            return True
        return False

    def _follow_status_write(self, uc, address, rt):
        """Fast mode, native Status: an MTC0 Status the CPU executes itself --
        the hook takes the value over and re-plans the slice when the write can
        bring an interrupt (_cp0_write's rule); only when that ends the slice
        here does the hook complete the write and move past it (the stop comes
        before the instruction).  Returns whether the PC moved."""
        val = self._reg_read(self.gpr_map[rt]) & 0xFFFFFFFF
        old = self.cp0_status
        self.cp0_status = val
        if not ((old ^ val) & 0xFF06 or val & ~old & 0x1):
            return False
        before = self._stop_reason
        self._reschedule_slice()
        if self._stop_reason is before:
            return False
        self._write_native_status(uc, val)
        self._reg_write(UC_MIPS_REG_PC, address + 4)
        return True

    def _repeated(self, address, w):
        """Fast mode, an MTC0 at address just emulated: how many words the PC
        moves on -- past up to three NOPs and the same MTC0 again, which writes
        the same value (the RTOS's interrupt disable writes Status twice, a
        hazard padding: one hook instead of two), unless a breakpoint or the
        stop address lies there; else 1."""
        words = self._ram_words
        i = (address & 0x1FFFFFFF) >> 2
        if self._code_hook_h is not None or words is None or (address >> 29) not in (4, 5) \
                or not 0 < i < len(words) - 4:
            return 1
        for k in range(1, 5):
            x = words[i + k]
            if x == w:
                end = address + 4 * k
                if (self.stop_instr is not None and address < self.stop_instr <= end) or \
                        any(address < b <= end for b in self.breakpoints):
                    return 1
                return k + 1
            if x:
                return 1
        return 1

    def _cp0_read(self, rd, sel):
        """What MFC0 of CP0 register rd, sel reads (Count, Compare, Status,
        Cause, EPC, EBase), or None for a register Unicorn keeps."""
        if rd == 12:
            return self.cp0_status
        if rd == 9:
            val = self._cp0_count_now()
            self._timer_update(val)
            self._count_observed = val
            return val
        if rd == 14:
            return self.cp0_epc
        if rd == 13:
            self._timer_update()
            return self._cause_value()
        if rd == 11:
            return self.cp0_compare
        if rd == 15 and sel == 1:
            return self.cp0_ebase
        return None

    def _cp0_write(self, uc, rd, sel, val):
        """MTC0 of val to CP0 register rd, sel: None for a register Unicorn
        keeps, else whether the write can change when the next interrupt comes
        (then the slice is re-planned: _reschedule_slice)."""
        if rd == 12:
            if self.force_erl:
                val &= ~0x4             # never adopt the ERL that only the native Status carries
            old = self.cp0_status
            self.cp0_status = val
            self._write_native_status(uc, val)
            # Only enabling (IE, an IM bit) or a change of EXL / ERL can make an
            # interrupt deliverable or move the slice's deadline: an interrupt
            # disable or a rewrite of the same value (critical sections) cannot.
            return bool((old ^ val) & 0xFF06 or val & ~old & 0x1)
        if rd == 9:
            self._timer_update()        # crossings before the write still count
            self.cp0_count = val
            self._count_icount = self.instruction_count
            self._count_t0 = self._vtime()
            self._timer_anchor = val
            self._count_observed = val
            self._timer_next_icount = 0
            return True
        if rd == 11:
            self._write_compare(val)
            return True
        if rd == 13:
            # Only IP1..0 (software interrupts), WP, IV and DC are writable.
            self.cp0_cause = (self.cp0_cause & ~0x08C00300) | (val & 0x08C00300)
            return True
        if rd == 14:
            self.cp0_epc = val
            return False
        if rd == 15 and sel == 1:       # EBase: bits 29..12 writable, 31..30 read as 0b10,
            self.cp0_ebase = 0x80000000 | (val & 0x3FFFF000) | (self.cp0_ebase & 0x3FF)    # CPUNum read-only
            return False
        return None

    def _eret(self, uc):
        """CP0 side of ERET (EXL cleared, UART re-arm); returns the target PC
        (EPC, bit 0 = ISA mode)."""
        self.cp0_status &= ~0x02            # clear EXL
        self._write_native_status(uc, self.cp0_status)
        uart_done = self._uart_ip3          # this ERET ends a UART interrupt
        self._uart_ip3 = False
        self._last_eret_vt = self._vtime()
        target = self.cp0_epc & 0xFFFFFFFF
        self._cur_m16 = bool(target & 1)
        self._mode_resync_in = 0
        self._next_in_delay_slot = False
        # Timer ticks end in an ERET each: log the first ones only.
        self._eret_logged += 1
        if self._eret_logged <= 64 or self._eret_logged % 1000 == 0:
            self.log(f"[ERET] Returning to {hex(target)}, Status=0x{self.cp0_status:08X}"
                     + (f" (ERET #{self._eret_logged})" if self._eret_logged > 64 else ""))
        # More RX bytes queued: interrupt again shortly after the UART ISR
        # returns (only then: timer ticks end in ERETs too, and must not
        # bring a setUartReceiveData() delay forward).
        if uart_done and len(self._uart_rx_queue) > 0:
            self._pending_uart_irq = True
            self._uart_irq_delivered = False
            self._uart_irq_arm_after = max(self._uart_irq_arm_after, self.instruction_count + 100)
        return target

    # ------------------------------------------------------------------
    # CP0 Count, interrupt entry
    # ------------------------------------------------------------------
    # ALi firmware addresses peripherals and the flash window through kuseg
    # (e.g. 0x18000058, 0x0FC00000) as if kuseg were identity mapped.  QEMU
    # only maps kuseg 1:1 while Status.ERL is set, so the native Status register
    # always carries ERL; the firmware's own view of Status (cp0_status) does not.
    force_erl = True

    def _write_native_status(self, uc, val):
        if self.force_erl:
            val |= 0x4
        try:
            (self._reg_write if uc is self.mu else uc.reg_write)(UC_MIPS_REG_CP0_STATUS, val & 0xFFFFFFFF)
        except Exception:
            pass

    def _vtime(self):
        """Emulation time in seconds: wall time spent inside emu_start() calls."""
        t = self._vt_accum
        if self._vt_slice_t0 is not None:
            now = self._vt_stop_t
            if now is None:
                now = self._clk_cache
                if now is None:
                    now = self._clk()
                    if self._in_cp0_hook:
                        self._clk_cache = now       # one reading per hooked CP0 instruction
            t += max(0.0, now - self._vt_slice_t0)
        return t

    def _setup_clock(self):
        """The emulation-time clock for the thread calling emu_start()."""
        import threading
        key = (threading.get_native_id(), self.count_clock)
        if key != self._clk_key:
            from thread_clock import make_thread_clock
            try:
                self._clk = make_thread_clock(self.count_clock)
            except ValueError:
                raise
            self._clk_key = key

    def _cp0_count_now(self):
        """Simulated CP0 Count.

        Full-hook mode: 2 ticks per executed instruction (deterministic, as the
        hardware does at half the CPU clock).  Fast mode: emulation time at
        count_hz, so firmware delay and timeout loops take real time instead
        of depending on how fast the host happens to emulate."""
        if self._code_hook_h is None:
            ticks = int((self._vtime() - self._count_t0) * self.count_hz)
        else:
            ticks = 2 * (self.instruction_count - self._count_icount)
        return (self.cp0_count + ticks) & 0xFFFFFFFF

    def _rebase_count(self):
        """Keep Count continuous when the Count formula changes (the exact
        per-instruction hook is installed or removed)."""
        self.cp0_count = self._cp0_count_now()
        self._count_icount = self.instruction_count
        self._count_t0 = self._vtime()
        self._timer_next_icount = 0

    # ------------------------------------------------------------------
    # CP0 timer
    # ------------------------------------------------------------------
    # MIPS32 R2 / 24K: when Count passes Compare, Cause.TI (bit 30) is set and
    # routed to IP7 (IntCtl.IPTI = 7); it stays set until Compare is written.
    # It is an edge, not "Count >= Compare": firmware that writes Compare = 0
    # right after Count = 0 (ali_sdk.bin) must not see IP7.  Crossings are
    # checked against the Count value of the previous check (_timer_anchor):
    # in fast mode at every slice boundary and every hooked CP0 instruction,
    # in exact mode at the precomputed instruction count of the next crossing.
    _M32 = 0xFFFFFFFF
    _LATE_COMPARE_WINDOW = 0x40000000   # Count ticks (~10.7 s at 100 MHz) since the guest read Count

    @property
    def timer_enabled(self):
        """CP0 timer interrupt on/off (e.g. off while single-stepping in the GUI)."""
        return self._timer_enabled

    @timer_enabled.setter
    def timer_enabled(self, on):
        self._timer_enabled = bool(on)
        if not on:
            self._ti = False            # a latched tick is dropped
        self._timer_next_icount = 0     # exact mode: re-check on the next instruction

    def _timer_update(self, now=None):
        """Latch Cause.TI if Count passed Compare since the last check."""
        if not self._timer_enabled:
            # The anchor stays put: a Compare that Count passes while the timer
            # is off fires (once) when it is switched on again.
            self._timer_next_icount = 1 << 62
            return
        if now is None:
            now = self._cp0_count_now()
        if self._timer_armed and not self._ti:
            d_cmp = (self.cp0_compare - self._timer_anchor) & self._M32
            if d_cmp and d_cmp <= ((now - self._timer_anchor) & self._M32):
                self._ti = True
        self._timer_anchor = now
        if self._code_hook_h is not None:
            if self._ti or not self._timer_armed:
                self._timer_next_icount = 1 << 62
            else:
                d = (self.cp0_compare - now) & self._M32 or (1 << 32)
                self._timer_next_icount = self.instruction_count + (d + 1) // 2

    def _write_compare(self, val):
        """MTC0 Compare: clears Cause.TI and arms the timer.

        Late-Compare rule: in fast mode Count follows the host clock, so a host
        stall between the tick handler's `mfc0 Count` and its `mtc0 Compare`
        (Compare = Count + period) can leave the new Compare behind Count, and
        the next tick would only come after Count wraps (43 s at 100 MHz).  The
        crossing is therefore checked from the Count value the guest last read
        (if recent), i.e. a Compare that Count passed in that time fires now."""
        now = self._cp0_count_now()
        self._timer_update(now)
        self.cp0_compare = val
        self._ti = False
        self._timer_armed = True
        obs = self._count_observed
        if obs is not None and ((now - obs) & self._M32) <= self._LATE_COMPARE_WINDOW:
            self._timer_anchor = obs
        self._count_observed = None
        self._timer_update(now)

    def _cause_value(self):
        """Cause as the guest reads it: stored bits plus the hardware lines."""
        v = self.cp0_cause
        if self._ti:
            v |= 0x40008000             # TI + IP7
        if self._uart_ip3 or self._ic_ip3():
            v |= 0x00000800             # IP3 (ALi interrupt controller)
        return v

    def _irq_deliverable(self):
        """A timer, software or modelled device (IP3, _ic_set_line) interrupt
        is requested: IE=1, EXL=0, ERL=0 and (IP & IM) != 0.  The UART
        interrupt is delivered by its own one-shot path (_irq_due /
        _enter_uart_irq)."""
        s = self.cp0_status
        if (s & 0x7) != 0x1:
            return False
        return bool((self._ti and s & 0x8000) or (self.cp0_cause & s & 0x300)
                    or (s & 0x800 and self._ic_ip3()))

    def _enter_interrupt(self, uc, epc):
        """Take an interrupt exception: EPC (ISA mode in bit 0), Cause.BD and
        ExcCode cleared (ExcCode 0 = Int), Status.EXL set.  Returns the vector."""
        self.cp0_epc = epc & self._M32
        self.cp0_cause &= ~0x8000007C
        self.cp0_status |= 0x02
        self._write_native_status(uc, self.cp0_status)
        bev = self.cp0_status & 0x00400000
        iv = self.cp0_cause & 0x00800000
        if self._ti and self.cp0_status & 0x8000:
            self.timer_irq_count += 1
            if self.timer_irq_count <= 8 or self.timer_irq_count % 1000 == 0:
                self.log(f"[TIMER IRQ] #{self.timer_irq_count} from 0x{epc & ~1:08X}")
        if self.cp0_status & 0x800 and not self._uart_ip3 and self._ic_ip3():    # (served in the same pass)
            self.ic_irq_count += 1
            if self.ic_irq_count <= 8 or self.ic_irq_count % 1000 == 0:
                rung = " and a doorbell" if self._doorbell_ip3() else ""
                self.log(f"[IC IRQ] #{self.ic_irq_count} lines 0x{self._ic_lines:X}{rung} from 0x{epc & ~1:08X}")
        return (0xBFC00200 if bev else self.cp0_ebase & 0xFFFFF000) + (0x200 if iv else 0x180)

    def _reschedule_slice(self):
        """Fast mode, inside a run() slice: an MTC0 Count / Compare / Status /
        Cause or an ERET changed when the next interrupt can be taken.

        If one is deliverable now, end the slice here and let run() take it at
        the boundary (the hook already moved the PC past the instruction; an
        interrupt is never injected inside a CP0 hook, where the kernel may
        have k0/k1 live).  Otherwise move the slice deadline to the next timer
        event: a tick handler's MTC0 Compare / ERET sets up the next tick."""
        if not (self._in_run and self._code_hook_h is None and self._slice_cap_end is not None):
            return
        count = self._cp0_count_now()       # one sample for the latch and the wait: a
        self._timer_update(count)           # crossing between two reads would be lost
        now = self._vtime()
        if self._irq_deliverable():
            hold = self._irq_gap_left(now)
            if hold > 0 and self._slice_uses_stopper:
                self._arm_deadline(hold)    # let the interrupted code run first
                self._slice_armed_end = now + hold
            else:
                self._stop_reason = 'irq'
                self._orig_emu_stop()
            return
        w = self._timer_wait_us(count)
        end = self._slice_cap_end if w is None else min(self._slice_cap_end, now + w / 1e6)
        if self._slice_uses_stopper:
            exl = bool(self.cp0_status & 0x2)
            if exl and not self._slice_armed_exl:
                # The guest entered exception level itself (a context switch:
                # MTC0 Status with EXL, then ERET a few instructions later): the
                # backstop needs the long EXL margin.  Before the deadline it is
                # async_stop_margin_us away, so it is simply moved; after it, the
                # short backstop may already be firing, so end the slice here
                # (synchronously, the MTC0 is done) -- the next slice, which runs
                # the ERET, starts with the long EXL backstop.
                if self._slice_deadline is None or time.perf_counter() >= self._slice_deadline:
                    self._stop_reason = 'resched'
                    self._orig_emu_stop()
                    return
            # (IE toggles: deadline unchanged; leaving EXL shortens the backstop)
            if abs(end - self._slice_armed_end) > 50e-6 or exl != self._slice_armed_exl:
                self._arm_deadline(max(end - now, 0.0))
                self._slice_armed_end = end
        elif self._slice_planned_end is not None and \
                end < self._slice_planned_end - max(self.min_slice_us / 1e6, 0.001):
            # Unicorn's timeout cannot be moved: end the slice now if the deadline
            # really moved earlier, run() plans the next one
            self._stop_reason = 'irq'
            self._orig_emu_stop()

    # QEMU MIPS_HFLAG_BMASK: the CPU is between a branch and its delay slot.
    _HFLAG_BMASK = 0x0087F800

    def _at_safe_point(self):
        """True if the PC can be redirected to an exception vector after an
        asynchronous slice stop (not between a branch and its delay slot,
        which can happen when a translation block ends at a page boundary)."""
        hf = self.get_hflags()
        return hf is None or not (hf & self._HFLAG_BMASK)

    def _timer_wait_us(self, count=None):
        """Fast mode: microseconds until the slice should end for the CP0
        timer, or None.  0 if a timer interrupt is pending and deliverable
        (its delivery was deferred); None if it is pending but masked by IE /
        EXL (the handler's ERET or an MTC0 Status re-plans the slice) or IM7 is
        off; otherwise the time until Count reaches Compare.  IE / EXL do not
        matter for the latter: they usually change before the deadline."""
        if not (self.timer_enabled and self._timer_armed):
            return None
        s = self.cp0_status
        if not (s & 0x8000) or (s & 0x4):
            return None
        if self._ti:
            return self._irq_gap_left() * 1e6 if self._irq_deliverable() else None
        if count is None:
            count = self._cp0_count_now()
        d = (self.cp0_compare - count) & self._M32
        return d * 1e6 / self.count_hz

    def _irq_gap_left(self, now=None):
        """Fast mode: seconds the guest still has to run after the last ERET
        before the next timer / software interrupt may be taken (0 = now)."""
        if self._code_hook_h is not None:
            return 0.0
        if now is None:
            now = self._vtime()
        return max(0.0, self._last_eret_vt + self.irq_min_gap_us / 1e6 - now)

    def _get_stopper(self):
        """The fast-mode slice stopper (created on first use), or None to use
        emu_start(timeout=)."""
        if self._stopper_made != self.slice_stopper:       # first use, or the setting changed
            if self._stopper is not None:
                self._stopper.close()
                self._stopper = None
            self._stopper_made = self.slice_stopper
            try:
                from slice_stopper import make_stopper
                self._stopper = make_stopper(self.mu, self.slice_stopper)
            except ValueError:
                self._stopper_made = None
                raise                       # unknown slice_stopper name
            except Exception as e:
                self.log(f"Warning: slice stopper '{self.slice_stopper}' unavailable ({e}); "
                         f"using Unicorn's emu_start timeout")
                self._stopper = None
            if self._stopper is not None:
                import weakref
                weakref.finalize(self, self._stopper.close)
        return self._stopper

    def _enter_uart_irq(self, uc, epc):
        """Set up the CP0 state for the UART receive interrupt and return the
        exception vector.  epc carries the ISA mode in bit 0 like real hardware."""
        self._uart_irq_delivered = True
        self._pending_uart_irq = False
        self._uart_irq_retries += 1
        # ALi interrupt controller: EISR/EIER bit 16 = UART IRQ 24
        uart_ic_bit = 1 << 16
        eisr, eier = self._ic, self._ic_en
        try:
            eisr_val = int.from_bytes(uc.mem_read(eisr, 4), 'little')
            uc.mem_write(eisr, (eisr_val | uart_ic_bit).to_bytes(4, 'little'))
            eier_val = int.from_bytes(uc.mem_read(eier, 4), 'little')
            uc.mem_write(eier, (eier_val | uart_ic_bit).to_bytes(4, 'little'))
        except Exception:
            pass
        self._uart_ip3 = True             # IP3, ORed into Cause (a pending IP7 stays visible)
        self.cp0_status |= 0x0800         # IM[3]
        exc_vector = self._enter_interrupt(uc, epc)
        self.log(f"[UART IRQ] Delivering interrupt #{self._uart_irq_retries} -> {hex(exc_vector)} "
                 f"(from {hex(epc & ~1)}, icount={self.instruction_count})")
        return exc_vector

    def _irq_due(self):
        """True if a UART interrupt is armed and may be taken now (Status IE, !EXL)."""
        if not (self._pending_uart_irq and not self._uart_irq_delivered):
            return False
        if self.instruction_count < self._uart_irq_arm_after:
            return False
        if getattr(self, '_uart_irq_force', False):
            return True
        return bool(self.cp0_status & 0x01) and not (self.cp0_status & 0x02)

    # ------------------------------------------------------------------
    # Fast mode: hook management
    # ------------------------------------------------------------------
    # MIPS32 encodings of MFC0/MTC0 rt, {Count, Compare, Status, Cause, EPC}
    # (sel 0), EBase (reg 15 sel 1) and ERET, little-endian, matched at any
    # byte offset and then filtered to 4-byte alignment.  Data or MIPS16 code
    # matching by accident is harmless: the site hook re-checks the ISA mode
    # and the encoding.
    _CP0_SITE_RE = re.compile(rb'(?:\x00[\x48\x58\x60\x68\x70]|\x01\x78)[\x00-\x1f\x80-\x9f]\x40|\x18\x00\x00\x42')
    _RAM_CODE_LIMIT = 0x02000000        # scan/track the first 32MB of RAM for code
    _VIRGIN_CHUNK = 0x00100000          # 1MB first-execution chunks

    def _want_full_hook(self):
        return (self.hook_every_instruction or self.trace_instructions or self.verify_isa_mode
                or self._step_full_hook)

    def _flush_tb(self):
        """Drop translated blocks so that newly added code hooks take effect."""
        try:
            self.mu.ctl_flush_tb()
        except Exception:
            try:
                self.mu.ctl_remove_cache(0, 0xFFFFFFFF)
            except Exception:
                pass
        self._tb_flush_needed = False

    def _sync_hooks(self):
        """Install the hook set for the current mode (called before emu_start)."""
        full = self._want_full_hook()
        if full and self._code_hook_h is None:
            for h in list(self._cp0_site_hooks.values()) + list(self._bp_hooks.values()) + list(self._virgin_hooks.values()):
                self.mu.hook_del(h)
            self._cp0_site_hooks.clear(); self._bp_hooks.clear(); self._virgin_hooks.clear()
            self._rom_sites_hooked, self._vector_page = False, None
            self._rebase_count()            # Count: emulation time -> instruction count
            self._code_hook_h = self.mu.hook_add(UC_HOOK_CODE, self._hook_code)
            self._tb_flush_needed = True
        elif not full and self._code_hook_h is not None:
            self._rebase_count()            # Count: instruction count -> emulation time
            self.mu.hook_del(self._code_hook_h)
            self._code_hook_h = None
            self._rescan_due = True
            self._tb_flush_needed = True
        if not full:
            # Breakpoints / stop address as single-address hooks
            wanted = set(self.breakpoints)
            if self.stop_instr is not None:
                wanted.add(self.stop_instr)
            for addr in list(self._bp_hooks):
                if addr not in wanted:
                    self.mu.hook_del(self._bp_hooks.pop(addr))
                    self._tb_flush_needed = True
            for addr in wanted:
                if addr not in self._bp_hooks:
                    self._bp_hooks[addr] = self.mu.hook_add(UC_HOOK_CODE, self._hook_breakpoint, begin=addr, end=addr)
                    self._tb_flush_needed = True
            if not self._virgin_hooks:
                for seg in (0x80000000, 0xA0000000):
                    for base in range(seg, seg + min(self.ram_size, self._RAM_CODE_LIMIT), self._VIRGIN_CHUNK):
                        self._virgin_hooks[base] = self.mu.hook_add(
                            UC_HOOK_CODE, self._hook_virgin, begin=base, end=base + self._VIRGIN_CHUNK - 1)
                self._tb_flush_needed = True
            if self._rescan_due or (self.rescan_interval and
                                    self.instruction_count - self._last_rescan_icount >= self.rescan_interval):
                self._rescan_cp0_sites()
        if self._tb_flush_needed:
            self._flush_tb()

    # (word & 0xFFE0FFFF) of MFC0/MTC0 rt, {Count, Compare, Status, Cause, EPC} sel 0 and EBase (15 sel 1)
    _CP0_WORDS = frozenset([op | (rd << 11) | sel for op in (0x40000000, 0x40800000)
                            for rd, sel in ((9, 0), (11, 0), (12, 0), (13, 0), (14, 0), (15, 1))])
    _CP0_WORD_ARRAY = None if _np is None else _np.array(sorted(_CP0_WORDS), dtype=_np.uint32)
    _ERET_WORD = 0x42000018

    def _find_cp0_sites(self, data, base):
        """Offsets (plus base) of 4-byte-aligned CP0 instruction encodings in data."""
        out = set()
        if _np is not None:
            n = len(data) & ~3
            # The words' top bytes (a strided view): MFC0 / MTC0 have 0x40, ERET
            # 0x42 -- rare in code and data, so one vector pass over them finds
            # the few candidates, a second classifies those.
            cand = _np.flatnonzero((_np.frombuffer(data, dtype=_np.uint8, count=n)[3::4] | 2) == 0x42)
            if len(cand):
                x = _np.frombuffer(data, dtype='<u4', count=n // 4)[cand]
                hit = (x == self._ERET_WORD) | _np.isin(x & _np.uint32(0xFFE0FFFF), self._site_word_array)
                out.update((base + 4 * cand[hit]).tolist())
            return out
        data = bytes(data)
        n = len(data)
        fullmatch = self._CP0_SITE_RE.fullmatch
        for m in self._CP0_SITE_RE.finditer(data):      # one linear pass
            p = m.start()
            if (p & 3) == 0:
                out.add(base + p)
            else:
                # a misaligned match swallows up to 3 bytes of the next aligned
                # word; check that word explicitly so nothing is missed
                q = (p & ~3) + 4
                if q + 4 <= n and fullmatch(data, q, q + 4):
                    out.add(base + q)
        if len(self._site_words) != len(self._CP0_WORDS):    # (native Status: no MFC0 Status sites)
            out = {a for a in out if (int.from_bytes(data[a - base:a - base + 4], 'little') & 0xFFE0FFFF)
                   in self._site_words or data[a - base:a - base + 4] == b"\x18\x00\x00\x42"}
        return out

    def _add_cp0_sites(self, sites):
        for addr in sites:
            if addr not in self._cp0_site_hooks:
                self._cp0_site_hooks[addr] = self.mu.hook_add(UC_HOOK_CODE, self._hook_cp0_site, begin=addr, end=addr)
                self._tb_flush_needed = True

    def _rescan_cp0_sites(self, ranges=None):
        """Scan ROM (cached) and RAM for CP0 instruction encodings and hook each
        site.  ranges: list of (start, length) in the 0x80000000 RAM view; None
        scans the whole tracked RAM area."""
        sites = set()
        if self._rom_sites_dirty or not self._rom_sites_hooked:
            if self._rom_sites_dirty:
                self._rom_sites = self._find_cp0_sites(self.rom_image, 0)
                self._rom_sites_dirty = False
                self._find_lzma_decoders(self.rom_image, 0, (0xAFC00000, 0xBFC00000, 0x8FC00000, 0x9FC00000))
            # Flash executes from KSEG1 (and the BEV vector) -- and through KSEG0: the
            # T750i's XIP bootloader runs its set-up (MTC0 EBase, Status) from the
            # flash window's cached view, where its CP0 instructions ran natively.
            for base in (0xAFC00000, 0xBFC00000, 0x8FC00000, 0x9FC00000):
                sites |= {base + off for off in self._rom_sites}
            self._rom_sites_hooked = True
        full = ranges is None
        if full:
            ranges = [(0x80000000, min(self.ram_size, self._RAM_CODE_LIMIT))] + self.chip.code_ranges()
        for start, length in ranges:
            phys = start & 0x1FFFFFFF
            if (start >> 29) in (0, 4, 5) and phys + length <= self.ram_size:
                ram = self._ram_view[phys:phys + length]            # (the RAM buffer itself, no copy)
            else:
                try:
                    ram = self.mu.mem_read(start, length)
                except UcError as e:
                    self.log(f"Warning: RAM scan for CP0 sites failed at {hex(start)}: {e}")
                    continue
            found = self._find_cp0_sites(ram, phys)                 # physical offsets
            for seg in (0x80000000, 0xA0000000):                     # KSEG0 and KSEG1 views
                sites |= {seg + off for off in found}
            if not full and (start >> 29) in (4, 5):                # (a chunk's first execution, new code)
                self._find_lzma_decoders(ram, phys, (0x80000000, 0xA0000000))
        self._add_cp0_sites(sites)
        if full:
            self._update_short_block_hook()
            self._rescan_due = False
            self._last_rescan_icount = self.instruction_count
        if self.debug_enabled:
            self.log(f"[fast] {len(self._cp0_site_hooks)} CP0 sites hooked (icount={self.instruction_count})")

    def _hook_breakpoint(self, uc, address, size, user_data):
        if self.is_stepping:
            return
        if self.stop_instr is not None and address == self.stop_instr:
            self.log(f"\n[STOP] Reached stop address: 0x{address:08X}")
            self._stop_reason = 'stop_instr'
            uc.emu_stop()
        elif address in self.breakpoints:
            self.log(f"\n[BREAKPOINT] Hit at 0x{address:08X}")
            self._stop_reason = 'breakpoint'
            uc.emu_stop()

    def _hook_virgin(self, uc, address, size, user_data):
        """First execution inside a RAM chunk: code was copied or decompressed
        there, so scan the chunk for CP0 sites and hook them before going on."""
        base = address & ~(self._VIRGIN_CHUNK - 1)
        h = self._virgin_hooks.pop(base, None)
        if h is None:
            return
        if self._vt_slice_t0 is not None and self._vt_stop_t is None:
            self._vt_stop_t = self._clk()           # the rescan is host time, not Count time
        uc.hook_del(h)
        phys = base & 0x1FFFFFFF
        self._rescan_cp0_sites([(0x80000000 + phys, self._VIRGIN_CHUNK)])
        # Flushing the translation cache from inside a hook can corrupt block
        # chaining (the current block is being executed), so stop the slice
        # here instead: the hook runs before this instruction executes, run()
        # resumes at the same PC, and _sync_hooks() flushes first.
        self._stop_reason = 'rescan'
        uc.emu_stop()

    def _hook_cp0_site(self, uc, address, size, user_data):
        """Fast-mode hook on one MFC0/MTC0/ERET encoding found by scanning."""
        # MIPS16 code that matched by accident is 2-byte instructions here: no
        # site's first halfword is an EXTEND or JAL(X) prefix (op 0x1E / 0x03;
        # they are ADDIUSP, ADDIU8, SLTIU, I8, LI, CMPI or XORI).
        if size != 4:
            return
        # The previous word tells whether this is a branch delay slot (a PC
        # redirect would be ignored there); treat it as MIPS32 (a MIPS16 caller
        # reaches MIPS32 code only via JALX, whose target is never a delay slot).
        if self._rom_dirty:
            self._rom_restore()
        words = self._ram_words
        i = (address & 0x1FFFFFFF) >> 2
        if words is not None and 0 < i < len(words) and (address >> 29) in (0, 4, 5):
            prev, w = words[i - 1], words[i]            # RAM (kuseg, KSEG0, KSEG1): its buffer
        else:
            try:
                both = uc.mem_read(address - 4, 8)
                prev, w = int.from_bytes(both[:4], 'little'), int.from_bytes(both[4:], 'little')
            except UcError:
                prev, w = None, int.from_bytes(uc.mem_read(address, 4), 'little')
        if (w >> 26) != 0x10:
            return                      # code changed since the scan
        in_ds = False
        if prev is not None:
            in_ds = self._delay_slot_words.get(prev)
            if in_ds is None:
                in_ds = self._delay_slot_words[prev] = self._insn_has_delay_slot(prev.to_bytes(4, 'little'), 4, False)
        # A breakpoint / stop address on this instruction: its hook may be queued
        # behind this one, and Unicorn skips the remaining hooks of an instruction
        # once a stop is requested (an interrupt made deliverable here does that).
        # So stop before the instruction here, like the breakpoint hook would.
        bp_reason = None
        if not self.is_stepping:
            if self.stop_instr is not None and address == self.stop_instr:
                bp_reason = 'stop_instr'
            elif address in self.breakpoints:
                bp_reason = 'breakpoint'
        if bp_reason and not in_ds:
            self.log(f"\n[{'STOP' if bp_reason == 'stop_instr' else 'BREAKPOINT'}] "
                     f"{'Reached stop address' if bp_reason == 'stop_instr' else 'Hit at'}: 0x{address:08X}")
            self._stop_reason = bp_reason
            uc.emu_stop()
            return
        # One clock reading for this instruction (Count, timer checks), taken
        # when first needed (_vtime): the thread clock costs ~0.5 us per read,
        # and MFC0 Status / EPC need none.
        self._in_cp0_hook = True
        try:
            self._emulate_cop0(uc, address, w, in_ds)
        finally:
            self._in_cp0_hook = False
            self._clk_cache = None
        if bp_reason and self._stop_reason == 'irq':
            self._stop_reason = bp_reason   # (delay slot: Unicorn completes the branch first)
        # Slice deadline, synchronously (see async_stop_margin_us): the hook has
        # emulated the instruction, so no CP0 instruction can run natively.
        elif self._slice_deadline is not None and self._stop_reason is None \
                and time.perf_counter() >= self._slice_deadline:
            self._stop_reason = 'deadline'
            self._orig_emu_stop()

    def _mips16_bytes(self, pc):
        """The bytes of the MIPS16 instruction at pc: 2, or 4 for JAL / JALX and EXTENDed ones."""
        insn_bytes = self.mu.mem_read(pc, 2)
        if ((int.from_bytes(insn_bytes, 'little') >> 11) & 0x1F) in (0x1E, 0x03):
            insn_bytes = self.mu.mem_read(pc, 4)
        return bytes(insn_bytes)

    def _decode_for_display(self, pc, m16):
        """(mnemonic, operands, size) of the instruction at pc in the given mode."""
        try:
            if m16:
                insn_bytes = self._mips16_bytes(pc)
                mnemonic, operands = MIPS16Decoder.decode(insn_bytes, pc)
                return mnemonic, operands, len(insn_bytes)
            insn_bytes = self.mu.mem_read(pc, 4)
            disasm = list(self.md.disasm(bytes(insn_bytes), pc))
            if disasm:
                return disasm[0].mnemonic, disasm[0].op_str, 4
            return "???", "", 4
        except Exception:
            return "???", "", 2 if m16 else 4

    def _log_unicorn_error(self, e):
        try:
            pc = self.mu.reg_read(UC_MIPS_REG_PC)
            m16 = self.is_mips16_mode()
            self.log(f"Unicorn Error: {e}")
            self.log(f"PC at error: {hex(pc)} ({'MIPS16' if m16 else 'MIPS32'})")
            self.log(f"Status at error: {hex(self.mu.reg_read(UC_MIPS_REG_CP0_STATUS))}")
            mnemonic, operands, sz = self._decode_for_display(pc, m16)
            raw = bytes(self.mu.mem_read(pc, sz)).hex()
            self.log(f"Instruction at PC: {raw} {mnemonic} {operands}")
            self.log(f"Instructions executed: {self.instruction_count}, last hooked: "
                     f"0x{self._last_hook_addr:08X} (size {self._last_hook_size})")
            if (pc & ~1) == 0 and self.force_erl and not self.mu.reg_read(UC_MIPS_REG_CP0_STATUS) & 0x4:
                self.log("Note: the forced Status.ERL is gone, so an ERET most likely ran natively (to "
                         "ErrorEPC = 0): Unicorn skips code hooks while an asynchronous stop is "
                         "pending (see async_stop_margin_us in simulator.py)")
        except Exception:
            pass

    def apply_manual_fixes(self):
        """No-op: kept for API compatibility with test scripts"""
        pass

    def invalidate_jit(self, address):
        """No-op: kept for API compatibility with test scripts"""
        pass

    def is_mips16_addr(self, address):
        """Heuristic to check if address is in known MIPS16 region"""
        # Main firmware body seems to be below 0x81E8E000
        # Loader/Trigger at 0x81E8E1B8 is MIPS32
        if (address & 0xFFE00000) == 0x81E00000:
             if address < 0x81E8E000:
                 return True
        return False

    def _take_interrupt_at_boundary(self, cur_pc):
        """Between slices: take a due UART interrupt, or a deliverable timer /
        software interrupt.  Returns the PC to continue at."""
        uart = self._irq_due()
        if not uart:
            self._timer_update()
            if not self._irq_deliverable() or self._irq_gap_left() > 0:
                return cur_pc               # (gap: the next slice is planned to end with it)
        if not self._at_safe_point():
            return cur_pc                   # between a branch and its delay slot: next boundary
        epc = cur_pc | (1 if self.is_mips16_mode() else 0)
        if uart:
            if self._code_hook_h is None:
                self._rescan_cp0_sites()    # fast mode: the ISR code must be hooked before it runs
                if self._tb_flush_needed:
                    self._flush_tb()
            vector = self._enter_uart_irq(self.mu, epc)
        else:
            # No full rescan for timer ticks (100-250 ms each): the vector chunk
            # is scanned when it first executes and the periodic rescan covers
            # code written later -- except the vector's own page, scanned here:
            # an application that writes its handler over the bootloader's takes
            # its first tick before the periodic rescan sees the new code, and an
            # EBase read that runs natively reports Unicorn's CPU number 0x3FF
            # (the URZ0086's handler then takes its second-CPU path).  The page
            # is scanned again only when its bytes changed.
            vector = self._enter_interrupt(self.mu, epc)
            page = vector & 0x1FFFF000
            if self._code_hook_h is None and page < min(self.ram_size, self._RAM_CODE_LIMIT):
                seen = self._vector_page
                if seen is None or seen[0] != page or self._ram_view[page:page + 0x1000] != seen[1]:
                    self._rescan_cp0_sites([(0x80000000 | page, 0x1000)])
                    self._vector_page = (page, bytes(self._ram_view[page:page + 0x1000]))
                    if self._tb_flush_needed:
                        self._flush_tb()
        self.mu.reg_write(UC_MIPS_REG_PC, vector)
        return vector

    def _arm_deadline(self, seconds):
        """End the running timed slice `seconds` from now: synchronously at the
        first hooked CP0 instruction after that (_hook_cp0_site), or by the
        asynchronous stopper async_stop_margin_us later."""
        self._slice_deadline = time.perf_counter() + seconds
        if self._slice_uses_stopper:
            exl = bool(self.cp0_status & 0x2)
            self._slice_armed_exl = exl
            margin = self.async_stop_margin_exl_us if exl else self.async_stop_margin_us
            self._stopper.arm(seconds + margin / 1e6)

    def _run_slice(self, cur_pc, end_addr, slice_us, count=0):
        """Fast mode: one native slice.  A timed slice (slice_us) ends after
        slice_us microseconds or at the next timer interrupt, whichever comes
        first, and CP0 hooks can move that deadline (_reschedule_slice).  A
        counted slice (slice_us=None) runs `count` instructions.  Returns the
        emulation time the slice took."""
        stopper = None
        if slice_us is not None:
            cap_us = max(self.min_slice_us, slice_us)
            wait = self._timer_wait_us()
            if self._ic_ip3() and self._irq_deliverable():
                # a device interrupt held back by irq_min_gap_us
                gap = self._irq_gap_left() * 1e6
                wait = gap if wait is None else min(wait, gap)
            if wait is not None:
                slice_us = min(slice_us, wait)
            slice_us = max(self.min_slice_us, slice_us)
            stopper = self._get_stopper()
        v0 = self._vtime()
        if slice_us is not None:
            self._slice_cap_end = v0 + cap_us / 1e6
            self._slice_planned_end = v0 + slice_us / 1e6
        else:
            # counted slice: hooks may still end it for a deliverable interrupt
            self._slice_cap_end = float('inf')
            self._slice_planned_end = None
        self._slice_uses_stopper = stopper is not None
        self._slice_armed_end = self._slice_planned_end
        self._slice_deadline = None
        self._stop_reason = None
        try:
            if stopper is not None:
                self._arm_deadline(slice_us / 1e6)
                try:
                    self.mu.emu_start(self._start_pc(cur_pc), end_addr, count=count)
                finally:
                    stopper.disarm()
            elif slice_us is not None:
                self._arm_deadline(slice_us / 1e6)          # (Unicorn's timeout is the backstop)
                self.mu.emu_start(self._start_pc(cur_pc), end_addr,
                                  timeout=max(1, int(slice_us + self.async_stop_margin_us)), count=count)
            else:
                self.mu.emu_start(self._start_pc(cur_pc), end_addr, count=count)
        except UcError:
            # A CP0 instruction ran natively (its hook skipped under an asynchronous
            # stop): with the forced ERL a native ERET jumps to ErrorEPC = 0 and
            # clears ERL, and the fetch at kuseg 0 then faults inside this slice.
            # Hand it to run()'s boundary repair, which redoes the ERET.
            if self.force_erl and (self.mu.reg_read(UC_MIPS_REG_PC) & ~1) == 0 \
                    and not self.mu.reg_read(UC_MIPS_REG_CP0_STATUS) & 0x4:
                self._stop_reason = None
            else:
                raise
        except OSError as e:
            # Unicorn 2.1.4 dies with an access violation while translating an
            # unhooked straight-line block of ~375+ instructions (also a jump
            # into zero-filled RAM); the Uc instance is unusable afterwards.
            raise RuntimeError(
                f"Unicorn crashed in fast mode near PC=0x{cur_pc:08X} ({e}): it cannot translate "
                f"straight-line blocks of ~375+ instructions without code hooks; rerun with "
                f"hook_every_instruction=True (exact mode)") from e
        finally:
            self._slice_cap_end = None
            self._slice_deadline = None
        return self._vtime() - v0

    # A core whose program waits for an interrupt in a branch-to-self (the RTOS's
    # idle task; the SEE's) spins away as much host time as it emulates: with
    # idle_skip (the default) run() moves its emulation time -- its Count and
    # its estimated instruction count with it -- on to its next timer interrupt
    # instead (_idle_until).  A loop found that way also ends the slices that
    # reach it (_hook_idle_loop): most turns start in the tick handler, which
    # returns into the loop.  dump_maciej's first 150 M instructions are a
    # third idle.
    idle_skip = True
    _IDLE_LOOP = bytes.fromhex("ffff0010" "00000000")      # b . / nop

    def _budget(self):
        """Fast mode: the instructions run() may still count -- up to
        max_instructions, and to a UART interrupt armed so many instructions
        ahead (setUartReceiveData) -- or None (no limit)."""
        budget = None
        if self.max_instructions:
            budget = self.max_instructions - self.instruction_count
        if self._pending_uart_irq and not self._uart_irq_delivered and \
                self._uart_irq_arm_after > self.instruction_count:
            arm = self._uart_irq_arm_after - self.instruction_count
            budget = arm if budget is None else min(budget, arm)
        return budget

    def _idle_until(self, max_vtime):
        """The emulation time an idle loop can skip to -- when interrupts are
        enabled (IE, not EXL / ERL): the next timer interrupt (one Count tick
        past Compare, where the timer latches), max_vtime, the end of the
        instruction budget (_budget) or batch_timeout_us on (the slice services
        see the time pass in steps), whichever comes first; with an interrupt
        deliverable, the end of irq_min_gap_us after the last ERET (the loop
        has nothing to run meanwhile) --, or None (nothing to skip to)."""
        if (self.cp0_status & 0x7) != 0x1 or self._irq_due():
            return None
        now = self._vtime()
        if self._irq_deliverable():
            hold = self._irq_gap_left(now)
            if hold <= 0:
                return None
            until = now + hold
        else:
            until = now + self.batch_timeout_us / 1e6
            wait = self._timer_wait_us()
            if wait is not None:
                until = min(until, now + wait / 1e6 + 1.0 / self.count_hz)
        if max_vtime is not None:
            until = min(until, max_vtime)
        budget = self._budget()
        if budget is not None:
            until = min(until, now + budget / self._insn_rate)
        return until if until > now else None

    def _skip_idle(self, pc, max_vtime):
        """Fast mode, between slices: in an idle loop that only an interrupt
        ends -- `b .` with a nop in its delay slot (_idle_until) --, the
        emulation time skips on, and the instruction count with it, at the
        estimated rate (instruction counts stay a measure of emulation time,
        as the loop's spinning would have made them; no CP0 rescan for those).
        Returns whether it moved."""
        until = self._idle_until(max_vtime)
        if until is None:
            return False
        try:
            if bytes(self.mu.mem_read(pc, 8)) != self._IDLE_LOOP:
                return False
        except UcError:
            return False
        if pc not in self._idle_loops:
            self._idle_loops[pc] = self.mu.hook_add(UC_HOOK_CODE, self._hook_idle_loop, begin=pc, end=pc)
            self._tb_flush_needed = True
        skipped = until - self._vtime()
        self.idle_skipped += skipped
        self._advance_time(skipped)
        return True

    def _advance_time(self, seconds):
        """Between slices: move the emulation time on, and the estimated
        instruction count with it (at most to the budget); no CP0 rescan is
        due for that time, no code ran."""
        self._vt_accum += seconds
        counted = round(seconds * self._insn_rate)
        budget = self._budget()
        if budget is not None:
            counted = min(counted, budget)
        self.instruction_count += counted
        self._last_rescan_icount += counted

    def _skip_busy(self, max_vtime):
        """Fast mode, between slices: the emulation time the CPU still owes for
        work done in Python (busy_pending: the LZMA decoder), moved on in steps
        of at most batch_timeout_us (the slice services -- a SEE core -- see it
        pass), within run()'s limits.  Interrupts wait until it is paid, as
        if they had been masked meanwhile: the time charged is what the whole
        emulated call took, its interrupts included (lzma_insns_per_byte).
        Returns whether it moved."""
        now = self._vtime()
        step = min(self.busy_pending, self.batch_timeout_us / 1e6)
        if max_vtime is not None:
            step = min(step, max_vtime - now)
        budget = self._budget()
        if budget is not None:
            step = min(step, budget / self._insn_rate)
        if step <= 0:
            return False
        self.busy_pending -= step
        self._advance_time(step)
        return True

    def _hook_idle_loop(self, uc, address, size, user_data):
        """A slice reached an idle loop (_skip_idle): with interrupts enabled
        only an interrupt leaves it, so end the slice there -- run() takes the
        interrupt, or moves the time on to it -- instead of spinning to the
        slice's end.  (Also when one is deliverable already: Cause.TI latches
        at CP0 hooks and slice boundaries, so a tick that came due in the
        slice's last task waited for the asynchronous backstop.)"""
        if self.idle_skip and self._code_hook_h is None and self._stop_reason is None \
                and (self.cp0_status & 0x7) == 0x1:
            self._stop_reason = 'idle'
            self._orig_emu_stop()

    # The ALi SDK bootloaders unpack the main code (and the SEE's) with the
    # LZMA SDK 4.0x LzmaDecode() of their boot library, compiled without
    # optimisation -- a function call per decoded bit: emulated, ~5 us per
    # output byte (the T750i's 3.4 MB SEE code took 23 s, its 8.6 MB main code
    # 48 s; Python's lzma module needs 0.1 s for each).  All but three of the
    # images carry that routine byte for byte (its first 43 instructions, up to
    # its first absolute jump: _LZMA_DECODE_SIG).  Found in the flash image and
    # by each RAM chunk's first-execution scan, its entry gets a code hook
    # (_hook_lzma) that decodes the stream with the lzma module, writes the
    # output and *outSizeProcessed, returns 0 (LZMA_RESULT_OK) to the caller and
    # charges the time the emulated decoder would have taken, as instructions
    # (lzma_insns_per_byte of the estimated count: 3.8-4.6 per output byte on
    # the T750i and dump_maciej; run() moves the emulation time on as
    # busy_pending), so instruction counts -- every test's timeline -- stay
    # what they were (0: no time, tv_gui).
    # Anything unexpected -- the arguments, a stream the module rejects or that
    # ends early, output outside the RAM, exact mode -- leaves the call to the
    # emulated decoder.  LzmaDecode(buffer, bufferSize, lc, lp, pb, inStream,
    # inSize, outStream, outSize, &outSizeProcessed): a0..a3, then the stack.
    lzma_hle = True
    lzma_insns_per_byte = 4.0
    _LZMA_DECODE_SIG = bytes.fromhex(
        "78ffbd278400bfaf8000beaf21f0a0038800c4af8c00c5af9000c6af9400c7af"
        "9000c38f9400c28f211862000003022404106200360742241000c2af8800c28f"
        "1400c2af3400c0af3800c0af3c00c0a3010002244000c2af4400c2af4800c2af"
        "4c00c2af5000c0af010003249800c28f04104300ffff42245400c2af9400c28f"
        "04104300ffff42245800c2af5c00c0af1000c28f401802008c00c28f2b104300"
        "040040100000000002000224")

    def _find_lzma_decoders(self, data, base, views):
        """Hook LzmaDecode() wherever data -- code at physical offset `base` --
        holds it, at that offset in each view (segment base)."""
        if not self.lzma_hle:
            return
        data = data if isinstance(data, (bytes, bytearray)) else bytes(data)
        i = data.find(self._LZMA_DECODE_SIG)
        while i >= 0:
            if i % 4 == 0:
                for view in views:
                    a = view + base + i
                    if a not in self._lzma_hooks:
                        self._lzma_hooks[a] = self.mu.hook_add(UC_HOOK_CODE, self._hook_lzma, begin=a, end=a)
                        self._tb_flush_needed = True
            i = data.find(self._LZMA_DECODE_SIG, i + 1)

    def _guest_bytes(self, address, size):
        """Up to `size` bytes of guest memory from `address`, as many as are
        mapped there (RAM straight from its buffer)."""
        phys = address & 0x1FFFFFFF
        if (address >> 29) in (0, 4, 5) and phys < self.ram_size:
            return bytes(self._ram_view[phys:min(phys + size, self.ram_size)])
        out = bytearray()
        while len(out) < size:
            try:
                out += self.mu.mem_read(address + len(out), min(0x10000, size - len(out)))
            except UcError:
                break
        return bytes(out)

    def _hook_lzma(self, uc, address, size, user_data):
        """LzmaDecode()'s entry: decode the stream with the lzma module and
        return to the caller, or leave the call to the emulated decoder."""
        if size != 4 or not self.lzma_hle or self._code_hook_h is not None or self.is_stepping:
            return
        near = range(address - 0x1000, address + 0x1000)    # (the decoder's functions: a breakpoint
        if self.stop_instr in near or any(b in near for b in self.breakpoints):     # there is honoured)
            return
        import lzma
        import struct
        try:
            if self._guest_bytes(address, len(self._LZMA_DECODE_SIG)) != self._LZMA_DECODE_SIG:
                return                              # (code changed since the scan)
            buf_size, lc, lp = (self._reg_read(self.gpr_map[n]) for n in (5, 6, 7))
            sp, ra = self._reg_read(UC_MIPS_REG_SP), self._reg_read(UC_MIPS_REG_RA)
            pb, in_addr, in_size, out_addr, out_size, done_ptr = struct.unpack("<6I", uc.mem_read(sp + 16, 24))
            uc.mem_read(done_ptr, 4)                # (mapped)
            out_phys = out_addr & 0x1FFFFFFF
            if lc > 8 or lp > 4 or pb > 4 or buf_size < (0x736 + (0x300 << (lc + lp))) * 2 \
                    or (out_addr >> 29) not in (0, 4, 5) or out_phys + out_size > self.ram_size:
                return
            dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{
                "id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": max(1 << 12, out_size)}])
            out = dec.decompress(self._guest_bytes(in_addr, min(in_size, 1 << 26)), max_length=out_size)
        except (lzma.LZMAError, UcError, ValueError, struct.error):
            return
        if len(out) < out_size and not dec.eof:
            return                                  # (the input ran out: the decoder's error)
        if self._stop_reason is None:
            self._stop_reason = 'lzma'
        self._orig_emu_stop()                       # (what follows is host time)
        # The output is written behind Unicorn's back (its buffer): the next
        # slice starts with its translations dropped (_sync_hooks).  It is code:
        # scanned for CP0 sites now (the emulated decoder took long enough for
        # the periodic rescans to see it appear).
        self._ram_view[out_phys:out_phys + len(out)] = out
        uc.mem_write(done_ptr, struct.pack("<I", len(out)))
        self._reg_write(self.gpr_map[2], 0)
        self._reg_write(UC_MIPS_REG_PC, ra)
        self._tb_flush_needed = True
        self._rescan_cp0_sites([(0x80000000 | out_phys, len(out))])
        self.busy_pending += len(out) * self.lzma_insns_per_byte / self._insn_rate
        self.lzma_decodes.append((address, in_addr, out_addr, len(out)))
        self.log(f"[LZMA] LzmaDecode at 0x{address:08X} (from 0x{ra:08X}): 0x{in_addr:08X} -> 0x{out_addr:08X}, "
                 f"{len(out)} bytes decoded in Python (lc {lc}, lp {lp}, pb {pb})")

    def run(self, max_instructions=None, max_vtime=None):
        """Run until max_instructions (an instruction count; estimated in fast
        mode) or, with max_vtime, until the emulation time (_vtime) reaches
        that -- a second core's turn between the first core's slices is a
        stretch of emulation time (chips/see.py SeeCore), which the estimated
        counts would not bound reliably."""
        if max_instructions is not None:
            self.max_instructions = max_instructions

        cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        note = "" if self._want_full_hook() else " [fast mode: instruction counts are estimates, no per-instruction history]"
        self.log(f"Starting emulation at {hex(cur_pc)} ({'MIPS16' if self.is_mips16_mode() else 'MIPS32'})...{note}")
        end_addr = self.base_addr + self.rom_size

        self._in_run = True
        self._run_tid = threading.get_ident()
        self._external_stop = False
        self._run_max_vtime = max_vtime
        try:
            while True:
                if self._external_stop:
                    break   # emu_stop() from another thread between slices
                if self.max_instructions and self.instruction_count >= self.max_instructions:
                    break
                if max_vtime is not None and self._vtime() >= max_vtime:
                    break

                # Sitting on a breakpoint / stop address: step over it first,
                # otherwise emu_start would stop on it immediately.
                if cur_pc in self.breakpoints or (self.stop_instr is not None and cur_pc == self.stop_instr):
                    self.step()
                    cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
                    if self.max_instructions and self.instruction_count >= self.max_instructions:
                        break
                    if (cur_pc & ~1) == 0:
                        break

                self._sync_hooks()
                full = self._code_hook_h is not None

                # Remote-control frames queued by ir_send_nec() / press_key()
                if self._irc_frames:
                    self._irc_service()
                for service in self.slice_services:      # e.g. the demultiplexer's transport stream
                    service()

                # Interrupts that could not be injected inside the previous slice
                # (fast mode: all of them; exact mode: MIPS16 branch self-loops).
                if self.busy_pending > 1e-9 and not full and self._skip_busy(max_vtime):
                    continue
                cur_pc = self._take_interrupt_at_boundary(cur_pc)
                if self.idle_skip and not full and self._skip_idle(cur_pc, max_vtime):
                    continue

                if full:
                    # Exact mode: _hook_code counts instructions, delivers IRQs,
                    # emulates CP0 and stops on breakpoints / max_instructions.
                    self._stop_reason = None
                    self.mu.emu_start(self._start_pc(cur_pc), end_addr)
                    executed = None
                    if self._stop_reason == 'flashhooks':
                        # the SF_INS store was counted and runs again on resume
                        self.instruction_count -= 1
                else:
                    # Fast mode: native batches, interrupts are taken at their boundaries.
                    # Exact (counted) slice when close to a limit, otherwise a
                    # wall-clock slice whose instruction count is estimated.
                    budget = self._budget()
                    small_budget = budget is not None and budget <= self.exact_count_threshold
                    calibrating = self._counted_slices < self.calibration_slices
                    if self._timeout_slices == 0 and (small_budget or calibrating):
                        batch = self.batch_size if budget is None else min(self.batch_size, budget)
                        batch = max(1, batch)
                        dt = self._run_slice(cur_pc, end_addr, None, count=batch)
                        if self._stop_reason is None:
                            executed = batch
                            if dt > 0 and batch >= 10_000:
                                self._insn_rate = batch / dt
                        elif self._stop_reason == 'rescan':
                            executed = 0    # stopped before the first instruction of a new RAM chunk
                        elif self._stop_reason == 'flashhooks':
                            # stopped right after an SF_INS store, typically a few
                            # instructions in: the (uncalibrated) rate estimate would
                            # overcount a lot; count 1 so a run() budget still ends
                            executed = 1
                        else:
                            # a hook stopped the slice early; Unicorn does not say how
                            # many instructions ran, so use the rate estimate
                            executed = min(batch, int(self._insn_rate * dt))
                        self._counted_slices += 1
                    else:
                        slice_us = self.batch_timeout_us
                        if budget is not None:
                            # aim the slice length at the remaining budget
                            slice_us = min(slice_us, budget / self._insn_rate * 1e6)
                        if max_vtime is not None:
                            slice_us = min(slice_us, max(0.0, max_vtime - self._vtime()) * 1e6)
                        dt = self._run_slice(cur_pc, end_addr, slice_us)
                        executed = 0 if self._stop_reason == 'rescan' else int(self._insn_rate * dt)
                        if budget is not None:
                            executed = min(executed, budget)
                        self._timeout_slices += 1

                if executed is not None:
                    self.instruction_count += executed
                if self._rom_dirty:
                    self._rom_restore()
                if not full and self.force_erl:
                    native = self.mu.reg_read(UC_MIPS_REG_CP0_STATUS)
                    if not native & 0x4:
                        # The forced ERL is gone: a CP0 instruction ran natively,
                        # its hook skipped by Unicorn under an asynchronous stop
                        # (stopper or user / GUI emu_stop; see async_stop_margin_us).
                        # Only a native ERET or MTC0 Status is visible this way.
                        self.native_cp0_repairs += 1
                        pc_now = self.mu.reg_read(UC_MIPS_REG_PC)
                        if (pc_now & ~1) == 0:
                            # An ERET went to ErrorEPC (0) (possibly after a native
                            # 'mtc0 Status' that set EXL): redo it to the shadow EPC.
                            self.cp0_status = (native & ~0x4) | 0x2
                            target = self._eret(self.mu)
                            self.mu.reg_write(UC_MIPS_REG_PC, target)
                            if self._stop_reason == 'null':
                                self._stop_reason = None
                            what = f"ERET (redone to 0x{target:08X})"
                        else:
                            # An MTC0 Status: the guest's value is in the native register.
                            self.cp0_status = native & 0xFFFFFFFF
                            what = f"MTC0 Status 0x{native:08X} (adopted)"
                        if self.native_cp0_repairs <= 8:
                            self.log(f"[WARN] native {what} after an asynchronous stop")
                    self._write_native_status(self.mu, self.cp0_status)
                elif not full:
                    # Native Status: the CPU's own register is the guest's (its
                    # MTC0 Status ran natively, followed by the hook -- or not, its
                    # hook skipped under an asynchronous stop).  An ERET that ran
                    # natively went to the native EPC, 0: redo it to the shadow EPC.
                    native = self._reg_read(UC_MIPS_REG_CP0_STATUS)
                    if (self.mu.reg_read(UC_MIPS_REG_PC) & ~1) == 0 and self.cp0_status & 0x2 \
                            and not native & 0x2:
                        self.native_cp0_repairs += 1
                        self.cp0_status = native | 0x2
                        target = self._eret(self.mu)
                        self.mu.reg_write(UC_MIPS_REG_PC, target)
                        if self._stop_reason == 'null':
                            self._stop_reason = None
                        if self.native_cp0_repairs <= 8:
                            self.log(f"[WARN] native ERET (redone to 0x{target:08X}) after an asynchronous stop")
                    else:
                        self.cp0_status = native
                cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)

                if (cur_pc & ~1) == 0 or self._stop_reason == 'null':
                    self.log("[!] Stopped: Jump to NULL")
                    break
                if cur_pc in self.breakpoints or (self.stop_instr is not None and cur_pc == self.stop_instr):
                    break
                if self._stop_reason in ('breakpoint', 'stop_instr'):
                    # The breakpoint sat in a branch delay slot or on a compact jump:
                    # Unicorn completes the branch first, so PC is now at its target.
                    self.log(f"    (stopped after the branch, PC=0x{cur_pc:08X})")
                    break
                if self._stop_reason == 'external' or self._external_stop:
                    break   # emu_stop() from user code / the GUI
                if full and self._stop_reason is None:
                    break   # end address reached
                # 'max_instructions' -> loop re-checks the limit; 'rescan' / batch
                # exhausted -> continue with the next batch.

        except UcError as e:
            self._log_unicorn_error(e)
            raise  # Re-raise so GUI can break
        except Exception as e:
            import traceback
            self.log(f"Error: {e}")
            self.log(traceback.format_exc())
            raise  # Re-raise so GUI can break
        finally:
            self._in_run = False
            self._run_max_vtime = None

    def _exec_one(self, pc):
        """Execute exactly one instruction at pc in the current ISA mode.

        Single steps always use the exact per-instruction hook (it counts the
        instruction, emulates CP0 and stops before the next one); fast-mode
        hooks are re-installed by the next run()."""
        end_addr = self.base_addr + self.rom_size
        self._step_full_hook = True
        try:
            self._sync_hooks()
            self._step_count = 0
            self._stop_reason = None
            self.is_stepping = True
            try:
                # No instruction count here: _hook_code stops before the second
                # instruction, and Unicorn's count hook after wall-clock slices
                # has been seen to stall for a long time.
                self.mu.emu_start(self._start_pc(pc), end_addr)
            finally:
                self.is_stepping = False
                if self._rom_dirty:
                    self._rom_restore()
        finally:
            self._step_full_hook = False

    def runStep(self):
        cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        try:
            self._exec_one(cur_pc)
            new_pc = self.mu.reg_read(UC_MIPS_REG_PC)
            if (new_pc & ~1) == 0:
                self.log("[!] Stopped: Jump to NULL")
        except UcError as e:
            self._log_unicorn_error(e)
            raise  # Re-raise so GUI can break
        except Exception as e:
            self.log(f"Error: {e}")
            raise  # Re-raise so GUI can break

    # NEW: Unified Stepping APIs

    def step(self) -> StepResult:
        """
        Execute one instruction in the current ISA mode

        Returns:
            StepResult with execution details
        """
        pc = self.mu.reg_read(UC_MIPS_REG_PC)
        m16_before = self.is_mips16_mode()
        mode_before = 'mips16' if m16_before else 'mips32'
        mnemonic, operands, insn_size = self._decode_for_display(pc, m16_before)

        if self.debug_enabled:
            self.log(f"[DEBUG] step() at PC=0x{pc:08X}, mode={mode_before}")
            if mnemonic == 'jalx':
                self.log(f"[DEBUG] Executing JALX at 0x{pc:08X} -> target {operands}")

        try:
            self._exec_one(pc)
        except UcError as e:
            self.log(f"[step] Unicorn error at 0x{pc:08X}: {e}")  # continue even on error

        next_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        m16_after = self.is_mips16_mode()
        mode_after = 'mips16' if m16_after else 'mips32'
        mode_switched = (m16_after != m16_before)

        # Detect and stop on jump to NULL (0x0)
        if (next_pc & ~1) == 0:
            self.log(f"\n[!] STOPPED: Program is about to jump to 0x0 from 0x{pc:08X}")
            self.log(f"    Instruction: {mnemonic} {operands}")
            raise Exception(f"Jump to NULL (0x0) detected at 0x{pc:08X}: {mnemonic} {operands}")

        if mode_switched:
            if m16_after and not self.debug_enabled:
                self.debug_enabled = True
                self.log("[DEBUG] MIPS16 mode entered - enabling debug logging")
            if self.debug_enabled:
                self.log(f"[DEBUG] Mode switched: {mode_before} -> {mode_after}")

        # Determine instruction type
        is_call = mnemonic in ['jal', 'jalr', 'jalx', 'jalrc', 'bal']
        is_return = mnemonic in ['jr', 'jrc'] and 'ra' in operands
        is_branch = mnemonic.startswith('b') or mnemonic.startswith('j')

        result = StepResult(
            address=pc,
            instruction=mnemonic,
            operands=operands,
            next_pc=next_pc,
            mode_before=mode_before,
            mode_after=mode_after,
            is_branch=is_branch,
            is_call=is_call,
            is_return=is_return,
            mode_switched=mode_switched,
            instruction_size=insn_size
        )

        # Track call stack for step_out
        if result.is_call:
            self.call_stack.append(result.address)
        elif result.is_return and self.call_stack:
            self.call_stack.pop()

        return result

    def step_into(self) -> StepResult:
        """
        Step into function calls (same as step())
        
        Returns:
            StepResult with execution details
        """
        return self.step()
    
    def step_over(self) -> StepResult:
        """
        Step over function calls (execute entire function if next instruction is a call)
        
        Returns:
            StepResult with execution details
        """
        # Execute one step
        result = self.step()
        
        # If it's a call, keep executing until we return
        if result.is_call:
            return_address = result.next_pc
            max_steps = 100000  # Safety limit
            steps = 0
            
            while steps < max_steps:
                current_pc = self.mu.reg_read(UC_MIPS_REG_PC)
                if current_pc == return_address:
                    # We've returned from the call
                    break
                
                step_result = self.step()
                steps += 1
                
                # If we hit a breakpoint or stop condition, return immediately
                if self.stop_instr and current_pc == self.stop_instr:
                    break
        
        return result
    
    def step_out(self) -> StepResult:
        """
        Step out of current function (execute until return)
        
        Returns:
            StepResult with execution details
        """
        initial_stack_depth = len(self.call_stack)
        max_steps = 100000  # Safety limit
        steps = 0
        last_result = None
        
        while steps < max_steps:
            last_result = self.step()
            steps += 1
            
            # Check if we've returned from the function
            if len(self.call_stack) < initial_stack_depth:
                break
            
            # If we hit a stop condition, break
            current_pc = self.mu.reg_read(UC_MIPS_REG_PC)
            if self.stop_instr and current_pc == self.stop_instr:
                break
        
        return last_result if last_result else StepResult(
            address=self.mu.reg_read(UC_MIPS_REG_PC),
            instruction="???",
            operands="",
            next_pc=self.mu.reg_read(UC_MIPS_REG_PC),
            mode_before=self.isa_mode.value,
            mode_after=self.isa_mode.value
        )
    
    def skipInstruction(self):
        """Skip the current instruction (advance PC by its size in the current ISA mode)"""
        try:
            cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
            m16 = self.is_mips16_mode()
            _, _, incr = self._decode_for_display(cur_pc, m16)
            self.mu.reg_write(UC_MIPS_REG_PC, (cur_pc + incr) | (1 if m16 else 0))
            self.log(f"Skipped instruction at 0x{cur_pc:08X} (size {incr})")
        except Exception as e:
            self.log(f"Error skipping instruction: {e}")

    def _instr_row(self, addr, code, mnemonic, operands, pc, breakpoints):
        """One entry of get_instructions_around_pc()."""
        return {'address': addr, 'bytes': ' '.join(f'{b:02x}' for b in code), 'mnemonic': mnemonic,
                'operands': operands, 'loop_count': self.visit_counts.get(addr, 0),
                'is_current': addr == pc, 'is_breakpoint': addr in breakpoints}

    def _mips16_row(self, addr, pc, breakpoints):
        """(entry, size) of the MIPS16 instruction at addr for get_instructions_around_pc()."""
        code = self._mips16_bytes(addr)
        mnemonic, operands = MIPS16Decoder.decode(code, addr)
        return self._instr_row(addr, code, mnemonic, operands, pc, breakpoints), len(code)

    def get_instructions_around_pc(self, pc, before=10, after=10, forced_mips16_addresses=None, breakpoints=None):
        if not self.mu: return []
        instructions = []
        forced_mips16_addresses = forced_mips16_addresses or set()
        breakpoints = breakpoints or {}
        
        # Backward scan (Tricky with variable length)
        # Strategy: Go back 'before * 4' bytes (approx), then disassemble forward.
        # If we desync at PC, adjust start point.
        
        start_attempts = [pc - (before * 4), pc - (before * 4) + 2]
        best_instrs = []
        
        for start_addr in start_attempts:
            if start_addr < 0: continue
            
            # Check if PC is a JALX target before scanning
            pc_is_jalx_target = False
            prev_exec = getattr(self, 'prev_executed_pc', None)
            if prev_exec:
                try:
                    prev_bytes = self.mu.mem_read(prev_exec, 4)
                    prev_disasm = list(self.md.disasm(prev_bytes, prev_exec))
                    if prev_disasm and prev_disasm[0].mnemonic == 'jalx':
                        pc_is_jalx_target = True
                        print(f"[DEBUG] PC 0x{pc:08X} is JALX target from 0x{prev_exec:08X}")
                except: pass
            
            temp_instrs = []
            curr = start_addr
            valid_sequence = False
            
            # Track if we're in a MIPS16 region (entered via JALX)
            in_mips16_region = False
            
            # Limit scan to reasonable amount to avoid infinite loops if something is wrong
            while curr <= pc + (after * 4): 
                # Decode one
                try:
                    # Check known size or Forced MIPS16
                    is_mips16 = False
                    
                    # 1. Execution History (exact ISA when the instruction was executed
                    #    with the per-instruction hook; otherwise its size)
                    known_size = self.instruction_sizes.get(curr)
                    known_isa = self.instruction_isa.get(curr)
                    if known_isa is not None:
                        is_mips16 = known_isa
                        if is_mips16:
                            in_mips16_region = True
                        known_size = 4 if not is_mips16 else known_size
                    elif known_size == 2:
                        is_mips16 = True
                        # print(f"[DEBUG] 0x{curr:08X} is MIPS16 from execution history")
                    
                    # 2. Forced Address (Manual Toggle)
                    if curr in forced_mips16_addresses:
                        is_mips16 = True
                    # 2b. The instruction at PC: exact current CPU mode
                    if curr == pc and known_isa is None and self._hflags_off is not None:
                        is_mips16 = self.is_mips16_mode()
                        if is_mips16:
                            in_mips16_region = True
                        # print(f"[DEBUG] 0x{curr:08X} is MIPS16 from forced addresses")
                    
                    # 3. JALX target detection
                    if not is_mips16 and curr == pc and pc_is_jalx_target:
                        is_mips16 = True
                        in_mips16_region = True  # Enter MIPS16 region
                        print(f"[DEBUG] 0x{curr:08X} is MIPS16 as JALX target - entering MIPS16 region")
                    
                    # 4. If we're in a MIPS16 region (and no execution history says otherwise), assume MIPS16
                    if not is_mips16 and in_mips16_region and known_size != 4:
                        is_mips16 = True
                        # print(f"[DEBUG] 0x{curr:08X} is MIPS16 from region continuation")

                    # 5. Check Simulator Heuristic (New)
                    if not is_mips16 and self.is_mips16_addr(curr):
                        is_mips16 = True
                        in_mips16_region = True

                    if is_mips16:
                        row, instr_size = self._mips16_row(curr, pc, breakpoints)
                        temp_instrs.append(row)
                        curr += instr_size
                        if curr == pc: valid_sequence = True
                        if curr > pc and not valid_sequence: break
                        if valid_sequence:
                             # check after count
                             count_after = sum(1 for i in temp_instrs if i['address'] > pc)
                             if count_after >= after: break
                        continue

                    # Try to disassemble as MIPS32 first
                    code = self.mu.mem_read(curr, 4)
                    disasm = list(self.md.disasm(code, curr))
                    
                    if not disasm:
                        # Fallback: treat as MIPS16 instruction
                        try:
                            row, instr_size = self._mips16_row(curr, pc, breakpoints)
                            temp_instrs.append(row)
                            curr += instr_size
                        except:
                            curr += 4  # Skip if read fails
                        continue
                        
                    instr = disasm[0]
                    temp_instrs.append(self._instr_row(curr, instr.bytes, instr.mnemonic, instr.op_str,
                                                       pc, breakpoints))
                    
                    if curr == pc:
                        valid_sequence = True
                        
                    curr += instr.size
                    
                    # If we passed PC
                    if curr > pc and not valid_sequence:
                         break # Desync
                         
                    # Stop if we have enough "after" instructions
                    if valid_sequence:
                        # Count how many after PC
                        count_after = 0
                        for i in reversed(temp_instrs):
                            if i['address'] > pc: count_after += 1
                            else: break
                        if count_after >= after: break
                        
                except:
                    curr += 4 # Fallback
            
            if valid_sequence:
                best_instrs = temp_instrs
                break
        
        if not best_instrs:
            # Ultimate fallback: Show raw hex dump around PC (suppress repeated prints)
            if not hasattr(self, '_last_fallback_pc') or self._last_fallback_pc != pc:
                print(f"[DEBUG] No valid disassembly found, using hex dump fallback at PC=0x{pc:08X}")
                self._last_fallback_pc = pc
            curr = max(0, pc - 20)  # Show a bit before PC
            for i in range(25):  # Show ~50 bytes
                try:
                    row, instr_size = self._mips16_row(curr, pc, breakpoints)
                    best_instrs.append(row)
                    curr += instr_size
                except:
                    curr += 2
                 
        # Filter to requested window
        # Find index of PC
        pc_idx = -1
        for i, item in enumerate(best_instrs):
            if item['address'] == pc: 
                pc_idx = i
                break
                
        if pc_idx != -1:
            start_idx = max(0, pc_idx - before)
            end_idx = min(len(best_instrs), pc_idx + after + 1)
            instructions = best_instrs[start_idx:end_idx]
        else:
            instructions = best_instrs[:before+after] # Fallback
            
        return instructions


