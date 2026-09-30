from unicorn import *
from unicorn.mips_const import *
from capstone import *
import sys
import re
import time
try:
    import numpy as _np          # fast CP0-site scans; optional
except ImportError:              # pragma: no cover
    _np = None
from enum import Enum
from dataclasses import dataclass
from typing import Optional
from mips16_decoder import MIPS16Decoder

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


class AliMipsSimulator:
    def __init__(self, rom_size=4*1024*1024, ram_size=128*1024*1024, log_handler=None):
        # The flash is mirrored every rom_size bytes inside the 16MB windows and
        # offsets are taken modulo rom_size, which needs a power of two that
        # divides the 0xAFC00000 base (1, 2 or 4 MB).
        if rom_size <= 0 or (rom_size & (rom_size - 1)) or 0xAFC00000 % rom_size:
            raise ValueError(f"rom_size must be a power of two dividing 0xAFC00000 (1/2/4 MB), got {rom_size:#x}")
        self.rom_size = rom_size
        self.ram_size = ram_size
        self.base_addr = 0xAFC00000
        self.mu = None
        self.md = None
        self.uart_callback = None
        self.spi_callback = None
        self.gpio_callback = None
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
        self.cp0_cause = 0
        self.cp0_epc = 0

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
        self.count_hz = 100_000_000          # CP0 Count rate in fast mode (wall clock based)
        self._count_t0 = time.perf_counter()
        self._step_full_hook = False         # _exec_one(): force the exact hook for one step
        self.rescan_interval = 1_000_000     # periodic RAM rescan for new CP0 sites (instructions)
        self._rom_sites = set()
        self._rom_sites_dirty = True
        self._code_hook_h = None
        self._cp0_site_hooks = {}            # address -> hook handle
        self._bp_hooks = {}                  # address -> hook handle
        self._virgin_hooks = {}              # chunk base -> hook handle
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
        self._spi_jedec_id = [0xEF, 0x40, 0x16]  # Winbond W25Q64 (capacity 0x16 is in device table)
        self._spi_ins = 0x03       # SF_INS: current SPI command (default: normal read)
        self._spi_fmt = 0x0D       # SF_FMT: default = HIT_CODE|HIT_ADDR|HIT_DATA (normal read)
        self._spi_dum = 0x00       # SF_DUM: dummy/data register
        self._spi_cfg = 0x00       # SF_CFG: config register
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

    def _init_unicorn(self):
        # Initialize Unicorn (MIPS32 + Little Endian)
        self.mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        # Set MIPS32R2 CPU model (24Kf) to match ALI hardware
        self.mu.ctl_set_cpu_model(UC_CPU_MIPS32_24KF)
        
        import ctypes
        
        # Shared ROM Buffer (Usually 4MB dumped flash)
        self.rom_buffer = ctypes.create_string_buffer(self.rom_size)
        rom_ptr = ctypes.addressof(self.rom_buffer)
        
        # Map ROM aliases to the same buffer
        # Ali SoCs commonly map flash repeatedly within a 16MB window
        self.log(f"Mapping Shared ROM mirrors in 16MB window for Phys, KSEG0, KSEG1")
        # 0x0F000000 is the ALi flash window (KSEG0 0x8F..., KSEG1 0xAF...).
        # 0x1F000000 (KSEG1 0xBF...) holds the MIPS reset/BEV exception vectors
        # (0xBFC00000 / 0xBFC00380) which the chip also decodes to the flash.
        for offset in range(0, 0x01000000, self.rom_size):
            for phys in (0x0F000000, 0x1F000000):
                for seg in (0x00000000, 0x80000000, 0xA0000000):
                    base = seg + phys + offset
                    try:
                        self.mu.mem_map_ptr(base, self.rom_size, UC_PROT_ALL, rom_ptr)
                    except Exception as e:
                        self.log(f"Warning: Failed to map ROM mirror at {hex(base)}: {e}")
        
        # Shared RAM Buffer (128MB as per device spec)
        self.ram_buffer = ctypes.create_string_buffer(self.ram_size)
        ram_ptr = ctypes.addressof(self.ram_buffer)
        
        # Map RAM aliases to same buffer
        self.log(f"Mapping Shared RAM at 0x80000000, 0xA0000000, 0x00000000")
        self.mu.mem_map_ptr(0x80000000, self.ram_size, UC_PROT_ALL, ram_ptr)
        self.mu.mem_map_ptr(0xA0000000, self.ram_size, UC_PROT_ALL, ram_ptr)
        self.mu.mem_map_ptr(0x00000000, self.ram_size, UC_PROT_ALL, ram_ptr)
        
        # Map MMIO
        MMIO_SIZE = 0x01000000
        mmio_regions = [
            (0x18000000, "Physical"),
            (0x98000000, "KSEG0 cached"),
            (0xB8000000, "KSEG1 uncached"),
        ]
        
        # One shared MMIO buffer: the physical, KSEG0 and KSEG1 views of a
        # register must agree, whichever segment the firmware uses.
        self.mmio_buffer = ctypes.create_string_buffer(MMIO_SIZE)
        mmio_ptr = ctypes.addressof(self.mmio_buffer)
        for base, name in mmio_regions:
            try:
                self.mu.mem_map_ptr(base, MMIO_SIZE, UC_PROT_ALL, mmio_ptr)
                self.log(f"Mapped {name} peripherals at {hex(base)} (shared)")
            except UcError as e:
                self.log(f"Warning: {name} at {hex(base)} - {e}")

        # Set UART LSR
        try:
            self.mu.mem_write(0xb8018305, b'\x20')
            # Mirror LSR to Physical and KSEG0 to avoid polling loops
            self.mu.mem_write(0x18018305, b'\x20')
            self.mu.mem_write(0x98018305, b'\x20')
            self.log("Initialized UART LSR at 0xb8018305 (and mirrors) to 0x20")
        except Exception as e:
            self.log(f"Failed to init UART LSR: {e}")

        # Set Magic Value at 0xb8000002 for testing
        try:
            val_bytes = b'\x11\x38' # 0x3811 Little Endian
            self.mu.mem_write(0xb8000002, val_bytes)
            self.mu.mem_write(0x18000002, val_bytes)
            self.mu.mem_write(0x98000002, val_bytes)
            self.log("Initialized magic value 0x3811 at 0xb8000002 (and mirrors)")
        except Exception as e:
            self.log(f"Failed to init magic value: {e}")

        # Hooks
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self._hook_mem_invalid)
        # Memory Sync Hook (KSEG0 <-> KSEG1)
        # KSEG0: 0x80000000, KSEG1: 0xA0000000
        # We hook both regions to sync writes
        kseg0_end = 0x80000000 + self.ram_size - 1
        kseg1_end = 0xA0000000 + self.ram_size - 1
        phys_end = self.ram_size - 1
        # RAM Sync Hooks REMOVED (Handled by mem_map_ptr)

        # UART Hooks (Aliased) — Write hooks for TX
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_uart_write, begin=0x18018300, end=0x18018305)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_uart_write, begin=0x98018300, end=0x98018305)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_uart_write, begin=0xb8018300, end=0xb8018305)
        # UART Hooks — Read hooks for RX simulation (LSR, URBR, UIIR)
        self.mu.hook_add(UC_HOOK_MEM_READ, self._hook_uart_read, begin=0x18018300, end=0x18018309)
        self.mu.hook_add(UC_HOOK_MEM_READ, self._hook_uart_read, begin=0x98018300, end=0x98018309)
        self.mu.hook_add(UC_HOOK_MEM_READ, self._hook_uart_read, begin=0xb8018300, end=0xb8018309)


        # GPIO DO Register Hooks — only Data-Output registers for I2C/panel decoding
        for mmio_base in [0x18000000, 0x98000000, 0xB8000000]:
            for gpio_off in self._GPIO_DO_OFFSETS:  # 0x054, 0x0D4, 0x0E8, 0x0F4
                addr = mmio_base + gpio_off
                self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_gpio_write, begin=addr, end=addr + 3)

        # GPIO DI→DO loopback: reads from DI registers return DO values
        # This is essential for I2C bit-bang — driver reads back pin state
        for mmio_base in [0x18000000, 0x98000000, 0xB8000000]:
            for di_off in self._GPIO_DI_TO_DO:  # 0x050, 0x0D0, 0x0E4, 0x0F0
                addr = mmio_base + di_off
                self.mu.hook_add(UC_HOOK_MEM_READ, self._hook_gpio_di_read, begin=addr, end=addr + 3)

        # SPI Flash Controller Register Hooks
        # Hook BOTH register bases: 0xB8000098 (default) and 0xB802E098 (M3329E rev>=5)
        # Each base has 4 registers: SF_INS(+0x98), SF_FMT(+0x99), SF_DUM(+0x9A), SF_CFG(+0x9B)
        for base in [0x18000098, 0x98000098, 0xB8000098,
                     0x1802E098, 0x9802E098, 0xB802E098]:
            self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_spi_write, begin=base, end=base + 3)
            self.mu.hook_add(UC_HOOK_MEM_READ, self._hook_spi_read, begin=base, end=base + 3)

        # SPI Flash Memory-Mapped Data Hooks (SYS_FLASH_BASE_ADDR)
        # Read hook covers the full range to log flash read offsets.
        # Passthrough path is cheap (page-change throttled logging).
        # Writes need full range for erase/program operations.
        # Cover every 16MB flash window (physical / KSEG0 / KSEG1 of 0x0F000000
        # and 0x1F000000): the firmware uses both 0xAFC00000 and 0x0FC00000.
        # The read hook is only installed while the SPI controller is in
        # command mode (or SPI dump logging is on): in normal read mode every
        # flash load would otherwise pay for a Python callback.
        self._flash_windows = [0x0F000000, 0x8F000000, 0xAF000000, 0x1F000000, 0x9F000000, 0xBF000000]
        self._flash_read_hooks = []
        for flash_base in self._flash_windows:
            self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_spi_flash_write,
                             begin=flash_base, end=flash_base + 0x00FFFFFF)
        self._update_flash_read_hooks()

        # Jumps to address 0 (NULL function pointers, end of a test program)
        # stop emulation instead of executing RAM as code.
        self.mu.hook_add(UC_HOOK_CODE, self._hook_null_jump, begin=0, end=3)

        # The per-instruction hook (_hook_code) and the fast-mode hooks are
        # installed on demand by _sync_hooks() (see run()).
        # Intercept emu_stop() so run() can tell a stop requested by user code
        # or the GUI from a batch that simply ran its instruction count.
        self._orig_emu_stop = self.mu.emu_stop
        def _emu_stop_wrapper():
            if self._stop_reason is None:
                self._stop_reason = 'external'
            self._orig_emu_stop()
        self.mu.emu_stop = _emu_stop_wrapper
        
        # CP0 Status configuration
        try:
            status = 0x10400000 # CU0=1, BEV=1
            self._write_native_status(self.mu, status)
            self.log(f"Set CP0 Status = 0x{status:08X}")
        except Exception as e:
            self.log(f"Warning: Could not set CP0 Status: {e}")

        self._calibrate_hflags()

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

    def setSPIDump(self, enabled):
        """Enable or disable SPI dump logging."""
        self._spi_dump_enabled = enabled
        if self._rom_dirty:
            self._rom_restore()
        self._update_flash_read_hooks()

    def _update_flash_read_hooks(self):
        """Install the flash-window read hook only when it has work to do."""
        wanted = (not self._spi_is_passthrough()) or self._spi_dump_enabled
        if wanted and not self._flash_read_hooks:
            for flash_base in self._flash_windows:
                self._flash_read_hooks.append(self.mu.hook_add(
                    UC_HOOK_MEM_READ, self._hook_spi_flash_read,
                    begin=flash_base, end=flash_base + 0x00FFFFFF))
        elif not wanted and self._flash_read_hooks:
            for h in self._flash_read_hooks:
                self.mu.hook_del(h)
            self._flash_read_hooks = []

    def _hook_null_jump(self, uc, address, size, user_data):
        if self.is_stepping:
            return
        self._stop_reason = 'null'
        uc.emu_stop()

    def setGpioHandler(self, handler, sda_gpio=None):
        """Set callback for GPIO DO register writes: handler(address, size, value).
        
        If sda_gpio is set (0-127), also simulate I2C ACK by clearing that
        bit in DI reads so the bit-bang driver sees slave pulling SDA low.
        """
        self.gpio_callback = handler
        if sda_gpio is not None:
            # Map gpio number to DI offset and bit mask
            if sda_gpio < 32:
                self._i2c_sda_di_offset = 0x050
            elif sda_gpio < 64:
                self._i2c_sda_di_offset = 0x0D0
                sda_gpio -= 32
            elif sda_gpio < 96:
                self._i2c_sda_di_offset = 0x0E4
                sda_gpio -= 64
            else:
                self._i2c_sda_di_offset = 0x0F0
                sda_gpio -= 96
            self._i2c_sda_mask = 1 << sda_gpio

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
        self.log(f"Loading {filename}...")
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
        self.mu.mem_write(self.base_addr, bytes(self.rom_image))
        # SPI flash controller back to its power-on state (normal read mode)
        self._spi_ins, self._spi_fmt, self._spi_dum, self._spi_cfg = 0x03, 0x0D, 0x00, 0x00
        self._spi_status, self._spi_wel = 0x00, False
        self._spi_response, self._spi_resp_idx, self._last_flash_read_page = [], 0, -1
        self._update_flash_read_hooks()

        # Set PC to start address
        self.mu.reg_write(UC_MIPS_REG_PC, self.base_addr)

        # Re-initialize globals if re-running
        self.instruction_count = 0
        self._count_icount = 0
        self._count_t0 = time.perf_counter()
        self.visit_counts = {}
        self.last_lui_addr = None
        self._rescan_due = True     # fast mode: (re)scan ROM + RAM for CP0 sites before running
        self._rom_sites_dirty = True
        # Install the hooks now as well: some test scripts drive sim.mu.emu_start()
        # directly instead of run(), and still need CP0 emulation.
        self._sync_hooks()

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
            self.mu.mem_write(self.base_addr + max_bytes, pad)
            self._rom_sites_dirty = True
            self._rescan_due = True
            self._sync_hooks()
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

    def _hook_uart_write(self, uc, access, address, size, value, user_data):
        # 0xb8018300 is base, store happens at offset 0 usually
        # Check all aliases: 0x18018300, 0x98018300, 0xB8018300
        if (address & 0xFFFFF) == 0x18300:
            self._uart_log(value)
            # Set LSR bit 5 (0x20 = Transmitter Holding Register Empty)
            # so firmware's uart_write_char doesn't timeout and retry 3x.
            # LSR is at UART base + 5 (SCI_16550_ULSR = 5).
            lsr_addr = (address & ~0xFFFFF) | 0x18305
            uc.mem_write(lsr_addr, b'\x20')

    def _hook_uart_read(self, uc, access, address, size, value, user_data):
        """Handle reads from UART registers for RX simulation.

        16550 UART registers at base 0xB8018300:
          +0 URBR  — Receive Buffer Register (read: get received byte)
          +2 UIIR  — Interrupt Identification Register
          +5 ULSR  — Line Status Register (bit0=DataReady, bit5=THRE)
        """
        reg_offset = (address & 0xF)  # offset within UART block
        if reg_offset == 5:  # ULSR — Line Status Register
            lsr = 0x20  # bit5 = THRE always set
            if len(self._uart_rx_queue) > 0:
                lsr |= 0x01  # bit0 = Data Ready
            uc.mem_write(address, bytes([lsr]))
        elif reg_offset == 0:  # URBR — Receive Buffer Register
            if len(self._uart_rx_queue) > 0:
                byte_val = self._uart_rx_queue.popleft()
                uc.mem_write(address, bytes([byte_val]))
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

    # GPIO DO register offsets for I2C/panel decoding
    _GPIO_DO_OFFSETS = {0x054, 0x0D4, 0x0E8, 0x0F4}

    # GPIO DI (data-in) → DO (data-out) loopback mapping
    # When firmware reads DI, return the DO value (pin loopback)
    _GPIO_DI_TO_DO = {
        0x050: 0x054,  # GPIO bank 0
        0x0D0: 0x0D4,  # GPIO bank 1
        0x0E4: 0x0E8,  # GPIO bank 2
        0x0F0: 0x0F4,  # GPIO bank 3
    }
    # Corresponding DIR register offsets
    _GPIO_DI_TO_DIR = {
        0x050: 0x058,  # GPIO bank 0
        0x0D0: 0x0D8,  # GPIO bank 1
        0x0E4: 0x0EC,  # GPIO bank 2
        0x0F0: 0x0F8,  # GPIO bank 3
    }

    def _notify_gpio(self, address, size, value):
        """Notify GPIO callback if this write targets a GPIO DO register."""
        if self.gpio_callback:
            offset = address & 0xFFF
            # Only match GPIO Data-Output registers, NOT direction (0x058) or other regs
            if offset in self._GPIO_DO_OFFSETS:
                # Read full 32-bit register value for correct bit extraction
                base = address & ~3
                try:
                    data = self.mu.mem_read(base, 4)
                    full_val = int.from_bytes(data, 'little')
                except:
                    full_val = value
                self.gpio_callback(base, 4, full_val)



    def _hook_gpio_write(self, uc, access, address, size, value, user_data):
        """UC_HOOK_MEM_WRITE for GPIO region. Decoder handles dedup."""
        if self.gpio_callback:
            if size < 4:
                base = address & ~3
                data = uc.mem_read(base, 4)
                value = int.from_bytes(data, 'little')
                address = base
                size = 4
            self.gpio_callback(address, size, value)

    def _hook_gpio_di_read(self, uc, access, address, size, value, user_data):
        """GPIO DI→DO loopback with DIR-aware ACK simulation.
        
        For each bit:
        - If DIR bit = 1 (output): return the DO value (master is driving)
        - If DIR bit = 0 (input):  return 0 (simulate slave pulling low = ACK)
        
        This makes I2C START succeed (SDA=output, DI returns 1) while also
        making ACK succeed (SDA=input after SET_SDA_IN, DI returns 0).
        """
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
                # Input bits (DIR=0): return 0 (simulated slave response)
                di_val = do_val & dir_val
                uc.mem_write(address & ~3, di_val.to_bytes(4, 'little'))
            except:
                pass

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
        self._spi_log(f"CMD 0x{cmd:02X} ({cmd_name}) [PC=0x{pc:08X}]")
        self._spi_resp_idx = 0
        if cmd == 0x9F:      # JEDEC Read ID: 3 bytes, padded to 4 for word reads
            self._spi_response = list(self._spi_jedec_id) + [0x00]
        elif cmd == 0x05:    # Read Status Register: bit0=WIP, bit1=WEL, bits[5:2]=BP
            self._spi_response = [self._spi_status]
        elif cmd == 0xAB:    # Release from Deep Power Down / Read Electronic ID
            self._spi_response = [self._spi_jedec_id[2], 0x00, 0x00, 0x00]
        elif cmd == 0x90:    # Read Manufacturer/Device ID
            self._spi_response = [self._spi_jedec_id[0], self._spi_jedec_id[2],
                                  self._spi_jedec_id[0], self._spi_jedec_id[2]]
        elif cmd == 0x06:    # Write Enable
            self._spi_wel = True
            self._spi_status |= 0x02
            self._spi_response = []
        elif cmd == 0x04:    # Write Disable
            self._spi_wel = False
            self._spi_status &= ~0x02
            self._spi_response = []
        else:                # WRSR / reads / program / erase: no response bytes
            self._spi_response = []

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
        regs = {0x8: self._spi_ins, 0x9: self._spi_fmt, 0xA: self._spi_dum, 0xB: self._spi_cfg}
        for i in range(size):
            reg = (address + i) & 0xF
            if reg in regs:
                uc.mem_write(address + i, bytes([regs[reg] & 0xFF]))

    def _spi_is_passthrough(self):
        """Check if SPI controller is in normal flash read mode (passthrough).
        
        In normal read mode, reads from SYS_FLASH_BASE_ADDR return actual
        flash content. The controller is in passthrough when:
          SF_INS = 0x03 (Read) or 0x0B (Fast Read)
        
        Note: SF_HIT_ADDR may or may not be set. In CONT_RD mode the firmware
        sets FMT=0x0D (DATA|ADDR|CODE) for the first read, then FMT=0x09
        (DATA|CODE) for sequential reads without address phase.
        """
        return self._spi_ins in (0x03, 0x0B)

    def _flash_offset(self, address):
        """Offset into the flash image for any mirror of the memory-mapped flash."""
        return address % self.rom_size

    def _rom_restore(self):
        """Undo transient writes to the memory-mapped flash window (see rom_image)."""
        for off, size in self._rom_dirty:
            end = min(off + size, self.rom_size)
            self.mu.mem_write(self.base_addr + off, bytes(self.rom_image[off:end]))
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
        self.mu.mem_write(self.base_addr + start, b'\xFF' * length)
        self._rom_sites_dirty = True

    def _hook_spi_flash_read(self, uc, access, address, size, value, user_data):
        """Handle reads from the memory-mapped flash region (SYS_FLASH_BASE_ADDR).

        When the SPI controller is in command mode (not passthrough), reads
        from the flash address space return SPI response data instead of
        flash content. This implements the hardware behavior where:

          write_uint8(SF_FMT, SF_HIT_CODE | SF_HIT_DATA);  // command mode
          write_uint8(SF_INS, 0x9F);                         // JEDEC Read ID
          result = *(volatile UINT32 *)SYS_FLASH_BASE_ADDR;  // read response

        The response bytes are placed in the ROM buffer for this one load and
        restored from rom_image at the next instruction, so they never leak
        into the flash contents the firmware reads later.
        """
        if self._rom_dirty:
            self._rom_restore()          # undo the previous transient bytes before this load
        off = self._flash_offset(address)
        if self._spi_is_passthrough():
            # Log flash read offset (throttled: only when 64KB sector changes)
            sector = off >> 16
            if self._last_flash_read_page != sector:
                self._last_flash_read_page = sector
                self._spi_log(f"  FLASH READ @ 0x{off:06X} (sector {sector})")
            return  # Normal read mode — let ROM content pass through

        # Command mode — inject SPI response data
        resp = bytearray(size)
        for i in range(size):
            if self._spi_resp_idx < len(self._spi_response):
                resp[i] = self._spi_response[self._spi_resp_idx]
                self._spi_resp_idx += 1
            else:
                resp[i] = 0x00      # no more response data: flash idle / not busy
        uc.mem_write(address, bytes(resp))
        self._rom_dirty.append((off, size))
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

        The guest's store itself is reverted at the next instruction; only the
        emulated program/erase changes rom_image.
        """
        if self._rom_dirty:
            self._rom_restore()
        off = self._flash_offset(address)
        self._rom_dirty.append((off, size))
        if self._spi_is_passthrough():
            return  # Normal mode — a write to the flash window has no effect

        cmd = self._spi_ins
        cmd_name = self._SPI_CMD_NAMES.get(cmd, f"0x{cmd:02X}")
        if cmd == 0x06:      # WREN — trigger
            self._spi_wel = True
            self._spi_status |= 0x02
            self._spi_log(f"  EXEC {cmd_name}")
        elif cmd == 0x04:    # WRDI — trigger
            self._spi_wel = False
            self._spi_status &= ~0x02
            self._spi_log(f"  EXEC {cmd_name}")
        elif cmd == 0x01:    # WRSR — write status register
            if self._spi_wel:
                self._spi_status = value & 0xFF
                self._spi_wel = False
                self._spi_status &= ~0x02  # Clear WEL after write
                self._spi_log(f"  EXEC {cmd_name} = 0x{value & 0xFF:02X}")
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
            self._spi_wel = False
            self._spi_status &= ~0x02
        elif cmd in (0x02, 0xAD):                        # page program / AAI
            if not self._spi_wel:
                self._spi_log(f"  EXEC {cmd_name} without WEL (applied anyway)")
            for i in range(size):
                self._flash_program(off + i, (value >> (8 * i)) & 0xFF)
            self._spi_log(f"  EXEC {cmd_name} @ flash[0x{off:06X}] = 0x{value & ((1 << (8 * size)) - 1):0{2 * size}X}")
            if cmd == 0x02:
                self._spi_wel = False
                self._spi_status &= ~0x02

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
        if self._hflags_off is not None:
            m16 = self.is_mips16_mode()
        else:
            m16 = self.is_mips16_addr(pc)
        self._cur_m16 = m16
        self._isa_mode_fallback = ISAMode.MIPS16 if m16 else ISAMode.MIPS32
        self._mode_resync_in = 0
        self._next_in_delay_slot = False
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

    def _hook_code(self, uc, address, size, user_data):
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

        # ---- UART receive interrupt injection ----
        # Delivered by redirecting the PC to the exception vector (MIPS32).
        # Not from a delay slot: Unicorn ignores PC writes there.
        # A PC write is also ignored on a MIPS16 compact jump (JRC/JALRC): the jump
        # completes inside the same instruction, so deliver at the next one.
        if self._pending_uart_irq and not self._uart_irq_delivered and not in_delay_slot and not compact_jump:
            if self.instruction_count >= self._uart_irq_arm_after:
                ie = self.cp0_status & 0x01
                exl = self.cp0_status & 0x02
                force = getattr(self, '_uart_irq_force', False)
                if force or (ie and not exl):
                    exc_vector = self._enter_uart_irq(uc, address | (1 if m16 else 0))
                    self._cur_m16 = False
                    self._mode_resync_in = 0
                    self._next_in_delay_slot = False
                    uc.reg_write(UC_MIPS_REG_PC, exc_vector)   # even -> MIPS32
                    return

        # ---- CP0 emulation (MIPS32 COP0 opcode 0x10: MFC0 / MTC0 / ERET) ----
        if size == 4 and not m16 and (insn[3] >> 2) == 0x10:
            self._emulate_cop0(uc, address, int.from_bytes(insn, 'little'), in_delay_slot)

        self.instruction_count += 1
        if stop_after:
            uc.emu_stop()
        elif self.max_instructions and not self.is_stepping and self.instruction_count >= self.max_instructions:
            self._stop_reason = 'max_instructions'
            uc.emu_stop()

    def _emulate_cop0(self, uc, address, w, in_delay_slot):
        """Emulate MFC0/MTC0 of Count, Status, Cause, EPC and ERET with the
        simulated CP0 state.  Returns True if the PC was redirected past the
        instruction (i.e. Unicorn will not execute it)."""
        rs = (w >> 21) & 0x1F
        rt = (w >> 16) & 0x1F
        rd = (w >> 11) & 0x1F
        funct = w & 0x3F
        if rs == 0x00:                      # MFC0 rt, rd
            if rd == 9:    val = self._cp0_count_now()
            elif rd == 11: val = self.cp0_compare
            elif rd == 12: val = self.cp0_status
            elif rd == 13: val = self.cp0_cause
            elif rd == 14: val = self.cp0_epc
            else:
                return False                # other registers: let Unicorn handle
            if in_delay_slot:
                self._delay_slot_skips += 1
                return False
            uc.reg_write(self.gpr_map[rt], val & 0xFFFFFFFF)
            uc.reg_write(UC_MIPS_REG_PC, address + 4)
            return True
        if rs == 0x04:                      # MTC0 rt, rd
            val = uc.reg_read(self.gpr_map[rt]) & 0xFFFFFFFF
            if rd == 9:
                self.cp0_count = val
                self._count_icount = self.instruction_count
                self._count_t0 = time.perf_counter()
            elif rd == 11:
                self.cp0_compare = val
            elif rd == 12:
                self.cp0_status = val
                self._write_native_status(uc, val)
            elif rd == 13:
                self.cp0_cause = val
            elif rd == 14:
                self.cp0_epc = val
            else:
                return False
            if in_delay_slot:
                self._delay_slot_skips += 1  # shadow updated; native MTC0 still executes
                return False
            uc.reg_write(UC_MIPS_REG_PC, address + 4)
            return True
        if rs == 0x10 and funct == 0x18:    # ERET
            if in_delay_slot:
                return False
            self.cp0_status &= ~0x02        # clear EXL
            self._write_native_status(uc, self.cp0_status)
            target = self.cp0_epc & 0xFFFFFFFF
            self._cur_m16 = bool(target & 1)
            self._mode_resync_in = 0
            self._next_in_delay_slot = False
            self.log(f"[ERET] Returning to {hex(target)}, Status=0x{self.cp0_status:08X}")
            if len(self._uart_rx_queue) > 0:
                self._pending_uart_irq = True
                self._uart_irq_delivered = False
                self._uart_irq_arm_after = self.instruction_count + 100
            uc.reg_write(UC_MIPS_REG_PC, target)   # bit 0 selects the ISA mode
            return True
        return False

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
            uc.reg_write(UC_MIPS_REG_CP0_STATUS, val & 0xFFFFFFFF)
        except Exception:
            pass

    def _cp0_count_now(self):
        """Simulated CP0 Count.

        Full-hook mode: 2 ticks per executed instruction (deterministic, as the
        hardware does at half the CPU clock).  Fast mode: wall clock at
        count_hz, so firmware delay and timeout loops take real time instead
        of depending on how fast the host happens to emulate."""
        if self._code_hook_h is None:
            ticks = int((time.perf_counter() - self._count_t0) * self.count_hz)
        else:
            ticks = 2 * (self.instruction_count - self._count_icount)
        return (self.cp0_count + ticks) & 0xFFFFFFFF

    def _enter_uart_irq(self, uc, epc):
        """Set up the CP0 state for the UART receive interrupt and return the
        exception vector.  epc carries the ISA mode in bit 0 like real hardware."""
        self._uart_irq_delivered = True
        self._pending_uart_irq = False
        self._uart_irq_retries += 1
        # ALi interrupt controller: EISR/EIER bit 16 = UART IRQ 24
        uart_ic_bit = 1 << 16
        try:
            eisr_val = int.from_bytes(uc.mem_read(0xB8000030, 4), 'little')
            uc.mem_write(0xB8000030, (eisr_val | uart_ic_bit).to_bytes(4, 'little'))
            eier_val = int.from_bytes(uc.mem_read(0xB8000038, 4), 'little')
            uc.mem_write(0xB8000038, (eier_val | uart_ic_bit).to_bytes(4, 'little'))
        except Exception:
            pass
        self.cp0_epc = epc
        self.cp0_cause = 0x00000800   # IP[3]
        self.cp0_status |= 0x0800     # IM[3]
        self.cp0_status |= 0x02       # EXL
        self._write_native_status(uc, self.cp0_status)
        bev = (self.cp0_status >> 22) & 1
        exc_vector = 0xBFC00380 if bev else 0x80000180
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
    # (sel 0) and ERET, little-endian, matched at any byte offset and then
    # filtered to 4-byte alignment.  Data or MIPS16 code matching by accident
    # is harmless: the site hook re-checks the ISA mode and the encoding.
    _CP0_SITE_RE = re.compile(rb'\x00[\x48\x58\x60\x68\x70][\x00-\x1f\x80-\x9f]\x40|\x18\x00\x00\x42')
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
            self._code_hook_h = self.mu.hook_add(UC_HOOK_CODE, self._hook_code)
            self._tb_flush_needed = True
        elif not full and self._code_hook_h is not None:
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

    # (word & 0xFFE0FFFF) of MFC0/MTC0 rt, {Count, Compare, Status, Cause, EPC} sel 0
    _CP0_WORDS = frozenset([0x40000000 | (rd << 11) for rd in (9, 11, 12, 13, 14)] +
                           [0x40800000 | (rd << 11) for rd in (9, 11, 12, 13, 14)])
    _ERET_WORD = 0x42000018

    def _find_cp0_sites(self, data, base):
        """Offsets (plus base) of 4-byte-aligned CP0 instruction encodings in data."""
        out = set()
        if _np is not None:
            n = len(data) & ~3
            w = _np.frombuffer(data, dtype='<u4', count=n // 4)
            # opcode 0x10 (COP0) words are rare in code and data: filter them in
            # one vector pass, then classify the few candidates.
            cand = _np.flatnonzero((w & _np.uint32(0xFC000000)) == _np.uint32(0x40000000))
            words = w[cand].tolist()
            for i, x in zip(cand.tolist(), words):
                if x == self._ERET_WORD or (x & 0xFFE0FFFF) in self._CP0_WORDS:
                    out.add(base + 4 * i)
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
        if self._rom_sites_dirty:
            self._rom_sites = self._find_cp0_sites(self.rom_image, 0)
            self._rom_sites_dirty = False
        sites = set()
        for base in (0xAFC00000, 0xBFC00000):         # flash executes from KSEG1 (and the BEV vector)
            sites |= {base + off for off in self._rom_sites}
        full = ranges is None
        if full:
            ranges = [(0x80000000, min(self.ram_size, self._RAM_CODE_LIMIT))]
        for start, length in ranges:
            try:
                ram = self.mu.mem_read(start, length)
            except UcError as e:
                self.log(f"Warning: RAM scan for CP0 sites failed at {hex(start)}: {e}")
                continue
            found = self._find_cp0_sites(ram, start & 0x1FFFFFFF)   # physical offsets
            for seg in (0x80000000, 0xA0000000):                     # KSEG0 and KSEG1 views
                sites |= {seg + off for off in found}
        self._add_cp0_sites(sites)
        if full:
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
        if size != 4 or self.is_mips16_mode():
            return                      # MIPS16 code / data that matched by accident
        w = int.from_bytes(uc.mem_read(address, 4), 'little')
        if (w >> 26) != 0x10:
            return                      # code changed since the scan
        if self._rom_dirty:
            self._rom_restore()
        # In a branch delay slot the PC redirect would be ignored; treat the
        # previous word as MIPS32 (a MIPS16 caller reaches MIPS32 code only via
        # JALX, whose target is never a delay slot).
        try:
            prev = uc.mem_read(address - 4, 4)
            in_ds = self._insn_has_delay_slot(prev, 4, False)
        except UcError:
            in_ds = False
        self._emulate_cop0(uc, address, w, in_ds)

    def _decode_for_display(self, pc, m16):
        """(mnemonic, operands, size) of the instruction at pc in the given mode."""
        try:
            if m16:
                insn_bytes = self.mu.mem_read(pc, 2)
                op = (int.from_bytes(insn_bytes, 'little') >> 11) & 0x1F
                if op in (0x1E, 0x03):          # EXTEND or JAL/JALX
                    insn_bytes = self.mu.mem_read(pc, 4)
                mnemonic, operands = MIPS16Decoder.decode(bytes(insn_bytes), pc)
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

    def run(self, max_instructions=None):
        if max_instructions is not None:
            self.max_instructions = max_instructions

        cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        note = "" if self._want_full_hook() else " [fast mode: instruction counts are estimates, no per-instruction history]"
        self.log(f"Starting emulation at {hex(cur_pc)} ({'MIPS16' if self.is_mips16_mode() else 'MIPS32'})...{note}")
        end_addr = self.base_addr + self.rom_size

        try:
            while True:
                if self.max_instructions and self.instruction_count >= self.max_instructions:
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

                if full:
                    # Exact mode: _hook_code counts instructions, delivers IRQs,
                    # emulates CP0 and stops on breakpoints / max_instructions.
                    self._stop_reason = None
                    self.mu.emu_start(self._start_pc(cur_pc), end_addr)
                    executed = None
                else:
                    # Fast mode: native batches.  IRQs are taken at batch boundaries.
                    if self._irq_due():
                        self._rescan_cp0_sites()      # the ISR code must be hooked before it runs
                        if self._tb_flush_needed:
                            self._flush_tb()
                        vector = self._enter_uart_irq(self.mu, cur_pc | (1 if self.is_mips16_mode() else 0))
                        self.mu.reg_write(UC_MIPS_REG_PC, vector)
                        cur_pc = vector
                    # Exact (counted) slice when close to a limit, otherwise a
                    # wall-clock slice whose instruction count is estimated.
                    budget = None
                    if self.max_instructions:
                        budget = self.max_instructions - self.instruction_count
                    if self._pending_uart_irq and not self._uart_irq_delivered and \
                            self._uart_irq_arm_after > self.instruction_count:
                        arm = self._uart_irq_arm_after - self.instruction_count
                        budget = arm if budget is None else min(budget, arm)
                    small_budget = budget is not None and budget <= self.exact_count_threshold
                    calibrating = self._counted_slices < self.calibration_slices
                    if self._timeout_slices == 0 and (small_budget or calibrating):
                        batch = self.batch_size if budget is None else min(self.batch_size, budget)
                        batch = max(1, batch)
                        self._stop_reason = None
                        t0 = time.perf_counter()
                        self.mu.emu_start(self._start_pc(cur_pc), end_addr, count=batch)
                        dt = time.perf_counter() - t0
                        if self._stop_reason is None:
                            executed = batch
                            if dt > 0 and batch >= 10_000:
                                self._insn_rate = batch / dt
                        elif self._stop_reason == 'rescan':
                            executed = 0    # stopped before the first instruction of a new RAM chunk
                        else:
                            # a hook stopped the slice early; Unicorn does not say how
                            # many instructions ran, so use the rate estimate
                            executed = min(batch, int(self._insn_rate * dt))
                        self._counted_slices += 1
                    else:
                        timeout_us = self.batch_timeout_us
                        if budget is not None:
                            # aim the slice length at the remaining budget
                            timeout_us = max(1000, min(timeout_us, int(budget / self._insn_rate * 1e6)))
                        self._stop_reason = None
                        t0 = time.perf_counter()
                        self.mu.emu_start(self._start_pc(cur_pc), end_addr, timeout=timeout_us)
                        dt = time.perf_counter() - t0
                        executed = 0 if self._stop_reason == 'rescan' else int(self._insn_rate * dt)
                        if budget is not None:
                            executed = min(executed, budget)
                        self._timeout_slices += 1

                if executed is not None:
                    self.instruction_count += executed
                if self._rom_dirty:
                    self._rom_restore()
                if not full and self.force_erl:
                    self._write_native_status(self.mu, self.cp0_status)
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
                if self._stop_reason == 'external':
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
                        # It's MIPS16! Decode it properly
                        # Read first 2 bytes to check instruction type
                        first_word = self.mu.mem_read(curr, 2)
                        word1 = int.from_bytes(first_word, byteorder='little')
                        major_op = (word1 >> 11) & 0x1F
                        is_4byte = (major_op == 0x03 or major_op == 0x1E)  # JAL/JALX opcode or EXTEND
                        
                        # Read appropriate number of bytes
                        if is_4byte:
                            valid_bytes = self.mu.mem_read(curr, 4)
                            instr_size = 4
                        else:
                            valid_bytes = first_word
                            instr_size = 2
                        
                        # Decode MIPS16 instruction (with address for JAL target calculation)
                        mnemonic, operands = MIPS16Decoder.decode(valid_bytes, curr)
                        bytes_str = ' '.join(f'{b:02x}' for b in valid_bytes)
                        
                        temp_instrs.append({
                            'address': curr,
                            'bytes': bytes_str,
                            'mnemonic': mnemonic,
                            'operands': operands,
                            'loop_count': self.visit_counts.get(curr, 0),
                            'is_current': (curr == pc),
                            'is_breakpoint': (curr in breakpoints)
                        })
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
                            # Read first 2 bytes to check instruction type
                            first_word = self.mu.mem_read(curr, 2)
                            word1 = int.from_bytes(first_word, 'little')
                            major_op = (word1 >> 11) & 0x1F
                            is_4byte = (major_op == 0x03 or major_op == 0x1E)
                            
                            # Read appropriate number of bytes
                            if is_4byte:
                                valid_bytes = self.mu.mem_read(curr, 4)
                                instr_size = 4
                            else:
                                valid_bytes = first_word
                                instr_size = 2
                            
                            mnemonic, operands = MIPS16Decoder.decode(valid_bytes, curr)
                            bytes_str = ' '.join(f'{b:02x}' for b in valid_bytes)
                            
                            temp_instrs.append({
                                'address': curr,
                                'bytes': bytes_str,
                                'mnemonic': mnemonic,
                                'operands': operands,
                                'loop_count': self.visit_counts.get(curr, 0),
                                'is_current': (curr == pc),
                                'is_breakpoint': (curr in breakpoints)
                            })
                            curr += instr_size
                        except:
                            curr += 4  # Skip if read fails
                        continue
                        
                    instr = disasm[0]
                    
                    item = {
                        'address': curr,
                        'bytes': ' '.join(f'{b:02x}' for b in instr.bytes),
                        'mnemonic': instr.mnemonic,
                        'operands': instr.op_str,
                        'loop_count': self.visit_counts.get(curr, 0),
                        'is_current': (curr == pc),
                        'is_breakpoint': (curr in breakpoints)
                    }
                    temp_instrs.append(item)
                    
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
                    # Read first 2 bytes to check instruction type
                    first_word = self.mu.mem_read(curr, 2)
                    word1 = int.from_bytes(first_word, byteorder='little')
                    major_op = (word1 >> 11) & 0x1F
                    is_4byte = (major_op == 0x03 or major_op == 0x1E)
                    
                    # Read appropriate number of bytes
                    if is_4byte:
                        code = self.mu.mem_read(curr, 4)
                        instr_size = 4
                    else:
                        code = first_word
                        instr_size = 2
                    
                    mnemonic, operands = MIPS16Decoder.decode(code, curr)
                    bytes_str = ' '.join(f'{b:02x}' for b in code)
                    
                    best_instrs.append({
                        'address': curr,
                        'bytes': bytes_str,
                        'mnemonic': mnemonic,
                        'operands': operands,
                        'loop_count': self.visit_counts.get(curr, 0),
                        'is_current': (curr == pc),
                        'is_breakpoint': (curr in breakpoints)
                    })
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


