"""
The simulator on the C++ core (engine 'cpp'): AliMipsSimulator(engine='cpp'),
or every simulator a process makes with ALISIM_ENGINE=cpp in the environment
(python run_all_tests.py --engine cpp).

What stays the same: every device model, chip family and API of
simulator.AliMipsSimulator -- the device register handlers (_mmio_on), the SPI
flash, the GE, the IR controller, the panels, the SEE's second core, press_key,
capture_screen, run(), step(), sim.mu (the core seen through Unicorn's Python
API, cpp_core.CppUc).  What the core does instead of Unicorn and the Python
hooks around it:

  * CP0 natively (Count / Compare, Status, Cause, EPC, EBase, ERET): no CP0
    instruction sites to scan and hook, no slice stopper, no replayed device
    accesses (a stop ends the instruction cleanly), no forced ERL or TLB trick
    (kuseg is 1:1);
  * interrupts -- the timer, the interrupt controller's lines and doorbells,
    the UART receive interrupt -- at the exact instruction they become
    deliverable (never in a delay slot), as the exact mode did;
  * the clock: emulation time is the instruction count, cpp_ips instructions
    per emulated second (deterministic, whatever the host does); Count runs at
    count_hz of it (with the defaults 2 Count ticks per instruction, the exact
    mode's rate);
  * idle loops (`b .` / nop, MIPS16 `b .`, WAIT) skip to the next event;
  * the device window's registers without a handler are read and written by
    the core itself; those with one call the Python handler (_mmio_read /
    _mmio_write), as an mmio_map callback did.

instruction_count keeps the Python engine's meaning, so the tests' budgets
mean what they did: exact while the first counted slices run (small budgets,
the start-up), then emulation time at _insn_rate (cpp_rate).
"""
import ctypes
import os
import struct
import sys
import threading

from unicorn import UcError, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_FETCH_PROT, \
    UC_HOOK_MEM_READ_PROT, UC_HOOK_MEM_WRITE_PROT, UC_PROT_ALL
from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_SP

import cpp_core
from cpp_core import (F_ICOUNT, F_EXECUTED, F_STATUS, F_CAUSE, F_CAUSE_VALUE, F_EPC, F_EBASE, F_COMPARE, F_COUNT,
                      F_TI, F_TIMER_ARMED, F_TIMER_ENABLED, F_TIMER_IRQS, F_IC_IRQS, F_IC_LINES, F_UART_IP3,
                      F_UART_PENDING, F_UART_DELIVERED, F_UART_AT, F_UART_FORCE, F_IDLE_SKIP, F_EXACT,
                      F_IRQS_ENABLED, F_M16, F_DS_ACTIVE, F_IDLE_SKIPPED, F_FAULT_PC, F_FAULT_ADDR,
                      F_STEP_OVER_BP, F_IRQ_DELIVERABLE, F_IC_IP3, F_TIMER_ANCHOR, F_LAST_ERROR,
                      F_PC_MODE, F_COUNT_OBSERVED, F_COUNT_OBSERVED_VALID, F_COUNT_RAW_WRITE,
                      F_COMPARE_WRITE, STOP_ERROR, STOP_BREAKPOINT, STOP_REQUEST, STOP_COUNT,
                      EVT_UART_ERET, EVT_CODE_CHUNK, EVT_FLASH_READ, EVT_UART_IRQ, DF_READ, DF_WRITE,
                      DF_GPIO_DO, DF_GPIO_DIR, F_UART_IRQS)
from simulator import AliMipsSimulator, ISAMode

DEFAULT_IPS = int(float(os.environ.get("ALISIM_CPP_IPS", "50e6")))     # instructions per emulated second
# instruction_count per emulated second in fast mode: what the Unicorn engine calibrates
# on this machine (~0.76 M/s), so a test's instruction budget is the same emulated time
DEFAULT_RATE = float(os.environ.get("ALISIM_CPP_RATE", "0.75e6"))
# emulated time a device register access handled in Python costs, in instructions: a
# poll loop on such a register (waiting for the RTC's next second, say) must see time
# pass -- the Unicorn engine charged the handler's host time, ~5 us
DEFAULT_ACCESS_COST = int(os.environ.get("ALISIM_CPP_ACCESS_COST", "250"))


# the native SPI controller's state (ali_spi_get / ali_spi_set)
(S_INS, S_FMT, S_DUM, S_CFG, S_STATUS, S_WEL, S_RESP_LEN, S_RESP_IDX, S_ON, S_COMMANDS,
 S_RESP0, S_RESP1, S_RESP2, S_RESP3, S_PROGRAMS, S_ERASES) = range(1, 17)
SPI_REGS = tuple(base + i for base in (0x00098, 0x2E098) for i in range(4))


def _spi_prop(field, doc, bool_=False):
    def get(self):
        v = cpp_core.lib().ali_spi_get(self._core.handle, field)
        return bool(v) if bool_ else v

    def set_(self, value):
        cpp_core.lib().ali_spi_set(self._core.handle, field, int(value) & 0xFF)
    return property(get, set_, doc=doc)


def _cpu_prop(field, doc, bool_=False):
    def get(self):
        v = self._core.get(field)
        return bool(v) if bool_ else v

    def set_(self, value):
        self._core.set(field, int(bool(value)) if bool_ else int(value) & 0xFFFFFFFFFFFFFFFF)
    return property(get, set_, doc=doc)


class _SimUc(cpp_core.CppUc):
    """sim.mu: the core's Unicorn-like API, with the simulator's bookkeeping
    around emu_start / emu_stop (as the Unicorn engine's wrappers did)."""

    def __init__(self, sim):
        super().__init__()
        self._sim = sim

    def emu_start(self, begin, until, timeout=0, count=0):
        sim = self._sim
        sim._cpp_sync()
        sim._stop_reason = None
        e0 = self.get(F_EXECUTED)
        try:
            super().emu_start(begin, until, timeout, count)
        finally:
            sim._cpp_after_start(self.get(F_EXECUTED) - e0)

    def emu_stop(self):
        sim = self._sim
        if sim._stop_reason is None:
            sim._stop_reason = 'external'
        if sim._in_run and threading.get_ident() != sim._run_tid:
            sim._external_stop = True       # a pause from another thread (GUI): run() returns
        super().emu_stop()


class CppAliMipsSimulator(AliMipsSimulator):
    engine = "cpp"
    native_status = True
    force_erl = False
    delay_hle = os.environ.get("ALISIM_CPP_DELAY_HLE", "0") == "1"   # (Python hooks: slower than the core running the loops)
    # A timed slice runs the timer interrupts in the core (it does not end at each
    # one, as the Unicorn engine's do): a slice service with a due() -- the
    # emulation time it next has work at -- ends the slice there instead, but
    # never sooner than this after its start
    SERVICE_MIN_SLICE_S = 0.0005
    skip_irq_disable = False

    # the CPU state the core keeps (the Python engine's shadow attributes)
    cp0_status = _cpu_prop(F_STATUS, "CP0 Status (the guest's)")
    cp0_cause = _cpu_prop(F_CAUSE, "CP0 Cause's stored bits (cause_value() adds the lines)")
    cp0_epc = _cpu_prop(F_EPC, "CP0 EPC")
    cp0_ebase = _cpu_prop(F_EBASE, "CP0 EBase")
    cp0_compare = _cpu_prop(F_COMPARE, "CP0 Compare (raw)")
    timer_irq_count = _cpu_prop(F_TIMER_IRQS, "timer interrupts delivered")
    ic_irq_count = _cpu_prop(F_IC_IRQS, "interrupt-controller interrupts delivered")
    _ti = _cpu_prop(F_TI, "Cause.TI latched", True)
    _timer_armed = _cpu_prop(F_TIMER_ARMED, "a Compare was written", True)
    _timer_anchor = _cpu_prop(F_TIMER_ANCHOR, "Count of the last crossing check")
    _uart_ip3 = _cpu_prop(F_UART_IP3, "IP3 of a delivered UART interrupt", True)
    _pending_uart_irq = _cpu_prop(F_UART_PENDING, "UART receive interrupt armed", True)
    _uart_irq_delivered = _cpu_prop(F_UART_DELIVERED, "... and delivered", True)
    _uart_irq_force = _cpu_prop(F_UART_FORCE, "... whatever Status says", True)
    _uart_irq_retries = _cpu_prop(F_UART_IRQS, "UART receive interrupts delivered")
    # the SPI flash controller's state lives in the core (its native model and the
    # Python one, _hook_spi_*, share it)
    _spi_ins = _spi_prop(S_INS, "SF_INS")
    _spi_fmt = _spi_prop(S_FMT, "SF_FMT")
    _spi_dum = _spi_prop(S_DUM, "SF_DUM")
    _spi_cfg = _spi_prop(S_CFG, "SF_CFG")
    _spi_status = _spi_prop(S_STATUS, "the part's status register")
    _spi_wel = _spi_prop(S_WEL, "its write-enable latch", True)
    _spi_resp_idx = _spi_prop(S_RESP_IDX, "the next response byte")

    @property
    def _spi_response(self):
        L, h = cpp_core.lib(), self._core.handle
        return [L.ali_spi_get(h, S_RESP0 + i) for i in range(L.ali_spi_get(h, S_RESP_LEN))]

    @_spi_response.setter
    def _spi_response(self, value):
        L, h = cpp_core.lib(), self._core.handle
        value = list(value)[:4]
        for i, b in enumerate(value):
            L.ali_spi_set(h, S_RESP0 + i, b)
        L.ali_spi_set(h, S_RESP_LEN, len(value))

    def _spi_native_wanted(self):
        """Whether the core's own SPI controller serves the firmware: not while the
        Python model is needed -- SPI logging, a family's byte-stream mode of the
        window (the M3821's), a parallel flash, an observer on its registers."""
        return (not self._spi_dump_enabled and not self._spi_dump_flash_reads and self._spi_stream is None
                and self.flash_device is None and getattr(self, "spi_native", True)
                and not any(lo <= off <= hi for _w, lo, hi, _cb in self._mmio_observers for off in SPI_REGS))

    def _cpp_spi_sync(self):
        """The native SPI controller on / off, on the current flash image."""
        want = self._spi_native_wanted()
        image = self.rom_image
        key = (want, id(image), len(image))
        if key == self.__dict__.get('_spi_key'):
            return
        self._spi_key = key
        if self._rom_dirty:
            self._rom_restore()
        if want:
            self._rom_image_ref = (ctypes.c_char * len(image)).from_buffer(image)     # (keeps it alive, fixed size)
            img_ptr = ctypes.addressof(self._rom_image_ref)
        else:
            self._rom_image_ref, img_ptr = None, None
        jedec = (self._spi_jedec_id[0] << 16) | (self._spi_jedec_id[1] << 8) | self._spi_jedec_id[2]
        cpp_core.lib().ali_spi_config(self._core.handle, int(want), ctypes.addressof(self.rom_buffer), img_ptr,
                                      self.rom_size, jedec)
        self._update_flash_read_hooks()
        self._dev_sig = None            # (the registers' flags change)

    def __init__(self, *args, **kwargs):
        shared = kwargs.get("share_memory_with")
        self._core = _SimUc(self)
        self._mmio_version = 0
        self._dev_pushed = {}           # offset -> flags pushed to the core
        self._dev_sig = None
        self._bp_pushed = None
        self._flash_cmd_on = False
        self._uart_arm_units = 0
        self._doorbell = None
        self._exact_hook = None
        self.cpp_ips = DEFAULT_IPS
        self._count_hz_v = 100_000_000
        self._cb_keep = []
        super().__init__(*args, **kwargs)
        self._insn_rate = DEFAULT_RATE
        self._apply_count_ratio()
        self._core.set(cpp_core.F_HOST_ACCESS_COST, DEFAULT_ACCESS_COST)
        self._hflags_off = 0            # (the ISA mode is the core's: is_mips16_mode)
        if os.environ.get("ALISIM_CPP_PROFILE"):
            import atexit
            self._core.prof(True)
            atexit.register(self._prof_report, os.environ["ALISIM_CPP_PROFILE"])

    def _prof_report(self, dest, n=30):
        """ALISIM_CPP_PROFILE=<file> (or 1: stderr): at exit, where the core ran
        (instructions per block start) and which instructions' device accesses
        went to Python, with their code."""
        import sys
        from mips16_decoder import MIPS16Decoder
        core = self._core
        out = [f"--- core {id(self) & 0xFFFF:04x}: {core.get(F_EXECUTED):,} instructions executed, "
               f"skipped: idle {core.get(F_IDLE_SKIPPED):,}, spin {core.get(cpp_core.F_SPIN_SKIPPED):,}, "
               f"Count polls {core.get(cpp_core.F_POLL_SKIPPED):,} ({core.get(cpp_core.F_POLL_SKIPS):,} loops); "
               f"counting loops {core.get(cpp_core.F_FF_SKIPPED):,}; "
               f"blocks {core.get(cpp_core.F_BLOCK_RUNS):,} runs, {core.get(cpp_core.F_BLOCK_BUILDS):,} builds"]
        for which, title in ((0, "instructions run, per block start"),
                             (1, "device accesses handled in Python, per instruction")):
            top = self._core.prof_top(which, n)
            total = sum(c for _, c in top) or 1
            out.append(f"--- {self.chip_name if hasattr(self, 'chip_name') else ''} core "
                       f"{id(self) & 0xFFFF:04x}, icount {self._core.get(F_ICOUNT):,}: {title} (top {len(top)})")
            for key, count in top:
                pc, m16 = key & ~1, key & 1
                try:
                    code = bytes(self.mu.mem_read(pc, 4))
                    if m16:
                        mn, ops = MIPS16Decoder.decode(code, pc)
                        text = f"{mn} {ops}"
                    else:
                        i = next(self.md.disasm(code, pc), None) if self.md else None
                        text = f"{i.mnemonic} {i.op_str}" if i else code.hex()
                except Exception:
                    text = "?"
                out.append(f"  {pc:08X}{'m' if m16 else ' '} {count:14,} {100 * count / total:5.1f}%  {text}")
                if which == 0 and not m16 and self.md and os.environ.get("ALISIM_CPP_PROFILE_CODE") and \
                        count * 20 > total:
                    try:                    # (a hot block's code: ALISIM_CPP_PROFILE_CODE=1)
                        for i in self.md.disasm(bytes(self.mu.mem_read(pc, 48)), pc):
                            out.append(f"      {i.address:08X}  {i.mnemonic} {i.op_str}")
                    except Exception:
                        pass
        text = "\n".join(out) + "\n"
        if dest == "1":
            sys.stderr.write(text)
        else:
            with open(dest, "a", encoding="utf-8") as f:
                f.write(text)

    # ------------------------------------------------------------------
    # The machine on the core
    # ------------------------------------------------------------------
    def _init_unicorn(self):
        core = self.mu = self._core
        self.rom_buffer = self._buffer('rom_buffer', self.rom_size)
        self._rom_view = memoryview(self.rom_buffer).cast('B')
        self._spi_status_injected = False
        slot = min(self.rom_size, 0x400000)
        for offset in range(0, 0x01000000, slot):
            for phys in (0x0F000000, 0x1F000000):
                for seg in (0x00000000, 0x80000000, 0xA0000000):
                    self._map_flash_mirror(seg + phys + offset, slot)
        self.ram_buffer = self._buffer('ram_buffer', self.ram_size)
        ram_ptr = ctypes.addressof(self.ram_buffer)
        for base in (0x80000000, 0xA0000000, 0x00000000):
            core.mem_map_ptr(base, self.ram_size, UC_PROT_ALL, ram_ptr)
        self._init_fast_access()
        self.force_erl = False
        self._site_words = set()
        self._site_word_array = None
        MMIO_SIZE = 0x01000000
        self.mmio_buffer = self._buffer('mmio_buffer', MMIO_SIZE)
        self._mmio_view = memoryview(self.mmio_buffer).cast('B')
        self._mmio_words = self._mmio_view.cast('I') if sys.byteorder == 'little' else None
        self._mmio_halfwords = self._mmio_view.cast('H') if sys.byteorder == 'little' else None
        mmio_ptr = ctypes.addressof(self.mmio_buffer)
        self._mmio_rd = {}
        self._mmio_wr = {}
        for base in (0x98000000, 0xB8000000):
            core.mem_map_ptr(base, MMIO_SIZE, UC_PROT_ALL, mmio_ptr)
        # the physical window: the core's own device window, the handlers through _cpp_dev
        L = cpp_core.lib()
        self._dev_cb = cpp_core._DEV_CB(self._cpp_dev)
        L.ali_set_device_window(core.handle, 0x18000000, mmio_ptr, MMIO_SIZE,
                                ctypes.cast(self._dev_cb, ctypes.c_void_p), None)
        core._map_changed()
        self._evt_cb = cpp_core._MACHINE_EVENT(self._cpp_event)
        L.ali_set_event_cb(core.handle, ctypes.cast(self._evt_cb, ctypes.c_void_p), None)
        self._gpio_cb = cpp_core._GPIO_CB(self._cpp_gpio)
        L.ali_set_gpio_cb(core.handle, ctypes.cast(self._gpio_cb, ctypes.c_void_p), None)
        count, pairs = ctypes.c_void_p(), ctypes.c_void_p()
        L.ali_gpio_log(core.handle, 1, ctypes.byref(count), ctypes.byref(pairs))   # (_cpp_dev empties it)
        self._gpio_count = (ctypes.c_uint32 * 1).from_address(count.value)
        self._gpio_pairs = (ctypes.c_uint32 * (2 * 4096)).from_address(pairs.value)
        if self._shared is None:
            core.mem_write(0xB8018305, b'\x20')
        core.hook_add(UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_FETCH_PROT | UC_HOOK_MEM_READ_PROT, self._hook_mem_invalid)
        core.hook_add(UC_HOOK_MEM_WRITE_PROT, self._hook_flash_write_prot)
        self._mmio_on('w', self._hook_uart_write, 0x18300, 0x18305)
        self._mmio_on('r', self._hook_uart_read, 0x18300, 0x18312)
        for gpio_off in self._GPIO_DO_OFFSETS:
            self._mmio_on('w', self._hook_gpio_write, gpio_off, gpio_off + 7)
        for di_off in self._GPIO_DI_TO_DO:
            self._mmio_on('r', self._hook_gpio_di_read, di_off, di_off + 3)
        for reg in self._SELF_COMPLETING:
            self._mmio_on('r', self._hook_selfcomplete_read, reg & ~3, reg)
        for reg in self._VE_STATUS_REGS:
            self._mmio_on('r', self._hook_ve_status_read, reg, reg + 3)
        self._mmio_on('w', self._hook_chip_id_store, 0x0000, 0x0003)
        self._mmio_on('w', self._hook_ge_write, 0xA004, 0xA00B)
        self._mmio_on('r', self._hook_ge_read, 0xA008, 0xA00B)
        self._mmio_on('r', self._hook_ic_status_read, self.ic_base, self.ic_base + 7)
        self._mmio_on('r', self._hook_mac_reset_read, 0x2C000, 0x2C000)
        self._mmio_on('r', self._hook_mac_mdio_read, 0x2C07C, 0x2C07F)
        self._mmio_on('r', self._hook_irc_read, 0x18101, 0x18101)
        self._mmio_on('r', self._hook_irc_read, 0x18107, 0x18108)
        self._mmio_on('w', self._hook_irc_write, 0x18107, 0x18107)
        for base in (0x00098, 0x2E098):
            self._mmio_on('w', self._hook_spi_write, base, base + 3)
            self._mmio_on('r', self._hook_spi_read, base, base + 3)
            if self._shared is None:
                self._mmio_view[base:base + 4] = b'\x03\x0d\x00\x00'
        import i2c_scb
        import smc_m36
        self.i2c_devices = self._shared.i2c_devices if self._shared else {}
        self.i2c_ack_all = False
        self._demod_address = None
        self.i2c_masters = [i2c_scb.I2cMaster(self, base, f"SCB{i}") for i, base in enumerate(self.I2C_SCB_BASES)]
        self.smc = smc_m36.SmartCard(self)
        self._flash_windows = [0x0F000000, 0x1F000000]
        self.flash_device = None
        self._flash_read_hooks = []
        self._flash_hooks_pending = False
        self._spi_cmd_vt = -1e9
        self._spi_dump_flash_reads = False
        self.flash_hook_changes = 0
        self._mmio_observers = []
        wins = (ctypes.c_uint32 * 2)(*self._flash_windows)       # (where the core finds the flash windows)
        L.ali_set_flash_cmd(core.handle, 0, wins, 2)
        self._update_flash_read_hooks()
        core.hook_add(UC_HOOK_CODE, self._hook_null_jump, begin=0, end=3)
        self._short_block_hook = None
        self._long_block_hooks = {}
        self._orig_emu_stop = cpp_core.CppUc.emu_stop.__get__(core)
        # the core's interrupt controller (EBase and Status: the shadow attributes, set before)
        L.ali_set_ic(core.handle, self.ic_base, self.ic_base + 8, self.ic_base)
        # first-execution reports of the RAM's 1 MB chunks (LzmaDecode found in new code)
        L.ali_set_chunks(core.handle, 20, min(self.ram_size, 0x08000000) >> 20)

    def _calibrate_hflags(self):
        pass

    def _setup_kuseg_tlb(self):
        return True

    def _write_native_status(self, uc, val):
        self._core.set(F_STATUS, val)

    # ---- the device window: which offsets need the Python handlers ----
    def _mmio_on(self, kind, handler, begin, end):
        super()._mmio_on(kind, handler, begin, end)
        self._mmio_version += 1

    def _mmio_off(self, kind, handler, begin, end):
        super()._mmio_off(kind, handler, begin, end)
        self._mmio_version += 1

    def add_mmio_hook(self, kind, callback, begin, end):
        h = super().add_mmio_hook(kind, callback, begin, end)
        self._mmio_version += 1
        return h

    def remove_mmio_hook(self, handle):
        super().remove_mmio_hook(handle)
        self._mmio_version += 1

    def _switch_family(self, family):
        super()._switch_family(family)
        self._mmio_version += 1

    def _cpp_dev_flags(self):
        """The device window offsets whose accesses go to Python, and how."""
        native_spi = bool(cpp_core.lib().ali_spi_get(self._core.handle, S_ON))
        sig = (self._mmio_version, id(self._mmio_rd), len(self._mmio_rd), id(self._mmio_wr), len(self._mmio_wr),
               len(self._mmio_observers), native_spi)
        if sig == self._dev_sig:
            return
        self._dev_sig = sig
        want = {}
        for off in self._mmio_rd:
            want[off] = want.get(off, 0) | DF_READ
        for off in self._mmio_wr:
            want[off] = want.get(off, 0) | DF_WRITE
        for write, lo, hi, _cb in self._mmio_observers:
            bit = DF_WRITE if write else DF_READ
            for off in range(lo, hi + 1):
                want[off] = want.get(off, 0) | bit
        if native_spi:
            spi_read, spi_write = self._hook_spi_read, self._hook_spi_write
            for off in SPI_REGS:
                if self._mmio_rd.get(off) == [spi_read] and self._mmio_wr.get(off) == [spi_write]:
                    want[off] = 8           # (Core::DF_NATIVE)
        # GPIO DO / DIR stores whose only handler is _hook_gpio_write: the core logs
        # the pin levels after each and hands them over in order (_cpp_gpio)
        gpio_write = self._hook_gpio_write
        for off, handlers in self._mmio_wr.items():
            if handlers == [gpio_write] and not (want[off] & DF_READ) and \
                    not any(w and lo <= off <= hi for w, lo, hi, _cb in self._mmio_observers):
                want[off] = DF_GPIO_DO if (off & ~3 & 0xFFF) in self._GPIO_DO_OFFSETS else DF_GPIO_DIR
        changes = [(off, f) for off, f in want.items() if self._dev_pushed.get(off) != f]
        changes += [(off, 0) for off in self._dev_pushed if off not in want]
        if changes:
            n = len(changes)
            offs = (ctypes.c_uint32 * n)(*[c[0] for c in changes])
            flags = (ctypes.c_uint8 * n)(*[c[1] for c in changes])
            cpp_core.lib().ali_set_dev_flags_list(self._core.handle, offs, flags, n)
        self._dev_pushed = want

    def _cpp_dev(self, user, write, offset, size, value):
        """A device window access that needs Python (the core's DevCb); the GPIO
        events the core logged before it first."""
        try:
            n = self._gpio_count[0]
            if n:
                data = self._gpio_pairs[:2 * n]
                self._gpio_count[0] = 0
                self._gpio_events(data, n)
            if write:
                self._mmio_write(self.mu, offset, size, value, None)
                return 0
            return self._mmio_read(self.mu, offset, size, None) & 0xFFFFFFFFFFFFFFFF
        except BaseException as e:
            self.mu._catch(e)
            return 0

    def _cpp_gpio(self, user, pairs, count):
        """GPIO stores the core logged (DF_GPIO_*), handed over before another
        call into Python than a device access (_cpp_dev empties the log itself)
        and when a run returns."""
        try:
            self._gpio_events(pairs[:2 * count], count)
        except BaseException as e:
            self.mu._catch(e)

    def _gpio_events(self, data, count):
        """The logged pin levels after each GPIO store, to the GPIO handler and
        the board's GPIO devices, in order (as _hook_gpio_write passes them)."""
        cb, devices = self.gpio_callback, self.gpio_devices
        if not cb and not devices:
            return
        for i in range(0, 2 * count, 2):
            address, levels = 0xB8000000 | data[i], data[i + 1]
            if cb:
                cb(address, 4, levels)
            for device in devices:
                device.on_gpio_write(address, 4, levels)

    def _cpp_event(self, user, kind, a, b):
        try:
            if kind == EVT_FLASH_READ:
                self._spi_flash_read(self.mu, a, b)
            elif kind == EVT_CODE_CHUNK:
                self._rescan_cp0_sites([(0x80000000 | a, b)])
            elif kind == EVT_UART_IRQ:
                self.log(f"[UART IRQ] Delivering interrupt #{self._uart_irq_retries} -> {hex(b)} "
                         f"(from {hex(a & ~1)}, icount={self.instruction_count})")
            elif kind == EVT_UART_ERET:
                if len(self._uart_rx_queue) > 0:
                    self._pending_uart_irq = True
                    self._uart_irq_delivered = False
                    self._uart_irq_arm_after = max(self._uart_irq_arm_after, self.instruction_count + 100)
        except BaseException as e:
            self.mu._catch(e)

    def _hook_flash_write_prot(self, uc, access, address, size, value, user_data):
        """A store to the flash window (the Python SPI / parallel flash models): the
        model carries it out, and nothing lands -- the flash shows what the model
        says at once (on Unicorn the store landed and was put back later)."""
        r = super()._hook_flash_write_prot(uc, access, address, size, value, user_data)
        if r is True and any(w <= address < w + 0x01000000 for w in self._flash_windows):
            self._rom_restore()
            return 2
        return r

    # (no replayed device accesses on this core: a stop ends an instruction cleanly)
    def _device_access(self, uc, hooked=False):
        self._dev_last = None

    def _dev_note(self, uc, kind, address, data, exact=None):
        pass

    def _clear_branch_flags(self):
        pass

    def _irq_soon(self):
        pass                            # (the core sees a raised line at the next instruction)

    # ---- the flash window's command mode ----
    def _spi_can_inline_status(self):
        # Native SPI already handles status reads without Python.  Its fallback
        # must use the flash callback: replacing ROM bytes with a status value
        # would leave those bytes behind when the native controller takes over.
        return False

    def _spi_write_ins(self, uc, cmd):
        super()._spi_write_ins(uc, cmd)
        # The shared fast paths do not install Unicorn hooks.  Keep this core's
        # separate flash callback flag in sync even when one returns early.
        self._update_flash_read_hooks()

    def _update_flash_read_hooks(self):
        native = '_core' in self.__dict__ and cpp_core.lib().ali_spi_get(self._core.handle, S_ON)
        wanted = self._flash_hooks_wanted() and not native
        if wanted:
            self._spi_cmd_vt = self._vtime()
        if wanted != self._flash_cmd_on:
            self._flash_cmd_on = wanted
            self.flash_hook_changes += 1
            wins = (ctypes.c_uint32 * len(self._flash_windows))(*self._flash_windows)
            cpp_core.lib().ali_set_flash_cmd(self._core.handle, int(wanted), wins, len(self._flash_windows))
        self._flash_hooks_pending = False

    def setSPIDump(self, enabled, flash_reads=False):
        super().setSPIDump(enabled, flash_reads)
        if '_core' in self.__dict__:
            self._cpp_spi_sync()

    def _apply_flash_hooks(self, force=False):
        self._update_flash_read_hooks()

    def _update_short_block_hook(self):
        pass

    # ---- the interrupt controller ----
    # (the modelled devices' lines are only ever set from Python: read back from a copy)
    @property
    def _ic_lines(self):
        return self.__dict__.get('_ic_lines_v', 0)

    @_ic_lines.setter
    def _ic_lines(self, value):
        self.__dict__['_ic_lines_v'] = value
        self._core.set(F_IC_LINES, value)

    def set_ic_layout(self, status, enable):
        super().set_ic_layout(status, enable)
        cpp_core.lib().ali_set_ic(self._core.handle, status, enable, self.ic_base)

    @property
    def doorbell_in(self):
        return self._doorbell

    @doorbell_in.setter
    def doorbell_in(self, value):
        self._doorbell = value
        if value is None:
            cpp_core.lib().ali_set_doorbell(self._core.handle, -1, 0)
        else:
            cpp_core.lib().ali_set_doorbell(self._core.handle, value[0], value[1])

    def _ic_ip3(self):
        return bool(self._core.get(F_IC_IP3))

    # ------------------------------------------------------------------
    # CPU state, time
    # ------------------------------------------------------------------
    def is_mips16_mode(self, pc=None):
        return bool(self._core.get(F_M16))

    def get_hflags(self):
        return (0x400 if self._core.get(F_M16) else 0) | (0x800 if self._core.get(F_DS_ACTIVE) else 0)

    @property
    def isa_mode(self):
        return ISAMode.MIPS16 if self.is_mips16_mode() else ISAMode.MIPS32

    @isa_mode.setter
    def isa_mode(self, value):
        self._isa_mode_fallback = value
        pc = self.mu.reg_read(UC_MIPS_REG_PC) & ~1
        self.mu.reg_write(UC_MIPS_REG_PC, pc | (1 if value == ISAMode.MIPS16 else 0))

    def _start_pc(self, pc):
        same = (pc & ~1) == self.mu.reg_read(UC_MIPS_REG_PC)
        m16 = self.is_mips16_mode() if same else bool(pc & 1) or self.is_mips16_addr(pc)
        return (pc & ~1) | (1 if m16 else 0)

    def _at_safe_point(self):
        return not self._core.get(F_DS_ACTIVE)

    def _vtime(self):
        """Emulation time in seconds: the core's instruction count at cpp_ips."""
        return self._core.get(F_ICOUNT) / self.cpp_ips

    def _setup_clock(self):
        pass

    @property
    def _vt_accum(self):
        """(The Unicorn engine's emulation time of finished slices: here the clock.)"""
        return self._vtime()

    @_vt_accum.setter
    def _vt_accum(self, value):
        if '_core' in self.__dict__ and self.__dict__.get('_hflags_off') is not None:
            self._core.set(F_ICOUNT, max(0, int(round(value * self.cpp_ips))))

    @property
    def idle_skipped(self):
        """Emulation time the core skipped in idle loops (seconds)."""
        return self._core.get(F_IDLE_SKIPPED) / self.cpp_ips

    @idle_skipped.setter
    def idle_skipped(self, value):
        self._core.set(F_IDLE_SKIPPED, int(round(value * self.cpp_ips)))

    @property
    def cpp_access_cost(self):
        """Instructions of emulated time a device access handled in Python costs."""
        return self._core.get(cpp_core.F_HOST_ACCESS_COST)

    @cpp_access_cost.setter
    def cpp_access_cost(self, value):
        self._core.set(cpp_core.F_HOST_ACCESS_COST, int(value))

    @property
    def count_hz(self):
        return self._count_hz_v

    @count_hz.setter
    def count_hz(self, value):
        self._count_hz_v = value
        if '_core' in self.__dict__ and self.__dict__.get('_hflags_off') is not None:
            self._apply_count_ratio()

    def _apply_count_ratio(self):
        """Count per instruction: 2 in exact mode (the hardware's half clock), else
        count_hz per emulated second."""
        if self._want_full_hook():
            cpp_core.lib().ali_set_count_ratio(self._core.handle, 2, 1)
        else:
            cpp_core.lib().ali_set_count_ratio(self._core.handle, int(self._count_hz_v), int(self.cpp_ips))

    @property
    def cp0_count(self):
        return self._core.get(F_COUNT)

    @cp0_count.setter
    def cp0_count(self, value):
        self._core.set(F_COUNT_RAW_WRITE, value)

    def _cp0_count_now(self):
        return self._core.get(F_COUNT)

    def _rebase_count(self):
        pass

    @property
    def _count_observed(self):
        return self._core.get(F_COUNT_OBSERVED) if self._core.get(F_COUNT_OBSERVED_VALID) else None

    @_count_observed.setter
    def _count_observed(self, value):
        self._core.set(F_COUNT_OBSERVED_VALID, value is not None)
        if value is not None:
            self._core.set(F_COUNT_OBSERVED, value)

    @property
    def timer_enabled(self):
        return bool(self._core.get(F_TIMER_ENABLED))

    @timer_enabled.setter
    def timer_enabled(self, on):
        self._core.set(F_TIMER_ENABLED, bool(on))

    def _timer_update(self, now=None):
        cpp_core.lib().ali_timer_update(self._core.handle)

    def _write_compare(self, val):
        self._core.set(F_COMPARE_WRITE, val)

    def _cause_value(self):
        return self._core.get(F_CAUSE_VALUE)

    def _irq_deliverable(self):
        cpp_core.lib().ali_timer_update(self._core.handle)     # (a Compare passed by a time step latches first)
        return bool(self._core.get(F_IRQ_DELIVERABLE))

    def _enter_interrupt(self, uc, epc):
        vec = cpp_core.lib().ali_enter_interrupt(self._core.handle, epc & 0xFFFFFFFF)
        return vec

    def _cp0_read(self, rd, sel):
        return cpp_core.lib().ali_cp0_read(self._core.handle, rd, sel)

    def _cp0_write(self, uc, rd, sel, val):
        cpp_core.lib().ali_cp0_write(self._core.handle, rd, sel, val & 0xFFFFFFFF)
        return False

    def _reschedule_slice(self):
        pass

    def _irq_gap_left(self, now=None):
        return 0.0

    def _timer_wait_us(self, count=None):
        """Microseconds of emulation time until Count reaches Compare (None: no tick
        due; 0: one is pending and deliverable)."""
        d = cpp_core.lib().ali_timer_wait(self._core.handle)      # (one call: the core checks all of it)
        if d < 0:
            return None if d == -1 else 0.0
        return d * 1e6 / self._count_hz_v

    def _get_stopper(self):
        return None

    # the UART receive interrupt's arming point, in instruction_count units for Python
    @property
    def _uart_irq_arm_after(self):
        return self._uart_arm_units

    @_uart_irq_arm_after.setter
    def _uart_irq_arm_after(self, value):
        self._uart_arm_units = value
        if self.__dict__.get('_hflags_off') is None:
            return                      # (still in __init__)
        ahead = max(0, value - self.instruction_count)
        exact = self._want_full_hook() or self._timeout_slices == 0
        per_unit = 1.0 if exact else self.cpp_ips / self._insn_rate
        self._core.set(F_UART_AT, self._core.get(F_ICOUNT) + int(ahead * per_unit))

    def _services_due(self):
        """The earliest due() of the slice services that have one, or None."""
        due = None
        for service in self.slice_services:
            fn = getattr(getattr(service, '__self__', None), 'due', None)
            t = fn() if fn is not None else None
            if t is not None and (due is None or t < due):
                due = t
        return due

    def _advance_time(self, seconds):
        """Between slices: the emulation time moves on (the core's clock), and the
        instruction count with it at _insn_rate (to the budget at most)."""
        ticks = int(round(seconds * self.cpp_ips))
        if seconds > 0 and ticks < 1:
            ticks = 1                   # (the clock is whole instructions: a shorter step would never end)
        self._core.set(F_ICOUNT, self._core.get(F_ICOUNT) + ticks)
        counted = round(seconds * self._insn_rate)
        budget = self._budget()
        if budget is not None:
            counted = min(counted, budget)
        self.instruction_count += counted

    def _delay_jump(self, wait):
        self._core.set(F_ICOUNT, self._core.get(F_ICOUNT) + int(round(wait * self.cpp_ips)))
        self.delay_skipped += wait

    # The RTOS's delay() shortcut (simulator.delay_hle): the Python hooks, with the
    # time a wait may skip ending at the slice's end or the next timer interrupt,
    # whichever comes first -- the core then takes the interrupt itself, inside the
    # wait as on the hardware (no slice stop needed).
    @property
    def _slice_cap_end(self):
        return self.__dict__.get('_cpp_slice_end')

    @_slice_cap_end.setter
    def _slice_cap_end(self, value):
        pass

    @property
    def _slice_armed_end(self):
        end = self.__dict__.get('_cpp_slice_end')
        if end is None:
            return None
        w = self._timer_wait_us()
        if w is not None:
            end = min(end, self._vtime() + w / 1e6)
        return end

    @_slice_armed_end.setter
    def _slice_armed_end(self, value):
        pass

    def _hook_delay_loop(self, uc, address, size, user_data):
        entry = self._delay_loops.get(address)
        routine = self._delay_routine(entry) if size == 4 and entry is not None else None
        if routine is None or self._slice_cap_end is None:
            return
        build = self._DELAYS[routine[3]]
        ticks, start = self._reg_read(self.gpr_map[build["ticks"]]), self._reg_read(self.gpr_map[build["start"]])
        if build["past"]:
            if ticks == 0xFFFFFFFF:
                return
            ticks += 1
        waited = (self._cp0_count_now() - start) & 0xFFFFFFFF
        if waited >= ticks:
            return
        wait, room = (ticks - waited) / self.count_hz, self._slice_armed_end - self._vtime()
        self.delay_jumps += 1
        self._delay_jump(min(wait, max(0.0, room)))

    # ------------------------------------------------------------------
    # Hooks: breakpoints, the exact mode's per-instruction bookkeeping,
    # LzmaDecode() found in new code
    # ------------------------------------------------------------------
    def _cpp_sync(self):
        """Before the core runs: the device window flags, the native breakpoints,
        the exact mode, the flash command mode."""
        self._cpp_spi_sync()
        self._cpp_dev_flags()
        wanted = set(self.breakpoints)
        if self.stop_instr is not None:
            wanted.add(self.stop_instr)
        if wanted != self._bp_pushed:
            self._bp_pushed = set(wanted)
            arr = (ctypes.c_uint32 * max(1, len(wanted)))(*sorted(a & 0xFFFFFFFF for a in wanted))
            cpp_core.lib().ali_set_breakpoints(self._core.handle, arr, len(wanted))
        full = self._want_full_hook()
        if full and self._exact_hook is None:
            self._exact_hook = self._core.hook_add(UC_HOOK_CODE, self._cpp_hook_code)
            self._code_hook_h = self._exact_hook
            self._core.set(F_EXACT, 1)
            self._apply_count_ratio()
        elif not full and self._exact_hook is not None:
            self._core.hook_del(self._exact_hook)
            self._exact_hook = None
            self._code_hook_h = None
            self._core.set(F_EXACT, 0)
            self._apply_count_ratio()
        if self._flash_hooks_pending:
            self._update_flash_read_hooks()

    def _cpp_after_start(self, executed):
        if self._rom_dirty:
            self._rom_restore()

    def _sync_hooks(self):
        self._cpp_sync()

    def _sync_hooks_if_ready(self):
        if '_core' in self.__dict__ and self.mu is not None:
            self._cpp_sync()

    def loadFile(self, filename, chip=None):
        if self.__dict__.get('_rom_image_ref') is not None:
            cpp_core.lib().ali_spi_config(self._core.handle, 0, ctypes.addressof(self.rom_buffer), None,
                                          self.rom_size, 0xEF4016)
            self._rom_image_ref = None
            self._spi_key = None
        super().loadFile(filename, chip=chip)
        self._cpp_spi_sync()

    def _rescan_all(self):
        """A new image: LzmaDecode() in the flash, every RAM chunk's first execution
        reported again."""
        self._rom_sites_dirty = True
        self._rescan_cp0_sites(None)
        cpp_core.lib().ali_set_chunks(self._core.handle, 20, min(self.ram_size, 0x08000000) >> 20)

    def _rescan_cp0_sites(self, ranges=None):
        """No CP0 sites on this core: only LzmaDecode() (and the RTOS's delay(), when
        delay_hle is on) is looked for, in the flash image or the given ranges."""
        if ranges is None:
            if self._rom_sites_dirty:
                self._rom_sites_dirty = False
                self._find_lzma_decoders(self.rom_image, 0, (0xAFC00000, 0xBFC00000, 0x8FC00000, 0x9FC00000))
            ranges = self.chip.code_ranges()
        for start, length in ranges:
            phys = start & 0x1FFFFFFF
            if (start >> 29) in (0, 4, 5) and phys + length <= self.ram_size:
                data = self._ram_view[phys:phys + length]
            else:
                try:
                    data = self.mu.mem_read(start, length)
                except UcError:
                    continue
            if (start >> 29) in (4, 5):
                self._find_lzma_decoders(data, phys, (0x80000000, 0xA0000000))
                self._find_delay_routines(data, phys, (0x80000000, 0xA0000000))

    def _cpp_hook_code(self, uc, address, size, user_data):
        """Exact mode: the per-instruction bookkeeping of the Python engine's
        _hook_code (history, visit counts, sizes, ISA, trace); the core does the
        rest itself."""
        m16 = size == 2 or uc.hook_m16 == 1          # (passed with the hook: no read-back per instruction)
        self.prev_executed_pc = self.current_executed_pc
        self.current_executed_pc = address
        self._last_hook_size, self._last_hook_addr = size, address
        self.pc_history.append(address)
        if len(self.pc_history) > self.history_size:
            self.pc_history.pop(0)
        self.visit_counts[address] = self.visit_counts.get(address, 0) + 1
        self.instruction_sizes[address] = size
        self.instruction_isa[address] = m16
        if self.trace_instructions:
            try:
                insn = bytes(uc.mem_read(address, size))
                loop_str = f" [LOOP {self.visit_counts[address]}]" if self.visit_counts[address] > 1 else ""
                bytes_str = ' '.join(f'{b:02x}' for b in insn)
                if m16:
                    from mips16_decoder import MIPS16Decoder
                    mnemonic, operands = MIPS16Decoder.decode(insn, address)
                    self.log(f"0x{address:08X}: {bytes_str:<15} {mnemonic}\t{operands}{loop_str}")
                else:
                    for i in self.md.disasm(insn, address):
                        self.log(f"0x{i.address:08X}: {bytes_str:<15} {i.mnemonic}\t{i.op_str}{loop_str}")
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Running
    # ------------------------------------------------------------------
    def _raise_core_error(self):
        err = self._core.get(F_LAST_ERROR)
        pc = self._core.get(F_FAULT_PC)
        self.log(f"Core error {err} at PC=0x{pc:08X} (address 0x{self._core.get(F_FAULT_ADDR):08X})")
        e = UcError(err)
        self._log_unicorn_error(e)
        raise e

    def _core_run(self, limit, idle):
        """One slice on the core: until its instruction count reaches limit.
        Returns (stop reason, instructions executed)."""
        core = self._core
        core.set(F_IDLE_SKIP, 1 if idle else 0)
        e0 = core.get(F_EXECUTED)
        r = core.run(limit)
        return r, core.get(F_EXECUTED) - e0

    def run(self, max_instructions=None, max_vtime=None):
        """As AliMipsSimulator.run: until max_instructions (instruction_count) or
        the emulation time max_vtime."""
        if max_instructions is not None:
            self.max_instructions = max_instructions
        core = self._core
        cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        note = "" if self._want_full_hook() else " [C++ core: instruction counts follow emulation time]"
        self.log(f"Starting emulation at {hex(cur_pc)} ({'MIPS16' if self.is_mips16_mode() else 'MIPS32'})...{note}")
        self._in_run = True
        self._run_tid = threading.get_ident()
        self._external_stop = False
        self._run_max_vtime = max_vtime
        try:
            while True:
                if self._external_stop:
                    break
                if self.max_instructions and self.instruction_count >= self.max_instructions:
                    break
                if max_vtime is not None and self._vtime() >= max_vtime:
                    break
                if cur_pc in self.breakpoints or (self.stop_instr is not None and cur_pc == self.stop_instr):
                    self.step()
                    cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
                    if self.max_instructions and self.instruction_count >= self.max_instructions:
                        break
                    if (cur_pc & ~1) == 0:
                        break
                self._cpp_sync()
                full = self._exact_hook is not None
                if self._irc_frames:
                    self._irc_service()
                for service in self.slice_services:
                    service()
                if self.busy_pending > 1e-9 and not full and self._skip_busy(max_vtime):
                    continue
                if not full and self.poll_skip and self._skip_poll(cur_pc, max_vtime):
                    continue
                budget = self._budget()
                self._stop_reason = None
                icount = core.get(F_ICOUNT)
                if full:
                    # exact mode: instruction_count is the core's executed count
                    n = budget if budget is not None else self.batch_size
                    if max_vtime is not None:
                        n = min(n, max(1, int((max_vtime - self._vtime()) * self.cpp_ips)))
                    r, executed = self._core_run(icount + max(1, n), False)
                    self.instruction_count += executed
                else:
                    small = budget is not None and budget <= self.exact_count_threshold
                    calibrating = self._counted_slices < self.calibration_slices
                    if self._timeout_slices == 0 and (small or calibrating):
                        batch = max(1, self.batch_size if budget is None else min(self.batch_size, budget))
                        if max_vtime is not None:
                            batch = max(1, min(batch, int((max_vtime - self._vtime()) * self.cpp_ips) + 1))
                        r, executed = self._core_run(icount + batch, False)
                        self.instruction_count += executed
                        self._counted_slices += 1
                    else:
                        slice_s = self.batch_timeout_us / 1e6
                        due = self._services_due()
                        if due is not None:
                            slice_s = min(slice_s, max(due - self._vtime(), self.SERVICE_MIN_SLICE_S))
                        if budget is not None:
                            slice_s = min(slice_s, budget / self._insn_rate)
                        if max_vtime is not None:
                            slice_s = min(slice_s, max(0.0, max_vtime - self._vtime()))
                        n = max(1, int(round(slice_s * self.cpp_ips)))
                        self._cpp_slice_end = (icount + n) / self.cpp_ips
                        try:
                            r, _executed = self._core_run(icount + n, self.idle_skip)
                        finally:
                            self._cpp_slice_end = None
                        dt = (core.get(F_ICOUNT) - icount) / self.cpp_ips
                        counted = int(self._insn_rate * dt)
                        if budget is not None:
                            counted = min(counted, budget)
                        if r == STOP_COUNT and budget is not None and slice_s >= budget / self._insn_rate - 1e-12:
                            counted = budget        # (the slice was the rest of the budget)
                        self.instruction_count += counted
                        self._timeout_slices += 1
                core._raise_pending()
                if self._rom_dirty:
                    self._rom_restore()
                if r == STOP_ERROR:
                    self._raise_core_error()
                cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
                if (cur_pc & ~1) == 0 or self._stop_reason == 'null':
                    self.log("[!] Stopped: Jump to NULL")
                    break
                if r == STOP_BREAKPOINT:
                    if self.stop_instr is not None and cur_pc == self.stop_instr:
                        self.log(f"\n[STOP] Reached stop address: 0x{cur_pc:08X}")
                        self._stop_reason = 'stop_instr'
                    else:
                        self.log(f"\n[BREAKPOINT] Hit at 0x{cur_pc:08X}")
                        self._stop_reason = 'breakpoint'
                    break
                if self._stop_reason == 'external' or self._external_stop:
                    break
        except UcError:
            raise
        except Exception as e:
            import traceback
            self.log(f"Error: {e}")
            self.log(traceback.format_exc())
            raise
        finally:
            self._in_run = False
            self._run_max_vtime = None

    def _exec_one(self, pc):
        """Exactly one instruction at pc (no interrupt: the next run() takes it; a
        breakpoint there is stepped over)."""
        core = self._core
        self._cpp_sync()
        core.set(F_IRQS_ENABLED, 0)
        core.set(F_STEP_OVER_BP, 1)
        self.is_stepping = True
        self._stop_reason = None
        e0 = core.get(F_EXECUTED)
        try:
            cpp_core.CppUc.emu_start(core, self._start_pc(pc), 0xFFFFFFFFFFFFFFFF, 0, 1)
            if core.get(F_DS_ACTIVE):
                # a branch: its delay slot too, as a step on Unicorn does (it cannot stop between them)
                cpp_core.CppUc.emu_start(core, core.get(F_PC_MODE), 0xFFFFFFFFFFFFFFFF, 0, 1)
        finally:
            self.is_stepping = False
            core.set(F_IRQS_ENABLED, 1)
            core.set(F_STEP_OVER_BP, 0)
            self.instruction_count += core.get(F_EXECUTED) - e0
            if self._rom_dirty:
                self._rom_restore()

    def _log_unicorn_error(self, e):
        try:
            pc = self.mu.reg_read(UC_MIPS_REG_PC)
            m16 = self.is_mips16_mode()
            self.log(f"Core error: {e}")
            self.log(f"PC at error: {hex(pc)} ({'MIPS16' if m16 else 'MIPS32'})")
            self.log(f"Status at error: {hex(self.cp0_status)}")
            mnemonic, operands, sz = self._decode_for_display(pc, m16)
            raw = bytes(self.mu.mem_read(pc, sz)).hex()
            self.log(f"Instruction at PC: {raw} {mnemonic} {operands}")
        except Exception:
            pass
