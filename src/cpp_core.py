"""
The C++ core (cpp/emulator, built by cpp\\build.bat into cpp/build/alicore.dll on
Windows, by cpp/build.sh into cpp/build/libalicore.so elsewhere)
seen through Unicorn's Python API: CppUc has the Uc methods the simulator, the
device models and the tests use -- mem_map_ptr, mmio_map, mem_read / mem_write,
reg_read / reg_write, hook_add / hook_del, emu_start / emu_stop, ctl_* -- with
Unicorn's semantics (addresses as mapped, code hooks before the instruction,
a PC written by a hook redirects, memory hooks get physical addresses), so
code written for Unicorn runs on it unchanged.  The core does the CPU side of
the ALi machine itself (CP0, the timer, interrupts, the clock); simulator_cpp
puts the simulator on it.

Exceptions raised inside a callback stop the emulation and are raised again by
the emu_start() / run() that ran it, as the Unicorn binding does.
"""
import ctypes
import os
import sys

from unicorn import UcError
from unicorn.unicorn_const import (UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
                                   UC_HOOK_MEM_FETCH, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_PROT,
                                   UC_HOOK_MEM_UNMAPPED, UC_HOOK_BLOCK)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# the core's library: cpp\build.bat (MSVC) builds alicore.dll, cpp/build.sh (g++ / clang) libalicore.so
LIB_NAME = "alicore.dll" if os.name == "nt" else "libalicore.so"
BUILD_HINT = "cpp\\build.bat" if os.name == "nt" else "cpp/build.sh"
DLL_PATH = os.environ.get("ALISIM_CPP_DLL") or os.path.join(ROOT, "cpp", "build", LIB_NAME)

# ali_get / ali_set fields (alicore_api.cpp)
(F_ICOUNT, F_EXECUTED, F_STATUS, F_CAUSE, F_CAUSE_VALUE, F_EPC, F_EBASE, F_COMPARE, F_COUNT, F_TI,
 F_TIMER_ARMED, F_TIMER_ENABLED, F_TIMER_IRQS, F_IC_IRQS, F_UART_IRQS, F_IC_LINES, F_UART_IP3, F_UART_PENDING,
 F_UART_DELIVERED, F_UART_AT, F_UART_FORCE, F_IDLE_SKIP, F_EXACT, F_IRQS_ENABLED, F_M16, F_DS_ACTIVE,
 F_IDLE_SKIPPED, F_CNUM, F_CDEN, F_FAULT_PC, F_FAULT_ADDR, F_FAULT_ACCESS, F_STEP_OVER_BP, F_IRQ_DELIVERABLE,
 F_IC_IP3, F_TIMER_ANCHOR, F_LAST_ERROR, F_STOP_REASON, F_ERROR_EPC, F_COMPARE_WRITE, F_PC_MODE,
 F_COUNT_OBSERVED, F_COUNT_OBSERVED_VALID, F_CHUNK_EVENTS, F_DS_TARGET, F_DS_M16, F_BADVADDR, F_LLBIT,
 F_TIMER_CHECK_AT, F_COUNT_RAW_WRITE, F_HOST_ACCESS_COST, F_BLOCKS_ON, F_BLOCK_RUNS, F_BLOCK_BUILDS,
 F_NEXT_EVENT, F_LIMIT, F_SPIN_SKIPPED, F_SPIN_SKIP, F_POLL_SKIPPED, F_POLL_SKIPS,
 F_FF_SKIPPED) = range(1, 62)

# run() / emu_start() stop reasons (alicore.h StopReason)
STOP_NONE, STOP_COUNT, STOP_UNTIL, STOP_REQUEST, STOP_ERROR, STOP_BREAKPOINT, STOP_NULL, STOP_TIMEOUT = range(8)
# machine events (alicore.h EVT_*)
EVT_UART_ERET, EVT_CODE_CHUNK, EVT_FLASH_READ, EVT_UART_IRQ = 1, 2, 3, 5
# device window flags (Core::DF_*)
DF_READ, DF_WRITE, DF_NATIVE, DF_GPIO_DO, DF_GPIO_DIR = 1, 2, 8, 16, 32

REG_F0 = 1000           # the FPU registers F0..F31 (64-bit) of the core
REG_CP0_BASE = 2000     # CP0 register rd, sel: REG_CP0_BASE + 8 * rd + sel

_MMIO_READ = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32)
_MMIO_WRITE = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint64)
_CODE_HOOK = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint32)
_MEM_HOOK = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int, ctypes.c_uint64, ctypes.c_int, ctypes.c_int64)
_EVENT_HOOK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_uint64, ctypes.c_int,
                               ctypes.c_int64)
_INTR_HOOK = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_uint32)
_DEV_CB = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32,
                           ctypes.c_uint64)
_MACHINE_EVENT = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int, ctypes.c_uint64, ctypes.c_uint64)
_GPIO_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32)

_lib = None


def available():
    """Whether the core's DLL is there (built)."""
    return os.path.exists(DLL_PATH)


def _shadow_copy(path):
    """A copy of the DLL to load (Windows locks a loaded DLL: with the copy,
    cpp\\build.bat can replace the original while simulations run).  One copy
    per build (named after its size and time), shared by every process that
    loads that build and made under a temporary name first, so a process never
    sees another's half-made or removed copy (a copy per process, cleaned by
    the next one, raced: one process removed another's before it was loaded).
    Other builds' copies are removed once an hour old and no longer loaded.
    ALISIM_CPP_NOSHADOW=1 loads the DLL itself."""
    import shutil
    import tempfile
    import time
    if os.environ.get("ALISIM_CPP_NOSHADOW"):
        return path
    folder = os.path.join(tempfile.gettempdir(), "alisim_cpp")
    try:
        st = os.stat(path)
        name = f"alicore_{st.st_size:x}_{st.st_mtime_ns:x}{os.path.splitext(path)[1]}"
        copy = os.path.join(folder, name)
        os.makedirs(folder, exist_ok=True)
        if not os.path.exists(copy):
            tmp = f"{copy}.{os.getpid()}.tmp"
            shutil.copyfile(path, tmp)
            try:
                os.replace(tmp, copy)
            except OSError:                 # (another process made it meanwhile: theirs is the same)
                os.remove(tmp)
        now = time.time()
        for other in os.listdir(folder):
            if other != name:
                try:
                    if now - os.path.getmtime(os.path.join(folder, other)) > 3600:
                        os.remove(os.path.join(folder, other))
                except OSError:
                    pass                    # (still loaded by a running simulation)
        return copy
    except OSError:
        return path


def lib():
    """The core's DLL, loaded once with its function signatures."""
    global _lib
    if _lib is not None:
        return _lib
    if not available():
        raise FileNotFoundError(f"the C++ core is not built: {DLL_PATH} (run {BUILD_HINT})")
    L = ctypes.CDLL(_shadow_copy(DLL_PATH))
    vp, u64, u32, i32 = ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_int
    sig = {
        "ali_new": (vp, []), "ali_free": (None, [vp]),
        "ali_map_ptr": (i32, [vp, u64, u64, u32, vp]), "ali_map_alloc": (i32, [vp, u64, u64, u32]),
        "ali_map_mmio": (i32, [vp, u64, u64, vp, vp, vp, vp]), "ali_unmap": (i32, [vp, u64, u64]),
        "ali_protect": (i32, [vp, u64, u64, u32]),
        "ali_mem_read": (i32, [vp, u64, vp, u64]), "ali_mem_write": (i32, [vp, u64, vp, u64]),
        "ali_regions": (i32, [vp, ctypes.POINTER(u64), i32]),
        "ali_reg_read": (i32, [vp, i32, ctypes.POINTER(u64)]), "ali_reg_write": (i32, [vp, i32, u64]),
        "ali_hook_add": (i32, [vp, i32, vp, vp, u64, u64, ctypes.POINTER(u64)]), "ali_hook_del": (i32, [vp, u64]),
        "ali_emu_start": (i32, [vp, u64, u64, u64, u64]), "ali_emu_stop": (None, [vp]),
        "ali_run": (i32, [vp, u64]), "ali_step_one": (i32, [vp]),
        "ali_set_device_window": (None, [vp, u32, vp, u32, vp, vp]),
        "ali_set_dev_flags": (None, [vp, u32, u32, ctypes.c_uint8]),
        "ali_set_dev_flags_list": (None, [vp, ctypes.POINTER(u32), ctypes.POINTER(ctypes.c_uint8), i32]),
        "ali_set_event_cb": (None, [vp, vp, vp]),
        "ali_set_breakpoints": (None, [vp, ctypes.POINTER(u32), i32]),
        "ali_set_chunks": (None, [vp, i32, u32]), "ali_chunk_mark": (None, [vp, u32, i32]),
        "ali_set_flash_cmd": (None, [vp, i32, ctypes.POINTER(u32), i32]),
        "ali_set_count_ratio": (None, [vp, u64, u64]),
        "ali_set_ic": (None, [vp, u32, u32, u32]), "ali_set_doorbell": (None, [vp, ctypes.c_int32, ctypes.c_int32]),
        "ali_uart_arm": (None, [vp, u64, i32]), "ali_enter_interrupt": (u32, [vp, u32]),
        "ali_timer_update": (None, [vp]), "ali_timer_wait": (ctypes.c_int64, [vp]), "ali_poke": (None, [vp]),
        "ali_cp0_read": (u32, [vp, i32, i32]), "ali_cp0_write": (None, [vp, i32, i32, u32]),
        "ali_get": (u64, [vp, i32]), "ali_set": (None, [vp, i32, u64]),
        "ali_spi_config": (None, [vp, i32, vp, vp, u32, u32]),
        "ali_spi_get": (u64, [vp, i32]), "ali_spi_set": (None, [vp, i32, u64]),
        "ali_set_gpio_cb": (None, [vp, vp, vp]),
        "ali_gpio_log": (None, [vp, i32, ctypes.POINTER(vp), ctypes.POINTER(vp)]),
        "ali_direct": (vp, [vp, u64, ctypes.POINTER(u64), ctypes.POINTER(u64)]),
        "ali_prof": (None, [vp, i32]), "ali_prof_top": (i32, [vp, i32, vp, vp, i32]),
    }
    for name, (res, args) in sig.items():
        f = getattr(L, name)
        f.restype, f.argtypes = res, args
    _lib = L
    return L


class CppUc:
    """A Uc look-alike on the C++ core (see the module docstring)."""

    def __init__(self, arch=None, mode=None):
        self._lib = lib()
        self._h = self._lib.ali_new()
        self._direct = []               # (begin, end, view) of plain regions mem_read reads in place
        self._keep = []                 # ctypes callbacks and buffers that must outlive their use
        self._hooks = {}                # handle -> (ctypes callback, ...)
        self._exc = None                # an exception raised inside a callback
        self._val = ctypes.c_uint64()
        self._ref = ctypes.byref(self._val)
        self._read, self._write = self._lib.ali_reg_read, self._lib.ali_reg_write
        self._get, self._set = self._lib.ali_get, self._lib.ali_set

    def __del__(self):
        try:
            if self._h:
                self._lib.ali_free(self._h)
                self._h = None
        except Exception:
            pass

    @property
    def handle(self):
        return self._h

    # ---- errors from callbacks ----
    def _catch(self, e):
        if self._exc is None:
            self._exc = e
        self._lib.ali_emu_stop(self._h)

    def _raise_pending(self):
        if self._exc is not None:
            e, self._exc = self._exc, None
            raise e

    # ---- configuration (Unicorn ctl_*): nothing to do for this core ----
    def ctl_set_cpu_model(self, model):
        pass

    def ctl_flush_tb(self):
        pass

    def ctl_remove_cache(self, begin, end):
        pass

    # ---- memory ----
    # mem_read of plain memory (RAM, the flash windows, the 0xB8 / 0x98 views of the
    # device registers) reads the region's host memory in place; the regions it
    # knows are dropped whenever the map changes
    def _direct_region(self, address):
        base, size = ctypes.c_uint64(), ctypes.c_uint64()
        ptr = self._lib.ali_direct(self._h, address, ctypes.byref(base), ctypes.byref(size))
        if not ptr:
            return None
        view = memoryview((ctypes.c_char * size.value).from_address(ptr)).cast('B')
        entry = (base.value, base.value + size.value, view)
        self._direct.insert(0, entry)
        del self._direct[8:]
        return entry

    def _map_changed(self):
        self._direct = []

    def mem_map(self, address, size, perms=7):
        self._map_changed()
        self._check(self._lib.ali_map_alloc(self._h, address, size, perms))

    def mem_map_ptr(self, address, size, perms, ptr):
        self._map_changed()
        self._check(self._lib.ali_map_ptr(self._h, address, size, perms, ptr))

    def mmio_map(self, address, size, read_cb, user_data_read, write_cb, user_data_write):
        uc = self

        def rd(user, offset, size):
            try:
                return read_cb(uc, offset, size, user_data_read) & 0xFFFFFFFFFFFFFFFF if read_cb else 0
            except BaseException as e:
                uc._catch(e)
                return 0

        def wr(user, offset, size, value):
            try:
                if write_cb:
                    write_cb(uc, offset, size, value, user_data_write)
            except BaseException as e:
                uc._catch(e)

        crd, cwr = _MMIO_READ(rd), _MMIO_WRITE(wr)
        self._keep += [crd, cwr]
        self._map_changed()
        self._check(self._lib.ali_map_mmio(self._h, address, size, ctypes.cast(crd, ctypes.c_void_p), None,
                                           ctypes.cast(cwr, ctypes.c_void_p), None))

    def mem_unmap(self, address, size):
        self._map_changed()
        self._check(self._lib.ali_unmap(self._h, address, size))

    def mem_protect(self, address, size, perms=7):
        self._map_changed()
        self._check(self._lib.ali_protect(self._h, address, size, perms))

    def mem_regions(self):
        buf = (ctypes.c_uint64 * (3 * 512))()
        n = self._lib.ali_regions(self._h, buf, 512)
        for i in range(min(n, 512)):
            yield (buf[3 * i], buf[3 * i + 1], buf[3 * i + 2])

    def mem_read(self, address, size):
        for lo, hi, view in self._direct:
            if lo <= address and address + size <= hi:
                return bytearray(view[address - lo:address - lo + size])
        entry = self._direct_region(address)
        if entry is not None and address + size <= entry[1]:
            return bytearray(entry[2][address - entry[0]:address - entry[0] + size])
        buf = ctypes.create_string_buffer(size)
        err = self._lib.ali_mem_read(self._h, address, buf, size)
        self._raise_pending()
        if err:
            raise UcError(err)
        return bytearray(buf.raw)

    def mem_write(self, address, data):
        data = bytes(data)
        err = self._lib.ali_mem_write(self._h, address, data, len(data))
        self._raise_pending()
        if err:
            raise UcError(err)

    # ---- registers ----
    def reg_read(self, reg_id, opt=None):
        err = self._read(self._h, reg_id, self._ref)
        if err:
            raise UcError(err)
        return self._val.value

    def reg_write(self, reg_id, value):
        err = self._write(self._h, reg_id, value & 0xFFFFFFFFFFFFFFFF)
        if err:
            raise UcError(err)

    # ---- hooks ----
    def hook_add(self, htype, callback, user_data=None, begin=1, end=0, arg1=0, arg2=0):
        uc = self
        if htype & UC_HOOK_CODE or htype & UC_HOOK_BLOCK:
            def cb(user, address, size, m16):
                uc.hook_m16 = m16           # (the instruction's ISA: 1 MIPS16, for the callback)
                try:
                    callback(uc, address, size, user_data)
                except BaseException as e:
                    uc._catch(e)
            ccb = _CODE_HOOK(cb)
            htype = UC_HOOK_CODE
        elif htype & (UC_HOOK_MEM_INVALID):
            def cb(user, access, address, size, value):
                try:
                    r = callback(uc, access, address, size, value, user_data)
                    # (True: go on, the store lands; 2: handled, the store does not land)
                    return r if type(r) is int and r == 2 else (1 if r else 0)
                except BaseException as e:
                    uc._catch(e)
                    return 0
            ccb = _EVENT_HOOK(cb)
        elif htype & (UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH):
            def cb(user, access, address, size, value):
                try:
                    callback(uc, access, address, size, value, user_data)
                except BaseException as e:
                    uc._catch(e)
            ccb = _MEM_HOOK(cb)
        elif htype & UC_HOOK_INTR:
            def cb(user, intno):
                try:
                    callback(uc, intno, user_data)
                except BaseException as e:
                    uc._catch(e)
            ccb = _INTR_HOOK(cb)
        else:
            raise UcError(9)     # UC_ERR_HOOK: not supported by this core
        hid = ctypes.c_uint64()
        self._check(self._lib.ali_hook_add(self._h, htype, ctypes.cast(ccb, ctypes.c_void_p), None, begin, end,
                                           ctypes.byref(hid)))
        self._hooks[hid.value] = ccb
        return hid.value

    def hook_del(self, handle):
        self._lib.ali_hook_del(self._h, handle)
        self._hooks.pop(handle, None)

    # ---- execution ----
    def emu_start(self, begin, until, timeout=0, count=0):
        err = self._lib.ali_emu_start(self._h, begin, until, timeout, count)
        self._raise_pending()
        if err:
            raise UcError(err)

    def emu_stop(self):
        self._lib.ali_emu_stop(self._h)

    def run(self, icount_limit):
        """The simulator's run: until the instruction count reaches icount_limit (a
        stop reason, STOP_*)."""
        r = self._lib.ali_run(self._h, icount_limit)
        self._raise_pending()
        return r

    # ---- context save / restore (CPU registers only) ----
    def context_save(self):
        return _Context(self)

    def context_update(self, ctx):
        ctx.update(self)

    def context_restore(self, ctx):
        ctx.restore(self)

    # ---- the core's own state ----
    def get(self, field):
        return self._get(self._h, field)

    def set(self, field, value):
        self._set(self._h, field, value & 0xFFFFFFFFFFFFFFFF)

    def prof(self, on):
        """The core's profile on (cleared) or off (ALISIM_CPP_PROFILE)."""
        self._lib.ali_prof(self._h, 1 if on else 0)

    def prof_top(self, which, n=40):
        """[(pc | mips16, count)], largest first: which 0 = instructions run per
        block start, 1 = device accesses handled in Python per instruction."""
        keys, counts = (ctypes.c_uint32 * n)(), (ctypes.c_uint64 * n)()
        got = self._lib.ali_prof_top(self._h, which, keys, counts, n)
        return [(keys[i], counts[i]) for i in range(got)]

    @staticmethod
    def _check(err):
        if err:
            raise UcError(err)


class _Context:
    """The registers of a CppUc (context_save / context_restore)."""
    IDS = [1] + list(range(2, 34)) + [129, 130]

    def __init__(self, uc):
        self.values = None
        self.mode = 0
        self.update(uc)

    def update(self, uc):
        self.values = [uc.reg_read(r) for r in self.IDS]
        self.mode = uc.get(F_PC_MODE)

    def restore(self, uc):
        for r, v in zip(self.IDS, self.values):
            if r != 1:
                uc.reg_write(r, v)
        uc.set(F_PC_MODE, self.mode)
