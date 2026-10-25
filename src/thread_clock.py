"""
CPU-time clocks for the emulation thread.

Fast mode derives the guest's CP0 Count from "emulation time".  With wall time,
a host stall (the emulation thread preempted by other processes, common on a
loaded machine) makes Count jump while the guest executes nothing, which
breaks firmware that relies on "nothing ticks within the next millisecond"
(e.g. the RTOS's first task dispatch: Count=0, Compare=+1 ms, then ~50
instructions with interrupts enabled).  These clocks only advance while the
emulation thread actually runs (native code and Python hooks alike).

make_thread_clock() returns a callable giving seconds of CPU time of the
calling thread.  Read it on that thread only: on Windows a read from another
thread lags (the counter of a running thread advances at its context
switches), elsewhere it returns None.  Windows: QueryThreadCycleTime on a real
thread handle, scaled by the TSC rate (calibrated once per process), with
reads rate-limited (see _REREAD_S).  Elsewhere: time.thread_time() (precise on
Linux / macOS).
"""
import ctypes
import sys
import threading
import time

_tsc_hz = None


def _calibrate_tsc(k32, handle):
    """TSC rate in Hz: the largest cycles-per-second ratio over short busy
    windows (a window in which the thread was preempted shows fewer cycles)."""
    c = ctypes.c_ulonglong()
    best = 0.0
    for _ in range(40):
        k32.QueryThreadCycleTime(handle, ctypes.byref(c))
        c0, t0 = c.value, time.perf_counter()
        while time.perf_counter() - t0 < 0.001:
            pass
        k32.QueryThreadCycleTime(handle, ctypes.byref(c))
        t1 = time.perf_counter()
        best = max(best, (c.value - c0) / (t1 - t0))
    return best


_win_clocks = {}


class _WinThreadClock:
    def __init__(self):
        global _tsc_hz
        import ctypes.wintypes as wt
        k32 = ctypes.WinDLL("kernel32", use_last_error=False)
        k32.GetCurrentThreadId.restype = wt.DWORD
        k32.OpenThread.restype = wt.HANDLE
        k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        k32.QueryThreadCycleTime.argtypes = [wt.HANDLE, ctypes.POINTER(ctypes.c_ulonglong)]
        k32.QueryThreadCycleTime.restype = wt.BOOL
        k32.CloseHandle.argtypes = [wt.HANDLE]
        THREAD_QUERY_LIMITED_INFORMATION = 0x0800
        self._k32 = k32
        # (while this handle is open the thread id cannot be reused by another thread)
        self.tid = k32.GetCurrentThreadId()
        self.handle = k32.OpenThread(THREAD_QUERY_LIMITED_INFORMATION, False, self.tid)
        if not self.handle:
            raise OSError("OpenThread failed")
        if _tsc_hz is None:
            hz = _calibrate_tsc(k32, self.handle)
            if hz < 1e8:
                raise OSError("implausible TSC rate %r" % hz)
            _tsc_hz = hz
        self._scale = 1.0 / _tsc_hz
        self._c = ctypes.c_ulonglong()
        self._ref = ctypes.byref(self._c)
        self._query = k32.QueryThreadCycleTime
        self._base_v = 0.0
        self._base_w = -1e9
        self._last = 0.0

    # The syscall costs ~5-10 us; within this long after a real read the
    # thread is assumed to have run (wall time is added).  Preemptions longer
    # than this -- scheduler quanta, the case this clock exists for -- are
    # still excluded.
    _REREAD_S = 200e-6

    def __call__(self, _perf=time.perf_counter):
        w = _perf()
        dw = w - self._base_w
        if dw < self._REREAD_S:
            v = self._base_v + dw
        else:
            self._query(self.handle, self._ref)
            v = self._c.value * self._scale
            self._base_v = v
            self._base_w = w
        if v < self._last:              # an interpolated value may have run ahead
            v = self._last
        self._last = v
        return v

    def make_callable(self):
        _perf = time.perf_counter
        _query = self._query
        _handle = self.handle
        _ref = self._ref
        _c = self._c
        _scale = self._scale
        _reread = self._REREAD_S
        base_v = 0.0
        base_w = -1e9
        last = 0.0

        def _read_clock(_self=self):
            nonlocal base_v, base_w, last
            w = _perf()
            dw = w - base_w
            if dw < _reread:
                v = base_v + dw
            else:
                _query(_handle, _ref)
                v = _c.value * _scale
                base_v = v
                base_w = w
            if v < last:
                v = last
            else:
                last = v
            return v

        return _read_clock

    def __del__(self):
        try:
            self._k32.CloseHandle(self.handle)
        except Exception:
            pass


class _PosixThreadClock:
    def __init__(self):
        self.tid = threading.get_native_id()

    def __call__(self):
        if threading.get_native_id() != self.tid:
            return None                 # another thread's CPU time is not readable here
        return time.thread_time()


def make_thread_clock(kind="thread"):
    """Clock for the calling thread: 'thread' (CPU time, falls back to wall
    time if unavailable) or 'wall' (time.perf_counter)."""
    if kind not in ("thread", "wall"):
        raise ValueError(f"unknown count clock {kind!r} (thread, wall)")
    if kind == "thread":
        try:
            if sys.platform == "win32":
                tid = threading.get_native_id()
                clk = _win_clocks.get(tid)
                if clk is None:
                    clk = _win_clocks[tid] = _WinThreadClock().make_callable()
                return clk
            if time.get_clock_info("thread_time").resolution <= 1e-6:
                return _PosixThreadClock()
        except Exception:
            pass
    return time.perf_counter
