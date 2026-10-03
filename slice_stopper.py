"""
Deadline stoppers for Unicorn emulation slices.

Fast mode runs the firmware natively in slices that must end at a wall-clock
deadline (the slice length, or the next CP0 timer interrupt).  Unicorn's own
emu_start(timeout=...) is unsuitable on Windows: every call creates a thread
that polls with a legacy 15.6 ms timer and emu_start() joins it, so slices
are 15-150 ms long and an early stop (breakpoint, interrupt) still costs about
10 ms.  The stoppers here are created once per Uc, are re-armable while a
slice runs (an interrupt handler that writes Compare moves the deadline), and
stop the emulation by calling the C function uc_emu_stop() directly.

NativeStopper (Windows, 64-bit): a high-resolution waitable timer registered
    with RegisterWaitForSingleObject whose callback *is* uc_emu_stop.  On the
    x64 / ARM64 Windows ABIs the callback's first argument (the context
    pointer) lands where uc_emu_stop(uc_engine *) expects its argument, the
    BOOLEAN second argument and the return value are ignored, so the stop
    needs no Python, no GIL and no thread per slice.  About 1-2 ms latency.
PyStopper (any platform): a persistent Python thread that sleeps until the
    deadline (time.sleep is high resolution since CPython 3.11) and calls
    uc_emu_stop through ctypes.  Needs the GIL, which the emulation thread
    only holds inside Python hooks.

Both re-fire the stop every millisecond until disarm(): uc_emu_start() clears
a pending stop request when it starts, so a stop that lands just before the
emulation starts would otherwise be lost.  A re-fire after the slice ended is
harmless (uc_emu_stop() does nothing while no emulation runs).
"""
import ctypes
import struct
import sys
import threading
import time


def _uc_stop_function():
    import unicorn
    return sys.modules[unicorn.Uc.__module__].uclib.uc_emu_stop


class PyStopper:
    kind = "python"

    def __init__(self, mu, refire=0.001):
        self._stop = _uc_stop_function()
        self._uch = mu._uch
        self._refire = refire
        self._cv = threading.Condition()
        self._deadline = None
        self._closed = False
        threading.Thread(target=self._run, name="emu-slice-stopper", daemon=True).start()

    # Condition.wait() wakes up early on arm() but is only as precise as the OS
    # timer (15.6 ms on Windows); the last stretch is a high-resolution sleep.
    _COARSE = 0.016 if sys.platform == "win32" else 0.001

    def _run(self):
        perf, sleep = time.perf_counter, time.sleep
        while True:
            with self._cv:
                while self._deadline is None and not self._closed:
                    self._cv.wait()
                if self._closed:
                    return
                dl = self._deadline
                rem = dl - perf()
                if rem > self._COARSE:
                    self._cv.wait(rem - self._COARSE)    # arm() / disarm() wake it up
                    continue                             # re-read the deadline
            while rem > 0 and self._deadline == dl:      # 1 ms steps: an earlier
                sleep(min(rem, 0.001))                   # re-arm is seen in time
                rem = dl - perf()
            if self._deadline != dl:
                continue                                 # moved while sleeping
            while True:
                with self._cv:                           # disarm() waits for a stop in progress
                    if self._deadline != dl or self._closed:
                        break
                    self._stop(self._uch)
                sleep(self._refire)

    def arm(self, seconds):
        with self._cv:
            self._deadline = time.perf_counter() + max(0.0, seconds)
            self._cv.notify()

    def disarm(self):
        with self._cv:
            self._deadline = None
            self._cv.notify()

    def close(self):
        with self._cv:
            self._deadline = None
            self._closed = True
            self._cv.notify()


class NativeStopper:
    kind = "native"

    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION = 0x2
    TIMER_ALL_ACCESS = 0x1F0003
    WT_EXECUTEINWAITTHREAD = 0x4
    WT_EXECUTEONLYONCE = 0x8
    INFINITE = 0xFFFFFFFF
    THREAD_PRIORITY_HIGHEST = 2
    _INVALID = ctypes.c_void_p(-1 & 0xFFFFFFFFFFFFFFFF)       # INVALID_HANDLE_VALUE

    def __init__(self, mu, refire_ms=1):
        if sys.platform != "win32" or struct.calcsize("P") != 8:
            raise OSError("NativeStopper needs 64-bit Windows")
        import ctypes.wintypes as wt
        self._wt = wt
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateWaitableTimerExW.restype = wt.HANDLE
        k32.CreateWaitableTimerExW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, wt.DWORD, wt.DWORD]
        k32.SetWaitableTimer.argtypes = [wt.HANDLE, ctypes.POINTER(ctypes.c_longlong), ctypes.c_long,
                                         ctypes.c_void_p, ctypes.c_void_p, wt.BOOL]
        k32.SetWaitableTimer.restype = wt.BOOL
        k32.CancelWaitableTimer.argtypes = [wt.HANDLE]
        k32.RegisterWaitForSingleObject.argtypes = [ctypes.POINTER(wt.HANDLE), wt.HANDLE, ctypes.c_void_p,
                                                    ctypes.c_void_p, wt.ULONG, wt.ULONG]
        k32.RegisterWaitForSingleObject.restype = wt.BOOL
        k32.UnregisterWaitEx.argtypes = [wt.HANDLE, wt.HANDLE]
        k32.CloseHandle.argtypes = [wt.HANDLE]
        self._k32 = k32
        self._stop_fn = ctypes.cast(_uc_stop_function(), ctypes.c_void_p).value
        self._uch = mu._uch
        self.timer = k32.CreateWaitableTimerExW(None, None, self.CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                                                self.TIMER_ALL_ACCESS)
        if not self.timer:                     # before Windows 10 1803: 15.6 ms legacy timer
            raise OSError(ctypes.get_last_error(), "no high-resolution waitable timer")
        # The stop callback is registered per arming and unregistered (waiting
        # for a callback in flight) by disarm(): CancelWaitableTimer alone does
        # not recall a callback the wait thread was already released for, which
        # would then stop the *next* slice at an arbitrary point.  A permanent
        # registration on a never-signalled event keeps the (boosted) wait
        # thread alive between slices.
        k32.CreateEventW.restype = wt.HANDLE
        k32.CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, ctypes.c_wchar_p]
        self._keep_event = k32.CreateEventW(None, True, False, None)
        self._keep_cb = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, wt.BOOLEAN)(lambda ctx, fired: None)
        self._keep_wait = wt.HANDLE()
        if not k32.RegisterWaitForSingleObject(ctypes.byref(self._keep_wait), self._keep_event,
                                               ctypes.cast(self._keep_cb, ctypes.c_void_p), None,
                                               self.INFINITE, self.WT_EXECUTEINWAITTHREAD):
            err = ctypes.get_last_error()
            k32.CloseHandle(self._keep_event)
            k32.CloseHandle(self.timer)
            raise OSError(err, "RegisterWaitForSingleObject failed")
        self.wait = None
        # Raise the priority of that wait thread: a one-shot callback registered
        # now lands on it.  Best effort.
        self._boost_cb = self._boost_wait_thread()
        self._refire_ms = refire_ms
        self._due = ctypes.c_longlong()
        self._closed = False

    def _boost_wait_thread(self):
        wt, k32 = self._wt, self._k32
        try:
            k32.CreateEventW.restype = wt.HANDLE
            k32.CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, ctypes.c_wchar_p]
            k32.SetEvent.argtypes = [wt.HANDLE]
            k32.GetCurrentThread.restype = wt.HANDLE
            k32.SetThreadPriority.argtypes = [wt.HANDLE, ctypes.c_int]
            done = threading.Event()

            def boost(ctx, fired):
                k32.SetThreadPriority(k32.GetCurrentThread(), self.THREAD_PRIORITY_HIGHEST)
                done.set()
            cb = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, wt.BOOLEAN)(boost)
            ev = k32.CreateEventW(None, False, False, None)
            w = wt.HANDLE()
            try:
                if k32.RegisterWaitForSingleObject(ctypes.byref(w), ev, ctypes.cast(cb, ctypes.c_void_p), None,
                                                   self.INFINITE,
                                                   self.WT_EXECUTEINWAITTHREAD | self.WT_EXECUTEONLYONCE):
                    k32.SetEvent(ev)
                    done.wait(1.0)
                    # wait for the callback to return, then free the registration
                    k32.UnregisterWaitEx(w, wt.HANDLE(-1 & 0xFFFFFFFFFFFFFFFF))
            finally:
                k32.CloseHandle(ev)
            return cb
        except Exception:
            return None

    def arm(self, seconds):
        """Stop the running (or next) emulation `seconds` from now."""
        self._due.value = -max(1, int(seconds * 1e7))          # relative, 100 ns units
        # (SetWaitableTimer also makes the timer non-signalled again)
        self._k32.SetWaitableTimer(self.timer, ctypes.byref(self._due), self._refire_ms, None, None, False)
        if self.wait is None:
            w = self._wt.HANDLE()
            if not self._k32.RegisterWaitForSingleObject(ctypes.byref(w), self.timer, self._stop_fn,
                                                         ctypes.cast(self._uch, ctypes.c_void_p),
                                                         self.INFINITE, self.WT_EXECUTEINWAITTHREAD):
                raise OSError(ctypes.get_last_error(), "RegisterWaitForSingleObject failed")
            self.wait = w

    def disarm(self):
        """Cancel; returns only after a stop callback already in flight has
        finished, so no stale stop can reach a later emulation."""
        self._k32.CancelWaitableTimer(self.timer)
        if self.wait is not None:
            # INVALID_HANDLE_VALUE: wait until a callback that already started has returned
            self._k32.UnregisterWaitEx(self.wait, self._INVALID)
            self.wait = None

    def close(self):
        if self._closed:
            return
        self._closed = True
        self.disarm()
        self._k32.UnregisterWaitEx(self._keep_wait, self._INVALID)
        self._k32.CloseHandle(self._keep_event)
        self._k32.CloseHandle(self.timer)


def make_stopper(mu, kind="auto"):
    """A stopper for this Uc, or None to fall back to emu_start(timeout=).
    kind: 'auto' (native on 64-bit Windows, else python), 'native', 'python', 'unicorn'."""
    if kind not in ("auto", "native", "python", "unicorn"):
        raise ValueError(f"unknown slice stopper {kind!r} (auto, native, python, unicorn)")
    if kind == "unicorn":
        return None
    if kind in ("auto", "native"):
        try:
            return NativeStopper(mu)
        except Exception:
            if kind == "native":
                raise
    try:
        return PyStopper(mu)
    except Exception:
        if kind == "python":
            raise
    return None
