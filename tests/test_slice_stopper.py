"""Re-arming a native slice deadline must not let an old stop reach a new slice.

Portable checks exercise deadline/drain decisions with a controlled clock.
On 64-bit Windows, real timer/wait APIs run a gated synthetic stop callback:
an old firing is held across re-arm and disarm to expose stale callbacks.
Each native scenario has a subprocess timeout; no firmware or Unicorn engine
is started, and the callback never dereferences its synthetic engine pointer.
"""
import ctypes
import json
import math
from pathlib import Path
import struct
import subprocess
import sys
import threading
import traceback
from types import SimpleNamespace
from unittest import SkipTest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import slice_stopper


def controlled_stopper():
    """Use the real arm/disarm methods with deterministic API observations."""
    stopper = slice_stopper.NativeStopper.__new__(slice_stopper.NativeStopper)
    stopper._closed = True  # no native resources for __del__ to release
    stopper._due_perf = float("inf")
    stopper._due = ctypes.c_longlong()
    stopper._due_ref = ctypes.byref(stopper._due)
    stopper._refire_ms = 1
    stopper.timer = object()
    stopper._wait_handle = ctypes.c_void_p(99)
    stopper.wait = stopper._wait_handle
    stopper._wait_ref = ctypes.byref(stopper._wait_handle)
    stopper._stop_fn = stopper._uch_ptr = None
    stopper._flags = stopper.WT_EXECUTEINWAITTHREAD
    observed = SimpleNamespace(programmed=[], unregistered=[], cancelled=[])
    stopper._set_timer = lambda *args: observed.programmed.append(stopper._due.value)
    stopper._cancel_timer = lambda handle: observed.cancelled.append(handle)
    stopper._unreg_wait = lambda *args: observed.unregistered.append(args)
    stopper._reg_wait = lambda *args: True
    return stopper, observed


def test_rearm_deadlines_and_drain():
    # Later re-arms must retain the old drain eligibility; earlier re-arms must
    # become eligible at their earlier deadline. Actual timer values follow
    # the requested duration in either case.
    for durations, times, disarm_at in (
            ([10, 20], [100, 101], 111),
            ([10, 3], [100, 101], 105),
            ([10, 3, 20], [100, 101, 102], 105)):
        stopper, observed = controlled_stopper()
        clock = SimpleNamespace(now=0)
        with patch.object(slice_stopper, "time", SimpleNamespace(perf_counter=lambda: clock.now)):
            for duration, now in zip(durations, times):
                clock.now = now
                stopper.arm(duration)
            clock.now = disarm_at
            stopper.disarm()
        assert observed.programmed == [-int(sec * 1e7) for sec in durations]
        assert len(observed.unregistered) == 1, "an earlier armed deadline still needs draining"
        assert observed.unregistered[0][1].value == stopper._INVALID.value
        assert stopper.wait is None and math.isinf(stopper._due_perf)


def test_early_disarm_and_reset():
    stopper, observed = controlled_stopper()
    clock = SimpleNamespace(now=100)
    with patch.object(slice_stopper, "time", SimpleNamespace(perf_counter=lambda: clock.now)):
        stopper.arm(10)
        clock.now = 101
        stopper.arm(20)
        clock.now = 102
        stopper.disarm()
        assert not observed.unregistered and stopper.wait is not None
        assert math.isinf(stopper._due_perf)
        # A fresh cycle after the OLD deadline still has its own cheap cancel.
        clock.now = 200
        stopper.arm(10)
        clock.now = 201
        stopper.disarm()
        assert not observed.unregistered and stopper.wait is not None
        assert math.isinf(stopper._due_perf)
        # Force cleanup must drain even before any deadline.
        stopper.arm(10)
        stopper.disarm(force_unreg=True)
        assert len(observed.unregistered) == 1 and stopper.wait is None


def native_scenario(name):
    """Observe actual Win32 drain behavior without calling uc_emu_stop."""
    import ctypes.wintypes as wt

    entered, release, complete = threading.Event(), threading.Event(), threading.Event()
    decision, returned = threading.Event(), threading.Event()
    stops, unregisters, errors, expired, programmed = [], [], [], [], []
    active = ["original"]

    @ctypes.WINFUNCTYPE(None, ctypes.c_void_p, wt.BOOLEAN)
    def delayed_stop(context, timed_out):
        entered.set()
        if not release.wait(6):
            expired.append(True)
        stops.append(active[0])
        complete.set()

    with patch.object(slice_stopper, "_uc_stop_function", lambda: delayed_stop):
        stopper = slice_stopper.NativeStopper(SimpleNamespace(_uch=ctypes.c_void_p(0x1234)))
    real_unregister, real_set = stopper._unreg_wait, stopper._set_timer

    def observe_unregister(handle, completion):
        unregisters.append(completion.value)
        decision.set()
        return real_unregister(handle, completion)

    def observe_set(*args):
        programmed.append(stopper._due.value)
        return real_set(*args)

    stopper._unreg_wait, stopper._set_timer = observe_unregister, observe_set
    worker = None
    try:
        if name == "early":
            for seconds in (60, 120, 30, 90):
                stopper.arm(seconds)
            stopper.disarm()
            returned_while_blocked = False
        else:
            if name == "earlier_then_later":
                stopper.arm(60)
            stopper.arm(0.02)
            assert entered.wait(3), "real timer did not enter the controlled callback"
            if name != "fired":
                stopper.arm(60)

            def disarm():
                try:
                    stopper.disarm(force_unreg=(name == "forced"))
                except BaseException:
                    errors.append(traceback.format_exc())
                finally:
                    returned.set()
                    decision.set()

            worker = threading.Thread(target=disarm, daemon=True)
            worker.start()
            assert decision.wait(3), "disarm neither returned nor entered its drain"
            returned_while_blocked = returned.wait(0.03) if unregisters else returned.is_set()
            if returned_while_blocked:
                active[0] = "successor"
            release.set()
            assert complete.wait(3) and returned.wait(3), "callback/drain failed to complete"
            assert not errors, errors

        result = {
            "scenario": name,
            "disarm_returned_while_callback_blocked": returned_while_blocked,
            "stop_slices": list(stops),
            "unregister_count": len(unregisters),
            "registration_retained": stopper.wait is not None,
            "deadline_reset": math.isinf(stopper._due_perf),
            "callback_gate_expired": bool(expired),
            "programmed_relative_100ns": list(programmed),
        }
        # Clearing the minimum must preserve the fast path on the next cycle.
        n = len(unregisters)
        stopper.arm(60)
        stopper.disarm()
        result["fresh_cycle_unregister_count"] = len(unregisters) - n
        result["fresh_cycle_registration_retained"] = stopper.wait is not None
        result["fresh_cycle_deadline_reset"] = math.isinf(stopper._due_perf)
        return result
    finally:
        # Always release before native cleanup, including on a failed assertion.
        release.set()
        if worker is not None:
            worker.join(timeout=3)
        stopper.close()


def test_real_windows_callbacks():
    if sys.platform != "win32" or struct.calcsize("P") != 8:
        raise SkipTest("real native callback cases require 64-bit Windows")
    failures = []
    for name in ("stale", "stale", "stale", "earlier_then_later", "fired", "forced", "early"):
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--native-case", name],
                               capture_output=True, text=True, timeout=20)
        assert child.returncode == 0, (name, child.stdout, child.stderr)
        result = json.loads(child.stdout)
        print(f"  native callback observation: {json.dumps(result, sort_keys=True)}", flush=True)
        early = name == "early"
        ok = (not result["disarm_returned_while_callback_blocked"] and
              result["unregister_count"] == (0 if early else 1) and
              result["registration_retained"] == early and
              result["stop_slices"] == ([] if early else ["original"]) and
              result["deadline_reset"] and not result["callback_gate_expired"] and
              result["fresh_cycle_unregister_count"] == 0 and
              result["fresh_cycle_registration_retained"] and result["fresh_cycle_deadline_reset"])
        expected_due = {
            "stale": [-200000, -600000000],
            "earlier_then_later": [-600000000, -200000, -600000000],
            "fired": [-200000], "forced": [-200000, -600000000],
            "early": [-600000000, -1200000000, -300000000, -900000000],
        }[name]
        ok = ok and result["programmed_relative_100ns"] == expected_due
        if not ok:
            failures.append(result)
    assert not failures, f"native callback safety failed: {json.dumps(failures, sort_keys=True)}"


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--native-case":
        print(json.dumps(native_scenario(sys.argv[2])), flush=True)
    else:
        failed = 0
        for test in (test_rearm_deadlines_and_drain, test_early_disarm_and_reset,
                     test_real_windows_callbacks):
            try:
                test()
                print(f"[PASS] {test.__name__}", flush=True)
            except SkipTest as exc:
                print(f"[SKIP] {test.__name__}: {exc}", flush=True)
            except Exception:
                failed += 1
                print(f"[FAIL] {test.__name__}", flush=True)
                traceback.print_exc()
        sys.exit(bool(failed))
