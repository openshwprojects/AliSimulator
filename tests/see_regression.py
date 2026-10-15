"""
Shared body of the dual-CPU regressions (run_dump_urz0086_see_start.py,
run_dump_x110ts_see_start.py, run_dump_hdxs2_app_starts.py,
run_dump_t750i_app_starts.py, run_dump_t760i_app_starts.py): boot a firmware
dump whose SEE co-processor's program runs on the second core (chips/see.py)
until the two CPUs have taken enough of each other's remote-call messages
(see.Doorbells.taken), then check the chip family, the SEE starts, the
message counts, the UART output and the test's own checks.  Exits the
process with the test's result.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

from simulator import AliMipsSimulator, flash_size_for, resolve_dump

LOGGED = ("[SEE] started", "[CAR]")     # log lines echoed and kept (Run.logs)
STEP = 2_000_000                        # instructions between the run's checks of its targets
START_TEXT = {"parked": "the SEE is sent to its boot code at 0x{:08X}, which parks it",
              "run on the SEE core": "the SEE's program at 0x{:08X} runs on the second core"}


class Run:
    """A boot for the checks: the simulator, the UART output, the LOGGED log
    lines, the exception that stopped the simulator (None)."""

    def __init__(self, sim):
        self.sim, self.uart, self.logs, self.error = sim, [], [], None

    @property
    def text(self):
        return "".join(self.uart)

    @property
    def see(self):
        return self.sim.chip.see

    @property
    def taken(self):
        return self.see.doorbells.taken


def run(dump, title, family, starts, calls, see_calls, limit, chip_id=None, uart=(), ebase=None, see_ebase=None,
        setup=None, wait_for=None, abort=None, checks=(), retries=1):
    """Boot `dump` and run until the SEE has taken `calls` of the main CPU's
    remote calls and the main CPU their answers, the main CPU `see_calls` of
    the SEE's own calls and the SEE their answers -- and wait_for(run), when
    given -- or until abort(run) or `limit` instructions.  setup(sim) runs
    after the load (hooks of the test's own).  Then it checks the family (the
    chip family's class name; chip_id: its chip ID), the SEE starts --
    [(address, what)] of see.SeeStart.starts, in order, and no others --, the
    message counts, that the UART output holds each of `uart`, the main CPU's
    and the SEE core's CP0 EBase (ebase / see_ebase, when given), each of
    `checks` -- check(run) returns (ok, description) -- and that the
    simulator ran without an error.  A run the simulator crashes (the
    asynchronous slice-stop race, README "Things learned") is booted again,
    `retries` times, before the error counts."""
    print(f"=== Regression Test: {title} ===")
    path = resolve_dump(dump)
    r = None

    def log(msg):
        if msg.startswith(LOGGED):
            print(f"[{r.sim.instruction_count:>11,}] {msg}", flush=True)
            r.logs.append(msg)

    def exchanges():
        """[(done, wanted, what)]: the main CPU's calls with their answers, the
        SEE's own calls with theirs -- each done as far as both sides took them."""
        t = r.taken
        return [(min(t["SEE"][0], t["main"][1]), calls,
                 f"the SEE takes the drivers' calls and the main CPU its answers ({t['SEE'][0]} / {t['main'][1]}"),
                (min(t["main"][0], t["SEE"][1]), see_calls,
                 f"the main CPU answers the SEE's own calls ({t['main'][0]} / {t['SEE'][1]}")]

    for attempt in range(retries + 1):
        r = Run(AliMipsSimulator(rom_size=flash_size_for(path), log_handler=log))
        sim = r.sim
        sim.setSPIDump(False)
        sim.setI2CDump(False)
        sim.setUartHandler(lambda c, r=r: r.uart.append(c if isinstance(c, str) else chr(c)))
        sim.loadFile(path)
        if setup:
            setup(sim)
        t0 = time.time()
        try:
            while sim.instruction_count < limit and not (abort and abort(r)) \
                    and not (all(done >= wanted for done, wanted, _ in exchanges()) and (wait_for is None or wait_for(r))):
                sim.run(max_instructions=sim.instruction_count + STEP)
        except Exception as e:
            r.error = e
        print(f"\n{time.time() - t0:.1f}s, {sim.instruction_count:,} instructions, messages taken {r.taken}"
              + (f", stopped: {r.error!r}" if r.error else ""))
        if r.error is None or attempt == retries:
            break
        print(f"[WARN] simulator crashed ({r.error!r}); booting again (retry {attempt + 1} of {retries})")

    name = type(sim.chip).__name__
    results = [(name == family and chip_id in (None, sim.chip.chip_id),
                f"the image is run as the {family} family" + (f" with the chip ID 0x{chip_id:04X}" if chip_id else "")
                + f" ({name}, 0x{sim.chip.chip_id:04X})")]
    got = r.see.starts
    for i, (address, what) in enumerate(starts):
        text = START_TEXT.get(what, "the SEE starts at 0x{:08X}: " + what).format(address)
        seen = f"0x{got[i][0]:08X}: {got[i][1]}" if i < len(got) else "none"
        results.append((got[i:i + 1] == [(address, what)], f"{text} ({seen})"))
    results.append((len(got) == len(starts), f"no other SEE start ({len(got)} in all)"))
    results += [(done >= wanted, f"{what}, {wanted} wanted)") for done, wanted, what in exchanges()]
    results += [(s in r.text, f"the UART shows {s!r}") for s in uart]
    if ebase is not None:
        results.append((sim.cp0_ebase == ebase, f"the application moved its exception vectors: EBase 0x{sim.cp0_ebase:08X}"))
    if see_ebase is not None:
        got_ebase = r.see.core.core.cp0_ebase if r.see.core else None
        results.append((got_ebase == see_ebase, f"the SEE's program moved its own, CPU number {see_ebase & 0x3FF}: "
                                                f"EBase 0x{got_ebase or 0:08X}"))
    results += [check(r) for check in checks]
    results.append((r.error is None, "the simulator runs on without an error"))
    ok = True
    for good, desc in results:
        print(f"  [{'PASS' if good else 'FAIL'}] {desc}")
        ok &= bool(good)
    print(f"\n[{'PASS' if ok else 'FAIL'}] {title}")
    sys.exit(0 if ok else 1)
