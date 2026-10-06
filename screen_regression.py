"""
Shared body of the screen-capture regressions (run_dump_*_capture_screen.py):
boot a firmware dump with its front panel (front_panel.py), wait until its OSD
has been drawn through the GE model, capture what the display layer shows,
compare it with the dump's golden PNG (golden/), and attach the frames, the final screen,
a difference map and the front-panel display to the test report
(report_artifacts.py).

The golden is made with `--make-golden` (or MAKE_GOLDEN=1): the captured screen
is saved as the reference and the run passes.  A firmware whose screen keeps
changing a little (a blinking element, a clock) compares with a tolerance,
max_diff_pct.

A `navigation` sequence then drives the UI: each step is a remote-control key
name (sent through the emulated IR receiver and the firmware's own key table,
see ir_remote.py) or ("panel", code) for a front-panel key (answered by the
panel decoder's key read), with the least number of pixels the step must
change.  Every step's screen goes to the report and the last one is compared
with <name>_nav_golden.png (also made by --make-golden).
"""
import os
import sys
import time

import numpy as np

import gma_capture
import report_artifacts
from front_panel import make_panel
from simulator import AliMipsSimulator

MAX_FRAMES = 6          # distinct intermediate frames attached to the report


def compare(rgb, golden):
    """(differing pixels, percent, max channel difference, mask)."""
    if rgb.shape != golden.shape:
        raise ValueError(f"shape mismatch: {rgb.shape} vs {golden.shape}")
    mask = (rgb != golden).any(axis=2)
    n = int(mask.sum())
    return n, 100.0 * n / (rgb.shape[0] * rgb.shape[1]), \
        int(np.abs(rgb.astype(int) - golden.astype(int)).max()) if n else 0, mask


class SimulatorCrash(Exception):
    """The simulator stopped with an exception (a native Unicorn fault), or the
    firmware stalled before drawing anything: both are the asynchronous
    slice-stop race (see README "Things learned"), so the boot is retried."""


def run(dump, golden, boot_limit_s, settle_s, min_ge_ops, max_diff_pct=0.0, min_colours=8,
        panel_text=None, title=None, retries=1, navigation=(), nav_diff_pct=None, nav_settle_s=0):
    """Boot `dump`, wait for min_ge_ops GE commands plus settle_s seconds, capture,
    compare with `golden` (a PNG in the golden/ directory).  Exits the process
    with the test's result.  A run the simulator itself crashes (the asynchronous
    slice-stop race, see README "Things learned": a hooked CP0 instruction
    running natively ends in a jump to a stale register) is retried `retries`
    times from a fresh boot before it counts as a failure."""
    print(f"=== {title or dump}: capture and verify the OSD drawn through the graphics engine ===")
    for attempt in range(retries + 1):
        try:
            _run(dump, golden, boot_limit_s, settle_s, min_ge_ops, max_diff_pct, min_colours,
                 panel_text, title, navigation, max_diff_pct if nav_diff_pct is None else nav_diff_pct,
                 nav_settle_s)
        except SimulatorCrash as e:
            if attempt < retries:
                print(f"[WARN] simulator crashed ({e}); booting again (retry {attempt + 1} of {retries})")
                continue
            print(f"[FAIL] simulator crashed again ({e})")
            sys.exit(1)
        return


def _run(dump, golden, boot_limit_s, settle_s, min_ge_ops, max_diff_pct, min_colours, panel_text, title,
         navigation, nav_diff_pct, nav_settle_s):
    make_golden = "--make-golden" in sys.argv or os.environ.get("MAKE_GOLDEN") == "1"
    name = os.path.splitext(os.path.basename(golden))[0].replace("_screen_golden", "")
    sim = AliMipsSimulator(log_handler=lambda m: None)
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    uart = []
    sim.setUartHandler(lambda c: uart.append(c))
    panel, _keys, panel_desc = make_panel(dump, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    sim.loadFile(dump)
    print(f"front panel: {panel_desc}")

    start = time.time()
    app_t = drawn_t = None
    last_probe = 0.0
    last_ops = captured_ops = 0
    frames, prev = 0, None
    panel_texts = []
    ok = True

    def note_panel():
        text = panel.get_display_text()
        if not panel_texts or panel_texts[-1] != text:
            panel_texts.append(text)
            print(f"[{time.time() - start:6.1f}s] front panel shows [{text}]")

    while True:
        now = time.time()
        if drawn_t is None and now - start > boot_limit_s:
            report_artifacts.panel(panel.digits, "front panel at the end", panel.get_display_text())
            raise SimulatorCrash(f"nothing drawn within {boot_limit_s:.0f} s (GE commands: {sim.ge_ops}, "
                                 f"UART: {''.join(uart)[-120:]!r})")
        if drawn_t is not None and now - drawn_t > settle_s:
            break
        try:
            sim.run(max_instructions=sim.instruction_count + 5_000_000)
        except Exception as e:
            raise SimulatorCrash(f"{type(e).__name__}: {e} at {time.time() - start:.0f} s, "
                                 f"{sim.ge_ops} GE commands") from e
        note_panel()
        if app_t is None and "Application version" in "".join(uart[-400:]):
            app_t = time.time()
            print(f"[{app_t - start:6.1f}s] application started")
        # "drawn" = enough GE commands AND something visible, probed every
        # 10 s whatever the GE does: the Globo shows a channel banner that
        # times out and clears before its no-signal message, and the
        # Cabletech's wizard keeps redrawing a little, so neither "N commands
        # done" nor "the GE went quiet" alone marks the screen to capture.
        if drawn_t is None and sim.ge_ops >= min_ge_ops and now - last_probe >= 10:
            last_probe = now
            rgb = sim.capture_screen()
            colours = len(np.unique(rgb.reshape(-1, 3), axis=0))
            if colours >= min_colours:
                drawn_t = time.time()
                print(f"[{drawn_t - start:6.1f}s] {sim.ge_ops} GE commands: the OSD is visible "
                      f"({colours} colours), settling {settle_s:.0f} s")
        if sim.ge_ops != last_ops:               # still drawing
            last_ops = sim.ge_ops
            continue
        if sim.ge_ops == captured_ops:           # quiet, nothing new
            continue
        captured_ops = sim.ge_ops
        rgb = sim.capture_screen()
        if frames < MAX_FRAMES and (prev is None or not np.array_equal(rgb, prev)):
            frames += 1
            path = report_artifacts.path(f"{name}_frame_{frames:02d}.png")
            gma_capture.save_png(path, rgb)
            print(f"[{time.time() - start:6.1f}s] {sim.ge_ops} GE commands: new frame -> {path}")
            report_artifacts.image(path, f"frame {frames} after {sim.ge_ops} GE commands "
                                         f"({time.time() - start:.0f} s)")
        prev = rgb

    out = report_artifacts.path(f"{name}_screen.png")
    rgb = sim.capture_screen(out)
    colours = len(np.unique(rgb.reshape(-1, 3), axis=0))
    unsupported = dict(sim.ge.unsupported) if sim.ge else {}
    print(f"saved {out}: {rgb.shape[1]}x{rgb.shape[0]}, {colours} colours, {sim.ge_ops} GE commands, "
          f"GE features not modelled: {unsupported or 'none'}")
    report_artifacts.image(out, f"final screen: {colours} colours, {sim.ge_ops} GE commands "
                                f"({time.time() - start:.0f} s)")
    report_artifacts.panel(panel.digits, "front panel at the end (" + " -> ".join(
        f"[{t}]" for t in panel_texts) + ")", panel.get_display_text())

    def check(cond, msg):
        nonlocal ok
        print(("  [PASS] " if cond else "  [FAIL] ") + msg)
        ok &= bool(cond)

    check(colours >= min_colours, f"the screen is not uniform ({colours} colours, need {min_colours})")
    if panel_text is not None:
        check(panel.get_display_text() == panel_text,
              f"front panel shows [{panel.get_display_text()}] (expected [{panel_text}])")
    def against_golden(rgb, golden_name, allowed_pct, what):
        golden_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden", golden_name)
        if make_golden:
            gma_capture.save_png(golden_path, rgb)
            print(f"  [PASS] golden reference written: {golden_path}")
            return
        if not os.path.exists(golden_path):
            check(False, f"golden reference {golden_name} missing (run with --make-golden)")
            return
        from PIL import Image
        gold = np.array(Image.open(golden_path).convert("RGB"))
        try:
            n, pct, maxd, mask = compare(rgb, gold)
        except ValueError as e:
            check(False, f"golden comparison: {e}")
            return
        check(pct <= allowed_pct, f"{what} matches the golden reference {golden_name}: {n} pixels differ "
                                  f"({pct:.2f}%, allowed {allowed_pct:.2f}%, max channel diff {maxd})")
        if n:
            diff = np.zeros_like(rgb)
            diff[mask] = [255, 0, 0]
            diff_path = report_artifacts.path(f"{os.path.splitext(golden_name)[0]}_diff.png")
            gma_capture.save_png(diff_path, diff)
            report_artifacts.image(diff_path, f"difference of the {what} to {golden_name}: {n} pixels "
                                              f"({pct:.2f}%), red = differing")

    against_golden(rgb, golden, max_diff_pct, "screen")

    # navigation: drive the UI with the remote / the front panel
    def run_for(seconds):
        t = time.time()
        while time.time() - t < seconds:
            sim.run(max_instructions=sim.instruction_count + 5_000_000)

    def settle(max_s, quiet_s, min_s=0):
        """Run until the GE has issued no command for quiet_s seconds (at
        least min_s, at most max_s): a redraw or a banner's timeout takes
        more wall time the busier the machine is, so a fixed wait captured
        half-drawn menus and banners that had not gone yet."""
        t0 = time.time()
        last_ops, last_change = sim.ge_ops, t0
        while time.time() - t0 < max_s:
            sim.run(max_instructions=sim.instruction_count + 5_000_000)
            now = time.time()
            if sim.ge_ops != last_ops:
                last_ops, last_change = sim.ge_ops, now
            elif now - last_change >= quiet_s and now - t0 >= min_s:
                return True
        return False

    previous = rgb
    for i, (key, min_px) in enumerate(navigation, 1):
        ops = sim.ge_ops
        try:
            if isinstance(key, tuple):                   # ("panel", code): a front-panel key
                panel.press_key(key[1], hold_reads=2)
                label = f"panel key {key[1]}"
            else:
                addr, cmd = sim.press_key(key)
                label = f"{key} (NEC 0x{addr:02X}/0x{cmd:02X})"
        except Exception as e:
            check(False, f"navigation step {i}: cannot press {key!r}: {e}")
            break
        t = time.time()
        while time.time() - t < 60 and sim.ge_ops - ops < 2:      # wait for the redraw to start
            sim.run(max_instructions=sim.instruction_count + 5_000_000)
        settle(120, 8, min_s=20)                                 # and to finish
        after = sim.capture_screen()
        changed = int((after != previous).any(axis=2).sum())
        path = report_artifacts.path(f"{name}_nav_{i}_{str(key[1] if isinstance(key, tuple) else key).replace('+', 'plus').replace('-', 'minus')}.png")
        gma_capture.save_png(path, after)
        report_artifacts.image(path, f"navigation step {i}: {label}: {sim.ge_ops - ops} GE commands, "
                                     f"{changed} pixels changed")
        check(changed >= min_px, f"navigation step {i}: {label} changed the screen "
                                 f"({changed} pixels, need {min_px}; {sim.ge_ops - ops} GE commands)")
        print(f"[{time.time() - start:6.1f}s] navigation {i}: {label}: {sim.ge_ops - ops} GE commands, "
              f"{changed} pixels changed, panel [{panel.get_display_text()}]")
        previous = after
    if navigation:
        if nav_settle_s:
            # let a banner or an animation finish before the comparison: wait
            # until the screen has become the golden one (a banner that has not
            # timed out yet is itself static, so "GE quiet" would not do), or
            # for the whole budget when there is no golden to wait for yet
            nav_golden_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden",
                                           f"{name}_nav_golden.png")
            if not make_golden and os.path.exists(nav_golden_path):
                from PIL import Image
                gold = np.array(Image.open(nav_golden_path).convert("RGB"))
                t0 = time.time()
                while True:
                    previous = sim.capture_screen()
                    try:
                        if compare(previous, gold)[1] <= nav_diff_pct:
                            break
                    except ValueError:
                        break
                    if time.time() - t0 >= nav_settle_s:
                        break
                    run_for(10)
                print(f"[{time.time() - start:6.1f}s] final screen settled after {time.time() - t0:.0f} s")
            else:
                run_for(nav_settle_s)
                previous = sim.capture_screen()
            path = report_artifacts.path(f"{name}_nav_final.png")
            gma_capture.save_png(path, previous)
            report_artifacts.image(path, f"screen {nav_settle_s:.0f} s after the last navigation step")
        report_artifacts.panel(panel.digits, "front panel after the navigation", panel.get_display_text())
        against_golden(previous, f"{name}_nav_golden.png", nav_diff_pct, "screen after the navigation")
    print(f"\n[{'PASS' if ok else 'FAIL'}] {title or dump} screen regression ({time.time() - start:.0f} s total)")
    sys.exit(0 if ok else 1)
