"""
Shared body of the screen-capture regressions (run_dump_*_capture_screen.py):
boot a firmware dump with its front panel (front_panel.py), wait until its OSD
has been drawn through the GE model, capture what the display layer shows,
compare it with the dump's golden PNG, and attach the frames, the final screen,
a difference map and the front-panel display to the test report
(report_artifacts.py).

The golden is made with `--make-golden` (or MAKE_GOLDEN=1): the captured screen
is saved as the reference and the run passes.  A firmware whose screen keeps
changing a little (a blinking element, a clock) compares with a tolerance,
max_diff_pct.
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


def run(dump, golden, boot_limit_s, settle_s, min_ge_ops, max_diff_pct=0.0, min_colours=16,
        panel_text=None, title=None):
    """Boot `dump`, wait for min_ge_ops GE commands plus settle_s seconds, capture,
    compare with `golden` (a PNG next to the scripts).  Exits the process with
    the test's result."""
    make_golden = "--make-golden" in sys.argv or os.environ.get("MAKE_GOLDEN") == "1"
    name = os.path.splitext(os.path.basename(golden))[0].replace("_screen_golden", "")
    print(f"=== {title or dump}: capture and verify the OSD drawn through the graphics engine ===")
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
            print(f"[FAIL] nothing drawn within {boot_limit_s:.0f} s (GE commands: {sim.ge_ops}, "
                  f"UART: {''.join(uart)[-200:]!r})")
            report_artifacts.panel(panel.digits, "front panel at the end", panel.get_display_text())
            sys.exit(1)
        if drawn_t is not None and now - drawn_t > settle_s:
            break
        try:
            sim.run(max_instructions=sim.instruction_count + 5_000_000)
        except Exception as e:
            print(f"[FAIL] simulator stopped: {e!r}")
            sys.exit(1)
        note_panel()
        if app_t is None and "Application version" in "".join(uart[-400:]):
            app_t = time.time()
            print(f"[{app_t - start:6.1f}s] application started")
        if drawn_t is None and sim.ge_ops >= min_ge_ops:
            drawn_t = time.time()
            print(f"[{drawn_t - start:6.1f}s] {sim.ge_ops} GE commands: the OSD is being drawn, "
                  f"settling {settle_s:.0f} s")
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
    golden_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), golden)
    if make_golden:
        gma_capture.save_png(golden_path, rgb)
        print(f"  [PASS] golden reference written: {golden_path}")
    elif not os.path.exists(golden_path):
        check(False, f"golden reference {golden} missing (run with --make-golden)")
    else:
        from PIL import Image
        gold = np.array(Image.open(golden_path).convert("RGB"))
        try:
            n, pct, maxd, mask = compare(rgb, gold)
        except ValueError as e:
            check(False, f"golden comparison: {e}")
        else:
            check(pct <= max_diff_pct, f"screen matches the golden reference {golden}: {n} pixels differ "
                                       f"({pct:.2f}%, allowed {max_diff_pct:.2f}%, max channel diff {maxd})")
            if n:
                diff = np.zeros_like(rgb)
                diff[mask] = [255, 0, 0]
                diff_path = report_artifacts.path(f"{name}_diff.png")
                gma_capture.save_png(diff_path, diff)
                report_artifacts.image(diff_path, f"difference to the golden reference: {n} pixels "
                                                  f"({pct:.2f}%), red = differing")
    print(f"\n[{'PASS' if ok else 'FAIL'}] {title or dump} screen regression ({time.time() - start:.0f} s total)")
    sys.exit(0 if ok else 1)
