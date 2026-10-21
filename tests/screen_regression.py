"""
Shared body of the screen-capture regressions (run_dump_*_capture_screen.py):
boot a firmware dump with its front panel (front_panel.py) and its tuner model
(tuners.py, from its sidecar; no signal unless asked), wait until its OSD
has been drawn through the GE model, capture what the display layer shows,
compare it with the dump's expected screen (a PNG in tests/expected/), and attach the frames, the final screen
and a difference map to the test report (report_artifacts.py) -- every
capture with the front-panel display and the tuner's frequency of that
moment, which the report shows beside it.

The expected screen is made with `--make-expected` (or MAKE_EXPECTED=1): the captured
screen is saved as the expected one and the run passes.  A firmware whose screen keeps
changing a little (a blinking element, a clock) compares with a tolerance,
max_diff_pct.

A `navigation` sequence then drives the UI: each step is a remote-control key
name (sent through the emulated IR receiver and the firmware's own key table,
see ir_remote.py), ("panel", code) for a front-panel key (answered by the
panel decoder's key reads: 2 of them see it pressed, ("panel", code, reads)
another number) or ("wait", seconds) for no key -- the firmware
goes on by itself for that long --, with the least number of pixels the step
must change.  Every step's screen goes to the report and the last one is compared
with <name>_nav.png (also made by --make-expected).

Every wait here -- settle_s, probe_s, the navigation's settling, ("wait", s),
nav_settle_s -- is in the firmware's own time (the simulator's emulation
time, sim._vtime()), not the host's: the firmware's banners and timeouts
follow it, whatever the host's load and however much of it the simulator
skips (idle loops, the bootloaders' LZMA decoder).  Only boot_limit_s, the
guard against a stalled or crashed boot, is wall-clock time.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

import numpy as np
from unicorn.mips_const import UC_MIPS_REG_PC

import dump_catalog
import gma_capture
import report_artifacts
from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

EXPECTED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "expected")   # the expected screens

MAX_FRAMES = 6          # distinct intermediate frames attached to the report


def compare(rgb, want):
    """(differing pixels, percent, max channel difference, mask)."""
    if rgb.shape != want.shape:
        raise ValueError(f"shape mismatch: {rgb.shape} vs {want.shape}")
    mask = (rgb != want).any(axis=2)
    n = int(mask.sum())
    return n, 100.0 * n / (rgb.shape[0] * rgb.shape[1]), \
        int(np.abs(rgb.astype(int) - want.astype(int)).max()) if n else 0, mask


class SimulatorCrash(Exception):
    """The simulator stopped with an exception (a native Unicorn fault), or the
    firmware stalled before drawing anything: both are the asynchronous
    slice-stop race (see README "Things learned"), so the boot is retried."""


def run(dump, expected, boot_limit_s, settle_s, min_ge_ops, max_diff_pct=0.0, min_colours=8,
        panel_text=None, title=None, retries=1, navigation=(), nav_diff_pct=None, nav_settle_s=0,
        signal=False, tuner=True, mux=False, slice_instructions=5_000_000, probe_s=10,
        signal_frequencies=None, ge=True):
    """Boot `dump`, wait for min_ge_ops GE commands plus settle_s seconds, capture,
    compare with `expected` (a PNG in tests/expected/).  Exits the process
    with the test's result.  A run the simulator itself crashes (the asynchronous
    slice-stop race, see README "Things learned": a hooked CP0 instruction
    running natively ends in a jump to a stale register) -- during the boot or
    any later phase -- is retried `retries` times from a fresh boot before it
    counts as a failure.  tuner=True puts the
    dump's tuner model on the I2C bus (sim.attach_tuner: a tuner that takes its
    settings, but no signal -- the demodulator stays unlocked), so every capture
    can show the frequency it is tuned to; signal=True boots with
    sim.set_signal(True): the tuner and a locked demodulator -- on every
    frequency, or on signal_frequencies (Hz) only; mux=True adds the
    transport stream behind it (sim.attach_mux: the demultiplexer model
    feeds the tables of one made-up service, so a channel change completes).
    The boot runs in slices of slice_instructions and looks for the drawn
    screen every probe_s seconds; a screen that is up for a few seconds only
    (a channel banner) is caught with small slices, probe_s=0 and settle_s=0:
    the screen of the first slice that shows it is the one compared.
    ge=False for a chip whose CPU draws its OSD itself (the M3329): the
    screen alone tells drawn (min_ge_ops is not looked at) and when a redraw
    is over (no change for a while)."""
    print(f"=== {title or dump}: capture and verify the OSD drawn through the graphics engine ===")
    for attempt in range(retries + 1):
        try:
            _run(dump, expected, boot_limit_s, settle_s, min_ge_ops, max_diff_pct, min_colours,
                 panel_text, title, navigation, max_diff_pct if nav_diff_pct is None else nav_diff_pct,
                 nav_settle_s, signal, tuner, mux, slice_instructions, probe_s, signal_frequencies, ge)
        except SimulatorCrash as e:
            if attempt < retries:
                print(f"[WARN] simulator crashed ({e}); booting again (retry {attempt + 1} of {retries})")
                continue
            print(f"[FAIL] simulator crashed again ({e})")
            sys.exit(1)
        return


def _run(dump, expected, boot_limit_s, settle_s, min_ge_ops, max_diff_pct, min_colours, panel_text, title,
         navigation, nav_diff_pct, nav_settle_s, signal, tuner, mux, slice_instructions, probe_s, signal_frequencies,
         ge=True):
    make_expected = "--make-expected" in sys.argv or os.environ.get("MAKE_EXPECTED") == "1"
    name = os.path.splitext(os.path.basename(expected))[0].replace("_screen", "")
    sim = AliMipsSimulator(rom_size=flash_size_for(dump), log_handler=lambda m: None)
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    uart = []
    sim.setUartHandler(lambda c: uart.append(c))
    panel, _keys, panel_desc = make_panel(dump, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    sim.loadFile(dump)
    print(f"front panel: {panel_desc}")
    if signal:
        model, demod = sim.set_signal(True, frequencies=signal_frequencies)
        where = ", ".join(f"{f / 1e6:.3f} MHz" for f in signal_frequencies) if signal_frequencies else "every frequency"
        print(f"signal ({where}): tuner model {type(model).__name__ if model else None}, demodulator locked: {demod}")
    elif tuner:
        model = sim.attach_tuner()
        print(f"tuner model: {type(model).__name__ if model else None} (no signal)")
    if mux:
        # a fixed clock: the EIT's programme times (and the TDT) must not follow the host's time of day
        import datetime
        import transport_stream
        dmx = sim.attach_mux(transport_stream.Mux(clock=datetime.datetime(2026, 10, 10, 12, 0, 0, tzinfo=datetime.timezone.utc)))
        print(f"transport stream: {'attached to the demultiplexer model' if dmx else 'no demultiplexer model for this chip'}")
    info = dump_catalog.load(dump)
    sidecar_panel = bool(info and info["device"].get("panel"))

    def has_panel():
        """Whether the box has a display to show beside a capture: its sidecar
        names a panel chip, or the decoder has seen the firmware drive one
        (buttons on GPIO alone, gpio_keys.py, have none)."""
        if not getattr(panel, "has_display", True):
            return False
        return sidecar_panel or getattr(panel, "i2c_transaction_count", 0) or getattr(panel, "frame_count", 0)

    def shot(path, caption):
        """Report a capture with the box's state at that moment: the front
        panel (when it has one) and the tuner's frequency (with a model)."""
        show = has_panel()
        report_artifacts.image(path, caption, panel=panel.digits if show else None,
                               panel_text=panel.get_display_text() if show else None,
                               tuner=sim.tuner_info())

    fw = sim._vtime                     # the firmware's time (see the module's docstring)
    start = time.time()
    app_t = drawn_t = drawn_fw = None
    last_probe = -1e9
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
            if has_panel():
                report_artifacts.panel(panel.digits, "front panel at the end", panel.get_display_text())
            raise SimulatorCrash(f"nothing drawn within {boot_limit_s:.0f} s (GE commands: {sim.ge_ops}, "
                                 f"UART: {''.join(uart)[-120:]!r})")
        if drawn_t is not None and fw() - drawn_fw > settle_s:
            break
        try:
            sim.run(max_instructions=sim.instruction_count + slice_instructions)
        except Exception as e:
            raise SimulatorCrash(f"{type(e).__name__}: {e} at {time.time() - start:.0f} s, "
                                 f"{sim.ge_ops} GE commands") from e
        if (sim.mu.reg_read(UC_MIPS_REG_PC) & ~1) == 0:
            raise SimulatorCrash(f"jump to NULL at {time.time() - start:.0f} s, {sim.ge_ops} GE commands")
        note_panel()
        if app_t is None and "Application version" in "".join(uart[-400:]):
            app_t = time.time()
            print(f"[{app_t - start:6.1f}s] application started")
        # "drawn" = enough GE commands AND something visible, probed every
        # 10 s whatever the GE does: the Globo shows a channel banner that
        # times out and clears before its no-signal message, and the
        # Cabletech's wizard keeps redrawing a little, so neither "N commands
        # done" nor "the GE went quiet" alone marks the screen to capture.
        if drawn_t is None and (sim.ge_ops >= min_ge_ops or not ge) and fw() - last_probe >= probe_s:
            last_probe = fw()
            rgb = sim.capture_screen()
            colours = len(np.unique(rgb.reshape(-1, 3), axis=0))
            if colours >= min_colours:
                drawn_t, drawn_fw = time.time(), fw()
                print(f"[{drawn_t - start:6.1f}s] {sim.ge_ops} GE commands: the OSD is visible "
                      f"({colours} colours, firmware time {drawn_fw:.0f} s), settling {settle_s:.0f} s")
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
            shot(path, f"frame {frames} after {sim.ge_ops} GE commands ({time.time() - start:.0f} s)")
        prev = rgb

    out = report_artifacts.path(f"{name}_screen.png")
    rgb = sim.capture_screen(out)
    colours = len(np.unique(rgb.reshape(-1, 3), axis=0))
    # a screen that is blank at this moment (a banner that has just cleared, a
    # channel change in progress) is given up to a minute to come back
    def advance(until):
        """One run() toward `until` (firmware time); False once the firmware
        no longer moves on (a stopped CPU), so no wait loops for ever.  A
        crash here is retried from a fresh boot like one during the boot."""
        before = fw()
        try:
            sim.run(max_instructions=sim.instruction_count + 5_000_000, max_vtime=until)
        except Exception as e:
            raise SimulatorCrash(f"{type(e).__name__}: {e} at {time.time() - start:.0f} s (after the boot)") from e
        if (sim.mu.reg_read(UC_MIPS_REG_PC) & ~1) == 0:
            raise SimulatorCrash(f"jump to NULL at {time.time() - start:.0f} s (after the boot)")
        return fw() > before

    def run_for(seconds):
        """Run the firmware for `seconds` of its own time."""
        until = fw() + seconds
        while fw() < until and advance(until):
            pass

    for _ in range(12):
        if colours >= min_colours:
            break
        run_for(5)
        rgb = sim.capture_screen(out)
        colours = len(np.unique(rgb.reshape(-1, 3), axis=0))
        if colours >= min_colours:
            print(f"[{time.time() - start:6.1f}s] the screen was blank at the capture: captured again ({colours} colours)")
    unsupported = dict(sim.ge.unsupported) if sim.ge else {}
    lines, size = gma_capture.output_mode(bytes(sim.mmio_buffer[0:0x10000]))
    mode = f"{size[0]}x{size[1]} ({lines} lines)" if size else f"{lines} lines"
    print(f"display engine output: {mode}; the capture shows the OSD at its own 1280x720")
    print(f"saved {out}: {rgb.shape[1]}x{rgb.shape[0]}, {colours} colours, {sim.ge_ops} GE commands, "
          f"GE features not modelled: {unsupported or 'none'}")
    shot(out, f"final screen: {colours} colours, {sim.ge_ops} GE commands ({time.time() - start:.0f} s)")
    print("front panel: " + (" -> ".join(f"[{t}]" for t in panel_texts) if has_panel() else "none")
          + f"; tuner: {sim.tuner_info() or 'no model'}" + (f"; {sim.dmx_info()}" if mux else ""))

    def check(cond, msg):
        nonlocal ok
        print(("  [PASS] " if cond else "  [FAIL] ") + msg)
        ok &= bool(cond)

    check(colours >= min_colours, f"the screen is not uniform ({colours} colours, need {min_colours})")
    if panel_text is not None:
        check(panel.get_display_text() == panel_text,
              f"front panel shows [{panel.get_display_text()}] (expected [{panel_text}])")
    def against_expected(rgb, expected_name, allowed_pct, what):
        expected_path = os.path.join(EXPECTED_DIR, expected_name)
        if make_expected:
            gma_capture.save_png(expected_path, rgb)
            print(f"  [PASS] expected screen written: {expected_path}")
            return
        if not os.path.exists(expected_path):
            check(False, f"expected screen {expected_name} missing (run with --make-expected)")
            return
        from PIL import Image
        want = np.array(Image.open(expected_path).convert("RGB"))
        try:
            n, pct, maxd, mask = compare(rgb, want)
        except ValueError as e:
            check(False, f"comparison with the expected screen: {e}")
            return
        check(pct <= allowed_pct, f"{what} matches the expected screen {expected_name}: {n} pixels differ "
                                  f"({pct:.2f}%, allowed {allowed_pct:.2f}%, max channel diff {maxd})")
        if n:
            diff = np.zeros_like(rgb)
            diff[mask] = [255, 0, 0]
            diff_path = report_artifacts.path(f"{os.path.splitext(expected_name)[0]}_diff.png")
            gma_capture.save_png(diff_path, diff)
            report_artifacts.image(diff_path, f"difference of the {what} to {expected_name}: {n} pixels "
                                              f"({pct:.2f}%), red = differing")

    against_expected(rgb, expected, max_diff_pct, "screen")

    # navigation: drive the UI with the remote / the front panel
    def settle(max_s, quiet_s, min_s=0):
        """Run until the GE has issued no command for quiet_s seconds of the
        firmware's time (at least min_s, at most max_s): a redraw or a
        banner's timeout must be over, a fixed wait captured half-drawn menus
        and banners that had not gone yet.  Without a GE, until the screen
        has not changed for quiet_s seconds."""
        t0 = fw()
        last_ops, last_change = sim.ge_ops, t0
        last_screen = None if ge else sim.capture_screen()
        while fw() - t0 < max_s:
            if not advance(t0 + max_s):
                return False
            now = fw()
            if not ge:
                screen = sim.capture_screen()
                if not np.array_equal(screen, last_screen):
                    last_screen, last_change = screen, now
                elif now - last_change >= quiet_s and now - t0 >= min_s:
                    return True
            elif sim.ge_ops != last_ops:
                last_ops, last_change = sim.ge_ops, now
            elif now - last_change >= quiet_s and now - t0 >= min_s:
                return True
        return False

    previous = rgb
    for i, (key, min_px) in enumerate(navigation, 1):
        ops = sim.ge_ops
        try:
            if isinstance(key, tuple) and key[0] == "wait":     # ("wait", seconds): no key, the firmware goes on
                run_for(key[1])
                label = f"{key[1]:.0f} s without a key"
            elif isinstance(key, tuple):                 # ("panel", code[, reads]): a front-panel key
                panel.press_key(key[1], hold_reads=key[2] if len(key) > 2 else 2)
                label = f"panel key {key[1]}"
            else:
                addr, cmd = sim.press_key(key)
                label = f"{key} (NEC 0x{addr:02X}/0x{cmd:02X})"
        except Exception as e:
            check(False, f"navigation step {i}: cannot press {key!r}: {e}")
            break
        # wait for the step's own change to appear (up to 2 minutes of the
        # firmware's time; a firmware that redraws something small on its own --
        # a blinking no-signal text -- must not count as the redraw having
        # started), then for the redraw to finish
        t = fw()
        while fw() - t < 120 and advance(t + 120):
            if (sim.ge_ops - ops >= 2 or not ge) and \
                    int((sim.capture_screen() != previous).any(axis=2).sum()) >= min_px:
                break
        settle(120, 8, min_s=20)
        after = sim.capture_screen()
        changed = int((after != previous).any(axis=2).sum())
        step = f"{key[0]}{key[1]:.0f}" if isinstance(key, tuple) and key[0] == "wait" else key[1] if isinstance(key, tuple) else key
        path = report_artifacts.path(f"{name}_nav_{i}_{str(step).replace('+', 'plus').replace('-', 'minus')}.png")
        gma_capture.save_png(path, after)
        shot(path, f"navigation step {i}: {label}: {sim.ge_ops - ops} GE commands, {changed} pixels changed")
        check(changed >= min_px, f"navigation step {i}: {label} changed the screen "
                                 f"({changed} pixels, need {min_px}; {sim.ge_ops - ops} GE commands)")
        # (the IR receiver's state: a frame waits in the queue until the firmware has drained
        # the previous one's FIFO and acknowledged its interrupt, see simulator._irc_service)
        print(f"[{time.time() - start:6.1f}s] navigation {i}: {label}: {sim.ge_ops - ops} GE commands, "
              f"{changed} pixels changed, panel [{panel.get_display_text()}]; IR frames delivered "
              f"{sim.ir_keys_sent}, queued {len(sim._irc_frames)}, FIFO {len(sim._irc_fifo)} bytes, "
              f"status 0x{sim._irc_status:02X}, IRCCFG 0x{sim.peek(0xB8018100, 1)[0]:02X}")
        previous = after
    if navigation:
        if nav_settle_s:
            # let a banner or an animation finish before the comparison: wait
            # until the screen has become the expected one (a banner that has not
            # timed out yet is itself static, so "GE quiet" would not do), or
            # for the whole budget when there is no expected screen to wait for yet
            nav_expected_path = os.path.join(EXPECTED_DIR, f"{name}_nav.png")
            if not make_expected and os.path.exists(nav_expected_path):
                from PIL import Image
                want = np.array(Image.open(nav_expected_path).convert("RGB"))
                t0 = fw()
                while True:
                    previous = sim.capture_screen()
                    try:
                        if compare(previous, want)[1] <= nav_diff_pct:
                            break
                    except ValueError:
                        break
                    if fw() - t0 >= nav_settle_s:
                        break
                    run_for(10)
                print(f"[{time.time() - start:6.1f}s] final screen settled after {fw() - t0:.0f} s of firmware time")
            else:
                run_for(nav_settle_s)
                previous = sim.capture_screen()
            path = report_artifacts.path(f"{name}_nav_final.png")
            gma_capture.save_png(path, previous)
            shot(path, f"screen {nav_settle_s:.0f} s after the last navigation step")
        against_expected(previous, f"{name}_nav.png", nav_diff_pct, "screen after the navigation")
    print(f"\n[{'PASS' if ok else 'FAIL'}] {title or dump} screen regression ({time.time() - start:.0f} s total)")
    sys.exit(0 if ok else 1)
