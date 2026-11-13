#!/usr/bin/env python3
"""The Maciej demo v4 on a Comsat TE 1050 HD (dump.bin's board), in the emulator.

The same shipped v4 flash image as run_dump_maciej_demo_v4.py (the Opticum
HD N2's bootloader and the demo), on the other board it runs on: no TM1650 on
GPIO 31 / 9 but two buttons on those pins, each pulled up and shorted to
ground when pressed (front_panel.py's dump.bin entry, gpio_keys.GpioKeys).
Checks that the demo finds no panel chip and lets go of both pins for good --
a pin driven high would be shorted by a pressed button -- reports the two
buttons on the UART, on the screen and through 'keys', refuses panel text,
names the board in 'info', and that 'video init' replays the Comsat's own
display set-up (recorded from dump.bin with a TV on the HDMI port) up to the
HDMI transmitter's start; 'video init opticum' the other board's.  The chip
answers revision 1 here (chip ID word 0x38110001), as the real Comsat box
does: the tables of that revision are replayed and the layer is enabled the
way both firmwares do it on revision 1 (0x00040001), its head carrying their
RGB -> YCbCr matrix -- and what the real box showed without it is shown here
too: the matrix zeroed, every colour black; bit 19 set, the RGB pixels taken
as YCbCr (the dark background green).  'video init comsat rev0' still
replays the revision-0 table.  A USB keyboard plugged in types into the
command line, the controller's PHY set up with the revision-1 values the
box's own firmware writes.  Then a restart through the original bootloader
comes back in the same mode, the keyboard (still plugged in) found before
the first prompt.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import numpy as np                                                   # noqa: E402

import run_dump_maciej_demo_v4 as v4                                 # noqa: E402
from run_dump_maciej_demo_v4 import (BIN, BT709_MATRIX, HEAD_PHYS, PROMPT, STEM, APP_BANNER, Box,  # noqa: E402
                                     check, check_head_block, check_keyboard_basics, check_usb_setup,
                                     check_video_state, check_watchdog_running, mmio, near, shown, type_on)
from usb_host import VirtualKeyboard                                 # noqa: E402

PINS = (1 << 31) | (1 << 9)
C_DIM = shown(120, 120, 140)


def color_pixels(rgb, y0, y1, x0, x1, color, tol=6):
    return int((np.abs(rgb[y0:y1, x0:x1] - color).max(axis=2) <= tol).sum())


def run(args):
    started = time.monotonic()
    box = Box(BIN / f"{STEM}.bin", args.engine, board="dump.bin")
    box.sim.poke(0xB8000000, (0x38110001).to_bytes(4, "little"))      # revision 1, as the real box
    gpio = []                    # the GPIO bank-0 output / direction stores: (vtime, offset, value)
    box.sim.add_mmio_hook("write", lambda uc, access, address, size, value, user_data=None:
                          gpio.append((box.sim._vtime(), address & 0xFFFFFF, value)), 0x54, 0x5B)
    boot = box.boot().decode("latin-1")
    check(f"{APP_BANNER}\r\nVersion: v4\r\n" in boot, "the original bootloader starts the v4 demo")
    check("No TM1650 front panel: GPIO 31 / 9 are read as two buttons (Comsat TE 1050 HD type board)" in boot,
          "the demo finds no TM1650 and says it reads the pins as two buttons")
    check(not mmio(box.sim, 0x58, 4) & PINS and not mmio(box.sim, 0x54, 4) & PINS,
          "both pins are inputs after the probe (GPIO direction bits 31 and 9 clear, output latch low)")
    check_watchdog_running(box, boot)
    mark = len(gpio)

    out = box.command("info")
    check("board: no TM1650; two buttons on GPIO 31 / 9 (Comsat TE 1050 HD type)" in out, "info names the board")
    check("revision byte 01" in out and mmio(box.sim, 0x6300, 4) == 0x40001 and mmio(box.sim, 0x63B8, 4) == 1,
          "a revision-1 chip: the layer is enabled with bit 18 set and bit 19 clear (0xB8006300 = 0x00040001), "
          "a true-colour region (0xB80063B8 = 1), as the originals do")
    check("display layer register 0xb8006300: 0x00000000 at the demo's start, 0x00040001 now" in out,
          "info: the layer register as the demo found it and now")
    check_head_block(box.sim, "revision 1")
    out = box.command("keys")
    check("buttons: UP (GPIO 31) released, DOWN (GPIO 9) released; 0 presses so far" in out,
          "keys: both buttons released")
    out = box.command("panel HELO")
    check("no front panel display on this board" in out, "panel text is refused: there is no display")

    # ---- the two buttons -------------------------------------------------------
    # (the demo polls every 100 ms of its CP0 Count clock, about 0.34 s of the emulator's time)
    box.panel.press_key(31, hold_reads=5)
    out = box.run(3.0)
    check("[panel] button UP (GPIO 31) pressed" in out and "[panel] button UP (GPIO 31) released" in out,
          "UP (GPIO 31): pressed and released are reported")
    box.panel.press_key(9, hold_reads=5)
    out = box.run(3.0)
    check("[panel] button DOWN (GPIO 9) pressed" in out and "[panel] button DOWN (GPIO 9) released" in out,
          "DOWN (GPIO 9): pressed and released are reported")
    box.panel.press_key(31, hold_reads=1)
    out = box.run(1.5)
    check("[panel] button" not in out, "a single low read is not a press: two reads 100 ms apart must agree")
    box.panel.press_key(31, hold_reads=8)
    box.run(1.0)
    out = box.command("keys")
    check("buttons: UP (GPIO 31) pressed, DOWN (GPIO 9) released; 3 presses so far" in out,
          "keys shows UP held down")
    rgb = box.screen("v4_comsat_button_screen.png", "Comsat board: UP held")
    check(color_pixels(rgb, 384, 400, 150, 600, C_DIM) > 100, "the front panel box says: buttons on GPIO 31 / 9, no display")
    white = np.abs(rgb[410:426] - 255).sum(axis=2) < 30
    check(white[:, 256:340].sum() > 30,
          "and shows the last button event (its text reaches past the boot placeholder '(press a key)', x 100..255)")
    out = box.run(4.0)
    check("[panel] button UP (GPIO 31) released" in out, "UP released once let go")
    bars = [(255, 255, 255), (255, 255, 0), (0, 255, 255), (0, 255, 0), (255, 0, 255), (255, 0, 0), (0, 0, 255), (0, 0, 0)]
    check(all(near(rgb[586, 676 + 68 * i + 34], c) for i, c in enumerate(bars)),
          "the demo picture is drawn, its colours through the head's BT.709 matrix")
    background = rgb[700, 640].copy()

    # ---- what the real box showed (revision 1) ---------------------------------
    matrix = 0xA0000000 | (HEAD_PHYS + 0x240)
    for i in range(12):
        box.command(f"mw 0x{matrix + 4 * i:08x} 0")
    rgb = box.screen("v4_comsat_zero_matrix_screen.png", "Comsat board, revision 1: the head's RGB -> YCbCr matrix zeroed")
    check(int(rgb.max()) == 0 and mmio(box.sim, 0x6300, 4) == 0x40001,
          "the head's matrix zeroed: every colour black, the layer still on (the real box's first black screen)")
    box.command("mw 0xb8006300 0x000c0001")
    rgb = box.screen("v4_comsat_bit19_screen.png", "Comsat board: bit 19 of 0xB8006300 set, RGB pixels read as YCbCr")
    dark = tuple(int(v) for v in rgb[700, 640])
    check(dark[1] > 60 and dark[0] < 20 and dark[2] < 20,
          f"bit 19 set: the matrix skipped, the RGB pixels taken as Cr / Y / Cb -- the dark background green {dark}")
    box.command("mw 0xb8006300 0x00040001")
    for i, word in enumerate(BT709_MATRIX[:12]):
        box.command(f"mw 0x{matrix + 4 * i:08x} 0x{word & 0xFFFFFFFF:08x}")
    rgb = box.screen("v4_comsat_matrix_back_screen.png", "Comsat board: the matrix written back")
    check(all(near(rgb[586, 676 + 68 * i + 34], c) for i, c in enumerate(bars)) and near(rgb[700, 640], background, 1)
          and max(background) < 40,
          f"the matrix written back: the colours again (the background dark blue {tuple(int(v) for v in background)})")

    # ---- the display set-up: this board's own -----------------------------------
    out = box.command("video init", timeout=60)
    check("of the Comsat TE 1050 HD's display set-up (dump.bin, chip revision 1" in out
          and "HDMI transmitter running (0xb802a007 = 7c)" in out,
          "video init picks the Comsat's revision-1 table (no TM1650, chip revision 1) and starts the HDMI transmitter")
    check_video_state(box.sim, "comsat", "video init", rev=1)
    out = box.command("video init opticum", timeout=60)
    check("of the Opticum HD N2's display set-up (dump_maciej.bin, chip revision 1" in out,
          "video init opticum replays the other board's (revision 1)")
    check_video_state(box.sim, "opticum", "video init opticum", rev=1)
    out = box.command("video init comsat rev0", timeout=60)
    check("of the Comsat TE 1050 HD's display set-up (dump.bin, chip revision 0" in out,
          "video init comsat rev0 replays the revision-0 table on request")
    check_video_state(box.sim, "comsat", "video init comsat rev0", rev=0)
    out = box.command("video init sky")
    check("usage: video init [opticum|comsat] [rev0|rev1]" in out and "this board's, comsat" in out,
          "an unknown board name gets the usage, which names this board's table")
    box.command("video init comsat", timeout=60)
    rgb = box.screen("v4_comsat_video_init_screen.png", "Comsat board: after video init")
    check(all(near(rgb[586, 676 + 68 * i + 34], c) for i, c in enumerate(bars)),
          "the demo picture is back after video init")
    drove = [f"0x{v:08x} at {t:.2f} s" for t, o, v in gpio[mark:] if o == 0x58 and v & PINS]
    check(not drove, f"the demo never made GPIO 31 / 9 outputs again{': ' + ', '.join(drove[:3]) if drove else ''}")

    # ---- a USB keyboard (revision 1: the PHY's own settings) ---------------------
    # (as the one on the real box, 1a2c:2d23: low speed, two interfaces, its keys on the interrupt endpoint only)
    kbd = VirtualKeyboard(get_report="empty", composite=True)
    box.usb.attach("low", kbd)
    check_keyboard_basics(box, kbd, "revision 1", speed="low")
    check_usb_setup(box, rev=1)
    out = box.command("usb")
    check("PHY settings (+0xf0, +0xf4): 0x6800355c 0x09000ff0" in out, "usb shows the PHY's settings")
    out = type_on(box, kbd, "echo Comsat{CTRL-u}echo typed\r")
    check("echo Comsat^C" in out and "\r\ntyped\r\n" in out,
          "Ctrl with a letter is its control code (Ctrl-U clears the line)")
    # the keyboard reset behind the demo's back (on the box the display set-up's stores did that):
    # it answers at address 0 only, unconfigured, until it is set up again
    kbd.address, kbd.configuration = 0, 0
    out = box.run(3.0)
    # (the error is the interrupt IN's, or -- once its data toggle is not known any more -- that of the
    #  CLEAR_FEATURE that would put it back to DATA0)
    check(re.search(r"keyboard: no answer \((interrupt IN|SETUP) stage: no response \(token error 0x20\)\) -- "
                    r"setting it up again", out) is not None
          and "[usb] keyboard set up again" in out and kbd.address == 1 and kbd.configuration == 1,
          "a keyboard that stops answering on its interrupt endpoint (no answer, not a stall) is set up again by "
          "itself")
    out = type_on(box, kbd, "ping\r")
    check("ping\r\npong v4" in out, "and types again")
    out = box.command("video init", timeout=60)
    check("USB device set up again after the display set-up: 1209:0002 Virtual USB keyboard" in out,
          "video init sets the USB device up again afterwards (on the box its stores knocked the keyboard out)")
    out = type_on(box, kbd, "ping\r")
    check("ping\r\npong v4" in out, "and the keyboard types after video init")

    # ---- a restart through the original bootloader comes back the same way -------
    # (the keyboard stays plugged in: found as the demo starts, as on the real box)
    out = box.keys(b"restart\r", PROMPT, timeout=90)
    check("Version: v4" in out and "No TM1650 front panel" in out, "after a restart: the demo again, again in button mode")
    check("[usb] device connected" in out and "keyboard on interface 0: boot protocol" in out
          and out.index("keyboard on interface 0") < out.rindex(PROMPT.decode()),
          "a keyboard plugged in before the demo starts is enumerated before its first prompt")
    out = type_on(box, kbd, "ping\r")
    check("ping\r\npong v4" in out, "and types at once")

    # ---- the watchdog restarts a stopped demo (on the chip) ------------------------
    # (the demo then spins in `b .` with interrupts off, which the emulator runs instruction by instruction,
    # so 2 s of the demo's clock are run, not the whole 8: the model tells when the counter will overflow)
    wd = box.watchdog
    timeout = (2 ** 32 - wd.start_value) / wd.rate()     # emulated seconds from a feed to the overflow
    out = box.keys(b"watchdog test\r", b"restarts within 8 s.\r\n", timeout=30)
    stopped, mark = box.sim._vtime(), len(wd.writes)
    box.run(timeout / 4)
    fed = [w for w in wd.writes[mark:] if w[1] == 0]
    due = wd.due()
    check("Not feeding the watchdog any more" in out and not fed and wd.control == 0x64 and due is not None
          and 0.95 * timeout <= due - stopped <= timeout,
          f"watchdog test: the demo stops feeding it, the counter runs on in reset mode and overflows 8 s of the "
          f"demo's clock after the last feed ({(due or 0) - stopped:.1f} s here) -- on the chip, the reset into "
          f"the original bootloader")

    elapsed = round(time.monotonic() - started, 1)
    log_dir = ROOT / "build/maciej_app/selftest" / args.engine / "demo_v4_comsat"
    log_dir.mkdir(parents=True, exist_ok=True)
    log = log_dir / "uart_demo_v4_comsat.log"
    log.write_bytes(bytes(box.t.received))
    print(f"UART log: {log}; {elapsed} s", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("cpp", "unicorn"), default=os.environ.get("ALISIM_ENGINE", "cpp"))
    args = parser.parse_args()
    print("=== The Maciej demo v4 on the Comsat TE 1050 HD's board ===", flush=True)
    run(args)
    if v4.failures:
        print(f"\n[FAIL] {len(v4.failures)} check(s) failed")
        sys.exit(1)
    print("\n[PASS] all demo v4 checks on the Comsat board")


if __name__ == "__main__":
    main()
