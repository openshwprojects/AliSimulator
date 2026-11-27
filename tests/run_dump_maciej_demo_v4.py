#!/usr/bin/env python3
"""The Maciej demo v4 on the original Opticum HD N2 bootloader, in the emulator.

Boots the shipped v4 flash image (firmware/maciej_app/bin: dump_maciej.bin
with the demo as its main code, started by the original bootloader) and
drives it only through its inputs -- UART bytes, IR frames into the remote
control receiver, front-panel key presses on the TM1650, a USB stick, a USB
keyboard, a USB mouse, a USB hub with devices behind it and an LTE module
(its AT ports; its RNDIS network link, where SSDP is checked) plugged into the
host port --
and checks its outputs: the
command line (whole lines, editing, history, every command; typed on the UART
or on the keyboard, read from its interrupt endpoint or with GET_REPORT), the
TV picture (the OSD layer, captured and checked pixel by pixel), the front
panel's digits, the decoded remote codes with their button names, the USB
port's state and the controller's set-up (the PHY's as the box's firmware
writes it), the watchdog (running in reset mode, fed, never overflowing:
src/watchdog.py's counter model), the
experimental display set-up (the Opticum's table, ending with the HDMI
transmitter's start), the restart through the original bootloader and the UART
updater's boot capture from the running demo (the same image on the Comsat TE
1050 HD's board, no TM1650 but two buttons: run_dump_maciej_demo_v4_comsat.py).
When a MIPS GCC is found the demo is also rebuilt from source and compared
with the shipped application byte for byte.  No guest register, RAM or flash
is patched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))

import numpy as np                                                   # noqa: E402

from maciej_image import extract_application, validate_image        # noqa: E402
from maciej_uart import BootloaderClient, FLASH_SIZE, MAIN_OFFSET, validate_maincode   # noqa: E402
from run_maciej_bootloader_update import APP_BANNER, SimulatorTransport  # noqa: E402
from front_panel import make_panel                                  # noqa: E402
from tm1650_decoder import TM1650Decoder                             # noqa: E402
from usb_host import VirtualHub, VirtualKeyboard, VirtualModem, VirtualMouse, VirtualStick   # noqa: E402
import report_artifacts                                              # noqa: E402

BIN = ROOT / "firmware/maciej_app/bin"
STEM = "elektroda_ali_m3801_maciej_v4"
PROMPT = b"m3801> "
FB_PHYS = 0x02000000                 # the demo's picture (hw.h)
HEAD_PHYS = 0x00F00000               # its region head block (hw.h: 0x280 bytes)
# the RGB -> YCbCr matrix both originals put at +0x240 of each head on a revision-1 S3811 (HD output)
BT709_MATRIX = [93, 314, 32, 0, -52, -173, 225, 0, 225, -204, -21, 0, 45]
failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}", flush=True)
    if not ok:
        failures.append(text)
    return ok


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def rev8(b):
    return int(f"{b & 0xFF:08b}"[::-1], 2)


def nec_code(address, command, address_hi=None):
    """The 32-bit code the SDK's NEC decoder (and the demo) shift in from a frame."""
    a2 = (~address & 0xFF) if address_hi is None else address_hi
    return rev8(address) << 24 | rev8(a2) << 16 | rev8(command) << 8 | rev8(~command & 0xFF)


def nec_for(table_code):
    """(address, command, address_hi) of the box's remote for a key-table code
    (gen_ir_keys.py): extended NEC, first address byte 0x40 (its bootloader's
    wake code 0x023750AF)."""
    hi, lo = table_code >> 8, table_code & 0xFF
    return 0x40, (~rev8(lo)) & 0xFF, rev8(hi)


def video_table(key, rev=0):
    """The (offset, size, value) entries of a board's table for a chip revision in video_init.h
    (size 0: a wait)."""
    text = (ROOT / "firmware/maciej_app/demo/video_init.h").read_text(encoding="utf-8")
    body = text[text.index(f"video_init_{key}_rev{rev}["):]
    body = body[:body.index("};")]
    return [(int(o, 16), int(n), int(v, 16)) for o, n, v in
            re.findall(r"\{0x([0-9a-f]+), (\d), 0x([0-9a-f]+)\}", body)]


def last_values(table):
    """{offset: (size, value)} of the last store to each register."""
    return {o: (n, v) for o, n, v in table if n}


def mmio(sim, offset, size):
    return struct.unpack_from({1: "<B", 2: "<H", 4: "<I"}[size], sim._mmio_view, offset)[0]


def check_video_state(sim, key, label, rev=0):
    """After 'video init': the DE timing, the HDMI transmitter out of reset and unmuted, the
    board's own TV encoder settings (registers whose last values differ between the boards' tables
    of that revision) and the layer enable of the chip's revision."""
    table = video_table(key, rev)
    other = video_table("comsat" if key == "opticum" else "opticum", rev)
    mine, theirs = last_values(table), last_values(other)
    check(mmio(sim, 0x600C, 4) == 0x02EE0F78, f"{label}: the display engine runs 720p (0xB800600C = 0x02ee0f78)")
    check(mmio(sim, 0x2A007, 1) == 0x7C and mmio(sim, 0x2A009, 1) & 0x08,
          f"{label}: the HDMI transmitter is out of soft reset and unmuted (0xB802A007 = 7c, 0xB802A009 bit 3)")
    own = sorted(o for o in mine if 0x8000 <= o < 0x8100 and o in theirs and mine[o] != theirs[o])
    check(bool(own) and all(mmio(sim, o, mine[o][0]) == mine[o][1] for o in own),
          f"{label}: the TV encoder holds this board's own values "
          f"({', '.join(f'0x{0xB8000000 | o:08x}' for o in own)})")
    check(mmio(sim, 0x400, 4) == 0x300 and mmio(sim, 0x6308, 4) == 0xFF and not mmio(sim, 0x54, 4) & (1 << 17),
          f"{label}: HDMI PHY 0xB8000400 = 0x300 and GPIO 17 low (both originals, at their HDMI start), the layer's "
          f"global alpha 0xB8006308 = 0xff, i.e. none (both originals' value on revision 1)")
    want = 0x40001 if sim._mmio_view[0] else 0x1
    check(mmio(sim, 0x6300, 4) == want, f"{label}: the layer enable of this chip's revision, as the originals "
                                        f"(0xB8006300 = 0x{want:x}; is 0x{mmio(sim, 0x6300, 4):x})")


def check_artifacts():
    manifest = json.loads((BIN / f"{STEM}.json").read_text(encoding="utf-8"))
    image = (BIN / f"{STEM}.bin").read_bytes()
    payload = (BIN / f"{STEM}.maincode.bin").read_bytes()
    flash, chunks, trailer = validate_image(image)
    application = extract_application(flash)
    check(trailer is None and len(flash) == FLASH_SIZE, "shipped v4 flash image is 4 MiB without a UART trailer")
    check(manifest["application_version"] == "v4" and manifest["banner"] == APP_BANNER, "manifest names v4 and the banner")
    for name, data in (("flash", flash), ("payload", payload), ("application", application)):
        check(len(data) == manifest[f"{name}_size"] and sha256(data) == manifest[f"{name}_sha256"],
              f"{name}: size and SHA-256 match the manifest")
    validate_maincode(payload)
    check(payload == flash[MAIN_OFFSET:MAIN_OFFSET + len(payload)], "UART payload is the image's main code chunk")
    original, _, _ = validate_image((ROOT / "dumps/dump_maciej.bin").read_bytes())
    check(flash[:MAIN_OFFSET] == original[:MAIN_OFFSET] and
          flash[MAIN_OFFSET + chunks[2].span:] == original[MAIN_OFFSET + chunks[2].span:],
          "bootloader, HDCP key and everything after the main code allocation unchanged")
    sources = {"maciej_uart.py": ROOT / "tools/maciej_uart.py", f"{STEM}.maincode.bin": BIN / f"{STEM}.maincode.bin",
               "README_UART.txt": BIN / "README_UART_v4.txt"}
    with zipfile.ZipFile(BIN / "maciej_uart_v4.zip") as bundle:
        ok = bundle.testzip() is None and sorted(bundle.namelist()) == sorted(sources) and \
            all(bundle.read(n) == p.read_bytes() for n, p in sources.items())
        bundle.read("README_UART.txt").decode("ascii")
    check(ok, "maciej_uart_v4.zip holds the current updater, payload and ASCII instructions")
    return flash, application, manifest


def check_rebuild(application, require):
    try:
        from firmware.maciej_app.build import DEMO_SOURCES, build, find_prefix
        prefix = find_prefix(None)
    except SystemExit as exc:
        if require:
            check(False, f"MIPS toolchain for the rebuild: {exc}")
        else:
            print(f"  [NOT APPLICABLE] rebuild from source: {exc}", flush=True)
        return
    if not all(shutil.which(prefix + t) for t in ("gcc", "objcopy", "objdump")):
        check(False, "complete MIPS toolchain (gcc, objcopy, objdump)")
        return
    out = ROOT / "build/maciej_app/selftest/demo_v4_rebuild"
    built = build(out, "v4", prefix, sources=DEMO_SOURCES).read_bytes()
    check(built == application, f"demo rebuilt from firmware/maciej_app/demo is byte for byte the shipped one "
                                f"({len(built)} bytes)")


class Box:
    """The emulated tuner running v4: the UART transport, the panel decoder, USB."""

    def __init__(self, image_path, engine, board="dump_maciej.bin"):
        self.t = SimulatorTransport(image_path, engine=engine, native_lzma=True, wall_timeout=180)
        self.sim = self.t.sim
        # the board's front panel (front_panel.py): the Opticum's TM1650, or the
        # Comsat's two buttons on the same pins (board="dump.bin")
        self.panel, _keys, _desc = make_panel(board, log_handler=lambda m: None)
        self.sim.setGpioHandler(self.panel.on_gpio_write)
        self.usb = self.sim.attach_usb_host()
        self.watchdog = self.sim.attach_watchdog()          # counts and records overflows; no reset
        self.log_mark = 0

    def boot(self, timeout=90):
        return self.t.wait_for(PROMPT, timeout)

    def command(self, text, timeout=15):
        self.t.pending.clear()
        self.t.write(text.encode("latin-1") + b"\r")
        out = self.t.wait_for(b"\r\n" + PROMPT, timeout)
        return out.decode("latin-1")

    def keys(self, raw, until=PROMPT, timeout=10):
        self.t.pending.clear()
        self.t.write(raw)
        return self.t.wait_for(until, timeout).decode("latin-1")

    def run(self, seconds):
        """Let the box run `seconds` of emulated time; the UART output meanwhile."""
        mark = len(self.t.received)
        end = self.sim._vtime() + seconds
        while self.sim._vtime() < end:
            self.t.read(1 << 20, end - self.sim._vtime())
        return bytes(self.t.received[mark:]).decode("latin-1")

    def screen(self, name, caption):
        rgb = self.sim.capture_screen()
        path = report_artifacts.path(name)
        import gma_capture
        gma_capture.save_png(path, rgb)
        report_artifacts.image(path, caption, panel=self.panel.digits, panel_text=self.panel.get_display_text())
        return rgb.astype(int)

    def flash(self):
        return bytes(self.sim.rom_image[:FLASH_SIZE])


def near(pixel, rgb, tol=10):
    return all(abs(int(a) - b) <= tol for a, b in zip(pixel, rgb))


def expand5(v8):
    """An 8-bit colour channel after ARGB1555 (5 bits, expanded back)."""
    v = v8 >> 3
    return (v << 3) | (v >> 2)


def rgb555(r, g, b):
    """The ARGB1555 word the demo stores for a colour (hw.h RGB(), alpha bit set)."""
    return 0x8000 | (r >> 3) << 10 | (g >> 3) << 5 | (b >> 3)


def shown(r, g, b):
    """The colour as the screen capture shows the demo's ARGB1555 pixel of it."""
    return expand5(r), expand5(g), expand5(b)


def fb_pixel(sim, x, y):
    """The 16-bit word the demo stored for pixel (x, y) of its picture (hw.h FB_PHYS)."""
    return struct.unpack_from("<H", sim.ram_buffer, FB_PHYS + 2 * (y * 1280 + x))[0]


def fb_rgb(sim):
    """The test screen's picture as RGB, read from its bitmap (it need not be on the TV)."""
    words = np.frombuffer(sim.ram_buffer, dtype="<u2", count=1280 * 720, offset=FB_PHYS).reshape(720, 1280)
    rgb = np.stack([(words >> 10) & 31, (words >> 5) & 31, words & 31], axis=2).astype(int)
    return (rgb << 3) | (rgb >> 2)


# the console (console.c): 105 x 42 cells of 12 x 16 pixels from (10, 32), the title's cells at y 5; the
# glyphs are the demo's 5 x 7 font (font5x7.h) at twice its size
CON_HEAD_PHYS, CON_FB_PHYS = 0x00F00800, 0x02200000
CON_COLS, CON_ROWS, CON_X0, CON_Y0, CON_TITLE_Y = 105, 42, 10, 32, 5


def _font():
    rows = [tuple(int(v, 16) for v in re.findall(r"0x([0-9a-f]{2})", line))
            for line in (ROOT / "firmware/maciej_app/demo/font5x7.h").read_text().splitlines()
            if line.strip().startswith("{0x")]
    glyphs = {}
    for i, g in enumerate(rows):
        glyphs.setdefault(g, chr(0x20 + i))
    return glyphs


FONT_GLYPHS = _font()


def read_cell(rgb, x, y):
    """The character in the cell at (x, y) and its colour (the cursor's inverted block too)."""
    bg = rgb[y, x + 10]                                     # (the spacing column: the cell's background)
    lit = lambda px: int(np.abs(px - bg).sum()) > 60       # noqa: E731
    rows, colour = [], None
    for r in range(7):
        bits = 0
        for c in range(5):
            px = rgb[y + 2 * r, x + 2 * c]
            if lit(px):
                bits |= 0x10 >> c
                colour = tuple(int(v) for v in px) if colour is None else colour
        rows.append(bits)
    return FONT_GLYPHS.get(tuple(rows), "?"), colour


def console_lines(rgb):
    """The console's 42 lines as text (trailing blanks dropped)."""
    return ["".join(read_cell(rgb, CON_X0 + c * 12, CON_Y0 + r * 16)[0] for c in range(CON_COLS)).rstrip()
            for r in range(CON_ROWS)]


def console_title(rgb):
    return "".join(read_cell(rgb, CON_X0 + c * 12, CON_TITLE_Y)[0] for c in range(CON_COLS)).strip()


def console_rgb(box):
    """The TV after a moment (the console draws what changed from its main loop, every 30 ms at most)."""
    box.run(0.3)
    return box.sim.capture_screen().astype(int)


def console_text(box):
    """What the TV's console shows now (it must be on the TV)."""
    return console_lines(console_rgb(box))


def check_console(box):
    """The console on the TV (console.c), the view after boot: what the UART shows, as a text terminal
    with a title bar -- the prompt green, what is typed white, the output grey -- 'clear', PgUp / PgDn
    looking back, and 'testscreen' / 'console' switching the TV between it and the test screen."""
    rgb = console_rgb(box)
    lines, title = console_lines(rgb), console_title(rgb)
    check(mmio(box.sim, 0x6304, 4) == CON_HEAD_PHYS and title.startswith("M3801 console - demo v4") and "up 0:" in title,
          f"after boot the TV shows the console: the layer at its own head (0xB8006304 = 0x{CON_HEAD_PHYS:08x}), a "
          f"title bar ({title!r})")
    head = list(struct.unpack_from("<160i", box.sim.ram_buffer, CON_HEAD_PHYS))
    test_head = head_block(box.sim)
    check(head[:7] == test_head[:7] and head[7] == CON_FB_PHYS and head[8:] == test_head[8:],
          f"its head is the test screen's but for the bitmap (0x{CON_FB_PHYS:08x}): the same format, size, matrix")
    check(lines[-3:] == ["m3801> ping", "pong v4", "m3801>"],
          f"it shows what the UART shows: the last command, its answer, the prompt ({lines[-3:]})")
    prompt_colour = read_cell(rgb, CON_X0, CON_Y0 + 39 * 16)[1]
    typed_colour = read_cell(rgb, CON_X0 + 7 * 12, CON_Y0 + 39 * 16)[1]
    output_colour = read_cell(rgb, CON_X0, CON_Y0 + 40 * 16)[1]
    check(near(prompt_colour, shown(100, 230, 100)) and near(typed_colour, shown(255, 255, 255))
          and near(output_colour, shown(200, 200, 200)),
          f"the prompt green, the command typed white, the output grey ({prompt_colour}, {typed_colour}, "
          f"{output_colour})")
    box.keys(b"clear\r", b"\x1b[2J\x1b[H" + PROMPT)          # (its prompt follows the escape codes)
    box.command("echo HELLO")
    lines = console_text(box)
    check(lines[:3] == ["m3801> echo HELLO", "HELLO", "m3801>"] and not any(lines[3:]),
          f"clear empties it: the prompt at the top, then what follows ({lines[:3]})")
    box.command("help", timeout=30)
    lines = console_text(box)
    check(lines[-1] == "m3801>" and not any("Commands (whole lines" in line for line in lines),
          "help's lines scroll the console: its end is on the screen")
    pages = 0
    while pages < 20 and not any("Commands (whole lines" in line for line in lines):
        send_keys(box, b"\x1b[5~")
        pages += 1
        rgb = console_rgb(box)
        lines, title = console_lines(rgb), console_title(rgb)
    check(any("Commands (whole lines" in line for line in lines) and f"{21 * pages} lines back - PgDn returns" in title,
          f"PgUp (ESC [ 5 ~) looks back half a screen a time: help's first lines after {pages}, the title says how far "
          f"({title!r})")
    for _ in range(pages):
        send_keys(box, b"\x1b[6~")
    rgb = console_rgb(box)
    check(console_lines(rgb)[-1] == "m3801>" and "lines back" not in console_title(rgb),
          "PgDn (ESC [ 6 ~) comes back to the end")
    out = box.command("testscreen")
    check(mmio(box.sim, 0x6304, 4) == HEAD_PHYS and "the test screen is on the TV" in out,
          f"testscreen shows the test screen (the layer at its head, 0x{HEAD_PHYS:08x})")
    box.command("console")
    lines = console_text(box)
    check(mmio(box.sim, 0x6304, 4) == CON_HEAD_PHYS and lines[-2:] == ["m3801> console", "m3801>"],
          "console brings the console back, drawn whole")


def send_keys(box, raw, seconds=0.5):
    """Bytes on the UART that print nothing (PgUp, ...), then a little time."""
    box.t.write(raw)
    box.run(seconds)


def head_block(sim):
    """The demo's region head block: 160 signed words (0x280 bytes at hw.h HEAD_PHYS)."""
    return list(struct.unpack_from("<160i", sim.ram_buffer, HEAD_PHYS))


# the USB PHY set-up of the box's own firmware (dump.bin's USB driver, traced in the emulator at
# both chip revisions): the PHY's reset pulse, then on revision 0 read-modify-writes from the
# registers' reset values (0 here), on revision 1 two plain words
USB_PHY_WRITES = {
    0: [(0xF2, 1, 7), (0xF2, 1, 0), (0xF0, 4, 0), (0xF4, 4, 0), (0xF0, 4, 0xF500), (0xF4, 4, 0),
        (0xF4, 4, 0x10000000), (0xF0, 4, 0x1500), (0xF0, 4, 0x60007500)],
    1: [(0xF2, 1, 7), (0xF2, 1, 0), (0xF0, 4, 0x6800355C), (0xF4, 4, 0x09000FF0)],
}


def check_usb_setup(box, rev):
    """The demo set the USB controller up as the box's firmware does at chip revision `rev`."""
    writes = [(o, s, v) for _t, o, s, v in box.usb.writes]
    want = USB_PHY_WRITES[rev]
    phy = [w for w in writes if w[0] >= 0xF0][:len(want)]
    check(phy == want, f"revision {rev}: the USB PHY set up as the box's firmware does it (+0xF2 reset pulse, then "
                       + ("+0xF0 / +0xF4 read-modify-writes to 0x60007500 / 0x10000000" if rev == 0 else
                          "+0xF0 = 0x6800355c, +0xF4 = 0x09000ff0") + ("" if phy == want else f": {phy}"))
    resets = [i for i, w in enumerate(writes) if w[0] == 0x10 and w[2] & 0x20]
    before = writes[:resets[0]] if resets else []
    check(bool(resets) and all(writes[i] == (0x10, 1, 0x20) for i in resets)
          and ((0x3D, 1, 0x60) in before) == (rev == 0) and (0x34, 1, 0x90) in writes and (0xA8, 1, 1) in writes
          and (0x8F, 1, 0x80) in writes,
          "host mode (+0x34 |= 0x90), NAK retry 1 (+0xA8), every bus reset written as +0x10 = 0x20"
          + (" after +0x3D |= 0x60 (revision 0)" if rev == 0 else " (no +0x3D write on revision 1)")
          + ", the per-endpoint device addresses on (+0x8F = 0x80)")


def check_watchdog_running(box, boot):
    """The demo runs the chip's watchdog as the originals do: reset mode (0x64), its counter started
    DOG_SECONDS = 8 s of the demo's clock before the overflow, fed every 0.1 s of that clock."""
    wd = box.watchdog
    demo_count_hz = int(re.search(r"CP0 Count (\d+) kHz", box.command("info")).group(1)) * 1000
    scale = demo_count_hz / box.sim.count_hz                 # emulated seconds per second of the demo's clock
    timeout = (2 ** 32 - wd.start_value) / wd.rate()
    check("Watchdog on: a demo stopped for 8 s restarts the box" in boot and wd.control == 0x64
          and abs(timeout - 8 * scale) < 0.03 * 8 * scale,
          f"the watchdog runs in reset mode (0xB8018504 = 0x64) from the demo's start, its counter started 8 s of the "
          f"demo's clock before the overflow (0x{wd.start_value:08x}: {timeout:.1f} s here, where Count runs at "
          f"{box.sim.count_hz / 1e6:.0f} MHz)")
    mark = len(wd.writes)
    box.run(10 * 0.1 * scale)
    feeds = [w for w in wd.writes[mark:] if w[1:] == (0, 4, wd.start_value)]
    check(8 <= len(feeds) <= 12, f"fed every 0.1 s of its clock ({len(feeds)} times in 1 s)")
    out = box.command("watchdog")
    check("watchdog at 0xb8018500: on, reset mode (control 0x64)" in out and "fed every 0.1 s" in out,
          "watchdog reports it")


def type_on(box, kbd, text, extra=0.8, **timing):
    """Type `text` on the virtual USB keyboard; the UART output while it is typed (+ extra s)."""
    return box.run(kbd.type(text, **timing) + extra)


SPEED_TEXT = {"low": "low speed (1.5 Mbit/s)", "full": "full speed (12 Mbit/s)", "high": "high speed (480 Mbit/s)"}
GET_REPORT = "a101000100000800"      # the SETUP of GET_REPORT (input report, 8 bytes)
CLEAR_HALT_81 = "0201000081000000"   # the SETUP of CLEAR_FEATURE(ENDPOINT_HALT) for endpoint 0x81: its toggle DATA0


def check_keyboard_basics(box, kbd, label, speed="full"):
    """A just plugged-in VirtualKeyboard: enumerated, recognised, typing into the command line --
    its reports read from its interrupt endpoint, which the controller's endpoint D polls by itself
    (the packets come out of that endpoint's FIFO; endpoints B and C send the keyboard nothing)."""
    wmark, smark, pmark = len(box.usb.writes), len(box.usb.setups), len(box.usb.interrupt_packets)
    tokens, polls = box.usb.in_tokens, box.usb.epd_polls
    out = box.run(2.5)
    expected = ["[usb] device connected", f"USB device 1209:0002, USB 1.10, endpoint 0: 8 bytes, {SPEED_TEXT[speed]}",
                "product: Virtual USB keyboard", "interface 0: class 03 (HID), subclass 01, protocol 01, 1 endpoints",
                "endpoint 81 interrupt, 8 bytes, every 10 ms", "configuration 1 set",
                "keyboard on interface 0: boot protocol, SET_IDLE set; reading its interrupt endpoint 81 -- type on it"]
    missing = [e for e in expected if e not in out]
    check(not missing, f"{label}: a {speed}-speed keyboard is enumerated (endpoint 0 of 8 bytes: the descriptors in "
                       f"8-byte packets) and recognised{missing or ''}")
    setups = [p.hex() for _t, p in box.usb.setups[smark:]]
    check(kbd.protocol == 0 and kbd.idle == 0 and "210b000000000000" in setups and "210a000000000000" in setups,
          f"{label}: the boot protocol selected (SET_PROTOCOL 0), reports only on a change (SET_IDLE 0)")
    writes = [(o, s, v) for _t, o, s, v in box.usb.writes[wmark:]]
    start = next((i for i, (o, _s, v) in enumerate(writes) if o == 0x2B and v & 0x08), None)
    before = writes[:start] if start is not None else []
    want = [(0x89, 1, 0x00), (0x88, 1, 0x02), (0x22, 1, 0xC4), (0x2E, 1, 0x77), (0xA3, 1, 7)]
    missing = [w for w in want if w not in before]
    check(start is not None and not missing
          and any(o == 0x31 and v & 0x70 == 0x00 for o, _s, v in before)        # (bits 0..2: endpoint C's)
          and any(o == 0x23 and v & 0x01 for o, _s, v in before) and CLEAR_HALT_81 in setups
          and box.usb.epd_polls > polls,
          f"{label}: the controller's endpoint D set polling as hcd_s3602_IntInD_start does: the keyboard's "
          "address (+0x88 = 1 << 1; no translator, +0x89 = 0) and endpoint 1 (+0x22 = 0xC4), 8-byte packets "
          "(+0x31 bits 4..6), flags 3 enabled (+0x2E = 0x77), a token every 8 ms for the endpoint's 10 (+0xA3 = "
          "7), then +0x2B bit 3 -- after both data toggles were put to DATA0 (CLEAR_FEATURE(ENDPOINT_HALT), +0x23 "
          "bit 0 pulsed)" + (f": {missing}" if missing else ""))
    check(box.usb.in_tokens == tokens
          and not any((o == 0x2B and v & 0x20) or o in (0x86, 0x87, 0xA2) for o, _s, v in writes),
          f"{label}: endpoints B and C are left alone: no IN token from endpoint B, and endpoint C -- the SDK's "
          "interrupt endpoint -- never set polling (+0x2B bit 5, +0x86, +0xA2; on a real S3811 it sends a "
          "low-speed device nothing)")
    out = type_on(box, kbd, "ping\r")
    setups = [p.hex() for _t, p in box.usb.setups[smark:]]
    reports = len(box.usb.interrupt_packets) - pmark
    check("ping\r\npong v4" in out and reports == 10 and GET_REPORT not in setups and box.usb.toggle_drops == 0
          and box.usb.in_tokens == tokens,
          f"{label}: ping typed on the keyboard -> pong v4, from its interrupt endpoint ({reports} reports: five "
          "keys down and up, each out of endpoint D's FIFO; no GET_REPORT, none dropped for its data toggle)")


def check_hub(box):
    """A hub on the port, as the one tried on a real box (Terminus 1a40:0101, seven ports as two
    chips): a high-speed hub with a second hub on its port 1, a stick on port 3 and the low-speed
    keyboard on port 4 -- every device enumerated, the keyboard read through the hub's transaction
    translator (the controller's split registers), devices plugged in and out of the hubs' ports."""
    import fat_image
    hub, hub2 = VirtualHub(4), VirtualHub(4)
    stick = VirtualStick(fat_image.build({"A.TXT": b"a"}, fat=12, size_mb=1, partition=False))
    kbd = VirtualKeyboard(get_report="empty", composite=True)
    hub.plug(1, hub2, "high")
    hub.plug(3, stick, "high")
    hub.plug(4, kbd, "low")
    wmark = len(box.usb.writes)
    box.usb.attach("high", hub)
    out = box.run(10.0)
    expected = ["[usb] device connected", "USB device 1209:0003, USB 2.00, endpoint 0: 64 bytes, high speed (480 Mbit/s)",
                "interface 0: class 09 (hub), subclass 00, protocol 00, 1 endpoints", "hub: 4 ports",
                "hub 1 port 1:", "  address 2\r\n", "hub 1 port 3:", "  address 3\r\n", "product: Virtual USB stick",
                "hub 1 port 4:", "USB device 1209:0002, USB 1.10, endpoint 0: 8 bytes, low speed (1.5 Mbit/s)",
                "address 4, reached through hub 1's transaction translator (its port 4)",
                "keyboard on interface 0: boot protocol, SET_IDLE set; reading its interrupt endpoint 81 -- type on it"]
    missing = [e for e in expected if e not in out]
    check(not missing and out.count("hub: 4 ports") == 2 and "hub 1 port 2:" not in out
          and [d.address for d in (hub, hub2, stick, kbd)] == [1, 2, 3, 4]
          and all(d.configuration == 1 for d in (hub, hub2, stick, kbd)),
          "a hub with a second hub, a stick and a low-speed keyboard behind it: all four enumerated, addresses 1 "
          f"to 4, each configured{missing or ''}")
    power = sorted(p for _t, how, f, p in hub.features if (how, f) == ("set", 8))
    resets = sorted(p for _t, how, f, p in hub.features if (how, f) == ("set", 4))
    cleared = {(f, p) for _t, how, f, p in hub.features if how == "clear"}
    check(power == [1, 2, 3, 4] and resets == [1, 3, 4] and all((f, p) in cleared for f in (16, 20) for p in resets),
          "the hub's ports powered (SET_FEATURE PORT_POWER), the three with a device reset one after the other "
          "(PORT_RESET; C_PORT_RESET and C_PORT_CONNECTION cleared)")
    writes = [(o, v) for _t, o, _s, v in box.usb.writes[wmark:]]
    check((0x81, 0x61) in writes and (0x80, 0x01) in writes and (0x80, 0x09) in writes and (0x80, 0x04) in writes
          and (0x80, 0x06) in writes and (0x80, 0x05) not in writes and (0x80, 0x07) not in writes,
          "the low-speed keyboard addressed through the hub's translator -- endpoint 0's split flag (+0x80 bit 0: "
          "0x01 at address 0, then 0x09) with +0x81 = 0x61 (low speed, port 4, hub 1) -- the high-speed hub and "
          "stick straight (+0x80 = 0x04, 0x06)")
    out = box.command("lsusb")
    lines = ["Bus 001 Device 001: ID 1209:0003 AliSimulator Virtual USB hub, high speed (480 Mbit/s)\r\n",
             "Bus 001 Device 002: ID 1209:0003 AliSimulator Virtual USB hub, high speed (480 Mbit/s), hub 1 port 1",
             "Bus 001 Device 003: ID 1209:0001 AliSimulator Virtual USB stick, high speed (480 Mbit/s), hub 1 port 3",
             "Bus 001 Device 004: ID 1209:0002 AliSimulator Virtual USB keyboard, low speed (1.5 Mbit/s), hub 1 port 4"]
    check(all(line in out for line in lines), "lsusb lists the four devices with their hub and port")
    wmark, drops = len(box.usb.writes), box.usb.toggle_drops
    out = type_on(box, kbd, "ping\r")
    writes = [(o, v) for _t, o, _s, v in box.usb.writes[wmark:]]
    check("ping\r\npong v4" in out and (0x88, 0x09) in writes and (0x89, 0x61) in writes
          and (0x84, 0x09) not in writes and box.usb.toggle_drops == drops,
          "ping typed on the keyboard behind the hub -> pong v4: endpoint D's tokens go through the translator "
          "too (+0x88 = 4 << 1 | 1, +0x89 = 0x61); endpoint B is never aimed at the keyboard")
    box.command("testscreen")
    rgb = box.screen("v4_usb_hub_screen.png", "a USB hub with a keyboard, a stick and a second hub")
    label = np.abs(rgb[590:606] - shown(150, 190, 255)).sum(axis=2) < 30
    check(label[:, 56:152].sum() > 100 and (np.abs(rgb[590:606, 160:600] - shown(255, 230, 120)).sum(axis=2) < 30).sum() > 300,
          "the TV's USB box names the keyboard in use and counts the rest ('Keyboard 1209:0002 Virtual USB keyboard +3')")
    out = box.command("usb ctl 0xa0 6 0x2900 0 9 2") + box.command("usb ctl 0x80 6 0x0100 0 18 9")
    check("9 bytes:" in out and "09 29 04 00 00 32 64 00 ff" in out and "failed: there is no device with that address" in out,
          "usb ctl with a device's address as its last argument: the second hub's hub descriptor; an address nobody has "
          "is refused")
    # a second keyboard (full speed) into the hub's port 2: listed, the first stays in use
    kbd2 = VirtualKeyboard()
    hub.plug(2, kbd2, "full")
    out = box.run(5.0)
    check("[usb] hub 1 port 2: device connected" in out and "full speed (12 Mbit/s)" in out
          and "address 5, reached through hub 1's transaction translator (its port 2)" in out
          and "a second keyboard: the first one stays in use" in out and kbd2.address == 5,
          "a keyboard plugged into the hub's port 2 is noticed and enumerated (address 5); the first one stays in use")
    # the first keyboard unplugged: said once, without an error line; the second takes over
    hub.unplug(4)
    out = box.run(5.0)
    check("[usb] hub 1 port 4: device removed (1209:0002 Virtual USB keyboard)" in out and "keyboard:" not in out
          and "keyboard on interface 0: boot protocol, SET_IDLE set; reading its interrupt endpoint 81" in out,
          "the first keyboard unplugged from the hub: removed without an error line, the second one starts typing")
    wmark = len(box.usb.writes)
    out = type_on(box, kbd2, "ping\r")
    writes = [(o, v) for _t, o, _s, v in box.usb.writes[wmark:]]
    check("ping\r\npong v4" in out and (0x88, 0x0B) in writes and (0x89, 0x11) in writes,
          "and types: a full-speed device through the translator (endpoint D's +0x88 = 5 << 1 | 1, +0x89 = 0x11: "
          "port 2, hub 1, not low speed)")
    # the low-speed keyboard into the second hub: that hub's translator
    hub2.plug(2, kbd, "low")
    out = box.run(6.0)
    check("[usb] hub 2 port 2: device connected" in out
          and "address 4, reached through hub 2's transaction translator (its port 2)" in out,
          "the low-speed keyboard plugged into the second hub: enumerated through that hub's translator")
    hub.unplug(2)
    out = box.run(6.0)
    wmark = len(box.usb.writes)
    out += type_on(box, kbd, "ping\r")
    writes = [(o, v) for _t, o, _s, v in box.usb.writes[wmark:]]
    check("[usb] hub 1 port 2: device removed (1209:0002 Virtual USB keyboard)" in out and "ping\r\npong v4" in out
          and (0x88, 0x09) in writes and (0x89, 0x52) in writes,
          "with the other keyboard unplugged it types from behind both hubs (endpoint D's +0x89 = 0x52: low speed, "
          "port 2, hub 2)")
    # the second hub unplugged: it and what was behind it are gone
    hub.unplug(1)
    out = box.run(6.0)
    listing = box.command("lsusb")
    check("[usb] hub 1 port 1: device removed (1209:0003 Virtual USB hub)" in out and "no USB keyboard" in box.command("usb kbd")
          and "Device 002" not in listing and "Device 004" not in listing and "Device 003" in listing,
          "the second hub unplugged: it and the keyboard behind it are gone, the stick stays")
    box.usb.detach()
    out = box.run(0.6)
    check("[usb] device removed" in out and "port: no device" in box.command("lsusb"), "the hub unplugged: nothing is left")
    # a full-speed hub (USB 1.1): a full-speed keyboard behind it works straight; a low-speed one would need the
    # hub's preamble packets, which this controller is not known to send -- it does not answer and is left alone
    hub, kbd, slow = VirtualHub(4), VirtualKeyboard(), VirtualKeyboard(get_report="empty")
    hub.plug(1, kbd, "full")
    hub.plug(2, slow, "low")
    wmark = len(box.usb.writes)
    box.usb.attach("full", hub)
    out = box.run(9.0)
    writes = [(o, v) for _t, o, _s, v in box.usb.writes[wmark:]]
    check("endpoint 0: 64 bytes, full speed (12 Mbit/s)" in out and "hub 1 port 1:" in out and "  address 2\r\n" in out
          and "a device (low speed (1.5 Mbit/s)) that does not answer" in out and not any(o == 0x80 and v & 1 for o, v in writes),
          "a full-speed hub: the full-speed keyboard behind it enumerated straight (no translator), the low-speed one "
          "does not answer and its port is switched off")
    out = type_on(box, kbd, "ping\r") + box.run(4.0)
    check("ping\r\npong v4" in out and out.count("that does not answer") == 0,
          "the keyboard behind the full-speed hub types; the silent port is not tried again and again")
    box.usb.detach()
    box.run(0.6)


DISK_TEXT = b"Hello from the virtual stick.\nSecond line\twith a tab.\n" * 12
DISK_LONG = bytes(range(97, 123)) * 200                  # 5200 bytes, no newline: one line when shown
DISK_FILES = {"README.TXT": DISK_TEXT, "Docs/A long file name.txt": DISK_LONG,
              "Docs/sub/deep.bin": bytes(range(256)) * 9, "Empty/": None, "lower.txt": b"lower case\n"}


def check_disks(box):
    """USB mass storage: a hub with a FAT32 stick (one file in clusters that are not one after the
    other), a card reader with a FAT16 card (TEST UNIT READY first answered 'the medium may have
    changed', as the real one's), a full-speed FAT12 stick without a partition table (a sector in
    eight 64-byte packets), and the keyboard -- 'disks', 'ls', 'cat', 'sector' on each, the keyboard
    typing between them (it has endpoint D; the disks share endpoints A and B, whose data toggles are
    put in step with each disk's before its command), a card reader without a card, a stick pulled
    out."""
    import fat_image
    stick = VirtualStick(fat_image.build(DISK_FILES, fat=32, size_mb=40, label="STICK32",
                                         fragmented=("Docs/A long file name.txt",)))
    card = VirtualStick(fat_image.build(DISK_FILES, fat=16, size_mb=16, label="CARD16"), unit_attention=True,
                        vendor="Generic", product="STORAGE DEVICE", revision="1404")
    floppy = VirtualStick(fat_image.build({"NOTES.TXT": b"FAT12 notes\n"}, fat=12, size_mb=2, label="",
                                          partition=False), full_speed=True)
    kbd = VirtualKeyboard(get_report="empty", composite=True)
    hub = VirtualHub(4)
    for port, dev, speed in ((1, stick, "high"), (2, card, "high"), (3, floppy, "full"), (4, kbd, "low")):
        hub.plug(port, dev, speed)
    drops = box.usb.toggle_drops
    box.usb.attach("high", hub)
    out = box.run(12.0)
    lines = ["disk 2: AliSim Virtual stick 1.00, 40 MB; partition 1: FAT32 'STICK32', 39 MB",
             "disk 3: Generic STORAGE DEVICE 1404, 16 MB; partition 1: FAT16 'CARD16', 15 MB",
             "disk 4: AliSim Virtual stick 1.00, 2 MB; no partition table: FAT12 'NO NAME', 2 MB"]
    missing = [l for l in lines if l not in out]
    first = [cb.hex() for _t, cb in card.commands[:4]]
    check(not missing and first[:3] == ["120000002400", "000000000000", "030000001200"] and len(card.commands) > 4,
          "three disks behind the hub found as they are set up: INQUIRY, TEST UNIT READY (the card's unit attention "
          f"answered with REQUEST SENSE), READ CAPACITY, the partitions and their file systems{missing or ''}")
    out = box.command("disks", timeout=60)
    want = ["device 2: AliSim Virtual stick 1.00, 81920 sectors of 512 bytes (40 MB)",
            "  partition 1: FAT32 'STICK32', 39 MB, from sector 2048",
            "device 3: Generic STORAGE DEVICE 1404, 32768 sectors of 512 bytes (16 MB)",
            "  partition 1: FAT16 'CARD16', 15 MB, from sector 2048",
            "device 4: AliSim Virtual stick 1.00, 4096 sectors of 512 bytes (2 MB)",
            "  no partition table: FAT12 'NO NAME', 2 MB"]
    check(all(w + "\r\n" in out for w in want), "disks: each disk's size, partitions, file systems and labels")
    out = box.command("ls", timeout=60)
    want = ["device 2 partition 1: FAT32 'STICK32', 39 MB", "2026-11-13 12:34        648  README.TXT",
            "2026-11-13 12:34      <DIR>  Docs", "2026-11-13 12:34      <DIR>  Empty",
            "2026-11-13 12:34         11  lower.txt", "2 files, 2 directories, 659 bytes"]
    check(all(w + "\r\n" in out for w in want), "ls: the first FAT volume's root (FAT32), its entries' dates, sizes, "
                                                "long and short names")
    out = box.command("ls 3:/Docs", timeout=60) + box.command("ls 2:/docs/SUB", timeout=60)
    check("device 3 partition 1: FAT16 'CARD16', 15 MB" in out and "      5200  A long file name.txt\r\n" in out
          and "      <DIR>  sub\r\n" in out and "      2304  deep.bin\r\n" in out and "1 file, 0 directories, 2304 bytes" in out,
          "ls 3:/Docs on the FAT16 card (a long file name), ls 2:/docs/SUB (paths in any case)")
    out = box.command("cat 2:/Docs/A long file name.txt", timeout=120)
    check(DISK_LONG.decode() + "\r\n" in out, "cat of a 5200-byte file in clusters that are not one after the other "
                                               "(FAT32: its chain followed through the FAT)")
    out = box.command("cat /readme.txt", timeout=60)
    check(DISK_TEXT.decode().replace("\t", " ").replace("\n", "\r\n") in out,
          "cat of a text file: its lines (a tab shown as a space)")
    out = box.command("cat 4:/notes.txt", timeout=60) + box.command("ls 4:", timeout=60)
    check("FAT12 notes\r\n" in out and "device 4: FAT12 'NO NAME', 2 MB" in out and "        12  NOTES.TXT" in out,
          "the full-speed FAT12 stick without a partition table: ls and cat (each sector in eight 64-byte packets)")
    out = box.command("cat 3:/docs/sub/deep.bin", timeout=60)
    check("a binary file, 2304 bytes; its first 256:" in out and "0000: 00 01 02 03 04 05 06 07" in out,
          "cat of a binary file: its first 256 bytes in hex")
    out = box.command("sector 2:0", timeout=60)
    check("device 2, sector 0:" in out and "1c0: ff ff 0c fe ff ff 00 08 00 00" in out and " 55 aa  " in out,
          "sector 2:0: the stick's MBR in hex (partition type 0c at 2048)")
    out = (box.command("ls 9:", timeout=30) + box.command("cat /nothing.txt", timeout=60)
           + box.command("ls 3.2:", timeout=30) + box.command("cat /Docs", timeout=60))
    check("device 9 is not a USB disk ('disks' lists them)" in out and "not found: nothing.txt" in out
          and "device 3: no FAT or NTFS volume there ('disks' lists it)" in out and "a directory: 'ls' lists it" in out,
          "errors: a device that is no disk, a missing file, a missing partition, cat of a directory")
    out = type_on(box, kbd, "ping\r")
    out += box.command("ls 4:", timeout=60) + type_on(box, kbd, "ping\r")
    stalled = sum(getattr(d, "stalled_commands", 0) for d in (stick, card, floppy))
    check(out.count("ping\r\npong v4") == 2 and "NOTES.TXT" in out and box.usb.toggle_drops == drops and not stalled,
          "the keyboard types between the disks' commands and they work after it: endpoint B's data toggle set "
          "right for each, before each command block (none dropped, no command broken)")
    box.usb.detach()
    box.run(0.6)
    reader = VirtualStick(fat_image.build({"A.TXT": b"a"}, fat=12, size_mb=1, partition=False), no_medium=True,
                          vendor="Generic", product="STORAGE DEVICE", revision="1404")
    box.usb.attach("high", reader)
    out = box.run(4.0) + box.command("disks", timeout=30) + box.command("ls", timeout=30)
    check("disk 1: Generic STORAGE DEVICE 1404: no medium" in out and "device 1: Generic STORAGE DEVICE 1404: no medium"
          in out and "no FAT or NTFS volume on a USB disk ('disks')" in out,
          "a card reader without a card: 'no medium' (sense 2/3A), nothing to list")
    box.usb.detach()
    box.run(0.6)
    # a stick that leaves the first command after an idle spell unanswered (as a real 64 GB stick did
    # after a minute or more): the demo waits 2 s for it, not 10, resets the stick (the bulk-only reset
    # recovery) and sends the command once more
    lazy = VirtualStick(fat_image.build({"LAZY.TXT": b"zzz\n"}, fat=16, size_mb=16, label="LAZY"),
                        lose_after_idle=20.0)
    box.usb.attach("high", lazy)
    box.run(4.0)
    t0 = box.sim._vtime()
    out = box.command("ls", timeout=60)
    quick = box.sim._vtime() - t0
    box.run(25.0)
    resets = lazy.resets
    t0 = box.sim._vtime()
    out += box.command("ls", timeout=120)
    slow = box.sim._vtime() - t0
    listing = box.command("disks", timeout=60)
    check(out.count("LAZY.TXT") == 2 and lazy.lost_commands == 1 and lazy.resets == resets + 1
          and "  1 command not answered in time, sent again" in listing and slow > quick + 3,
          f"a stick that does not answer the first command after idling: ls still lists it -- after {slow:.1f} s "
          f"of emulated time instead of {quick:.1f} s, one reset recovery, the command sent once more; 'disks' "
          "counts it")
    box.usb.detach()
    box.run(0.6)
    hub = VirtualHub(4)
    hub.plug(1, VirtualStick(fat_image.build({"ONE.TXT": b"1"}, fat=12, size_mb=1, partition=False)), "high")
    box.usb.attach("high", hub)
    box.run(8.0)
    hub.unplug(1)
    out = box.run(3.0) + box.command("disks", timeout=30)
    check("[usb] hub 1 port 1: device removed (1209:0001 Virtual USB stick)" in out
          and "no USB disk (plug a stick in; 'lsusb' lists the devices)" in out,
          "a stick pulled out of the hub: its disk is gone")
    box.usb.detach()
    box.run(0.6)


def pointer_at(box):
    """The pointer's place as 'usb mouse' tells it: (x, y), or None."""
    m = re.search(r"pointer at (\d+),(\d+)", box.command("usb mouse"))
    return (int(m.group(1)), int(m.group(2))) if m else None


def check_mouse(box):
    """A USB mouse as on the real box: a low-speed mouse on the second hub's port 4, the low-speed
    keyboard on the first hub's port 4, a stick on the second hub -- the keyboard's interrupt endpoint
    polled by the controller's endpoint D (the SDK's hcd_s3602_IntInD_start: a keyboard gets it first,
    a report it lost would be a key that repeats), so the mouse's is read through endpoint B, one IN
    at a time: the pointer on the TV moves, the buttons click and paint, the wheel turns, while the
    keyboard types and the stick's transfers come and go -- none of them loses anything here."""
    import fat_image
    hub, hub2 = VirtualHub(4), VirtualHub(4)
    mouse = VirtualMouse()
    kbd = VirtualKeyboard(get_report="empty", composite=True)
    stick = VirtualStick(fat_image.build({"MOUSE.TXT": b"squeak\n"}, fat=16, size_mb=16, label="MICE"))
    hub.plug(1, hub2, "high")
    hub2.plug(2, stick, "high")
    hub2.plug(4, mouse, "low")
    hub.plug(4, kbd, "low")
    box.command("testscreen")                                # (the pointer paints on the test screen)
    wmark, drops, polls = len(box.usb.writes), box.usb.toggle_drops, box.usb.epd_polls
    box.usb.attach("high", hub)
    out = box.run(12.0)
    expected = ["USB device 1209:0004, USB 1.10, endpoint 0: 8 bytes, low speed (1.5 Mbit/s)",
                "address 4, reached through hub 2's transaction translator (its port 4)",
                "interface 0: class 03 (HID), subclass 01, protocol 02, 1 endpoints",
                "mouse on interface 0: boot protocol, SET_IDLE set; the pointer is on the TV",
                "keyboard on interface 0: boot protocol, SET_IDLE set; reading its interrupt endpoint 81 -- type on it",
                "disk 3: AliSim Virtual stick 1.00, 16 MB; partition 1: FAT16 'MICE', 15 MB"]
    missing = [e for e in expected if e not in out]
    check(not missing and [d.address for d in (hub, hub2, stick, mouse, kbd)] == [1, 2, 3, 4, 5]
          and mouse.protocol == 0 and mouse.idle == 0,
          "a mouse behind the second hub (as on the box), with a keyboard and a stick: enumerated, recognised as a "
          f"boot mouse, the boot protocol selected and reports only on a change (SET_IDLE 0){missing or ''}")
    writes = [(o, v) for _t, o, _s, v in box.usb.writes[wmark:]]
    want = [(0x89, 0x61), (0x88, 0x0B), (0x22, 0xC4), (0x2E, 0x77), (0xA3, 7),      # endpoint D: the keyboard
            (0x85, 0x62), (0x84, 0x09), (0x16, 0x84)]                              # endpoint B: the mouse
    missing = [w for w in want if w not in writes]
    check(not missing and any(o == 0x2B and v & 0x08 for o, v in writes) and (0x88, 0x09) not in writes
          and any(o == 0x23 and v & 0x01 for o, v in writes) and getattr(kbd, "halt_clears", 0) >= 1
          and any(o == 0x17 and v & 0x01 for o, v in writes) and not getattr(mouse, "halt_clears", 0)
          and box.usb.epd_polls > polls,
          "the keyboard has the controller's endpoint D, set up as hcd_s3602_IntInD_start does and through hub 1's "
          "translator (+0x89 = 0x61: low speed, port 4, hub 1; +0x88 = 5 << 1 | 1), interrupt endpoint 1 (+0x22 = "
          "0xC4), flags 3 enabled (+0x2E = 0x77), every 8 ms (+0xA3 = 7 for its 10 ms), +0x2B bit 3, both its data "
          "toggles DATA0 first (CLEAR_FEATURE(ENDPOINT_HALT), +0x23 bit 0 pulsed) -- so the mouse is read through "
          "endpoint B's IN, through hub 2's translator (+0x85 = 0x62: low speed, port 4, hub 2; +0x84 = 4 << 1 | 1; "
          "endpoint 1, +0x16 = 0x84), endpoint D never aimed at it; its toggle is DATA0 since its configuration (no "
          "CLEAR_FEATURE to it), endpoint B's put there (+0x17 bit 0 pulsed)"
          + (f": {missing}" if missing else ""))
    check(pointer_at(box) == (640, 360) and fb_pixel(box.sim, 640, 360) == rgb555(0, 0, 0)
          and fb_pixel(box.sim, 641, 362) == rgb555(255, 255, 255),
          "the pointer (a black and white arrow) is drawn in the middle of the TV picture")
    tokens = box.usb.in_tokens
    box.run(mouse.move(60, 30, over=0.6) + 0.5)
    writes = [(o, v) for _t, o, _s, v in box.usb.writes[wmark:]]
    tokens = box.usb.in_tokens - tokens
    check(pointer_at(box) == (700, 390) and fb_pixel(box.sim, 700, 390) == rgb555(0, 0, 0)
          and fb_pixel(box.sim, 641, 362) != rgb555(255, 255, 255) and (0x88, 0x09) not in writes
          and box.usb.toggle_drops == drops and tokens >= 60,
          "the mouse moved by (60, 30): the pointer follows to 700,390 (the picture under its old place put back), "
          f"every report through endpoint B's IN ({tokens} tokens in 1.1 s: asked again every millisecond while the "
          "mouse has nothing to say; endpoint D never aimed at the mouse, nothing dropped)")
    mouse.click(1)
    out = box.run(0.7)
    check("[usb] mouse: left down at 700,390" in out and "[usb] mouse: left up at 700,390" in out,
          "a click: the left button's down and up told on the UART with the pointer's place")
    mouse.press(1)
    mouse.move(40, 0, over=0.4, delay=0.05)
    mouse.release(1, delay=0.05)
    out = box.run(1.0)
    # (looked at before any command: the line is inside the command line box, which a command redraws)
    painted = [fb_pixel(box.sim, 720, 388), fb_pixel(box.sim, 705, 391), fb_pixel(box.sim, 720, 396)]
    rgb = box.screen("v4_usb_mouse_screen.png", "the mouse pointer after painting a line (a USB mouse behind a hub)")
    check(painted[:2] == [rgb555(255, 230, 120)] * 2 and painted[2] != rgb555(255, 230, 120)
          and pointer_at(box) == (740, 390),
          "held down, the left button paints a line along the way (a 5-pixel yellow brush) to 740,390")
    check(near(rgb[388, 720], shown(255, 230, 120)) and near(rgb[390, 740], (0, 0, 0))
          and near(rgb[392, 741], (255, 255, 255)),
          "the TV picture shows the painted line and the pointer at its end")
    mouse.click(2)
    mouse.wheel(2, delay=0.3)
    out = box.run(1.0)
    check("mouse: right down at 740,390; paint colour red" in out and "mouse: wheel 2 (2 in all) at 740,390" in out,
          "the right button picks the next paint colour (red); the wheel is told")
    status = box.command("usb mouse")
    check("mouse: device 4, interface 0, interrupt endpoint 81 (8 bytes, every 10 ms)" in status
          and "read through endpoint B, which disk and network transfers share (endpoint D polls device 5); 0 reports "
              "dropped for their data toggle" in status
          and "pointer at 740,390, buttons 00, wheel 2; paint colour red" in status,
          "usb mouse: the device, read through endpoint B (endpoint D polls device 5, the keyboard), the pointer, the "
          "buttons, the wheel, the colour")
    # the keyboard types on endpoint D while the mouse moves on endpoint B
    mouse.move(-100, -50, over=2.0)
    out = type_on(box, kbd, "ping\r", extra=1.5)
    status = box.command("usb kbd")
    check("ping\r\npong v4" in out and pointer_at(box) == (640, 340) and box.usb.toggle_drops == drops
          and "through the controller's endpoint D (it polls by itself, every 8000 us); 0 reports dropped" in status
          and " 0 errors" in status,
          "typing while the mouse moves: the keyboard on endpoint D, the mouse on endpoint B, every key and every "
          "movement arrives (pointer at 640,340), nothing dropped")
    # a disk's transfers on endpoints A and B meanwhile: they end the mouse's IN, which starts again after them
    mouse.move(30, 0, over=0.8)
    out = box.command("ls 3:", timeout=60) + box.command("cat 3:/mouse.txt", timeout=60)
    box.run(1.5)
    x, y = pointer_at(box) or (0, 0)
    stalled = getattr(stick, "stalled_commands", 0)
    check("MOUSE.TXT" in out and "squeak\r\n" in out and 670 <= x <= 700 and y == 340 and not stalled
          and box.usb.toggle_drops == drops,
          f"ls and cat on the stick while the mouse moves: both work, the movement arrives (pointer at {x},{y}: "
          "what the mouse could not report while a command ran it reports afterwards), nothing dropped")
    # unplugged: the pointer goes, endpoint B's IN ends -- endpoint D polls the keyboard on; plugged in again:
    # it comes back in the middle
    wmark, tokens, polls = len(box.usb.writes), box.usb.in_tokens, box.usb.epd_polls
    hub2.unplug(4)
    out = box.run(3.0)
    after = [(o, v) for _t, o, _s, v in box.usb.writes[wmark:]]
    tokens = box.usb.in_tokens - tokens
    check("[usb] hub 2 port 4: device removed (1209:0004 Virtual USB mouse)" in out and "mouse:" not in out
          and "no USB mouse" in box.command("usb mouse") and fb_pixel(box.sim, x + 1, y + 2) != rgb555(255, 255, 255)
          and any(o == 0x17 and v & 0x10 for o, v in after) and tokens <= 3
          and mmio(box.sim, 0x320A3, 1) == 7 and mmio(box.sim, 0x3202B, 1) & 0x08 and box.usb.epd_polls - polls > 300,
          "the mouse unplugged: removed without an error line, the pointer gone, endpoint B's IN ended (its FIFO "
          f"reset, +0x17 bit 4; {tokens} more of its tokens) -- and endpoint D polls the keyboard on (+0xA3 = 7, "
          "+0x2B bit 3 still set)")
    mouse2 = VirtualMouse()
    hub2.plug(4, mouse2, "low")
    out = box.run(6.0)
    box.run(mouse2.move(-40, 20, over=0.4) + 0.5)
    check("mouse on interface 0: boot protocol, SET_IDLE set; the pointer is on the TV" in out
          and pointer_at(box) == (600, 380),
          "a mouse plugged in again: set up, its pointer starts in the middle and follows it (600,380)")
    out = type_on(box, kbd, "ping\r")
    check("ping\r\npong v4" in out, "the keyboard still types")
    box.usb.detach()
    box.run(0.6)


def check_many_devices(box):
    """More than seven devices, as the real box got (two hub chips, a CH341, a card reader, two sticks, a
    keyboard -- and the mouse as the eighth, which an earlier build refused): fifteen are kept (the
    endpoints' address registers hold four bits of an address), a hub only among the first seven (the
    split registers hold three bits of its address) -- and the first seven are kept for high-speed devices
    (on the real box they lose bulk data at addresses 8 and up): a hub that comes when they are taken gets
    the place of a low- or full-speed device, which moves to the highest free address."""
    import fat_image
    hub, hub2, hub3 = VirtualHub(4), VirtualHub(4), VirtualHub(4)
    sticks = [VirtualStick(fat_image.build({f"S{i}.TXT": b"%d\n" % i}, fat=12, size_mb=1, partition=False))
              for i in range(3)]
    kbd, kbd2, mouse = VirtualKeyboard(get_report="empty", composite=True), VirtualKeyboard(), VirtualMouse()
    hub.plug(1, hub2, "high")
    hub2.plug(1, sticks[0], "high")
    hub2.plug(2, kbd2, "full")
    hub2.plug(3, kbd, "low")
    hub2.plug(4, sticks[1], "high")
    hub.plug(2, sticks[2], "high")
    hub.plug(3, mouse, "low")
    hub.plug(4, hub3, "high")
    kbd3 = VirtualKeyboard()
    hub3.plug(1, kbd3, "full")                               # behind the hub that comes ninth
    wmark = len(box.usb.writes)
    box.usb.attach("high", hub)
    out = box.run(18.0)
    kept = (hub, hub2, sticks[0], kbd2, sticks[1], sticks[2], mouse)
    listing = box.command("lsusb")
    check([d.address for d in kept] == [1, 2, 3, 4, 6, 7, 8] and all(d.configuration == 1 for d in kept)
          and "Bus 001 Device 008: ID 1209:0004 AliSimulator Virtual USB mouse, low speed (1.5 Mbit/s), hub 1 port 3"
          in listing and all(f"disk {n}: " in out for n in (3, 6, 7)),
          "eight devices behind two hubs: each configured at the address it got as it came, the mouse as device 8 "
          f"(lsusb), the three sticks' disks{[d.address for d in kept]}")
    check("hub 2 port 3: its device (address 5, not high speed) moves to a higher address: the first 7 are kept "
          "for high-speed devices" in out and kbd.address == 15 and kbd.configuration == 1
          and hub3.address == 5 and hub3.configuration == 1 and kbd3.address == 9 and kbd3.configuration == 1
          and "a hub, but the first 7 addresses are taken" not in out and "Device 015: ID" in listing,
          "a third hub as the ninth device, the first seven addresses taken: the low-speed keyboard among them "
          "moves to address 15 (its port reset, set up again), the hub gets its address 5 and the keyboard behind "
          f"it address 9{[kbd.address, hub3.address, kbd3.address]}")
    box.run(mouse.move(30, 0, over=0.3) + 0.5)
    writes = [(o, v) for _t, o, _s, v in box.usb.writes[wmark:]]
    out = type_on(box, kbd2, "ping\r")
    check((0x84, 0x11) in writes and (0x85, 0x59) in writes and (0x88, 0x09) in writes and (0x89, 0x12) in writes
          and (0x88, 0x11) not in writes and pointer_at(box) == (670, 360) and "ping\r\npong v4" in out,
          "the mouse at address 8 is read through endpoint B (+0x84 = 8 << 1 | 1, +0x85 = 0x59: low speed, port 3, "
          "hub 1) and moves the pointer; the first keyboard, which endpoint D polls (+0x88 = 4 << 1 | 1, +0x89 = "
          "0x12: port 2, hub 2, not low speed), types")
    box.usb.detach()
    box.run(0.6)


class JunkFirstKeyboard(VirtualKeyboard):
    """A keyboard whose interrupt endpoint's first packet is not a report: the 4 bytes endpoint D handed
    over on the real box now and then, right after it was opened."""

    def interrupt_in(self, endpoint):
        if endpoint == 1 and self.interrupt and self.configuration and not getattr(self, "junk_sent", False):
            self.junk_sent = True
            return getattr(self, "junk", bytes.fromhex("29863001"))
        return super().interrupt_in(endpoint)


def check_usb_faults(box):
    """Two things the real box did when it was left alone with its devices (2026-11-15).  The keyboard's
    endpoint gave 4 bytes that are no report (29 86 30 01): taken as one they were Shift + ] held for good
    -- a '}' repeated on the command line until a real key was pressed.  And a hub behind two others
    stopped answering while its port still called it connected: the hot-plug poll went back to that port,
    found nothing changed, came to the silent hub again, and never looked at the first hub's ports any
    more -- nothing plugged in was seen."""
    hub, hub2, hub3 = VirtualHub(4), VirtualHub(4), VirtualHub(4)
    kbd, mouse = JunkFirstKeyboard(), VirtualMouse()
    hub.plug(1, hub2, "high")
    hub2.plug(1, hub3, "high")
    hub.plug(2, kbd, "low")
    box.usb.attach("high", hub)
    out = box.run(9.0)
    state = box.command("usb kbd")
    check([d.address for d in (hub, hub2, hub3, kbd)] == [1, 2, 3, 4] and kbd.junk_sent and "}" not in out
          and "1 reports, 0 keys, 1 errors" in state and "keys held now: none" in state,
          "a keyboard whose endpoint first gives 4 bytes that are no report (29 86 30 01, as on the real box): "
          "counted as an error, no key held, nothing typed")
    out = type_on(box, kbd, "ping\r")
    check("ping\r\npong v4" in out, "and its real reports type")
    kbd.junk_sent = False
    kbd.junk = bytes.fromhex("0200010000000000")          # a whole report, an error code (1) among its keys
    box.command("usb kbd interrupt")
    out = box.run(1.0)
    state = box.command("usb kbd")
    check(kbd.junk_sent and "keys held now: none" in state and "\x1b" not in out,
          "a whole 8-byte report with an error code among its keys: no key held")
    hub3.setup = lambda packet: None                         # every request stalled, its port as it was
    out = box.run(14.0)
    listing = box.command("lsusb")
    check("[usb] hub 3 (1209:0003, on hub 2 port 1) has stopped answering: forgotten with what was behind it, "
          "its port reset" in out and out.count("has stopped answering") == 1
          and "Device 003" not in listing and "Device 002" in listing,
          "a hub behind two others stops answering, its port still connected and enabled: after three rounds of "
          "the hot-plug poll it is forgotten and set up again once from its port's reset (which fails: the port is "
          "switched off), said once")
    hub.plug(3, mouse, "low")
    out = box.run(4.0)
    check("[usb] hub 1 port 3: device connected" in out and mouse.configuration == 1,
          "and the poll goes on: a mouse plugged into the first hub afterwards is set up")
    del hub3.setup
    hub2.unplug(1)
    box.run(1.0)
    hub2.plug(1, hub3, "high")
    out = box.run(4.0)
    check("[usb] hub 2 port 1: device connected" in out and hub3.configuration == 1 and hub3.address == 5,
          "the hub replugged: set up again (the mouse has its address 3 now: it gets 5)")
    box.usb.detach()
    box.run(0.6)


def tiny_gb_cartridge(colour_only=False):
    """A 32 KB Game Boy cartridge made here: it switches the picture off, fills tile 0 with colour 1, sets the
    palette, switches the picture on, and then shows colour 1 as shade 1 -- or as shade 2 while A is held. The
    Game Boy Color one (colour_only) sets the Color's background palette 0's colour 1 to red first (its BGP
    writes then change nothing)."""
    colour = "3E82 E068 3E1F E069 3E00 E069" if colour_only else ""    # BCPS = 82; BCPD = 1F, 00: red
    code = bytes.fromhex(
        "F3 31FEFF AF E040" + colour + "210080 0608"    # di; ld sp,FFFE; xor a; ldh (LCDC),a; ld hl,8000; ld b,8
        "3EFF 22 AF 22 05 20F8"                   # (lo FF, hi 00) eight times: colour 1 everywhere
        "3EE4 E047 3E91 E040"                     # BGP = E4; LCDC = 91: picture on, tile 0 everywhere
        "3E10 E000 F000 E601 2004 3E1B 1802 3EE4 E047 18EC")    # the buttons: A held -> BGP 1B (shade 2)
    rom = bytearray(32768)
    rom[0x100:0x104] = bytes.fromhex("00C35001")             # nop; jp 0150
    rom[0x134:0x13B] = b"ALITEST"
    rom[0x143] = 0xC0 if colour_only else 0x00
    rom[0x150:0x150 + len(code)] = code
    rom[0x14D] = (-sum(rom[0x134:0x14D]) - (0x14D - 0x134)) & 0xFF
    return bytes(rom)


def check_gameboy(box):
    """The Game Boy player ('gb'): a cartridge made here (tiny_gb_cartridge) run 60 frames on a stick -- its
    160 x 144 picture five times as large, 800 x 720 in the middle of the screen, in the Game Boy's shades; A
    held by a test script changes the palette; a cartridge for the Game Boy Color alone in its colours."""
    import fat_image
    stick = VirtualStick(fat_image.build({"T.GB": tiny_gb_cartridge(), "C.GB": tiny_gb_cartridge(True)}, fat=12,
                                         size_mb=1, partition=False))
    box.usb.attach("high", stick)
    box.run(4.0)
    # (looked at while it plays: when it ends the picture behind it is put back) -- A held from frame 90 on
    out = box.keys(b"gb -k 0:0,90:1 1:/T.GB\r", until=b"Ctrl-C or Esc ends", timeout=30)
    box.run(1.0)
    shade1, shade2, black = rgb555(0x88, 0xC0, 0x70), rgb555(0x34, 0x68, 0x56), rgb555(0, 0, 0)
    sim = box.sim
    picture = [fb_pixel(sim, x, y) for x, y in ((240, 0), (640, 360), (1039, 719))]
    sides = [fb_pixel(sim, x, y) for x, y in ((239, 360), (1040, 360))]
    box.screen("v4_gameboy_screen.png", "gb: a cartridge made in the test (tile 0 in colour 1 everywhere), 160 x 144 five "
               "times as large in the middle of the screen")
    check("1:/T.GB: ALITEST: ROM only, ROM 32 KB" in out and picture == [shade1] * 3 and sides == [black] * 2,
          "gb: a cartridge made here plays; its picture fills 800 x 720 in the middle (x 240 to 1039) in the Game "
          f"Boy's second shade, black at its sides{[hex(v) for v in picture + sides]}")
    out = box.keys(b"\x03", timeout=10)
    check("frames in" in out, "Ctrl-C ends it")
    # the same frames as the PC's gb.c (the picture's CRC-32): without buttons, and with A held from the start
    runs = [box.command(f"gb -f 60 {k}1:/T.GB", timeout=120) for k in ("", "-k 0:1 ")]
    check("picture CRC-32 76250edf" in runs[0] and "picture CRC-32 d0288f62" in runs[1],
          "gb -f 60: the picture's CRC-32 as gb.c's on a PC after 60 frames (76250edf), and with A held -- the "
          "program changes its palette -- d0288f62")
    # a cartridge for the Color alone: looked at while it plays, then its CRC-32 after 60 frames
    out = box.keys(b"gb 1:/C.GB\r", until=b"Ctrl-C or Esc ends", timeout=30)
    box.run(1.0)
    red = rgb555(0xF8, 0, 0)
    colours = [fb_pixel(sim, x, y) for x, y in ((240, 0), (640, 360), (1039, 719))]
    box.keys(b"\x03", timeout=10)
    out += box.command("gb -f 60 1:/C.GB", timeout=120)
    check("ALITEST: ROM only, ROM 32 KB, Game Boy Color only" in out and "picture CRC-32 f31b3bd0" in out
          and colours == [red] * 3,
          "a cartridge for the Game Boy Color alone runs as on one: its palette's colour 1 set to red is red on the "
          f"TV, the picture's CRC-32 as gb.c's on a PC (f31b3bd0){[hex(v) for v in colours]}")
    box.usb.detach()
    box.run(0.6)


def tiny_sega_cartridge(game_gear=False):
    """A 32 KB Master System (or Game Gear) cartridge made here: the picture chip in mode 4 with the picture on,
    colour 0 of both palettes red (every tile is tile 0, all colour 0: the whole picture red), then, once button
    1 (Z, the pad's B) is held, blue for good.  The Game Gear's colours are two bytes each (----BBBB GGGGRRRR,
    the low byte first), the Master System's one (--BBGGRR)."""
    red, blue = ("0F00", "000F") if game_gear else ("0300", "3000")
    code = bytes.fromhex(
        "F3 ED56 31F0DF 213000 0608 0EBF EDB3"   # di; im 1; ld sp,DFF0; ld hl,regs; ld b,8; ld c,BF; otir
        "06" + red[:2] + "16" + red[2:] + "CD4000"              # ld b,lo; ld d,hi; call set
        "DBDC CB67 20FA"                                        # wait: in a,(DC); bit 4,a; jr nz,wait
        "06" + blue[:2] + "16" + blue[2:] + "CD4000 18FE")      # blue; jr $
    regs = bytes.fromhex("0480 FF82 0087 4081")                 # mode 4, names at 3800, backdrop 0, picture on
    # set: colour 0 and colour 16 (the sprites' 0) to b (the Game Gear: b, d); colour addresses x2 on the GG
    one = "78D3BE 7AD3BE" if game_gear else "78D3BE"
    put = bytes.fromhex("3E00D3BF 3EC0D3BF" + one + "3E" + ("20" if game_gear else "10") + "D3BF 3EC0D3BF" + one
                        + "C9")
    rom = bytearray(32768)
    rom[:len(code)] = code
    rom[0x30:0x38] = regs
    rom[0x40:0x40 + len(put)] = put
    return bytes(rom)


def tiny_zx_files():
    """A stand-in for the Spectrum's ROM (the real one is Amstrad's: not in the repository) and a snapshot that
    starts it: the ROM sets the border red, clears the picture, makes every cell's paper red, then waits for
    SPACE (port 7FFE bit 0) and turns the border blue.  The .sna's stack holds 0000: its RETN goes there."""
    rom = bytearray(16384)
    code = bytes.fromhex(
        "F3 AF 3100FF 3E02 D3FE"                 # di; xor a (zx.c knows a 48K ROM by these two); ld sp,FF00;
                                                 # ld a,2; out (FE),a: a red border
        "210040 110140 01FF17 3600 EDB0"         # the pixels 0
        "210058 110158 01FF02 3610 EDB0"         # the attributes 10: paper red, ink black
        "01FE7F ED78 E601 20FA"                  # wait: ld bc,7FFE; in a,(c); and 1; jr nz,wait
        "3E01 D3FE 18FE")                        # the border blue; jr $
    rom[:len(code)] = code
    header = bytearray(27)
    header[0] = 0x3F                             # I
    header[23:25] = (0x8000).to_bytes(2, "little")   # SP: the word 0000 there is the PC
    header[25] = 1                               # IM 1
    header[26] = 7
    return bytes(rom), bytes(header) + bytes(49152)


def red_or_blue(v):
    """'red' / 'blue' / '' for an ARGB1555 word: that channel strong, the other two dark."""
    r, g, b = (v >> 10) & 31, (v >> 5) & 31, v & 31
    return "red" if r >= 20 and g < 4 and b < 4 else "blue" if b >= 20 and r < 4 and g < 4 else ""


def check_sega_and_spectrum(box):
    """The Master System, Game Gear and ZX Spectrum players ('sms', 'gg', 'zx'): programs made here
    (tiny_sega_cartridge, tiny_zx_files) on a stick -- the Master System's 256 x 192 three times as large (768 x
    576) in the middle of the screen, the Game Gear's 160 x 144 five times (800 x 720), the Spectrum's 320 x 240
    with its border three times (960 x 720); the pad's button 1 held by a test script, SPACE typed on the UART."""
    import fat_image
    rom, sna = tiny_zx_files()
    stick = VirtualStick(fat_image.build({"T.SMS": tiny_sega_cartridge(), "T.GG": tiny_sega_cartridge(True),
                                          "ZX/48.ROM": rom, "ZX/T.SNA": sna}, fat=12, size_mb=1, partition=False))
    box.usb.attach("high", stick)
    box.run(4.0)
    sim = box.sim
    for cmd, name, inside, outside in (
            ("sms", "1:/T.SMS", ((256, 72), (640, 360), (1023, 647)), ((255, 360), (640, 71), (640, 648))),
            ("gg", "1:/T.GG", ((240, 0), (640, 360), (1039, 719)), ((239, 360), (1040, 360)))):
        seen = []
        for script in ("", "-k 0:02 "):          # (no buttons; button 1 held from the start)
            out = box.keys(f"{cmd} {script}{name}\r".encode(), until=b"Esc ends", timeout=30)
            box.run(1.0)
            seen.append(([red_or_blue(fb_pixel(sim, x, y)) for x, y in inside],
                         [fb_pixel(sim, x, y) for x, y in outside], out))
            box.keys(b"\x03", timeout=10)
        (plain, sides, out), (held, _, _) = seen
        check(plain == ["red"] * 3 and held == ["blue"] * 3 and set(sides) == {rgb555(0, 0, 0)}
              and "ROM 32 KB" in out,
              f"{cmd}: a cartridge made here plays: its picture red in the middle of the screen, black around it; "
              f"with button 1 held, blue {plain} {held} {[hex(v) for v in sides]}")
    out = box.keys(b"zx 1:/ZX/T.SNA\r", until=b"Esc ends", timeout=30)
    box.run(1.0)
    before = [red_or_blue(fb_pixel(sim, x, y)) for x, y in ((170, 360), (640, 360), (1110, 10))]
    box.t.write(b" ")                            # (the Spectrum echoes nothing: no waiting for output)
    box.run(1.0)
    after = [red_or_blue(fb_pixel(sim, x, y)) for x, y in ((170, 360), (640, 360), (1110, 10))]
    out += box.keys(b"\x03", timeout=10)
    check("ROM: 1:/ZX/48.rom" in out and before == ["red"] * 3 and after == ["blue", "red", "blue"]
          and "frames in" in out,
          "zx: a snapshot made here with a stand-in ROM beside it runs: border and paper red over 960 x 720; SPACE "
          f"typed on the UART is the Spectrum's SPACE: the border blue, the paper still red {before} {after}")
    box.usb.detach()
    box.run(0.6)


def tiny_atari_cartridge():
    """A 4 KB Atari 2600 cartridge made here: each frame three lines of vertical sync, then 250 lines of the
    background colour -- 0x44 (a red) or, while the joystick's button is held (INPT4 bit 7 low), 0x84 (a blue)."""
    code = bytes.fromhex(
        "78 D8 A2FF 9A"                          # sei; cld; ldx #FF; txs
        "A902 8500 8502 8502 8502 A900 8500 8501"   # frame: VSYNC on, 3 x WSYNC, VSYNC and VBLANK off
        "A944 240C 3002 A984 8509"               # lda #44; bit INPT4; bmi +2; lda #84; sta COLUBK
        "A2FA 8502 CA D0FB 4C05F0")              # ldx #250; WSYNC x 250; jmp frame
    rom = bytearray(4096)
    rom[:len(code)] = code
    rom[0xFFC:0xFFE] = (0xF000).to_bytes(2, "little")     # the reset vector
    return bytes(rom)


def check_atari(box):
    """The Atari 2600 player ('a26'): a cartridge made here (tiny_atari_cartridge) -- its 160 x 228 picture five
    times as wide and three times as high (800 x 684) in the middle of the screen, red; blue with the button
    held by a test script."""
    import fat_image
    stick = VirtualStick(fat_image.build({"T.A26": tiny_atari_cartridge()}, fat=12, size_mb=1, partition=False))
    box.usb.attach("high", stick)
    box.run(4.0)
    sim = box.sim
    seen = []
    for script in ("", "-k 0:01 "):
        out = box.keys(f"a26 {script}1:/T.A26\r".encode(), until=b"Esc ends", timeout=30)
        box.run(1.0)
        inside = [fb_pixel(sim, x, y) for x, y in ((240, 18), (640, 360), (1039, 701))]
        outside = [fb_pixel(sim, x, y) for x, y in ((239, 360), (1040, 360), (640, 17), (640, 702))]
        seen.append((inside, outside, out))
        box.keys(b"\x03", timeout=10)

    def hue(v):
        r, b = (v >> 10) & 31, v & 31
        return "red" if r > b + 8 else "blue" if b > r + 8 else ""
    (plain, sides, out), (held, _, _) = seen
    check("4K: 4 KB" in out and len(set(plain)) == 1 and hue(plain[0]) == "red" and len(set(held)) == 1
          and hue(held[0]) == "blue" and set(sides) == {rgb555(0, 0, 0)},
          "a26: a cartridge made here plays: its background red over 800 x 684 in the middle of the screen, black "
          f"around it; blue while the button is held {[hex(v) for v in plain + held + sides]}")
    box.usb.detach()
    box.run(0.6)


def tiny_c64_roms():
    """Stand-ins for the C64's ROMs (the real ones are Commodore's: not in the repository).  The KERNAL's reset
    goes to its own $E000: the border and background red (colour 2), the picture left off ($D011 0: all
    border), then it waits for joystick 2's fire (CIA 1 port A bit 4 low) and makes the border blue (6).
    BASIC is only "CBM" where c64.c looks for it; the characters are blank."""
    code = bytes.fromhex(
        "78 D8 A2FF 9A"                          # sei; cld; ldx #FF; txs
        "A900 8D11D0 A902 8D20D0 8D21D0"         # $D011 = 0 (no picture); border, background red
        "AD00DC 2910 D0F9"                       # wait: lda $DC00; and #$10; bne wait
        "A906 8D20D0 4C1EE0")                    # border blue; jmp $E01E (itself)
    kernal = bytearray(8192)
    kernal[:len(code)] = code
    kernal[0x1FFC:0x1FFE] = (0xE000).to_bytes(2, "little")     # the reset vector
    basic = bytearray(8192)
    basic[4:7] = b"CBM"
    return bytes(kernal), bytes(basic), bytes(4096)


def check_c64(box):
    """The C64 player ('c64'): stand-in ROMs made here (tiny_c64_roms) in C64/ and a program file -- its 352 x
    240 picture three times as large (1056 x 720) in the middle of the screen, red; blue with fire held by a
    test script."""
    import fat_image
    kernal, basic, chargen = tiny_c64_roms()
    prg = (0x0801).to_bytes(2, "little") + bytes(4)
    stick = VirtualStick(fat_image.build({"C64/KERNAL.ROM": kernal, "C64/BASIC.ROM": basic,
                                          "C64/CHARGEN.ROM": chargen, "C64/T.PRG": prg},
                                         fat=12, size_mb=1, partition=False))
    box.usb.attach("high", stick)
    box.run(4.0)
    sim = box.sim
    seen = []
    for script in ("", "-k 0:01 "):
        out = box.keys(f"c64 {script}1:/C64/T.PRG\r".encode(), until=b"Esc ends", timeout=30)
        box.run(1.0)
        inside = [fb_pixel(sim, x, y) for x, y in ((112, 0), (640, 360), (1167, 719))]
        outside = [fb_pixel(sim, x, y) for x, y in ((111, 360), (1168, 360))]
        seen.append((inside, outside, out))
        box.keys(b"\x03", timeout=10)

    def hue(v):
        r, b = (v >> 10) & 31, v & 31
        return "red" if r > b + 8 else "blue" if b > r + 8 else ""
    (plain, sides, out), (held, _, _) = seen
    check("ROM: 1:/C64/kernal.rom" in out and "a .prg file" in out and len(set(plain)) == 1
          and hue(plain[0]) == "red" and len(set(held)) == 1 and hue(held[0]) == "blue"
          and set(sides) == {rgb555(0, 0, 0)},
          "c64: stand-in ROMs made here run: the picture red over 1056 x 720 in the middle of the screen, black "
          f"around it; blue while fire is held {[hex(v) for v in plain + held + sides]}")
    box.usb.detach()
    box.run(0.6)


def tiny_kickstart():
    """A stand-in for the Amiga's Kickstart (the real ones are sold: not in the repository): 256 KB starting 11 11
    as amiga.c wants, its reset going to its own code -- COLOR00 red (the whole picture: no bitplanes), then it
    waits for the joystick's fire (CIA-A port A bit 7 low) and makes it blue."""
    rom = bytearray(0x40000)
    rom[0:8] = bytes.fromhex("1111 4EF9 00F80010")    # the reset's stack word (unused) and PC: 0xF80010
    rom[12:16] = bytes.fromhex("0022 0005")           # "Kickstart 34.5"
    code = bytes.fromhex(
        "33FC 0F00 00DFF180"                    # move.w #$0F00,COLOR00
        "0839 0007 00BFE001 66F6"               # wait: btst #7,$BFE001; bne wait
        "33FC 000F 00DFF180 60FE")              # move.w #$000F,COLOR00; bra *
    rom[0x10:0x10 + len(code)] = code
    return bytes(rom)


def check_amiga(box):
    """The Amiga player ('amiga'): a stand-in Kickstart made here (tiny_kickstart) as AMIGA/KICK.ROM and an empty
    floppy image -- its 352 x 272 picture twice as large (704 x 544) in the middle of the screen, red; blue with
    fire held by a test script."""
    import fat_image
    stick = VirtualStick(fat_image.build({"AMIGA/KICK.ROM": tiny_kickstart(), "AMIGA/T.ADF": bytes(901120)},
                                         fat=16, size_mb=16, partition=False))
    box.usb.attach("high", stick)
    box.run(4.0)
    sim = box.sim
    seen = []
    for script in ("", "-k 0:01 "):
        out = box.keys(f"amiga {script}1:/AMIGA/T.ADF\r".encode(), until=b"Esc ends", timeout=30)
        box.run(1.0)
        inside = [fb_pixel(sim, x, y) for x, y in ((288, 88), (640, 360), (991, 631))]
        outside = [fb_pixel(sim, x, y) for x, y in ((287, 360), (992, 360), (640, 87), (640, 632))]
        seen.append((inside, outside, out))
        box.keys(b"\x03", timeout=10)

    def hue(v):
        r, b = (v >> 10) & 31, v & 31
        return "red" if r > b + 8 else "blue" if b > r + 8 else ""
    (plain, sides, out), (held, _, _) = seen
    check("ROM: 1:/AMIGA/kick.rom" in out and "Kickstart 34.5, a floppy in DF0:" in out and len(set(plain)) == 1
          and hue(plain[0]) == "red" and len(set(held)) == 1 and hue(held[0]) == "blue"
          and set(sides) == {rgb555(0, 0, 0)},
          "amiga: a stand-in Kickstart made here runs: the picture red over 704 x 544 in the middle of the screen, "
          f"black around it; blue while fire is held {[hex(v) for v in plain + held + sides]}")
    box.usb.detach()
    box.run(0.6)


def tiny_dos_program():
    """A DOS .com program made here: VGA mode 13h, the whole screen colour 4 (red), then it polls the keyboard
    controller's port 0x60 for Space's make code (0x39) and fills it with colour 1 (blue)."""
    return bytes.fromhex(
        "B81300 CD10"                            # mov ax,13h; int 10h
        "B800A0 8EC0 31FF B900FA B004 F3AA"      # es = A000; di = 0; cx = 64000; al = 4; rep stosb
        "E460 3C39 75FA"                         # wait: in al,60h; cmp al,39h; jne wait
        "31FF B900FA B001 F3AA EBFE")            # di = 0; cx = 64000; al = 1; rep stosb; jmp $


def check_dos(box):
    """The DOS player ('dos'): a .com made here (tiny_dos_program) -- its 320 x 200 picture three times as large
    (960 x 600) in the middle of the screen, red; blue with the pad's B (Space) held by a test script."""
    import fat_image
    stick = VirtualStick(fat_image.build({"DOS/T.COM": tiny_dos_program()}, fat=12, size_mb=1, partition=False))
    box.usb.attach("high", stick)
    box.run(4.0)
    sim = box.sim
    seen = []
    for script in ("", "-k 0:02 "):
        out = box.keys(f"dos {script}1:/DOS/T.COM\r".encode(), until=b"typed on it", timeout=30)
        box.run(1.0)
        inside = [fb_pixel(sim, x, y) for x, y in ((160, 60), (640, 360), (1119, 659))]
        outside = [fb_pixel(sim, x, y) for x, y in ((159, 360), (1120, 360), (640, 59), (640, 660))]
        seen.append((inside, outside, out))
        box.keys(b"\x03", timeout=10)

    def hue(v):
        r, b = (v >> 10) & 31, v & 31
        return "red" if r > b + 8 else "blue" if b > r + 8 else ""
    (plain, sides, out), (held, _, _) = seen
    check("T.COM" in out.upper() and len(set(plain)) == 1 and hue(plain[0]) == "red" and len(set(held)) == 1
          and hue(held[0]) == "blue" and set(sides) == {rgb555(0, 0, 0)},
          "dos: a .com made here runs: the picture red over 960 x 600 in the middle of the screen, black around "
          f"it; blue while Space (the pad's B) is held {[hex(v) for v in plain + held + sides]}")
    box.usb.detach()
    box.run(0.6)


def tiny_md_cartridge():
    """A 1 KB Mega Drive cartridge made here: its header ("SEGA MEGA DRIVE", the regions JUE), its reset going to
    0x200: the VDP's picture on (mode 5, H40), the background colour (CRAM 0) red over the whole picture (every
    tile is tile 0: transparent), then it waits for the pad's B (TH high, bit 4: the player's A, X on the
    keyboard) and makes it blue."""
    rom = bytearray(0x400)
    rom[0:8] = bytes.fromhex("00FFFE00 00000200")             # the stack, the reset's PC
    rom[0x100:0x110] = b"SEGA MEGA DRIVE "
    rom[0x120:0x150] = rom[0x150:0x180] = b"ALI TEST".ljust(48)
    rom[0x1F0:0x200] = b"JUE".ljust(16)
    code = bytes.fromhex(
        "41F9 00C00004"                         # lea $C00004,a0 (the VDP's control port)
        "30BC 8144 30BC 8C81 30BC 8700"         # registers 1 = 0x44 (picture on), 12 = 0x81 (H40), 7 = 0
        "20BC C0000000 317C 000E FFFC"          # CRAM 0 = 0x00E: red
        "13FC 0040 00A10009 13FC 0040 00A10003"     # wait: TH an output, high
        "0839 0004 00A10003 66E6"               # btst #4,$A10003 (B, 0 pressed); bne wait
        "20BC C0000000 317C 0E00 FFFC 60FE")    # CRAM 0 = 0xE00: blue; bra *
    rom[0x200:0x200 + len(code)] = code
    return bytes(rom)


def check_md(box):
    """The Mega Drive player ('megadrive'): a cartridge made here (tiny_md_cartridge) -- its 320 x 224 picture
    three times as large (960 x 672) in the middle of the screen, red; blue with the pad's B (the player's A)
    held by a test script."""
    import fat_image
    stick = VirtualStick(fat_image.build({"MD/T.MD": tiny_md_cartridge()}, fat=12, size_mb=1, partition=False))
    box.usb.attach("high", stick)
    box.run(4.0)
    sim = box.sim
    seen = []
    for script in ("", "-k 0:01 "):
        out = box.keys(f"megadrive {script}1:/MD/T.MD\r".encode(), until=b"Esc ends", timeout=30)
        box.run(1.0)
        inside = [fb_pixel(sim, x, y) for x, y in ((160, 24), (640, 360), (1119, 695))]
        outside = [fb_pixel(sim, x, y) for x, y in ((159, 360), (1120, 360), (640, 23), (640, 696))]
        seen.append((inside, outside, out))
        box.keys(b"\x03", timeout=10)

    def hue(v):
        r, b = (v >> 10) & 31, v & 31
        return "red" if r > b + 8 else "blue" if b > r + 8 else ""
    (plain, sides, out), (held, _, _) = seen
    check("ALI TEST, ROM 1 KB, NTSC (U)" in out and len(set(plain)) == 1 and hue(plain[0]) == "red"
          and len(set(held)) == 1 and hue(held[0]) == "blue" and set(sides) == {rgb555(0, 0, 0)},
          "megadrive: a cartridge made here runs: the picture red over 960 x 672 in the middle of the screen, "
          f"black around it; blue while the pad's B is held {[hex(v) for v in plain + held + sides]}")
    box.usb.detach()
    box.run(0.6)


# A 32 x 32 H.264 stream of two flat-coloured pictures (an IDR, a P) -- made with
#   ffmpeg -f lavfi -i color=c=0x3060a0:size=32x32:rate=25 -frames:v 2 -c:v libx264 -profile:v baseline -level 1.0
#          -x264-params keyint=25:scenecut=0:ref=1 -bsf:v filter_units=remove_types=6 flat32.264
# (the encoder's SEI left out); ffmpeg decodes it to Y 0x5c, Cb 0xa3, Cr 0x66.
TINY_H264 = bytes.fromhex(
    "00000001" "6742c00ada25b011000003000100000300320f1226a0"     # SPS: Baseline 1.0, 2 x 2 macroblocks, 25 frames/s
    "00000001" "68ce0f2c80"                                       # PPS
    "000001" "6588840bf118a00023571c00043ca38000856c9d75e0"       # the IDR picture's slice
    "00000001" "419a202bcb")                                      # the P picture's


# A 32 x 16 baseline JPEG, 4:2:0, its left half red and its right half blue -- made with Pillow:
#   Image.fromarray(a, "RGB").save(f, "JPEG", quality=90, subsampling=2, optimize=True)
TINY_JPEG = bytes.fromhex(
    "ffd8ffe000104a46494600010100000100010000ffdb0043000302020302020303030304030304050805050404050a070706"
    "080c0a0c0c0b0a0b0b0d0e12100d0e110e0b0b1016101113141515150c0f171816141812141514ffdb004301030404050405"
    "09050509140d0b0d141414141414141414141414141414141414141414141414141414141414141414141414141414141414"
    "1414141414141414ffc00011080010002003012200021101031101ffc4001600010101000000000000000000000000000007"
    "08ffc40014100100000000000000000000000000000000ffc4001501010100000000000000000000000000000907ffc40014"
    "110100000000000000000000000000000000ffda000c03010002110311003f00ce8021854d0200e30747ffd9")


def check_view_jpeg(box):
    """The picture viewer on a baseline JPEG ('view'): the video engine's JPEG mode first (jpeghw.c) -- the
    emulator has none (its registers are plain RAM), so jpeghw finds the engine read nothing and image.c's decoder
    shows it: red on the left, blue on the right, 40 times larger (1280 x 640), black above; 'view -s' does not try
    the engine; 'view -c' (both, compared) says why the engine's half failed."""
    import fat_image
    stick = VirtualStick(fat_image.build({"PICS/RB.JPG": TINY_JPEG}, fat=12, size_mb=1, partition=False))
    box.usb.attach("high", stick)
    box.run(4.0)
    sim = box.sim
    out = shell(box, "view -1 1:/PICS/RB.JPG", timeout=60)
    left, right, top = fb_pixel(sim, 320, 360), fb_pixel(sim, 960, 360), fb_pixel(sim, 640, 20)
    soft = shell(box, "view -1 -s 1:/PICS/RB.JPG", timeout=60)
    both = shell(box, "view -c 1:/PICS/RB.JPG", timeout=60)

    def hue(v):
        r, b = (v >> 10) & 31, v & 31
        return "red" if r > b + 8 else "blue" if b > r + 8 else ""
    ok = ("JPEG 32x16, baseline, 4:2:0; shown 1280x640 (whole times larger)" in out
          and "by the CPU (the video engine: the engine" in out and hue(left) == "red" and hue(right) == "blue"
          and top == rgb555(0, 0, 0) and "shown 1280x640" in soft and "video engine" not in soft
          and "1:/PICS/RB.JPG: the engine" in both)
    check(ok, "view: a baseline JPEG goes to the video engine first; the emulator's engine reads nothing, so the "
              "CPU decodes it (red left, blue right, 40 times larger); view -s skips the engine; view -c reports it"
              + ("" if ok else f" {out!r} {soft!r} {both!r} {[hex(v) for v in (left, right, top)]}"))
    box.usb.detach()
    box.run(0.6)


def tiny_ts(stream_type, es=b""):
    """A transport stream of a PAT, a PMT (program 1 at PID 0x100: one video stream of that type at PID 0x101) and
    ten packets of that stream: a PES header, `es` (the elementary stream's bytes, up to 175), zeros."""
    def crc32_mpeg(b):
        c = 0xFFFFFFFF
        for x in b:
            c ^= x << 24
            for _ in range(8):
                c = (c << 1) ^ 0x04C11DB7 if c & 0x80000000 else c << 1
            c &= 0xFFFFFFFF
        return c

    def section(table_id, ext, body):
        s = bytes([table_id]) + (0xB000 | (len(body) + 9)).to_bytes(2, "big") + ext.to_bytes(2, "big") + \
            bytes([0xC1, 0, 0]) + body
        return s + crc32_mpeg(s).to_bytes(4, "big")

    def packet(pid, payload, start, cc):
        p = bytes([0x47, (0x40 if start else 0) | pid >> 8, pid & 0xFF, 0x10 | cc & 15]) + payload
        return p + b"\xff" * (188 - len(p))
    pat = section(0x00, 1, bytes([0, 1, 0xE1, 0x00]))
    pmt = section(0x02, 1, bytes([0xE1, 0x01, 0xF0, 0x00, stream_type, 0xE1, 0x01, 0xF0, 0x00]))
    out = packet(0, b"\x00" + pat, True, 0) + packet(0x100, b"\x00" + pmt, True, 0)
    pes = b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00"
    for i in range(10):
        body = pes + es if not i else b""
        out += packet(0x101, body + bytes(184 - len(body)), not i, i)
    return out


def tiny_mp4(es, entry=b"avc1", len_size=4, co64=False, gap=16):
    """An .mp4 of an Annex B H.264 stream: its SPS / PPS in the avcC box, each slice a sample in a chunk of its own
    (each NAL unit after a len_size-byte length), `gap` bytes of something else after each chunk (a sound's), the
    index (moov) after the samples (mdat) -- as cameras and ffmpeg write it; stco or co64 for the chunks' places."""
    def box(t, body):
        return struct.pack(">I", 8 + len(body)) + t + body

    def full(t, body, flags=0):
        return box(t, struct.pack(">I", flags) + body)
    nals = [p.rstrip(b"\0") for p in es.split(b"\0\0\1")[1:]]
    sps, pps, slices = nals[0], nals[1], nals[2:]
    ftyp = box(b"ftyp", b"isom" + struct.pack(">I", 0x200) + b"isomavc1")
    samples = [len(s).to_bytes(len_size, "big") + s for s in slices]
    data, places = b"", []
    for s in samples:
        places.append(len(ftyp) + 8 + len(data))
        data += s + b"\xaa" * gap
    avcc = bytes([1, sps[1], sps[2], sps[3], 0xFC | (len_size - 1), 0xE1]) + struct.pack(">H", len(sps)) + sps + \
        b"\x01" + struct.pack(">H", len(pps)) + pps
    visual = bytes(6) + struct.pack(">H", 1) + bytes(16) + struct.pack(">HHII", 32, 32, 0x480000, 0x480000) + \
        bytes(4) + struct.pack(">H", 1) + bytes(32) + struct.pack(">Hh", 0x18, -1)
    n = len(samples)
    stbl = box(b"stbl", full(b"stsd", struct.pack(">I", 1) + box(entry, visual + box(b"avcC", avcc)))
               + full(b"stts", struct.pack(">III", 1, n, 512))
               + full(b"stsc", struct.pack(">IIII", 1, 1, 1, 1))
               + full(b"stsz", struct.pack(">II", 0, n) + b"".join(struct.pack(">I", len(s)) for s in samples))
               + (full(b"co64", struct.pack(">I", n) + b"".join(struct.pack(">Q", p) for p in places)) if co64 else
                  full(b"stco", struct.pack(">I", n) + b"".join(struct.pack(">I", p) for p in places))))
    minf = box(b"minf", full(b"vmhd", bytes(8), 1) + box(b"dinf", full(b"dref", struct.pack(">I", 1)
                                                                         + full(b"url ", b"", 1))) + stbl)
    mdia = box(b"mdia", full(b"mdhd", struct.pack(">IIIIHH", 0, 0, 12800, 512 * n, 0x55C4, 0))
               + full(b"hdlr", bytes(4) + b"vide" + bytes(12) + b"\0") + minf)
    tkhd = full(b"tkhd", struct.pack(">IIIII", 0, 0, 1, 0, 512 * n) + bytes(16) + bytes(36)
                + struct.pack(">II", 32 << 16, 32 << 16), 3)
    mvhd = full(b"mvhd", struct.pack(">IIIIIH", 0, 0, 1000, 80, 0x10000, 0x100) + bytes(70) + struct.pack(">I", 2))
    return ftyp + box(b"mdat", data) + box(b"moov", mvhd + box(b"trak", tkhd + mdia))


def check_dma_receiver(box):
    """Every IN on endpoint B ends with the DMA receiver set back (+0x60 = 0x20, init_dma_rx_state) before an OUT
    starts the transmitter (+0x60 bit 0).  Left started, the box's receiver woke with the OUT's en_dma_transfer
    and wrote into the bulk buffer the OUT was sending: FTP uploads to a card came back with wrong bytes (usb.c,
    epb_end).  The emulator's controller model writes nothing then, so the order of the stores is what is
    checked, over every transfer of the run."""
    started, outs, bad = False, 0, []
    for t, o, _s, v in box.usb.writes:
        if o != 0x60:
            continue
        if v & 0x20:
            started = False
        if v & 0x10:
            started = True
        if v & 0x01:
            outs += 1
            if started:
                bad.append(t)
    check(outs > 0 and not bad, f"every endpoint B IN is ended with the DMA receiver set back before an OUT starts "
                                f"the transmitter ({outs} OUTs"
                                + (f"; {len(bad)} with the receiver still started, the first at {bad[0]} s)"
                                   if bad else ")"))


def check_play(box):
    """The video player ('play'): the emulator has no MPEG-2 or H.264 decoder, so only how a file is taken apart --
    an H.264 stream's parameter sets read and its picture set up, then the decoder found silent and the play ended
    cleanly, from a .ts and from an .mp4 (its index after its samples: the reader seeks there and back); an .mp4
    of HEVC refused; a file of no stream refused; 'av status' reads the decoder's registers."""
    import fat_image
    stick = VirtualStick(fat_image.build({"VIDEO/AVC.TS": tiny_ts(0x1B, TINY_H264),
                                          "VIDEO/AVC.MP4": tiny_mp4(TINY_H264, len_size=2, co64=True, gap=40000),
                                          "VIDEO/HEVC.MP4": tiny_mp4(TINY_H264, entry=b"hvc1"),
                                          "VIDEO/JUNK.TS": bytes(range(256)) * 8},
                                         fat=12, size_mb=1, partition=False))
    box.usb.attach("high", stick)
    box.run(4.0)
    avc = shell(box, "play 1:/VIDEO/AVC.TS", timeout=60)
    status = shell(box, "av status", timeout=30)
    junk = shell(box, "play 1:/VIDEO/JUNK.TS", timeout=60)
    ok = ("transport stream" in avc and "video PID 0x101 (type 0x1b: H.264), no sound" in avc
          and "video: H.264 Baseline 1.0, 32 x 32, 25.00 frames/s, pixels 1:1, 1 reference frame," in avc
          and "play: the H.264 decoder does not answer" in avc and "\n0 pictures decoded" in avc
          and "H.264 decoder 0xb8004200" in status and "last stream: 32 x 32 (2 x 2 macroblocks)" in status
          and "not a transport stream" in junk)
    check(ok, "play: an H.264 .ts: its stream described (SPS: Baseline 1.0, 32 x 32), the emulator's missing decoder "
              "reported, 'av status' on the H.264 decoder, junk refused"
              + ("" if ok else f" {avc!r} {status!r} {junk!r}"))
    mp4 = shell(box, "play 1:/VIDEO/AVC.MP4", timeout=60)
    hevc = shell(box, "play 1:/VIDEO/HEVC.MP4", timeout=60)
    ok = ("MP4 / QuickTime file" in mp4 and "mp4: video track 1: H.264, 2 frames, 25.00 frames/s; no sound" in mp4
          and "video: H.264 Baseline 1.0, 32 x 32, 25.00 frames/s, pixels 1:1, 1 reference frame," in mp4
          and "play: the H.264 decoder does not answer" in mp4
          and "play: the video is hvc1 (HEVC): only H.264 (avc1) is played from an .mp4" in hevc)
    check(ok, "play: an .mp4 (2-byte NAL lengths, 64-bit chunk places, its index 80 KB in, after its samples: seeks "
              "there, back and over a 40 KB sound chunk): its track read, its avcC's SPS described, its first sample "
              "given to the decoder; an HEVC .mp4 refused"
              + ("" if ok else f" {mp4!r} {hevc!r}"))
    box.usb.detach()
    box.run(0.6)


def check_extra_consoles(box):
    """Smoke check for the expanded console emulators (built-in Vectrex Vector Storm, PC Engine, Neo Geo Pocket,
    Sony PlayStation 1 PS-X EXE, and Capcom CPS-2) from tiny self-contained test programs on a VirtualStick."""
    import fat_image
    pce = bytearray(b"\x00" * 8192)
    pce_code = bytes([
        0x78, 0xD4,                         # SEI; CSH
        0xA9, 0xFF, 0x53, 0x01,             # LDA #$FF; TAM #$01 (I/O at $0000)
        0x9C, 0x02, 0x04, 0x9C, 0x03, 0x04, # STZ $0402; STZ $0403 (VCE addr 0)
        0xA9, 0xC0, 0x8D, 0x04, 0x04,       # LDA #$C0; STA $0404
        0xA9, 0x01, 0x8D, 0x05, 0x04,       # LDA #$01; STA $0405
        0x80, 0xFE,                         # BRA .
    ])
    pce[0:len(pce_code)] = pce_code
    struct.pack_into("<H", pce, 0x1FFE, 0xE000)

    ngp = bytearray(b"\xff" * 0x10000)
    ngp[0:16] = b"COPYRIGHT BY SNK"
    struct.pack_into("<I", ngp, 0x1C, 0x00200040)
    ngp[0x23] = 0x10
    ngp[0x24:0x30] = b"SMOKETEST   "
    ngp_code = bytes([0xF1, 0xE0, 0x83, 0x02, 0xF0, 0x00, 0xF1, 0x18, 0x81, 0x00, 0x80, 0x68, 0xFE])
    ngp[0x40:0x40 + len(ngp_code)] = ngp_code

    psx = bytearray(4096)
    psx[0:8] = b"PS-X EXE"
    struct.pack_into("<IIII", psx, 0x10, 0x80010000, 0, 0x80010000, 0x800)
    struct.pack_into("<I", psx, 0x30, 0x801FFF00)
    for idx, w in enumerate((
        0x3C081F80,                         # lui  $t0, 0x1F80
        0x3C0902FF, 0x35292010, 0xAD091810, # GP0(02): Quick Fill color
        0xAD001810,                         # x=0, y=0
        0x3C0900F0, 0x35290140, 0xAD091810, # w=320, h=240
        0x1000FFFF, 0x00000000,             # b . ; nop
    )):
        struct.pack_into("<I", psx, 0x800 + idx * 4, w)

    cps_hdr = bytearray(256)
    cps_hdr[0:4] = b"CPS2"
    struct.pack_into("<5I", cps_hdr, 0x04, 0x11, 0x400, 0, 0, 0x400)
    cps_hdr[0x18], cps_hdr[0x19] = 13, 0xFF
    cps_hdr[0x44:0x4D] = b"SMOKETEST"
    cps_prom = bytearray(0x400)
    cps_prom[0:8] = bytes.fromhex("00FFFE00 00000200")
    cps_code = bytes.fromhex(
        "33FC FF0F 00910402"                # Scroll1 pal 0 pen 1 = bright red ($FF0F)
        "33FC 0001 00904000"                # Scroll1 cell (0,0) = tile 1
        "33FC 9040 00800102"                # Scroll1 base = $904000
        "33FC FFC0 0080010C"                # Scroll1 X = 0
        "33FC FFF0 0080010E"                # Scroll1 Y = 0
        "33FC 12CE 00800166"                # Layer ctrl = enable Scr1..3
        "33FC 003F 00800170"                # Pal ctrl = all 6 pages
        "33FC 9100 0080010A"                # Palette DMA from $910000
        "33FC 1260 00400004"                # CPS-2 layer priorities
        "60FE"                              # bra.s *
    )
    cps_prom[0x200:0x200 + len(cps_code)] = cps_code
    cps_gfx = bytearray(b"\xff" * 0x400)
    for y in range(8):
        cps_gfx[64 + y * 8 : 64 + y * 8 + 4] = b"\xff\x00\x00\x00"  # tile 1 = solid pen 1
    cps = bytes(cps_hdr + cps_prom + cps_gfx)

    # MSX2: tiny 16 KB V9938 Graphic 7 (SCREEN 8) cartridge setting border/backdrop bright cyan
    mx2 = bytearray(0x4000)
    mx2[0:4] = b"AB\x10\x40"
    mx2_code = bytes([
        0xF3, 0xDB, 0x99,
        0x3E, 0x0E, 0xD3, 0x99, 0x3E, 0x80, 0xD3, 0x99,   # R#0 = $0E (SCREEN 8)
        0x3E, 0x62, 0xD3, 0x99, 0x3E, 0x81, 0xD3, 0x99,   # R#1 = $62
        0x3E, 0x1F, 0xD3, 0x99, 0x3E, 0x82, 0xD3, 0x99,   # R#2 = $1F
        0x3E, 0xE3, 0xD3, 0x99, 0x3E, 0x87, 0xD3, 0x99,   # R#7 = $E3
        0x18, 0xFE,
    ])
    mx2[0x10:0x10 + len(mx2_code)] = mx2_code

    # Atari ST: tiny GEMDOS .prg ($601A header) setting Shifter color 0 = $0700 (red) and looping
    st_code = bytes.fromhex("33FC 0700 00FF8240 60FE")
    st_prg = struct.pack(">HIIIIIIH", 0x601A, len(st_code), 0, 0, 0, 0, 0, 0) + st_code + b"\x00\x00\x00\x00"

    # Sega System 16B: tiny .s16 arcade image setting CRAM[0] = $000F (red) and looping
    s16_hdr = bytearray(256)
    s16_hdr[0:4] = b"S16B"
    struct.pack_into("<I", s16_hdr, 0x04, 1)                # YM2151
    struct.pack_into("<I", s16_hdr, 0x08, 0x400)            # 1 KB 68k ROM
    struct.pack_into("<I", s16_hdr, 0x18, 192)              # 3 planes x 8 tiles x 8B = 192B tile GFX
    struct.pack_into("<I", s16_hdr, 0x1C, 64)               # 64B sprite GFX
    s16_hdr[0x40:0x49] = b"SMOKETEST"
    s16_prom = bytearray(0x400)
    s16_prom[0:8] = bytes.fromhex("00FFFE00 00000100")
    s16_code = bytes.fromhex("33FC 000F 00840000 60FE")
    s16_prom[0x100:0x100 + len(s16_code)] = s16_code
    s16_rom = bytes(s16_hdr + s16_prom + bytes(192 + 64))

    # Atari 800XL/130XE: tiny 8 KB cartridge ($A000..$BFFF) setting COLBK ($D01A) = $44 and looping
    a8_cart = bytearray(b"\xff" * 0x2000)
    a8_code = bytes([0xA9, 0x44, 0x8D, 0x1A, 0xD0, 0x4C, 0x05, 0xA0, 0x60])
    a8_cart[0:len(a8_code)] = a8_code
    a8_cart[0x1FFA:0x2000] = bytes([0x00, 0xA0, 0x00, 0x04, 0x08, 0xA0])

    # Atari 5200: tiny 8 KB cartridge ($8000..$9FFF mirrored to $BFFF) with diagnostic $FF immediate start
    a52_cart = bytearray(b"\xff" * 0x2000)
    a52_code = bytes([0xA9, 0x96, 0x8D, 0x1A, 0xC0, 0x4C, 0x05, 0x80])
    a52_cart[0:len(a52_code)] = a52_code
    a52_cart[0x1FFD:0x2000] = bytes([0xFF, 0x00, 0x80])

    stick = VirtualStick(fat_image.build({"T.PCE": bytes(pce), "T.NGP": bytes(ngp), "T.EXE": bytes(psx), "T.CPS": cps,
                                          "T.MX2": bytes(mx2), "T.PRG": st_prg, "T.S16": s16_rom,
                                          "ATARI8/T.ROM": bytes(a8_cart), "T.A52": bytes(a52_cart)},
                                         fat=12, size_mb=1, partition=False))
    box.usb.attach("high", stick)
    box.run(4.0)
    r_vec = box.command("vectrex -f 2", timeout=60)
    r_pce = box.command("pce -f 2 1:/T.PCE", timeout=60)
    r_ngp = box.command("ngp -f 2 1:/T.NGP", timeout=60)
    r_psx = box.command("psx -f 2 1:/T.EXE", timeout=60)
    r_cps = box.command("cps -f 2 1:/T.CPS", timeout=60)
    r_mx2 = box.command("msx2 -f 2 1:/T.MX2", timeout=60)
    r_st  = box.command("atarist -f 5 1:/T.PRG", timeout=60)
    r_s16 = box.command("sys16 -f 2 1:/T.S16", timeout=60)
    r_a8  = box.command("atari8 -f 2 1:/ATARI8/T.ROM", timeout=60)
    r_a52 = box.command("a5200 -f 2 1:/T.A52", timeout=60)
    check("picture CRC-32" in r_vec and "picture CRC-32" in r_pce and "picture CRC-32" in r_ngp
          and "PlayStation 1 PS-X EXE" in r_psx and "picture CRC-32" in r_psx
          and "CPS-2: SMOKETEST" in r_cps and "picture CRC-32" in r_cps
          and "MSX2 (V9938" in r_mx2 and "picture CRC-32" in r_mx2
          and "Atari" in r_st and "picture CRC-32" in r_st
          and "SMOKETEST" in r_s16 and "picture CRC-32" in r_s16
          and "Atari 130XE" in r_a8 and "picture CRC-32" in r_a8
          and "Atari 5200" in r_a52 and "picture CRC-32" in r_a52,
          "vectrex, pce, ngp, psx, cps, msx2, atarist, sys16, atari8 and a5200 run and render deterministic frames")
    box.usb.detach()
    box.run(0.6)


def shell(box, line, cwd="", timeout=60):
    """A command line on the UART; its output up to the prompt -- "m3801> ", or with a current directory
    "m3801 <cwd>> " (so the prompt is checked too)."""
    prompt = b"m3801> " if not cwd else b"m3801 " + cwd.encode("latin-1") + b"> "
    box.t.pending.clear()
    box.t.write(line.encode("latin-1") + b"\r")
    return box.t.wait_for(b"\r\n" + prompt, timeout).decode("latin-1")


def fat_volume(stick):
    """The stick's FAT volume, read by the tests' own reader: its MBR's first partition, or none."""
    from fat_image import Volume
    image = bytes(stick.image)
    start = int.from_bytes(image[454:458], "little") if image[450] in (0x01, 0x04, 0x06, 0x0B, 0x0C, 0x0E) else 0
    return Volume(image, start)


def fats_alike(vol):
    """Every copy of the FAT the same (the demo writes them all)."""
    b = vol.image[vol.start * 512:vol.start * 512 + 512]
    fats, size = b[16], int.from_bytes(b[22:24], "little") or int.from_bytes(b[36:40], "little")
    first = vol.image[vol.fat_start * 512:(vol.fat_start + size) * 512]
    return fats >= 2 and all(vol.image[(vol.fat_start + i * size) * 512:(vol.fat_start + (i + 1) * size) * 512] == first
                             for i in range(1, fats))


def name83(e):
    short = e["short"].decode("ascii")
    return short[:8].rstrip() + ("." + short[8:].rstrip() if short[8:].strip() else "")


def entry_named(vol, cluster, name):
    """The entry with that name (long, or 8.3 in any case) in a directory."""
    for e in vol.entries(cluster):
        if name == e["long"] or name.upper() == name83(e):
            return e
    return None


def fat_problems(vol):
    """What is wrong with a FAT volume: a file's chain not as long as its size needs, a cluster in two
    chains, one marked used that nothing uses (lost), a directory's '.' or '..' not where it should point."""
    problems, owner = [], {}
    csize = vol.spc * 512
    if vol.fat == 32:
        for c in vol.chain(vol.root_cluster):
            owner[c] = "/"

    def walk(cluster, parent, path):
        for e in vol.entries(cluster):
            name = e["long"] or name83(e)
            if e["attr"] & 0x08:
                continue
            if name in (".", ".."):
                want = cluster if name == "." else parent
                if e["cluster"] != want:
                    problems.append(f"{path}: '{name}' -> {e['cluster']}, not {want}")
                continue
            chain = vol.chain(e["cluster"]) if e["cluster"] else []
            for c in chain:
                if c in owner:
                    problems.append(f"{path}/{name}: cluster {c} is {owner[c]}'s too")
                owner[c] = f"{path}/{name}"
            if e["attr"] & 0x10:
                walk(e["cluster"], cluster, f"{path}/{name}")
            elif len(chain) != -(-e["size"] // csize):
                problems.append(f"{path}/{name}: {len(chain)} clusters for {e['size']} bytes")

    walk(0, 0, "")
    lost = [c for c in range(2, vol.clusters + 2) if vol.next(c) != 0 and c not in owner]
    if lost:
        problems.append(f"used, but nothing uses them: {lost[:8]}")
    return problems


def file_data(vol, cluster, path):
    """A file's bytes by its path from a directory (names as entry_named takes them); None: not there."""
    parts = [p for p in path.split("/") if p]
    e = None
    for part in parts:
        e = entry_named(vol, cluster, part)
        if e is None:
            return None
        cluster = e["cluster"]
    return vol.read(e["cluster"], e["size"]) if e["cluster"] else b""


def check_shell(box):
    """A shell on the USB disks: cd / pwd / dir / mkdir / rmdir / rm / touch on writable sticks -- FAT16 with
    a partition table, FAT32, FAT12 without one -- the prompt showing the current directory; what the demo
    writes read back by an independent FAT reader: entries with long names and
    their checksums, '.' and '..', freed clusters, every copy of the FAT alike (fat_image.Volume).  A
    write-protected stick is left alone."""
    import fat_image                                         # (its Volume reads the sticks back)
    exact = bytes(range(256)) * 8                            # (one cluster of the FAT16 image, 2 KB, full)
    w16 = VirtualStick(fat_image.build({"README.TXT": b"hi\n", "Docs/A.TXT": b"a\n", "Docs/EXACT.BIN": exact},
                                       fat=16, size_mb=16, label="W16"), writable=True)
    w32 = VirtualStick(fat_image.build({"BOOT.INI": b"x\n"}, fat=32, size_mb=40, label="W32"), writable=True)
    w12 = VirtualStick(fat_image.build({"F.TXT": b"f\n"}, fat=12, size_mb=2, partition=False), full_speed=True,
                       writable=True)
    locked = VirtualStick(fat_image.build({"KEEP.TXT": b"k\n"}, fat=16, size_mb=16, label="RO"))
    hub = VirtualHub(4)
    for port, stick in enumerate((w16, w32, w12, locked), 1):
        hub.plug(port, stick, "full" if stick is w12 else "high")
    box.usb.attach("high", hub)
    out = box.run(14.0)
    check(all(f"disk {n}: " in out for n in (2, 3, 4, 5)), "four sticks behind a hub: disks 2 to 5")
    out = shell(box, "pwd")
    check("no current directory" in out, "pwd before any cd: none (the prompt as before, 'm3801> ')")
    out = shell(box, "cd 2:", "2:/") + shell(box, "pwd", "2:/")
    check("\r\n2:/\r\n" in out, "cd 2: -- the prompt shows it ('m3801 2:/> '), pwd says 2:/")
    out = shell(box, "mkdir New Folder", "2:/") + shell(box, "dir", "2:/")
    check("<DIR>  New Folder\r\n" in out and "README.TXT" in out, "mkdir New Folder (a long name); dir lists it")
    out = shell(box, "cd new folder", "2:/New Folder") + shell(box, "touch notes.txt", "2:/New Folder")
    out += shell(box, "mkdir sub", "2:/New Folder") + shell(box, "mkdir lower", "2:/New Folder")
    out += shell(box, "ls", "2:/New Folder")
    check("<DIR>  sub\r\n" in out and "         0  notes.txt\r\n" in out and "<DIR>  lower\r\n" in out
          and "2026-11-13 12:00" in out,
          "cd into it (spelt as the disk has it, any case typed); touch, mkdir; ls there (made 2026-11-13 12:00: "
          "the box has no clock)")
    out = shell(box, "cd sub", "2:/New Folder/sub") + shell(box, "cd ..", "2:/New Folder")
    out += shell(box, "cd /Docs", "2:/Docs") + shell(box, "cd ../..", "2:/") + shell(box, "cat Docs/A.TXT", "2:/")
    check("a\r\n" in out, "cd sub, cd .., cd /Docs, cd ../.. (the root's .. is the root); cat a relative path")
    vol = fat_volume(w16)
    nf = entry_named(vol, 0, "New Folder")
    inside = {(e["long"] or name83(e)).lower(): e for e in vol.entries(nf["cluster"])} if nf else {}
    dots = vol.entries(nf["cluster"])[:2] if nf else []
    check(nf is not None and nf["attr"] == 0x10 and nf["sum_ok"] and nf["short"] == b"NEWFOL~1   "
          and [d["short"] for d in dots] == [b".          ", b"..         "]
          and dots[0]["cluster"] == nf["cluster"] and dots[1]["cluster"] == 0
          and inside.get("notes.txt", {}).get("size") == 0 and inside.get("sub", {}).get("attr") == 0x10
          and inside.get("lower", {}).get("long", 1) is None and fats_alike(vol),
          "on the disk: 'New Folder' with its long name (NEWFOL~1, the checksum right), '.' and '..' (0: the "
          "root), notes.txt of 0 bytes and sub and lower as 8.3 names (lower case by Windows' flags); both FATs "
          "alike")
    used = vol.chain(nf["cluster"]) if nf else []
    out = shell(box, "rmdir New Folder", "2:/")
    check("rmdir: not empty: New Folder" in out, "rmdir refuses a directory that is not empty")
    out = shell(box, "rm New Folder/notes.txt", "2:/") + shell(box, "rmdir New Folder/sub", "2:/")
    out += shell(box, "rmdir New Folder/lower", "2:/") + shell(box, "rmdir New Folder", "2:/")
    listing = shell(box, "dir", "2:/")                      # (the others' output holds their echoed lines)
    vol = fat_volume(w16)
    check("rm:" not in out and "rmdir:" not in out and "New Folder" not in listing
          and entry_named(vol, 0, "New Folder") is None and all(vol.next(c) == 0 for c in used) and fats_alike(vol),
          "rm, rmdir: no complaint, gone from the directory, their clusters free again, both FATs alike")
    out = shell(box, "rm Docs", "2:/") + shell(box, "mkdir README.TXT", "2:/") + shell(box, "rmdir ..", "2:/")
    check("rm: a directory" in out and "mkdir: 'README.TXT' exists" in out and "not that one" in out,
          "refused: rm of a directory, mkdir of a name there already, rmdir of '..'")
    # FAT32: the root directory is a chain of clusters -- long names enough to need another one
    root32 = len(fat_volume(w32).chain(fat_volume(w32).root_cluster))
    names = [f"A rather long file name number {i} for the FAT32 root directory" for i in range(4)]
    out = shell(box, "cd 3:", "3:/")
    for name in names:
        out += shell(box, f"touch {name}", "3:/")
    out += shell(box, "dir", "3:/")
    vol = fat_volume(w32)
    found = [entry_named(vol, 0, n) for n in names]
    check(all(f"0  {n}\r\n" in out for n in names) and all(e and e["sum_ok"] for e in found)
          and len(vol.chain(vol.root_cluster)) > root32 and fats_alike(vol),
          f"FAT32: four files with long names in the root; it grew a cluster ({root32} -> "
          f"{len(vol.chain(vol.root_cluster))}); both FATs alike")
    fsinfo = vol.image[(vol.start + 1) * 512:(vol.start + 2) * 512]
    check(fsinfo[488:492] == b"\xff\xff\xff\xff", "FAT32's FSInfo free count made unknown (the next system counts)")
    # FAT12 without a partition table, full speed: 64-byte packets, entries of 12 bits
    out = shell(box, "mkdir 4:/Logs", "3:/") + shell(box, "touch 4:/Logs/today.log", "3:/")
    out += shell(box, "ls 4:/logs", "3:/")
    vol = fat_volume(w12)
    logs = entry_named(vol, 0, "Logs")
    check("0  today.log" in out and logs is not None and logs["attr"] == 0x10 and fats_alike(vol)
          and entry_named(vol, logs["cluster"], "today.log") is not None,
          "FAT12 (no partition table, a full-speed stick): mkdir and touch by a path with its disk ('4:/Logs')")
    out = shell(box, "rm 4:/Logs/today.log", "3:/") + shell(box, "rmdir 4:/Logs", "3:/")
    vol = fat_volume(w12)
    check(entry_named(vol, 0, "Logs") is None and vol.next(logs["cluster"]) == 0 and fats_alike(vol),
          "and removed again: the 12-bit FAT entry free")
    out = shell(box, "mkdir 5:/NEW", "3:/")
    check("device 5 is write-protected" in out and not locked.writes,
          "a write-protected stick (MODE SENSE) is not written")
    out = shell(box, "cd", "")
    check(out.endswith("m3801> "), "cd alone: no current directory, the prompt as before")
    check_files(box, w16, w32, w12, exact)
    box.usb.detach()
    box.run(0.6)


# the file explorer (explorer.c): its path bar's text from (90, 62), the list's rows every 22 pixels from y 124
# (the names' cells from x 40, 64 of them), the status lines every 24 pixels from y 648
EXP_PATH, EXP_ROW_Y, EXP_ROW_H, EXP_NAME_X, EXP_STATUS_Y = (90, 62), 124, 22, 40, 648


def cells_text(rgb, x, y, n):
    """n of the 12 x 16 cells from (x, y) as text, trailing blanks dropped."""
    return "".join(read_cell(rgb, x + 12 * c, y)[0] for c in range(n)).rstrip()


def explorer_view(box, settle=0.6):
    """The explorer on the TV after a moment: its path bar, the names of its 23 rows, its 3 status lines."""
    box.run(settle)
    rgb = box.sim.capture_screen().astype(int)
    rows = [cells_text(rgb, EXP_NAME_X, EXP_ROW_Y + EXP_ROW_H * r + 3, 64) for r in range(23)]
    status = [cells_text(rgb, 16, EXP_STATUS_Y + 24 * i, 104) for i in range(3)]
    return cells_text(rgb, *EXP_PATH, 97), rows, status


def any_prompt(box, line, timeout=30):
    """A command line on the UART; its output up to the prompt, whatever directory it shows."""
    box.t.pending.clear()
    box.t.write(line.encode("latin-1") + b"\r")
    out, deadline = bytearray(), box.sim._vtime() + timeout
    while not re.search(rb"\r\nm3801[^\r\n>]*> $", bytes(out)):
        if box.sim._vtime() >= deadline:
            raise AssertionError(f"no prompt after {line!r}: {bytes(out[-300:])!r}")
        out.extend(box.t.read(4096, deadline - box.sim._vtime()))
    return out.decode("latin-1")


def mouse_to(box, mouse, x, y):
    """The pointer moved slowly to (x, y) -- a count every 10 ms: under 7 a report even when the mouse takes turns
    with the keyboard on endpoint B, so no acceleration; there?"""
    for _ in range(3):
        m = re.search(r"pointer at (\d+),(\d+)", any_prompt(box, "usb mouse"))
        dx, dy = x - int(m.group(1)), y - int(m.group(2))
        if not dx and not dy:
            return True
        box.run(mouse.move(dx, dy, over=(max(abs(dx), abs(dy)) + 1) * 0.01) + 0.4)
    return False


def check_explorer(box):
    """The file explorer on the TV ('explorer'), with a FAT32 stick, a keyboard and a mouse behind a hub: the
    disks' volumes before any cd; a directory's entries (directories first, then files, by name); synced with the
    shell both ways -- a cd typed on the UART lists the new directory, one opened on the TV is the shell's (the
    prompt follows); the keyboard's keys and the mouse's buttons are its own (no painting, no mouse lines); a path
    typed into its path bar, a wrong one told in its status line; a file's beginning shown on the TV, not on the
    UART; a directory made in the shell listed; Esc back to the console."""
    import fat_image
    files = {"README.TXT": DISK_TEXT, "Docs/A long file name.txt": DISK_LONG, "Docs/sub/deep.bin": bytes(range(256)),
             "Docs/notes.txt": b"first line\n", "Empty/": None, "lower.txt": b"lower case\n"}
    for i in range(30):
        files[f"Many/file{i:02d}.txt"] = b"%d\n" % i
    stick = VirtualStick(fat_image.build(files, fat=32, size_mb=40, label="EXPLORE"), writable=True)
    kbd, mouse, hub = VirtualKeyboard(get_report="empty", composite=True), VirtualMouse(), VirtualHub(4)
    for port, dev in ((1, stick), (2, kbd), (3, mouse)):
        hub.plug(port, dev, "high" if dev is stick else "low")
    box.usb.attach("high", hub)
    out = box.run(12.0)
    check("disk 2: AliSim Virtual stick 1.00, 40 MB; partition 1: FAT32 'EXPLORE', 39 MB" in out,
          "explorer: a stick, a keyboard and a mouse behind a hub")
    out = any_prompt(box, "explorer")
    path, rows, status = explorer_view(box, 1.0)
    check("the explorer is on the TV, in the list of disks" in out and mmio(box.sim, 0x6304, 4) == HEAD_PHYS
          and rows[0].startswith("2:  FAT32 'EXPLORE', 39 MB  -  AliSim Virtual stick 1.00")
          and status[0].startswith("1 volume on 1 USB disk"),
          f"explorer before any cd: the disks' volumes on the test screen's picture ({rows[0]!r})")
    mark = len(box.t.received)
    box.run(kbd.type("\r") + 0.8)
    path, rows, status = explorer_view(box)
    uart = bytes(box.t.received[mark:]).decode("latin-1")
    check(path == "2:/" and rows[:7] == ["..  (the list of disks)", "Docs", "Empty", "Many", "lower.txt", "README.TXT",
                                         ""] and status[0] == "3 directories, 2 files, 659 bytes"
          and uart.endswith("\x1b[Km3801 2:/> "),
          f"Enter on the keyboard opens it: the root, directories first, then files by name; the shell's prompt "
          f"follows ('m3801 2:/> '): {rows[:6]}")
    any_prompt(box, "cd Docs")
    path, rows, status = explorer_view(box)
    check(path == "2:/Docs" and rows[:4] == ["..  (one directory up)", "sub", "A long file name.txt", "notes.txt"],
          f"cd typed on the UART: the explorer lists the new directory ({path!r}, {rows[:4]})")
    # the mouse: dragged with the left button down (no painting), a click selects, a double-click opens
    x = 850                                                  # (right of the names, left of the sizes)
    moved = mouse_to(box, mouse, x, EXP_ROW_Y + 2 * EXP_ROW_H + 11)
    mouse.press(1)
    mouse.move(30, 0, over=0.3, delay=0.05)
    mouse.release(1, delay=0.05)
    out = box.run(1.0)
    path, rows, status = explorer_view(box, 0.2)
    rgb = box.sim.capture_screen().astype(int)
    painted = (np.abs(rgb[130:620, 20:1240] - shown(255, 230, 120)).sum(axis=2) < 10).sum()
    check(moved and not painted and "mouse: left" not in out and status[1].startswith("A long file name.txt: 5200 bytes"),
          "a click on a row selects it (the status line tells its size); the left button does not paint, the mouse "
          "lines stay off the UART")
    mouse_to(box, mouse, x, EXP_ROW_Y + EXP_ROW_H + 11)
    mark = len(box.t.received)
    mouse.click(1, hold=0.1)
    mouse.click(1, hold=0.1, delay=0.15)
    box.run(2.0)
    path, rows, status = explorer_view(box)
    uart = bytes(box.t.received[mark:]).decode("latin-1")
    check(path == "2:/Docs/sub" and rows[:2] == ["..  (one directory up)", "deep.bin"]
          and "m3801 2:/Docs/sub> " in uart, f"a double-click opens 'sub': the shell's cd too ({path!r})")
    box.run(kbd.type("{BS}") + 0.8)
    path, rows, status = explorer_view(box)
    check(path == "2:/Docs" and status[1].startswith("sub: a directory"),
          "Backspace goes up, the directory come from selected")
    # the path bar: Tab puts the caret there, Ctrl-U clears, Enter goes; a wrong path is told, Esc cancels
    box.run(kbd.type("{TAB}{CTRL-U}2:/Many\r") + 0.8)
    path, rows, status = explorer_view(box)
    check(path == "2:/Many" and rows[1] == "file00.txt" and status[0] == "0 directories, 30 files, 80 bytes"
          and rows[22] == "file21.txt", f"a path typed into the path bar: listed ({status[0]!r})")
    box.run(kbd.type("{DOWN}{DOWN}") + 0.5)
    mouse.wheel(-2)
    path, rows, status = explorer_view(box)
    check(rows[0] == "file05.txt" and status[1].startswith("file01.txt: 2 bytes"),
          f"Down moves the selection, the wheel scrolls ({rows[0]!r} on top)")
    box.run(kbd.type("/nothere\r") + 0.8)
    path, rows, status = explorer_view(box)
    check(path == "2:/Many/nothere" and status[1] == "not found: nothere",
          f"a path that is not there: told in the status line, the path kept to be put right ({status[1]!r})")
    box.run(kbd.type("{ESC}{TAB}{CTRL-U}/\rr") + 0.8)
    path, rows, status = explorer_view(box)
    mark = len(box.t.received)
    box.run(kbd.type("\r") + 0.8)
    box.run(0.6)
    rgb = box.screen("v4_explorer_preview_screen.png", "the explorer: README.TXT's beginning on the TV")
    uart = bytes(box.t.received[mark:]).decode("latin-1")
    check(path == "2:/" and status[1].startswith("README.TXT: 648 bytes")
          and cells_text(rgb, 24, 128, 100) == "Hello from the virtual stick." and "Hello" not in uart,
          "Esc cancels the path, '/' Enter the root, 'r' jumps to README.TXT, Enter shows its beginning on the TV "
          "(not on the UART)")
    box.run(kbd.type("x") + 0.5)
    any_prompt(box, "mkdir NEWDIR")
    path, rows, status = explorer_view(box, 1.0)
    rgb = box.screen("v4_explorer_screen.png", "the file explorer on the TV after 'mkdir NEWDIR' in the shell")
    check(rows[4] == "NEWDIR" and rows[6] == "README.TXT", "a key closes it; a directory made in the shell is listed")
    box.run(kbd.type("{ESC}") + 0.5)
    out = box.run(kbd.type("cd\r") + 0.8)
    check(mmio(box.sim, 0x6304, 4) == CON_HEAD_PHYS and out.endswith("m3801> "),
          "Esc: the console on the TV again, the keyboard types into the shell")
    box.usb.detach()
    box.run(0.6)


def check_modem(box):
    """USB serial ports: an LTE module (usb_host.VirtualModem, the A7670E's interfaces and endpoints) behind
    a hub, a writable stick next to it.  tty lists the module's four ports; at sends one AT command to the
    first "Mobile AT Interface" and shows the answer up to its final result -- the answers are short
    packets, read one at a time: endpoint B's DMA asked for 1 byte, the packet's rest taken from its FIFO
    -- a line typed as AT... goes there too, and > writes the answer into a file; cu joins the terminal to
    a port ("~." at a line's start or Ctrl-] ends it, Enter goes out as CR whatever the terminal sends); a
    web page through the module's HTTP client (its result after the command's OK, the page after
    AT+HTTPREAD's); both go on through IN tokens spoilt on the bus; a module that lost its configuration
    (restarted) is set up again by the command that finds it so; unplugged, its ports are gone."""
    import fat_image
    modem = VirtualModem(pin="1234")
    stick = VirtualStick(fat_image.build({"README.TXT": b"hi\n"}, fat=16, size_mb=16, label="LOGS"), writable=True)
    hub = VirtualHub(4)
    hub.plug(1, modem, "high")
    hub.plug(2, stick, "high")
    box.t.pending.clear()
    box.usb.attach("high", hub)
    out = box.t.wait_for(b"disk 3: ", 15).decode("latin-1")     # (the stick is set up last)
    ports = [(0, 2, "Mobile Diag Interface"), (1, 4, "Mobile AT Interface"), (2, 5, "Mobile AT Interface"),
             (3, 3, "Mobile Diag Interface")]
    check(all(f"ttyUSB{n}: a serial port (interface {i}, {name}): 'cu {n}'" in out for n, i, name in ports)
          and "disk 3: " in out and sorted(modem.line_states) == [(2, 3), (3, 3), (4, 3), (5, 3)],
          "an LTE module (1e0e:9011) behind a hub: its four vendor-class ports in the descriptors' order "
          "(ttyUSB0..3; its network interfaces left alone), DTR and RTS on for each; the stick next to it: disk 3")
    out = box.command("tty")
    check("ttyUSB1  device 2 interface 4: Mobile AT Interface (bulk in 86, out 0f, 512-byte packets)" in out
          and "ttyUSB3  device 2 interface 3: Mobile Diag Interface (bulk in 85, out 0e, 512-byte packets)" in out,
          "tty lists them: device, interface, name, endpoints")
    wmark, drains, drops = len(box.usb.writes), box.usb.fifo_drains, box.usb.toggle_drops
    out = box.command("at")
    check("\r\nAT\r\nOK\r\n" in out and modem.received[-1] == (4, b"AT\r"),
          "at: \"AT\" to the AT port (interface 4); its echo and OK shown")
    out = box.command("at i")
    counts = [v for _t, o, s, v in box.usb.writes[wmark:] if o == 0x38 and s == 1]
    check("\r\nATi\r\n" in out and "Model: A7670E-FASE\r\n" in out and f"IMEI: {VirtualModem.IMEI}\r\n" in out
          and "+GCAP: +CGSM,+FCLASS,+DS\r\n\r\nOK\r\n" in out and 1 in counts and box.usb.fifo_drains > drains
          and box.usb.toggle_drops == drops,
          "at i: the module's lines as they came -- each answer one short packet: the DMA asked for 1 byte, "
          "then started again for the packet's rest in endpoint B's FIFO; no data toggle lost")
    out = box.command("at +cpin?")
    check("+CPIN: SIM PIN\r\n" in out, "at +cpin?: the SIM wants its PIN")
    out = box.command('at +cpin="1234"')
    check("\r\nOK\r\n" in out and modem.received[-1] == (4, b'AT+cpin="1234"\r') and not modem.locked,
          'at +cpin="1234": the command as typed, quotes kept ("AT" put in front); OK, the SIM unlocked')
    out = box.command("at +cpin?") + box.command("at +spic")
    check("+CPIN: READY\r\n" in out and "+SPIC: 3,10,3,10\r\n" in out,
          "+CPIN: READY (the module's own +CPIN: READY after the PIN, waiting on the port, not taken for the "
          "answer); +SPIC: three tries again")
    out = box.command("AT+CSQ") + box.command("/AT+CGMR")
    check("+CSQ: 25,99\r\n" in out and "+CGMR: A011B07A7670M7_F\r\n" in out
          and modem.received[-2:] == [(4, b"AT+CSQ\r"), (4, b"AT+CGMR\r")],
          "a line typed as AT+CSQ goes to the module as it is (/AT+CGMR too, without the '/')")
    out = box.command("at +bogus")
    check("\r\nERROR\r\n" in out, "an unknown command: ERROR, its final result")
    box.command("at +csq > 3:/csq.txt")
    vol = fat_volume(stick)
    check(file_data(vol, 0, "csq.txt") == b"AT+csq\n+CSQ: 25,99\n\nOK\n" and not fat_problems(vol),
          "at +csq > 3:/csq.txt: the answer in a file on the stick")
    out = box.command('at +cmgs="+48600100200"')
    check(out.endswith("\r\n> \r\nm3801> "), 'at +cmgs="+48600100200": back at the module\'s "> " (the text: cu)')
    out = box.keys(b"cu\r", until=b"Ctrl-] ends.\r\n")
    out += box.keys(b"hello\x1a", until=b"OK\r\n") + box.keys(b"\r~.", until=PROMPT)
    check("Connected to ttyUSB1 (device 2 interface 4, Mobile AT Interface)" in out and "+CMGS: 1\r\n" in out
          and modem.sms == [("+48600100200", "hello")] and "Disconnected from ttyUSB1." in out,
          "cu (the AT port): the message's text typed, Ctrl-Z passed on (+CMGS: 1); \"~.\" at a line's start "
          "ends it")
    mark = len(modem.received)
    out = box.keys(b"cu 2\r", until=b"Ctrl-] ends.\r\n") + box.keys(b"ATI\n", until=b"OK\r\n")
    out += box.keys(b"\x1d", until=PROMPT)
    sent = b"".join(d for i, d in modem.received[mark:] if i == 5)
    check("Model: A7670E-FASE" in out and sent == b"ATI\r" and "Disconnected from ttyUSB2." in out,
          "cu 2 (the other AT port): ATI with LF for Enter goes out as ATI CR; Ctrl-] ends it")
    out = box.command("cu 7")
    check("no serial port 7" in out, "cu 7: no such port")
    # a web page through the module's own HTTP client: its result comes seconds after AT+HTTPACTION's OK,
    # the page after AT+HTTPREAD's OK -- at shows both
    out = box.command("at +httpinit") + box.command('at +httppara="URL","http://example.com/"')
    out += box.command("at +httpaction=0")
    check(out.count("\r\nOK\r\n") == 3 and "+HTTPACTION" not in out and modem.requests == ["http://example.com/"],
          "at +httpinit, +httppara (the URL in quotes), +httpaction=0: OK each, the result not yet there")
    box.run(2.0)                                            # (the module's 1.5 s request)
    page = VirtualModem.PAGE.decode("latin-1")
    out = box.command(f"at +httpread=0,{len(page)}")
    urc, echo = out.find("+HTTPACTION: 0,200,"), out.find("AT+httpread=0,")
    check(0 <= urc < echo and "\r\nOK\r\n" in out[echo:]
          and f"\r\n+HTTPREAD: {len(page)}\r\n{page}\r\n+HTTPREAD: 0\r\n" in out[echo:],
          f"at +httpread: the +HTTPACTION that came after the last command shown first; the page that follows "
          f"OK shown too ({len(page)} bytes on one line, whole)")
    box.usb.epb_fail_next = 2
    out = box.command("at i")
    check("Model: A7670E-FASE\r\n" in out and "\r\nOK\r\n" in out and "failed" not in out
          and box.usb.epb_fail_next == 0,
          "at through two IN tokens spoilt on the bus (UTMI errors): each tried again in usb.c, the answer whole")
    out = box.keys(b"cu\r", until=b"Ctrl-] ends.\r\n")
    box.usb.epb_fail_next = 3
    out += box.keys(b"ATI\r", until=b"OK\r\n") + box.keys(b"~.", until=PROMPT)
    check("(a USB transfer failed: bulk IN stage: UTMI error (token error 0x04) -- going on)" in out
          and "Model: A7670E-FASE" in out and "Disconnected from ttyUSB1." in out and box.usb.epb_fail_next == 0,
          "cu goes on when an IN fails three times in a row (the UTMI error the real box got while the module "
          "sent over GSM, past usb.c's two tries again): said once, the session goes on")
    modem.restart()
    commands = len(stick.commands)
    out = box.command("at +csq", timeout=60)
    check("not set up any more" in out and "ttyUSB1 is back: the command again" in out and "+CSQ: 25,99\r\n" in out
          and 0 <= out.find("\r\nRDY\r\n") < out.find("AT+csq") and modem.configuration
          and len(stick.commands) == commands,
          "the module restarted (its configuration lost, the port's connection unchanged, as the real one once "
          "after AT+CRESET): at finds it so, sets that hub port alone up again (the stick next to it untouched), "
          "sends the command again; the module's start-up messages (RDY ...) shown before it, not taken for its "
          "answer")
    hub.unplug(1)
    out = box.t.wait_for(b"device removed", 5).decode("latin-1") + box.command("tty")
    check("no USB serial ports" in out, "unplugged: its ports are gone")
    box.usb.detach()
    box.run(0.6)


def check_ssdp(box):
    """SSDP (ssdp.c) over the LTE module's network link -- the emulator has no Ethernet adapter, and the demo
    takes the module's RNDIS function when there is none: the packet filter it sets takes all multicast; once
    DHCP gave the address, NOTIFY ssdp:alive for the device's three names goes to 239.255.255.250:1900 in
    rounds 2 s apart (TTL 4), with an IGMPv2 report for the group (TTL 1); an M-SEARCH from the module's router
    to the group, or to the box itself, is answered to its sender for upnp:rootdevice / ssdp:all, one for
    another device type is not; netstat counts them.  (/ssdp/device.xml needs TCP, which the module's small
    network does not carry.)"""
    modem = VirtualModem()
    box.t.pending.clear()
    box.usb.attach("high", modem)
    out = box.t.wait_for(b"(DHCP), router", 30).decode("latin-1")
    me, router = bytes([192, 168, 225, 100]), bytes([192, 168, 225, 1])
    group, group_mac = bytes([239, 255, 255, 250]), bytes.fromhex("01005e7ffffa")
    uuid = "uuid:4d333830-3176-3400-8000-" + VirtualModem.RNDIS_MAC.hex()
    box.run(10.0)           # (rounds at once and 2 s later by the demo's clock: 6.8 s here, where Count runs at
    sent = list(modem.rndis_frames)                         # 100 MHz and the demo counts the chip's 337.5)
    notify = [f for f in sent if f[:6] == group_mac and f[23] == 17 and f[36:38] == b"\x07\x6c"]
    texts = [f[42:].decode("latin-1") for f in notify]
    names = sorted({m.group(1) for t in texts for m in [re.search(r"\r\nNT: (\S+)\r\n", t)] if m})
    check("192.168.225.100 (DHCP)" in out and modem.rndis_filter == 0x0F and len(notify) >= 6
          and names == sorted(["upnp:rootdevice", uuid, "urn:schemas-upnp-org:device:Basic:1"])
          and all(f[26:30] == me and f[30:34] == group and f[22] == 4 for f in notify)
          and all(t.startswith("NOTIFY * HTTP/1.1\r\n") and "\r\nNTS: ssdp:alive\r\n" in t
                  and "\r\nLOCATION: http://192.168.225.100/ssdp/device.xml\r\n" in t for t in texts),
          f"SSDP: the RNDIS packet filter takes all multicast (0x{modem.rndis_filter or 0:02x}); after DHCP "
          f"{len(notify)} NOTIFY ssdp:alive (two rounds at least) to 239.255.255.250:1900 (TTL 4) for "
          f"upnp:rootdevice, {uuid} (the link's MAC) and the Basic:1 device type, LOCATION the web page's "
          f"/ssdp/device.xml")
    igmp = [f for f in sent if f[:6] == group_mac and f[23] == 2 and f[22] == 1 and f[34] == 0x16
            and f[38:42] == group and VirtualModem._csum(f[34:42]) == 0]
    check(bool(igmp), "SSDP: an IGMPv2 membership report for 239.255.255.250 (TTL 1, its checksum right)")

    def search(st, to_box=False, port=50000):
        text = (f"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n"
                f"ST: {st}\r\n\r\n").encode()
        udp = struct.pack(">HHHH", port, 1900, 8 + len(text), 0) + text
        dst_mac = VirtualModem.RNDIS_MAC if to_box else group_mac
        mark = len(modem.rndis_frames)
        modem.network_frame(dst_mac + VirtualModem.NET_MAC + b"\x08\x00"
                            + modem._ip(router, me if to_box else group, 17, udp))
        box.run(2.0)                                        # (answered within 0.3 s of the demo's clock)
        return [f[42:].decode("latin-1") for f in modem.rndis_frames[mark:]
                if f[:6] == VirtualModem.NET_MAC and f[23] == 17 and f[30:34] == router
                and f[34:36] == b"\x07\x6c" and struct.unpack(">H", f[36:38])[0] == port]

    root = search("upnp:rootdevice")
    every = search("ssdp:all", port=50001)
    other = search("urn:schemas-upnp-org:device:MediaRenderer:1", port=50002)
    direct = search("upnp:rootdevice", to_box=True, port=50003)
    check(len(root) == 1 and root[0].startswith("HTTP/1.1 200 OK\r\n") and "\r\nST: upnp:rootdevice\r\n" in root[0]
          and f"\r\nUSN: {uuid}::upnp:rootdevice\r\n" in root[0] and "\r\nEXT:\r\n" in root[0]
          and "\r\nLOCATION: http://192.168.225.100/ssdp/device.xml\r\n" in root[0]
          and len(every) == 3 and not other and len(direct) == 1,
          "SSDP: an M-SEARCH for upnp:rootdevice to the group answered to its sender (200 OK, ST, USN, EXT, "
          "LOCATION); ssdp:all: three answers; another device type: none; one sent to the box's own address: "
          "answered too")
    out = box.command("netstat")
    check(re.search(r"SSDP \(UPnP discovery, UDP 1900\): " + re.escape(uuid) + r", \d+ NOTIFYs sent, 4 searches "
                    r"seen, 5 answers sent \(the last to 192\.168\.225\.1\)", out) is not None,
          "netstat: the SSDP line (its UUID, NOTIFYs, 4 searches, 5 answers, the last to the router)")
    box.usb.detach()
    box.run(0.6)


def check_files(box, w16, w32, w12, exact):
    """Files' contents written: a command's output into a file ('>' and '>>'), cp (into a directory, onto
    another disk), mv (rename, into a directory, a directory with its '..', the current directory's path),
    quotes; each file read back, and every volume left without a lost cluster or a chain of the wrong
    length (FAT16 2 KB clusters, FAT32 512-byte ones, FAT12)."""
    cwd = "2:/Quoted Dir"
    prompt = f"m3801 {cwd}> "
    out = shell(box, 'mkdir "2:/Quoted Dir"', "") + shell(box, "cd '2:/quoted dir'", cwd)
    check(out.endswith(prompt) and "not" not in out, "quotes keep a name's space: mkdir \"2:/Quoted Dir\", "
                                                      "cd '2:/quoted dir' (the prompt spells it as the disk has it)")
    out = shell(box, "echo hello world > notes.txt", cwd)
    out += shell(box, "echo second   line>>notes.txt", cwd) + shell(box, "cat notes.txt", cwd)
    vol = fat_volume(w16)
    qd = entry_named(vol, 0, "Quoted Dir")["cluster"]
    check(file_data(vol, qd, "notes.txt") == b"hello world\nsecond line\n"
          and "cat notes.txt\r\nhello world\r\nsecond line\r\n" in out,
          "echo hello world > notes.txt, echo ...>>notes.txt: the file holds both lines (Linux line ends), cat "
          "shows them")
    quiet = shell(box, "help > help.txt", cwd)
    shown = shell(box, "help", cwd)
    text = shown.split("\r\n", 1)[1][:-len(prompt)].replace("\r\n", "\n").encode("latin-1")
    vol = fat_volume(w16)
    h = entry_named(vol, qd, "help.txt")
    check(quiet == "help > help.txt\r\n" + prompt and file_data(vol, qd, "help.txt") == text
          and h["size"] > 2048 and len(vol.chain(h["cluster"])) == -(-h["size"] // 2048),
          f"help > help.txt: nothing on the terminal, the file is what help prints ({len(text)} bytes, "
          f"{-(-len(text) // 2048)} clusters)")
    out = shell(box, 'cp notes.txt "copy of notes.txt"', cwd) + shell(box, "mkdir sub", cwd)
    out += shell(box, "cp help.txt sub", cwd) + shell(box, "cp help.txt 3:/", cwd)
    same = shell(box, "cp help.txt help.txt", cwd) + shell(box, "cp help.txt HELP.TXT", cwd)
    vol, vol32 = fat_volume(w16), fat_volume(w32)
    check(file_data(vol, qd, "copy of notes.txt") == b"hello world\nsecond line\n"
          and file_data(vol, qd, "sub/help.txt") == text and file_data(vol32, 0, "help.txt") == text
          and len(vol32.chain(entry_named(vol32, 0, "help.txt")["cluster"])) == -(-len(text) // 512)
          and same.count("cp: the same file") == 2,
          "cp to a new name, into a directory, onto the FAT32 stick (512-byte clusters); onto itself refused")
    copy = entry_named(vol, qd, "copy of notes.txt")
    out = shell(box, 'mv "copy of notes.txt" renamed.txt', cwd) + shell(box, "mv renamed.txt sub", cwd)
    sub = entry_named(fat_volume(w16), qd, "sub")
    out += shell(box, 'mv sub "/moved sub"', cwd)
    vol = fat_volume(w16)
    moved = entry_named(vol, 0, "moved sub")
    inner = entry_named(vol, moved["cluster"], "renamed.txt") if moved else None
    dots = vol.entries(moved["cluster"])[:2] if moved else []
    check(out.count("\r\n") == 3 and entry_named(vol, qd, "sub") is None and moved is not None
          and moved["cluster"] == sub["cluster"] and inner is not None and inner["cluster"] == copy["cluster"]
          and file_data(vol, moved["cluster"], "renamed.txt") == b"hello world\nsecond line\n"
          and [d["cluster"] for d in dots] == [moved["cluster"], 0],
          "mv to a new name, into a directory, a directory to the root with a new name: the same clusters, its "
          "'..' now the root")
    out = shell(box, 'mv "/moved sub" "/moved sub/inner"', cwd) + shell(box, "mv notes.txt 3:/", cwd)
    out += shell(box, "mv notes.txt help.txt", cwd)
    check("mv: a directory into itself" in out and "mv: to another volume" in out and "mv: 'help.txt' exists" in out,
          "refused: a directory into itself, to another disk, onto a name there")
    out = shell(box, "cd '/moved sub'", "2:/moved sub") + shell(box, "mv '/moved sub' '/Moved Again'", "2:/Moved Again")
    out += shell(box, "pwd", "2:/Moved Again")
    check("\r\n2:/Moved Again\r\n" in out, "mv of the current directory: the prompt and pwd follow it")
    out = shell(box, "echo tail >> /Docs/EXACT.BIN", "2:/Moved Again") + shell(box, "echo more >> /README.TXT",
                                                                                "2:/Moved Again")
    out += shell(box, "echo short > '/Quoted Dir/help.txt'", "2:/Moved Again")
    vol = fat_volume(w16)
    ex = entry_named(vol, entry_named(vol, 0, "Docs")["cluster"], "EXACT.BIN")
    hl = entry_named(vol, qd, "help.txt")
    check(file_data(vol, 0, "Docs/EXACT.BIN") == exact + b"tail\n" and len(vol.chain(ex["cluster"])) == 2
          and file_data(vol, 0, "README.TXT") == b"hi\nmore\n"
          and file_data(vol, qd, "help.txt") == b"short\n" and len(vol.chain(hl["cluster"])) == 1,
          ">> onto a full cluster (a cluster added) and into a sector's middle; > over a file of several clusters: "
          "one left")
    out = shell(box, "echo x > 5:/x", "2:/Moved Again") + shell(box, "echo x > /nothing/x", "2:/Moved Again")
    out += shell(box, "echo x > '/Moved Again'", "2:/Moved Again") + shell(box, "echo x >", "2:/Moved Again")
    check("device 5 is write-protected" in out and "not found: nothing" in out and ">: a directory" in out
          and "a file name after '>'" in out, "> refused: a write-protected stick, a missing directory, onto a "
                                               "directory, no name")
    out = shell(box, "ls > 4:/list.txt", "2:/Moved Again") + shell(box, "cd", "")
    vol12 = fat_volume(w12)
    listing = file_data(vol12, 0, "list.txt") or b""
    check(b"renamed.txt" in listing and b"help.txt" in listing, "ls > 4:/list.txt: onto the FAT12 stick")
    problems = fat_problems(fat_volume(w16)) + fat_problems(fat_volume(w32)) + fat_problems(fat_volume(w12))
    check(not problems and fats_alike(fat_volume(w16)) and fats_alike(fat_volume(w32)) and fats_alike(vol12),
          f"all three volumes whole: no lost cluster, every chain as long as its file, '.' and '..' right, both "
          f"FATs alike {problems[:3]}")


def check_head_block(sim, label):
    """The 40-byte head the demo's picture needs, the scaling filter table zero and the
    originals' BT.709 matrix at +0x240 (what a revision-1 S3811 converts the colours with)."""
    words = head_block(sim)
    head = [w & 0xFFFFFFFF for w in words[:8]]
    want = [0xAA200B51, 0, 1279 << 16, 719 << 16, (720 << 16) | 1280, (2560 << 16) | 0x0F, 0, FB_PHYS]
    check(head == want and not any(words[8:0x240 // 4]) and words[0x240 // 4:0x240 // 4 + 13] == BT709_MATRIX
          and not any(words[0x240 // 4 + 13:]) and mmio(sim, 0x6304, 4) == HEAD_PHYS,
          f"{label}: the head (ARGB1555, 1280x720, pitch 2560, bitmap 0x{FB_PHYS:08x}), the filter table zero, "
          f"the originals' BT.709 matrix at +0x240, the layer pointing at it (0xB8006304 = 0x{HEAD_PHYS:08x}, physical)")


def run(args):
    started = time.monotonic()
    flash, application, manifest = check_artifacts()
    check_rebuild(application, args.require_toolchain)
    image_path = BIN / f"{STEM}.bin"
    box = Box(image_path, args.engine)
    boot = box.boot().decode("latin-1")
    check("bl_verify_sw" in boot and "success!" in boot, "the original bootloader verifies and starts the demo")
    check(f"{APP_BANNER}\r\nVersion: v4\r\nRAM app via original bootloader\r\n" in boot, "v4 banner on the UART")
    check(not box.sim.lzma_hle, "the bootloader's own LZMA decoder unpacked the demo")
    check_watchdog_running(box, boot)

    # ---- the command line ------------------------------------------------
    out = box.command("help")
    names = ["help", "version", "ping", "info", "uptime", "loop", "echo", "md", "mr", "mw", "screen", "testscreen",
             "console", "explorer", "panel", "keys", "ir", "usb", "lsusb", "disks", "ls", "dir", "cd", "pwd", "cat",
             "nes", "gb", "sms", "gg", "sg", "zx", "a26", "c64", "amiga", "dos", "megadrive",
             "pce", "coleco", "msx", "msx2", "ws", "snes", "neogeo", "gba", "a78", "lynx", "vectrex", "fds", "ngp",
             "odyssey2", "intv", "psx", "cps", "atarist", "sys16", "atari8", "a5200",
             "mkdir", "rmdir", "rm", "touch", "cp", "mv", "sector", "tty", "cu", "at", "ifconfig", "dhcp", "arp",
             "watchdog", "clear", "history", "video", "reboot", "restart", "bootloader"]
    check(all(f"\r\n  {n} " in out for n in names), f"help lists all {len(names)} commands")
    check("pong v4" in box.command("ping"), "ping -> pong v4")
    check("pong v4" in box.command("/ping"), "a command may start with '/' (/ping)")
    check("hold 'c'" in box.command("help /bootloader"), "help /bootloader explains it")
    check(f"{APP_BANNER}\r\nVersion: v4" in box.command("version"), "version")
    out = box.command("info")
    check("board: TM1650 front panel on GPIO 31 / 9 (Opticum HD N2 type)" in out, "info names the board (TM1650 found)")
    check("display layer register 0xb8006300: 0x00000000 at the demo's start, 0x00000001 now" in out,
          "info: the layer register as the demo found it (0 in the emulator) and now")
    check("3811 (S3811" in out and "CPU 675 MHz" in out, "info: chip ID 0x3811 (S3811) and the 675 MHz strap")
    check("hello demo world" in box.command("echo hello demo world"), "echo with several words")
    out = box.command("md 0x80000200 16")
    check("80000200: 00 60 08 40" in out, "md shows the demo's first instruction (mfc0 $t0, Status)")
    out = box.command("mw 0x80700000 0x12345678")
    check("80700000 <- 12345678 (reads back 12345678)" in out, "mw writes RAM and reads it back")
    check("80700000: 12345678" in box.command("mr 0x80700000"), "mr reads the word")
    check("refused" in box.command("md 0x00000000 4") and "refused" in box.command("mw 0xafc00000 1"),
          "md / mw refuse unmapped addresses and the flash window")
    check("unknown command 'frobnicate'" in box.command("frobnicate"), "an unknown command is reported")
    out = box.keys(b"pinx\x08g\r", b"\r\n" + PROMPT)
    check("pong v4" in out, "Backspace edits the line (pinx<BS>g -> ping)")
    out = box.keys(b"\x1b[A\r", b"\r\n" + PROMPT)
    check("pong v4" in out, "Up arrow recalls the last command")
    out = box.keys(b"abc\x03", PROMPT)
    check("^C" in out, "Ctrl-C cancels the line")
    check("pong v4" in box.command("ping"), "the line is empty again after Ctrl-C")

    # ---- the TV picture: the console, then the test screen ---------------------------
    check_console(box)
    rgb = box.screen("v4_console_screen.png", "the console on the TV (the view after boot)")
    box.command("testscreen")
    rgb = box.screen("v4_demo_screen.png", "v4 demo screen after boot ('testscreen')")
    check(mmio(box.sim, 0x6300, 4) == 0x1 and mmio(box.sim, 0x63B8, 4) == 1,
          f"the layer is on as the originals switch it on (revision 0: 0xB8006300 = 1; is 0x{mmio(box.sim, 0x6300, 4):x})"
          f" and marked true-colour (0xB80063B8 = 1)")
    check_head_block(box.sim, "after boot")
    title = rgb[14:42, 220:1060]
    check((np.abs(title - 255).sum(axis=2) < 30).sum() > 2000, "the banner is drawn in white at the top")
    check(fb_pixel(box.sim, 5, 5) == rgb555(24, 48, 128) and near(rgb[5, 5], shown(24, 48, 128), tol=0),
          f"the header band has its colour (24, 48, 128): ARGB1555 0x{fb_pixel(box.sim, 5, 5):04x}")
    bars = [(255, 255, 255), (255, 255, 0), (0, 255, 255), (0, 255, 0), (255, 0, 255), (255, 0, 0), (0, 0, 255), (0, 0, 0)]
    check(all(near(rgb[586, 676 + 68 * i + 34], c) for i, c in enumerate(bars)), "the eight colour bars are in place")
    check(all(fb_pixel(box.sim, 676 + 68 * i + 34, 586) == rgb555(*c) for i, c in enumerate(bars)),
          f"the bars' ARGB1555 words ({', '.join(f'{fb_pixel(box.sim, 676 + 68 * i + 34, 586):04x}' for i in range(8))})")
    box.command("screen clear 102030")
    rgb = box.screen("v4_clear_screen.png", "screen clear 102030")
    bg = shown(0x10, 0x20, 0x30)
    check(bool((np.abs(rgb - bg).max(axis=2) <= 1).all()) and near(bg, (0x10, 0x20, 0x30), tol=6),
          f"screen clear fills all 1280x720 pixels (as {bg})")
    check(fb_pixel(box.sim, 0, 0) == fb_pixel(box.sim, 1279, 719) == rgb555(0x10, 0x20, 0x30),
          f"with the colour's ARGB1555 word 0x{rgb555(0x10, 0x20, 0x30):04x} (0x{fb_pixel(box.sim, 1279, 719):04x})")
    box.command("screen rect 100 100 200 50 ff0000")
    box.command("screen text 100 300 HELLO_TV")
    rgb = box.screen("v4_draw_screen.png", "screen rect + screen text")
    inside = [(100, 100), (299, 149), (150, 120)]
    outside = [(99, 120), (300, 120), (150, 99), (150, 150)]
    check(all(near(rgb[y, x], shown(255, 0, 0), tol=1) for x, y in inside) and
          all(near(rgb[y, x], bg, tol=1) for x, y in outside),
          "screen rect draws exactly its rectangle (x 100..299, y 100..149: corners in, the four neighbours out)")
    white = np.abs(rgb - 255).sum(axis=2) < 30
    check(white[300:321, 100:241].sum() > 200 and white[300:321, 226:241].any() and not white[300:330, 244:400].any()
          and not white[321:330, 100:400].any(),
          "screen text draws its words at scale 3 (HELLO TV: eight 18-pixel cells from x 100, 21 rows from y 300)")
    check(bool((np.abs(rgb[385:480, 670:1230] - bg).max(axis=2) <= 1).all()),
          "the demo's live boxes stay away while the picture is drawn by commands")
    out = box.command("screen")
    check("picture on: GMA layer 0 (0xb8006300 = 0x00000001)" in out and "1280x720 ARGB1555" in out,
          "screen reports the layer register and the pixel format")
    box.command("screen off")
    rgb = box.screen("v4_off_screen.png", "screen off")
    check(int(rgb.max()) == 0 and not mmio(box.sim, 0x6300, 4) & 1 and fb_pixel(box.sim, 0, 0) == rgb555(0x10, 0x20, 0x30),
          "screen off hides the OSD layer (enable bit 0 clear; the picture stays in RAM)")
    box.command("screen on")
    box.command("screen demo")
    rgb = box.screen("v4_demo_again_screen.png", "screen demo")
    check(all(near(rgb[586, 676 + 68 * i + 34], c) for i, c in enumerate(bars)), "screen demo redraws the demo picture")

    # ---- the front panel --------------------------------------------------
    check(box.panel.get_display_text().strip() in ("U4", "V4"), f"panel shows the version after boot "
                                                                 f"({box.panel.get_display_text()!r})")
    box.command("panel HELO")
    check(box.panel.get_display_text() == "HELO", f"panel HELO reaches the TM1650 ({box.panel.get_display_text()!r})")
    report_artifacts.panel(box.panel.digits, "front panel after 'panel HELO'", box.panel.get_display_text())
    box.panel.press_key(TM1650Decoder.key_code(1, 4, pressed=False), hold_reads=2)
    out = box.run(1.5)
    check("[panel] key 47 pressed: KI1/DIG4 UP (KI1/DIG4)" in out, "front-panel UP key (KI1/DIG4) is reported")
    check("[panel] key released" in out, "and its release")
    box.panel.press_key(TM1650Decoder.key_code(2, 4, pressed=False), hold_reads=2)
    out = box.run(1.5)
    check("[panel] key 4f pressed: KI2/DIG4 DOWN (KI2/DIG4)" in out, "front-panel DOWN key (KI2/DIG4) is reported")
    check(box.panel.get_display_text() == "P OF", f"the panel shows the key code ({box.panel.get_display_text()!r})")
    out = box.command("keys")
    check("key byte 0f: released (last) KI2/DIG4; 2 presses" in out, "keys reports the last key and the count")

    # ---- the remote control -----------------------------------------------
    for table_code, name in ((0x37AF, "POWER"), (0x374F, "OK"), (0x37FD, "MENU"), (0x377F, "1")):
        address, command, address_hi = nec_for(table_code)
        code = f"{nec_code(address, command, address_hi):08x}"
        box.sim.ir_send_nec(address, command, label=name, address_hi=address_hi)
        out = box.run(1.0)
        check(f"[ir] NEC {code}" in out and f"  {name}\r\n" in out, f"remote {name}: NEC {code} decoded and named")
        if name == "POWER":
            check(code == "023750af", "POWER is the bootloader's own wake code 0x023750AF")
    rgb = box.screen("v4_remote_screen.png", "after the remote's POWER, OK, MENU and 1")
    value = np.abs(rgb[164:188] - shown(255, 230, 120)).sum(axis=2) < 30
    check(value[:, 676:694].sum() > 20 and not value[:, 700:1220].any(),
          "the remote box shows the last button's name, '1' (one glyph at scale 3; the boot text is gone)")
    check(box.panel.get_display_text().strip() == "1", f"the panel shows the button ({box.panel.get_display_text()!r})")
    box.sim.ir_send_nec(0x12, 0x34, label="other remote")
    out = box.run(1.0)
    other = f"{nec_code(0x12, 0x34):08x}"
    check(f"[ir] NEC {other}  address 12 ed  command 34 cb  (unknown button)" in out,
          f"another remote's code ({other}): decoded, no button name")
    out = box.command("ir")
    check("5 frames" in out, "ir counts the frames")
    for name in ("OK", "EXIT", "9"):
        box.sim.press_key(name)                # by name, from the key table the demo carries in RAM
        out = box.run(1.0)
        last = out.split("[ir] NEC")[-1] if "[ir] NEC" in out else ""
        check(name in last, f"the emulator's virtual remote finds the demo's key table: {name}")

    # ---- USB ----------------------------------------------------------------
    out = box.command("usb")
    check("port status 0x00: no device" in out, "usb: no device on the port")
    out = box.command("lsusb")
    check("Bus 001: ALi USB 2.0 host controller at 0xb8032000, port: no device" in out and "Device 001" not in out,
          "lsusb: the controller, no device")
    import fat_image
    box.usb.attach("high", VirtualStick(fat_image.build({"README.TXT": b"a stick\n"}, fat=16, size_mb=16,
                                                        label="STICK")))
    out = box.run(3.0)
    check("[usb] device connected" in out, "plugging a device in is noticed")
    expected = ["USB device 1209:0001, USB 2.00, endpoint 0: 64 bytes", "manufacturer: AliSimulator",
                "product: Virtual USB stick", "serial: 000000000001",
                "interface 0: class 08 (mass storage), subclass 06, protocol 50, 2 endpoints",
                "endpoint 81 bulk, 512 bytes", "endpoint 02 bulk, 512 bytes", "configuration 1 set",
                "disk 1: AliSim Virtual stick 1.00, 16 MB; partition 1: FAT16 'STICK', 15 MB"]
    missing = [e for e in expected if e not in out]
    check(not missing, f"the demo enumerates it over endpoint 0: descriptors, strings, configuration{missing or ''}")
    setups = [p.hex() for _t, p in box.usb.setups]
    check(setups[:3] == ["8006000100000800", "0005010000000000", "8006000100001200"] and
          "0009010000000000" in setups,
          "SETUP packets: GET_DESCRIPTOR(device, 8), SET_ADDRESS(1), GET_DESCRIPTOR(device), ..., SET_CONFIGURATION(1)")
    rgb = box.screen("v4_usb_screen.png", "a USB stick plugged in: enumerated, its name on the screen")
    check((np.abs(rgb[596:612, 200:600] - shown(255, 230, 120)).sum(axis=2) < 30).sum() > 100,
          "the USB box shows the device")
    out = box.command("lsusb")
    check("Bus 001 Device 001: ID 1209:0001 AliSimulator Virtual USB stick, high speed (480 Mbit/s)" in out,
          "lsusb: one line for the stick (ID, manufacturer, product, speed)")
    out = box.command("usb")
    check("speed: high speed (480 Mbit/s)" in out and "product: Virtual USB stick" in out,
          "usb reports the high-speed device and enumerates it again")
    out = box.command("usb reset")
    check("bus reset: done after" in out, "usb reset drives a bus reset the controller completes")
    check_usb_setup(box, rev=0)
    box.usb.detach()
    out = box.run(0.6)
    check("[usb] device removed" in out, "unplugging is noticed")

    # ---- a USB keyboard ----------------------------------------------------------
    # (as the real one the demo was tried with on a box, 1a2c:2d23: low speed, two interfaces, and GET_REPORT
    #  always answering "no keys" -- its keys come from its interrupt endpoint only)
    kbd = VirtualKeyboard(get_report="empty", composite=True)
    box.usb.attach("low", kbd)
    check_keyboard_basics(box, kbd, "keyboard", speed="low")
    out = type_on(box, kbd, "echo Hello, World! ~{BS}?\r")
    check("\r\nHello, World! ?\r\n" in out, "Shift, punctuation and Backspace: 'echo Hello, World! ~<BS>?' prints "
                                           "'Hello, World! ?'")
    out = type_on(box, kbd, "{UP}\r")
    check("\r\nHello, World! ?\r\n" in out, "Up recalls the last command")
    out = type_on(box, kbd, "{CAPS}abc{CAPS}d{ESC}")
    check("ABCd^C" in out, "Caps Lock on and off; Escape cancels the line (as Ctrl-C)")
    out = box.run(kbd.type("x", hold=3.0) + 0.3) + type_on(box, kbd, "{ESC}")
    held = max((len(m) for m in re.findall(r"x+", out)), default=0)
    check(held >= 4, f"a held key repeats (x held 3 s: {held} x)")
    out = type_on(box, kbd, "ccc{ESC}")
    check("ccc^C" in out and "Bootloader capture requested" not in out,
          "'ccc' typed on the keyboard is only text (the restart for the UART updater listens to the UART)")
    box.command("testscreen")
    out = type_on(box, kbd, "echo back\r")
    check("echo back\r\nback\r\n" in out and mmio(box.sim, 0x6304, 4) == CON_HEAD_PHYS,
          "on the test screen a key on the USB keyboard brings the console back -- and types: 'echo back' runs")
    type_on(box, kbd, "echo on the tv")
    lines = console_text(box)
    box.screen("v4_usb_keyboard_screen.png", "a USB keyboard: the line being typed on the TV's console")
    check(lines[-1] == "m3801> echo on the tv", f"the TV's console shows the line being typed ({lines[-1]!r})")
    rgb = fb_rgb(box.sim)
    label = np.abs(rgb[436:452] - shown(150, 190, 255)).sum(axis=2) < 30
    white = np.abs(rgb[436:452] - 255).sum(axis=2) < 30
    check(label[:, 676:690].sum() > 10 and white[:, 696:880].sum() > 150 and not white[:, 890:1220].any(),
          "and the test screen's command line box has it too ('> echo on the tv_', 15 cells from x 696)")
    label = np.abs(rgb[590:606] - shown(150, 190, 255)).sum(axis=2) < 30
    check(label[:, 56:152].sum() > 100 and label[:, 130:152].sum() > 10 and
          (np.abs(rgb[590:606, 160:600] - shown(255, 230, 120)).sum(axis=2) < 30).sum() > 300,
          "and the USB box names the keyboard ('Keyboard 1209:0002 Virtual USB keyboard')")
    type_on(box, kbd, "{ESC}")
    out = box.command("usb kbd")
    check("read from its interrupt endpoint through the controller's endpoint D (it polls by itself, every 8000 us); "
          "0 reports dropped for their data toggle" in out
          and " 0 errors" in out and "interface 0, interrupt endpoint 81 (8 bytes, every 10 ms)" in out,
          "usb kbd: the keyboard read from its interrupt endpoint through endpoint D, no errors")
    tokens, polls = box.usb.in_tokens, box.usb.epd_polls
    box.run(1.0)
    polls = box.usb.epd_polls - polls
    check(115 <= polls <= 135 and box.usb.in_tokens == tokens,
          f"while no key changes endpoint D asks again every 8 ms ({polls} IN tokens in 1 s: +0xA3 = 7, one every "
          "2^6 microframes), endpoint B not at all")
    out = box.command("usb ctl 0x80 6 0x0100 0 18")
    check("18 bytes:" in out and "12 01 10 01 00 00 00 08 09 12 02 00" in out,
          "a control request goes through while endpoint D polls the keyboard (usb ctl: GET_DESCRIPTOR, the device's "
          "18 bytes)")
    smark = len(box.usb.setups)
    out = box.command("usb kbd report")
    check("read with GET_REPORT over endpoint 0 every 16 ms" in out, "usb kbd report: GET_REPORT over endpoint 0 instead")
    out = type_on(box, kbd, "ping\r")
    polls = [p.hex() for _t, p in box.usb.setups[smark:]].count(GET_REPORT)
    check("pong" not in out and polls > 20,
          f"that way this keyboard types nothing: its GET_REPORT always answers eight zero bytes ({polls} asked), as "
          "the real 1a2c:2d23's -- why the interrupt endpoint is the way used first")
    out = box.command("usb kbd interrupt") + type_on(box, kbd, "ping\r")
    check("read from its interrupt endpoint" in out and "ping\r\npong v4" in out,
          "usb kbd interrupt: back on the interrupt endpoint, ping -> pong v4")
    out = box.command("lsusb")
    check("Bus 001 Device 001: ID 1209:0002 AliSimulator Virtual USB keyboard, low speed (1.5 Mbit/s)" in out,
          "lsusb names the keyboard")
    out = box.command("usb") + type_on(box, kbd, "ping\r")
    check("reading its interrupt endpoint 81" in out and "ping\r\npong v4" in out and box.usb.toggle_drops == 0,
          "usb enumerates it again and it types on: the data toggles start together again (no report dropped)")
    box.usb.detach()
    out = box.run(0.6)
    check("[usb] device removed" in out and "keyboard:" not in out and "no USB keyboard" in box.command("usb kbd"),
          "unplugged while endpoint D polls it: the keyboard is gone, without an error line")
    # a full-speed keyboard whose GET_REPORT carries its keys: both ways of reading it type
    kbd = VirtualKeyboard()
    box.usb.attach("full", kbd)
    check_keyboard_basics(box, kbd, "a full-speed keyboard")
    smark = len(box.usb.setups)
    out = box.command("usb kbd report") + type_on(box, kbd, "ping\r")
    check("ping\r\npong v4" in out and GET_REPORT in [p.hex() for _t, p in box.usb.setups[smark:]],
          "usb kbd report with a keyboard whose GET_REPORT carries its keys: ping -> pong v4 over endpoint 0")
    box.usb.detach()
    box.run(0.6)
    kbd = VirtualKeyboard(get_report=False)
    box.usb.attach("full", kbd)
    box.run(2.5)
    out = box.command("usb kbd report") + box.run(1.5)
    check("keyboard: GET_REPORT failed (IN data stage: stall (token error 0x80)); reading its interrupt endpoint 81 "
          "instead" in out, "a keyboard that stalls GET_REPORT: after three failures the demo is back on its interrupt "
                            "endpoint")
    out = type_on(box, kbd, "ping\r")
    check("ping\r\npong v4" in out, "and typing on it works")
    box.usb.detach()
    box.run(0.6)
    kbd = VirtualKeyboard(interrupt=False)
    box.usb.attach("full", kbd)
    out = box.run(5.0)
    check("keyboard: its interrupt endpoint 81 stalls (interrupt IN stage: stall (token error 0x80)); reading it with "
          "GET_REPORT instead" in out, "a keyboard whose interrupt endpoint is halted: after three stalls the demo reads "
                                       "it with GET_REPORT")
    out = type_on(box, kbd, "ping\r")
    check("ping\r\npong v4" in out, "and typing on it works")
    box.usb.detach()
    box.run(0.6)
    kbd = VirtualKeyboard(get_report=False, interrupt=False)
    box.usb.attach("full", kbd)
    out = box.run(6.0)
    check("keyboard: neither its interrupt endpoint 81 nor GET_REPORT works" in out and "given up" in out
          and "no USB keyboard" in box.command("usb kbd"),
          "a keyboard that stalls both ways is given up, once (no endless switching)")
    box.usb.detach()
    box.run(0.6)

    # ---- a USB hub ---------------------------------------------------------------
    check_hub(box)

    # ---- USB disks ---------------------------------------------------------------
    check_disks(box)

    # ---- a USB mouse -------------------------------------------------------------
    check_mouse(box)

    # ---- more than seven USB devices ----------------------------------------------
    check_many_devices(box)

    # ---- a junk packet from the keyboard, a hub that stops answering ----------------
    check_usb_faults(box)

    # ---- the Game Boy player --------------------------------------------------------
    check_gameboy(box)

    # ---- the Master System, Game Gear and ZX Spectrum players -----------------------
    check_sega_and_spectrum(box)
    check_atari(box)
    check_c64(box)
    check_amiga(box)
    check_dos(box)
    check_md(box)
    check_extra_consoles(box)
    check_play(box)
    check_view_jpeg(box)

    # ---- a shell on the USB disks: cd, mkdir, rm, ... ------------------------------
    check_shell(box)

    # ---- the file explorer on the TV ------------------------------------------------
    check_explorer(box)

    # ---- USB serial ports: an LTE module's AT ports (tty, at, cu) --------------------
    check_modem(box)
    check_ssdp(box)
    check_dma_receiver(box)

    # ---- the experimental display set-up ---------------------------------------
    box.command("testscreen")
    out = box.command("video init", timeout=60)
    check("of the Opticum HD N2's display set-up (dump_maciej.bin, chip revision 0" in out
          and "done: output timing 0x02ee0f78" in out
          and "HDMI transmitter running (0xb802a007 = 7c)" in out,
          "video init replays this board's display set-up (Opticum: TM1650 found) up to the HDMI start")
    check_video_state(box.sim, "opticum", "video init")
    rgb = box.screen("v4_video_init_screen.png", "after video init")
    check(all(near(rgb[586, 676 + 68 * i + 34], c) for i, c in enumerate(bars)), "the demo picture is back after video init")

    # ---- restart, and the updater's capture from the running demo ------------------
    check(not box.watchdog.overflows,
          "the watchdog never overflowed: fed through every command above (video init, USB, drawing, typing)"
          f"{': ' + repr(box.watchdog.overflows[:3]) if box.watchdog.overflows else ''}")
    before = box.flash()
    dog = []                      # the watchdog's stores (0xB8018500: count, +4 control)
    hook = box.sim.add_mmio_hook("write", lambda uc, access, address, size, value, user_data=None:
                                 dog.append((address & 0xFFFFFF, size, value)), 0x18500, 0x18507)
    out = box.keys(b"reboot\r", PROMPT, timeout=90)
    box.sim.remove_mmio_hook(hook)
    check("Restarting via original bootloader" in out and "bl_verify_sw" in out and "success!" in out and
          "Version: v4" in out, "reboot restarts through the original bootloader into the demo")
    # platform_restart: arm, (no reset here) stop; then the restarted demo's dog_start stops it again first
    restart = [(0x18500, 4, 0xFFFFF000), (0x18504, 1, 0x67), (0x18504, 1, 0), (0x18504, 1, 0)]
    first = dog.index(restart[0]) if restart[0] in dog else len(dog)
    check(dog[first:first + 4] == restart and all(w[:2] == (0x18500, 4) for w in dog[:first]),
          "the restart arms the watchdog as the M3801 loaders' reboot does (0xB8018500 = 0xfffff000, then 0x67; "
          "before that only the demo's feeding), and only without a reset (the emulator has no chip reset) "
          f"stops it and jumps{'' if dog[first:first + 4] == restart else ': ' + repr(dog[first:first + 5])}")
    check(box.watchdog.overflows and box.watchdog.overflows[0][1:] == (0xFFFFF000, 0x67),
          "the watchdog model saw that arming overflow at once (on the chip: the reset)")
    out = box.keys(b"/restart\r", PROMPT, timeout=90)
    check("Restarting via original bootloader" in out and "Version: v4" in out, "/restart does the same")

    # 'bootloader', then a person holding the c key (auto-repeat: after 0.5 s, 30 per second)
    box.t.pending.clear()
    box.t.write(b"bootloader\r")
    box.t.wait_for(b"Restarting into the original bootloader", 10)
    mark = len(box.t.received)
    start = box.sim._vtime()
    while box.sim._vtime() < start + 0.5:
        box.t.read(4096, start + 0.5 - box.sim._vtime())
    # (38 s: the bootloader checks the main code before it looks for 'c' -- 4.7 s of emulated time for the 588 KB
    # demo with the Z80 / 2600 players, 8.3 s for the 1.1 MB one with TLS, ~26.5 s for the 4.6 MB v4; maciej_uart.py
    # on the real box keeps sending for up to 90 s)
    while box.sim._vtime() < start + 38:
        box.t.write(b"c")
        nxt = box.sim._vtime() + 1 / 30
        while box.sim._vtime() < nxt:
            box.t.read(4096, nxt - box.sim._vtime())
    box.t.write(b"\r")
    for _ in range(20):
        if not box.t.read(4096, 0.2):
            break
    client = BootloaderClient(box.t)
    client.handshake()
    check(b"bl_verify_sw" in bytes(box.t.received[mark:]),
          "bootloader + holding the c key: the original bootloader's shell takes the handshake")
    client.reboot()
    check("Version: v4" in box.boot().decode("latin-1"), "and its reboot command starts the demo again")
    box.t.pending.clear()
    mark = len(box.t.received)
    deadline = box.sim._vtime() + 38                   # (the bootloader's check first: ~26.5 s for 4.6 MB v4)
    while box.sim._vtime() < deadline:                 # maciej_uart.capture_boot's pacing, in emulated time
        box.t.write(b"c")
        nxt = min(deadline, box.sim._vtime() + 0.05)
        while box.sim._vtime() < nxt:
            box.t.read(4096, nxt - box.sim._vtime())
    box.t.write(b"\r")
    for _ in range(20):
        if not box.t.read(4096, 0.2):
            break
    client = BootloaderClient(box.t)
    client.handshake()
    captured = bytes(box.t.received[mark:])
    check(b"Bootloader capture requested ('ccc')" in captured and b"bl_verify_sw" in captured,
          "the updater's paced 'c' restart the demo and the original bootloader takes the handshake")
    client.reboot()
    check("Version: v4" in box.boot().decode("latin-1"), "the bootloader's reboot command starts the demo again")
    check(box.flash() == before == flash, "the flash is unchanged (nothing in the demo writes it)")

    elapsed = round(time.monotonic() - started, 1)
    out = ROOT / "build/maciej_app/selftest" / args.engine / "demo_v4"
    out.mkdir(parents=True, exist_ok=True)
    log = out / "uart_demo_v4.log"
    log.write_bytes(bytes(box.t.received))
    print(f"UART log: {log}; {elapsed} s", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("cpp", "unicorn"), default=os.environ.get("ALISIM_ENGINE", "cpp"))
    parser.add_argument("--require-toolchain", action="store_true",
                        default=os.environ.get("GITHUB_ACTIONS", "").lower() == "true")
    args = parser.parse_args()
    print("=== The Maciej demo v4 on the original bootloader ===", flush=True)
    run(args)
    if failures:
        print(f"\n[FAIL] {len(failures)} check(s) failed")
        sys.exit(1)
    print("\n[PASS] all demo v4 checks")


if __name__ == "__main__":
    main()
