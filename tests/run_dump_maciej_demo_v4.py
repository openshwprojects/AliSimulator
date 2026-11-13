#!/usr/bin/env python3
"""The Maciej demo v4 on the original Opticum HD N2 bootloader, in the emulator.

Boots the shipped v4 flash image (firmware/maciej_app/bin: dump_maciej.bin
with the demo as its main code, started by the original bootloader) and
drives it only through its inputs -- UART bytes, IR frames into the remote
control receiver, front-panel key presses on the TM1650, a USB stick, a USB
keyboard, a USB mouse and a USB hub with devices behind it plugged into the
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
from usb_host import VirtualHub, VirtualKeyboard, VirtualMouse, VirtualStick   # noqa: E402
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


USB_DMA_PHYS = 0x00F00400            # where the demo has the controller put a received packet (hw.h)
SPEED_TEXT = {"low": "low speed (1.5 Mbit/s)", "full": "full speed (12 Mbit/s)", "high": "high speed (480 Mbit/s)"}
GET_REPORT = "a101000100000800"      # the SETUP of GET_REPORT (input report, 8 bytes)


def check_keyboard_basics(box, kbd, label, speed="full"):
    """A just plugged-in VirtualKeyboard: enumerated, recognised, typing into the command line --
    its reports read from its interrupt endpoint (an IN on the controller's endpoint B, received
    into RAM by DMA)."""
    wmark, smark, pmark = len(box.usb.writes), len(box.usb.setups), len(box.usb.interrupt_packets)
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
    start = next((i for i, (o, _s, v) in enumerate(writes) if o == 0x32 and v & 0x0C == 0x0C), None)
    before = writes[:start] if start is not None else []
    strobes = [v for o, _s, v in before if o == 0x60]
    want = [(0x84, 1, 0x02), (0x16, 1, 0x84), (0x40, 4, USB_DMA_PHYS), (0x38, 1, 8), (0x68, 1, 0x80)]
    check(start is not None and all(w in before for w in want) and strobes[-2:] == [0x20, 0x10]
          and any(o == 0x30 and v & 0xF0 == 0x80 for o, _s, v in before)        # (bits 0..3: endpoint A's)
          and any(o == 0x17 and v & 0x01 for o, _s, v in before),
          f"{label}: an IN started on the controller's endpoint B as hcd_s3602_bulkin_start does: the keyboard's "
          "address (+0x84 = 1 << 1) and endpoint 1 (+0x16 = 0x84), 8-byte packets (+0x30), the packet by DMA into "
          f"the RAM at 0x{USB_DMA_PHYS:08x} (+0x40, +0x38 = 8, +0x68 = 0x80, the +0x60 strobes), then +0x32 bits 2 "
          "and 3 -- after the data toggle's reset (+0x17 bit 0 pulsed)"
          + ("" if start is not None else f": {[w for w in want if w not in before]}"))
    check(not any(o in (0x2B, 0x31, 0x86, 0xA2) for o, _s, _v in writes),
          f"{label}: endpoint C, the SDK's interrupt endpoint, is left alone (on a real S3811 it sends a low-speed "
          "device nothing)")
    out = type_on(box, kbd, "ping\r")
    setups = [p.hex() for _t, p in box.usb.setups[smark:]]
    reports = len(box.usb.interrupt_packets) - pmark
    check("ping\r\npong v4" in out and reports == 10 and GET_REPORT not in setups and box.usb.toggle_drops == 0,
          f"{label}: ping typed on the keyboard -> pong v4, from its interrupt endpoint ({reports} reports: five "
          "keys down and up; no GET_REPORT, none dropped for its data toggle)")


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
    check("ping\r\npong v4" in out and (0x84, 0x09) in writes and (0x85, 0x61) in writes and box.usb.toggle_drops == drops,
          "ping typed on the keyboard behind the hub -> pong v4: the IN on endpoint B goes through the translator "
          "too (+0x84 = 4 << 1 | 1, +0x85 = 0x61)")
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
    check("ping\r\npong v4" in out and (0x84, 0x0B) in writes and (0x85, 0x11) in writes,
          "and types: a full-speed device through the translator (+0x85 = 0x11: port 2, hub 1, not low speed)")
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
          and (0x85, 0x52) in writes,
          "with the other keyboard unplugged it types from behind both hubs (+0x85 = 0x52: low speed, port 2, hub 2)")
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
    typing between them (endpoint B shared: both data toggles kept in step), a card reader without
    a card, a stick pulled out."""
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
          and "device 3: no FAT volume there ('disks' lists it)" in out and "a directory: 'ls' lists it" in out,
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
          in out and "no FAT volume on a USB disk ('disks')" in out,
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
    keyboard on the first hub's port 4, a stick on the second hub -- the mouse's interrupt endpoint
    polled by the controller's endpoint D (the SDK's hcd_s3602_IntInD_start), so the keyboard keeps
    endpoint B: the pointer on the TV moves, the buttons click and paint, the wheel turns, while the
    keyboard types and the stick's transfers come and go -- none of them disturbs another."""
    import fat_image
    hub, hub2 = VirtualHub(4), VirtualHub(4)
    mouse = VirtualMouse()
    kbd = VirtualKeyboard(get_report="empty", composite=True)
    stick = VirtualStick(fat_image.build({"MOUSE.TXT": b"squeak\n"}, fat=16, size_mb=16, label="MICE"))
    hub.plug(1, hub2, "high")
    hub2.plug(2, stick, "high")
    hub2.plug(4, mouse, "low")
    hub.plug(4, kbd, "low")
    wmark, smark, drops = len(box.usb.writes), len(box.usb.setups), box.usb.toggle_drops
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
    setups = [p.hex() for _t, p in box.usb.setups[smark:]]
    want = [(0x89, 0x62), (0x88, 0x09), (0x22, 0xC4), (0x2E, 0x77), (0xA3, 7)]
    check(all(w in writes for w in want) and any(o == 0x2B and v & 0x08 for o, v in writes)
          and any(o == 0x23 and v & 0x01 for o, v in writes) and "0201000081000000" in setups
          and box.usb.epd_polls > 0,
          "its endpoint polled by the controller's endpoint D as hcd_s3602_IntInD_start sets it up: the mouse "
          "through hub 2's translator (+0x89 = 0x62: low speed, port 4, hub 2; +0x88 = 4 << 1 | 1), interrupt "
          "endpoint 1 (+0x22 = 0xC4), flags 3 enabled (+0x2E = 0x77), every 8 ms (+0xA3 = 7 for its 10 ms), +0x2B "
          "bit 3 -- both data toggles DATA0 first (CLEAR_FEATURE(ENDPOINT_HALT), +0x23 bit 0 pulsed)"
          + ("" if all(w in writes for w in want) else f": {[w for w in want if w not in writes]}"))
    check(pointer_at(box) == (640, 360) and fb_pixel(box.sim, 640, 360) == rgb555(0, 0, 0)
          and fb_pixel(box.sim, 641, 362) == rgb555(255, 255, 255),
          "the pointer (a black and white arrow) is drawn in the middle of the TV picture")
    polls = box.usb.epd_polls
    box.run(mouse.move(60, 30, over=0.6) + 0.5)
    writes = [(o, v) for _t, o, _s, v in box.usb.writes[wmark:]]
    check(pointer_at(box) == (700, 390) and fb_pixel(box.sim, 700, 390) == rgb555(0, 0, 0)
          and fb_pixel(box.sim, 641, 362) != rgb555(255, 255, 255) and (0x84, 0x09) not in writes
          and box.usb.toggle_drops == drops and box.usb.epd_polls - polls >= 60,
          "the mouse moved by (60, 30): the pointer follows to 700,390 (the picture under its old place put back), "
          f"every report through endpoint D ({box.usb.epd_polls - polls} polls in 1.1 s; endpoint B never aimed at "
          "the mouse, nothing dropped)")
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
          and "read through endpoint D, polled every 8.0 ms;" in status and " 0 dropped for their data toggle" in status
          and "pointer at 740,390, buttons 00, wheel 2; paint colour red" in status,
          "usb mouse: the device, read through endpoint D every 8 ms, the pointer, the buttons, the wheel, the colour")
    # the keyboard types on endpoint B while the mouse moves on endpoint D
    mouse.move(-100, -50, over=2.0)
    out = type_on(box, kbd, "ping\r", extra=1.5)
    status = box.command("usb kbd")
    check("ping\r\npong v4" in out and pointer_at(box) == (640, 340) and box.usb.toggle_drops == drops
          and "(an IN pending on the controller's endpoint B)" in status,
          "typing while the mouse moves: the keyboard keeps endpoint B to itself (no turns), every key and every "
          "movement arrives (pointer at 640,340), nothing dropped")
    # a disk's transfers on endpoints A and B meanwhile: endpoint D carries on
    mouse.move(30, 0, over=0.8)
    out = box.command("ls 3:", timeout=60) + box.command("cat 3:/mouse.txt", timeout=60)
    box.run(1.5)
    x, y = pointer_at(box) or (0, 0)
    stalled = getattr(stick, "stalled_commands", 0)
    check("MOUSE.TXT" in out and "squeak\r\n" in out and 670 <= x <= 700 and y == 340 and not stalled
          and box.usb.toggle_drops == drops,
          f"ls and cat on the stick while the mouse moves: both work, the movement arrives (pointer at {x},{y}: "
          "reports wait in endpoint D's FIFO while a command runs), nothing dropped")
    # unplugged: the pointer goes, endpoint D stops; plugged in again: it comes back in the middle
    wmark = len(box.usb.writes)
    hub2.unplug(4)
    out = box.run(3.0)
    after = [(o, v) for _t, o, _s, v in box.usb.writes[wmark:]]
    last_a3 = [v for o, v in after if o == 0xA3]
    last_2b = [v for o, v in after if o == 0x2B]
    check("[usb] hub 2 port 4: device removed (1209:0004 Virtual USB mouse)" in out and "mouse:" not in out
          and "no USB mouse" in box.command("usb mouse") and fb_pixel(box.sim, x + 1, y + 2) != rgb555(255, 255, 255)
          and last_a3[-1:] == [0] and last_2b and not last_2b[-1] & 0x08,
          "the mouse unplugged: removed without an error line, the pointer gone, endpoint D stopped (+0xA3 = 0, "
          "+0x2B bit 3 cleared)")
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
    names = ["help", "version", "ping", "info", "uptime", "echo", "md", "mr", "mw", "screen", "panel", "keys",
             "ir", "usb", "lsusb", "disks", "ls", "cat", "sector", "watchdog", "clear", "video", "reboot", "restart",
             "bootloader"]
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

    # ---- the TV picture ---------------------------------------------------
    rgb = box.screen("v4_demo_screen.png", "v4 demo screen after boot")
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
    type_on(box, kbd, "echo on the tv")
    rgb = box.screen("v4_usb_keyboard_screen.png", "a USB keyboard: the line being typed shown on the TV")
    label = np.abs(rgb[436:452] - shown(150, 190, 255)).sum(axis=2) < 30
    white = np.abs(rgb[436:452] - 255).sum(axis=2) < 30
    check(label[:, 676:690].sum() > 10 and white[:, 696:880].sum() > 150 and not white[:, 890:1220].any(),
          "the TV shows the line being typed in the command line box ('> echo on the tv_', 15 cells from x 696)")
    label = np.abs(rgb[590:606] - shown(150, 190, 255)).sum(axis=2) < 30
    check(label[:, 56:152].sum() > 100 and label[:, 130:152].sum() > 10 and
          (np.abs(rgb[590:606, 160:600] - shown(255, 230, 120)).sum(axis=2) < 30).sum() > 300,
          "and the USB box names the keyboard ('Keyboard 1209:0002 Virtual USB keyboard')")
    type_on(box, kbd, "{ESC}")
    out = box.command("usb kbd")
    check("read from its interrupt endpoint (an IN pending on the controller's endpoint B)" in out
          and " 0 errors" in out and "interface 0, interrupt endpoint 81 (8 bytes, every 10 ms)" in out,
          "usb kbd: the keyboard read from its interrupt endpoint, no errors")
    tokens = box.usb.in_tokens
    box.run(1.0)
    polls = box.usb.in_tokens - tokens
    check(900 <= polls <= 1100, f"while no key changes the controller asks again every millisecond ({polls} IN tokens "
                                "in 1 s: +0xA8 = 1, one per frame)")
    out = box.command("usb ctl 0x80 6 0x0100 0 18")
    check("18 bytes:" in out and "12 01 10 01 00 00 00 08 09 12 02 00" in out,
          "a control request goes through while the IN is pending (usb ctl: GET_DESCRIPTOR, the device's 18 bytes)")
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
          "unplugged with the IN pending: the keyboard is gone, without an error line")
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

    # ---- the experimental display set-up ---------------------------------------
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
    while box.sim._vtime() < start + 4:
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
    deadline = box.sim._vtime() + 5
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
