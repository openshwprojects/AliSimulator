#!/usr/bin/env python3
"""Generate video_init.h: the register writes with which the original
applications bring up their picture, recorded in the emulator, for the demo's
'video init' command -- one table per board and chip revision, each from the
board's own firmware:

    opticum   dumps/dump_maciej.bin   maciej_333's Opticum HD N2 (TM1650 panel)
    comsat    dumps/dump.bin          the Comsat TE 1050 HD (two buttons, no panel chip)

The firmwares branch on the S3811's revision (sys_ic_get_rev_id: the low byte
of the chip ID word 0xB8000000, 0 -> IC_REV_0, else IC_REV_1): the TV
encoder's set-up differs (0xB8008004 / 8084 / 8086 / 8087 / 809B) and on
revision 1 the Comsat's application switches its output on (display engine
0xB8006000 / 6080 / 6084, the clock bit 16 of 0xB8000078) 0.8 s after the HDMI
transmitter starts instead of 0.08 s.  The emulator answers revision 0 unless
told otherwise; a real box (the Comsat TE 1050 HD tested) reads revision 1.
So each board is recorded twice, with the chip ID word set to 0x38110000 and
0x38110001, and the demo replays the table of the revision its chip reports.

The emulator's device registers start at 0, the chip's do not: the HDMI
transmitter's PHY bytes (+0x0A..+0x0F) come up as 02 92 24 49 82 21, the
display engine with a PAL timing set, the TV encoder with dozens of values,
0xB800006C / 0xB80000B0 as 0x80000000 / 0x00030100.  The drivers set many of
these bits read-modify-write, so a recording made from zeros writes values the
chip never gets from its own firmware -- and on the real box the TV saw no
signal.  The recording therefore first presets the values read on a real S3811
revision 1 after a reset (s3811_rev1_reset_values.json; the same set for the
revision-0 tables, for want of such a chip).

The bootloader never touches the display: on the box the TV stays dark until
the application programs the display engine (0xB8006000), the TV encoder
(0xB8008000), the VCAP block (0xB800F000), the HDMI transmitter (0xB802A000),
its PHY setting at 0xB8000400 (0x300, written as the HDMI driver starts; it
reads 0 on a box until then) and a few clock / reset registers.  The HDMI
driver (the SDK's libHDMI: hdmi_ctrl_task) leaves the transmitter in soft
reset (bit 0 of +0x07) until it sees a TV: hot plug and receiver sense, bits
0 and 1 of +0x08.  The recording therefore makes those two bits read as set
-- a TV on the HDMI port -- so that it includes the transmitter's start (its
PHY and packet set-up, reset released, three AV-unmute pulses on +0x09).  The
TV's EDID makes no difference to what the drivers write (checked with a TV
EDID on the DDC lines: the same stores, three of them in another order).

This records every store to those ranges from the application's start until
1.5 s after the transmitter leaves its reset (past the output switch-on of
both revisions), in order, with its width -- but not the GMA layer registers
(0xB8006300.., the demo sets its own), the SPI flash controller, the
interrupt controller, GPIO (the DDC and panel lines are bit-banged there) or a
reset of the USB host (bit 28 of 0xB8000080, the demo's own).  Where the
original paused 2 ms or more between two of these stores the table holds a
wait (size 0, value = milliseconds, at most 100), so the replay leaves the
clocks and the PHY the time they had.  The display buffers the original
pointed its registers at (all zero when the picture comes up) are left where
they were; the demo keeps its own picture clear of them (hw.h FB_PHYS).
Replaying stores without the drivers' status polls is a guess at what the
hardware needs.

    python firmware/maciej_app/demo/gen_video_init.py
"""
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from simulator import AliMipsSimulator, flash_size_for   # noqa: E402
from chips.base import ReadyBits                          # noqa: E402

BOARDS = [
    ("opticum", "dump_maciej.bin", "Opticum HD N2"),
    ("comsat", "dump.bin", "Comsat TE 1050 HD"),
]
REVISIONS = (0, 1)
RANGES = [(0x0000, 0x00FF), (0x0400, 0x0403), (0x6000, 0x6FFF), (0x8000, 0x80FF), (0xF000, 0xF0FF),
          (0x2A000, 0x2A0FF)]
SKIP = set(range(0x6300, 0x6400)) | {0x0098, 0x0099, 0x009A, 0x009B} | set(range(0x0028, 0x0040)) | \
    set(range(0x0050, 0x005C))
HDMI_CTRL, HDMI_MUTE, HDMI_STATUS = 0x2A007, 0x2A009, 0x2A008
GMA0_ENABLE = 0x6300
USB_RESET = (0x0080, 0x10000000)
AFTER_START = 1.5                              # seconds recorded after the transmitter's start
WAIT_MIN_MS, WAIT_MAX_MS = 2, 100
RESET_VALUES = {int(a, 16): int(v, 16) for a, v in json.loads(
    Path(__file__).with_name("s3811_rev1_reset_values.json").read_text(encoding="utf-8"))["words"].items()}


def record(image_name, revision):
    """[(vtime, offset, size, value)] of the application's display set-up, up to
    AFTER_START s after the HDMI transmitter's start, on a chip of `revision`;
    and the values it wrote to the GMA layer's enable register."""
    image = ROOT / "dumps" / image_name
    sim = AliMipsSimulator(rom_size=flash_size_for(str(image)), log_handler=lambda m: None, engine="cpp")
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    uart = bytearray()
    app_started = [False]

    def on_uart(ch):
        # (synchronous: the stores right after the application's first line count)
        uart.extend(ch.encode("latin-1"))
        if not app_started[0] and uart.endswith(b"MC: APP"):
            app_started[0] = True

    sim.setUartHandler(on_uart)
    sim.loadFile(str(image))
    sim.poke(0xB8000000, ((0x3811 << 16) | revision).to_bytes(4, "little"))   # the chip ID word
    for address, value in RESET_VALUES.items():   # the chip's own reset values (see the module doc)
        sim.poke(address, value.to_bytes(4, "little"))
    ReadyBits(sim, {HDMI_STATUS: 0x03})          # a TV on the HDMI port: hot plug + receiver sense
    writes, gma = [], []
    state = {"start": None, "unmutes": 0}

    def observe(uc, access, address, size, value, user_data=None):
        off = address & 0xFFFFFF
        value &= (1 << (8 * size)) - 1
        if not app_started[0]:
            return
        t = sim._vtime()
        if state["start"] is not None and t > state["start"] + AFTER_START:
            return
        if off == GMA0_ENABLE:
            gma.append(value)
        if off in SKIP or (off == USB_RESET[0] and value & USB_RESET[1]):
            return
        writes.append((t, off, size, value))
        if off == HDMI_CTRL and size == 1 and not value & 1 and state["start"] is None:
            state["start"] = t
        elif off == HDMI_MUTE and size == 1 and value & 0x08 and state["start"] is not None:
            state["unmutes"] += 1

    for lo, hi in RANGES + [(GMA0_ENABLE, GMA0_ENABLE)]:
        sim.add_mmio_hook("write", observe, lo, hi)
    osd_on = False
    while sim._vtime() < 300 and (state["start"] is None or sim._vtime() < state["start"] + AFTER_START):
        sim.run(max_instructions=sim.instruction_count + 10 ** 11, max_vtime=sim._vtime() + 0.25)
        osd_on = osd_on or bool(struct.unpack_from("<I", sim._mmio_view, 0x6300)[0] & 1)
    if not osd_on:
        raise SystemExit(f"{image_name}: the original application did not enable its OSD layer")
    if state["unmutes"] < 3:
        raise SystemExit(f"{image_name} rev {revision}: the HDMI transmitter did not start "
                         f"(unmute pulses: {state['unmutes']})")
    return writes, gma


def with_waits(writes):
    """(offset, size, value) entries; a pause of 2 ms or more becomes (0, 0, ms)."""
    out, last = [], None
    for t, off, size, value in writes:
        if last is not None:
            ms = int(round((t - last) * 1000))
            if ms >= WAIT_MIN_MS:
                out.append((0, 0, min(ms, WAIT_MAX_MS)))
        out.append((off, size, value))
        last = t
    return out


def generate(tables):
    lines = ["/* Generated by gen_video_init.py: the original applications' display",
             "   set-up, recorded in the emulator with a TV on the HDMI port, one table",
             "   per board and chip revision (offsets in the 0xB8000000 window, store",
             "   width, value; width 0 = wait `value` milliseconds).  Edit",
             "   gen_video_init.py, not this file. */",
             "#ifndef VIDEO_INIT_H", "#define VIDEO_INIT_H", "",
             "struct video_write { unsigned int offset : 24, size : 8; unsigned int value; };", ""]
    for key, rev, image, label, entries, gma in tables:
        name = f"{key}_rev{rev}"
        stores = sum(1 for e in entries if e[1])
        waits = [e[2] for e in entries if not e[1]]
        lines += [f"/* {label}, chip revision {rev}: {image}, {stores} stores, {len(waits)} waits "
                  f"({sum(waits)} ms); its GMA layer 0 enable values: "
                  f"{', '.join(f'0x{v:08x}' for v in sorted(set(gma)))} */",
                  f"#define VIDEO_INIT_{name.upper()}_COUNT {len(entries)}",
                  f"static const struct video_write video_init_{name}[VIDEO_INIT_{name.upper()}_COUNT] = {{"]
        for off, size, value in entries:
            lines.append(f"    {{0x{off:05x}, {size}, 0x{value:08x}}},")
        lines += ["};", ""]
    lines += ["#endif", ""]
    return "\n".join(lines)


def main():
    tables = []
    for key, image, label in BOARDS:
        for rev in REVISIONS:
            writes, gma = record(image, rev)
            entries = with_waits(writes)
            tables.append((key, rev, image, label, entries, gma))
            print(f"{key} rev {rev}: {image}: {sum(1 for e in entries if e[1])} stores, "
                  f"{sum(e[2] for e in entries if not e[1])} ms of waits; GMA enable values "
                  f"{[hex(v) for v in sorted(set(gma))]}")
    out = Path(__file__).with_name("video_init.h")
    out.write_text(generate(tables), encoding="utf-8", newline="\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
