#!/usr/bin/env python3
"""Run the established UART bootloader flash procedure on every firmware image
in the emulator and report, per image, how far it gets.

The procedure is tools/maciej_uart.py's `flash` command, the one used on the
physical Opticum STB HD N2 on 2026-11-11: hold the bootloader by sending 'c' from
power-on, the classic `comtest 2` + two-byte handshake, a CRC-checked full
`dump` as the backup, `address` + `transfer` + `burn` of a new main code chunk,
a second full `dump` to verify every byte, `reboot`, and the new application
on the UART.  The application is a small test program (firmware/maciej_app/
hello.c: the demo's banner and a 'p' -> pong reply) packed into each image's
own main code chunk the way its bootloader unpacks it -- LZMA-alone (the ALi
SDK's un7zip) or LZO1X behind a 16-byte header (the vic.wang M3801 builds,
tools/lzo1x.py) -- linked at the chunk's load address and talking to the
chip's console UART.  A last check boots a fresh machine from the flash the
guest wrote.  Images whose main code is in neither format get the same
procedure with their own main code chunk, renamed (a valid chunk whose bytes
differ), so the write path is still tested.

The two full UART dumps are the slow part: the loaders stream the flash
byte by byte with a microsecond delay() between bytes, so an 8 MB dump is a
few minutes of host time.  Images whose bootloader bytes and flash size are
identical behave identically there, so the dumps run once per such group --
on its representative (a flash dump read from a box when the group has one)
-- and the other images of the group get every other step: capture,
handshake, the loader's 'version' table (its CRC of every chunk, over the
UART), transfer, burn, the written flash compared byte for byte with the
expected image, reboot and cold boot.  --all-dumps dumps every image.

Host bytes reach the guest only through the UART, at 115200 baud through a
16-byte receive FIFO (the paced capture probes are lost when it is full, as
on the wire); nothing patches guest registers, RAM or flash.  The shipped client's own
safety checks (only dump_maciej.bin's loader, only offset 0x50000, only
4 MiB) are relaxed into "the image's own main code chunk and flash size";
whether the shipped tool would accept the loader is reported separately.

A loader that the paced 'c' do not hold gets one more try, on a fresh
machine: when the 'c' were echoed but no shell answered the handshake,
'comtest 2' straight after the first echo (the Amiko ALI3606's M3602 loader
looks at the UART only for a moment, after its main code check); when
nothing echoed but the firmware read the UART, the word 'upgreq' every 50 ms
(the AB CryptoBox loaders answer it with 0x80 and wait for a binary protocol
of their own).

Usage:
  python tools/bootloader_flash_survey.py --jobs 4            # every image
  python tools/bootloader_flash_survey.py -k maciej -k Globo   # a selection
  python tools/bootloader_flash_survey.py --rerun "no capture" # the missing ones, and again by verdict
  python tools/bootloader_flash_survey.py --report-only        # re-render

Results: build/flash_survey/<image>/result.json + uart.log, the summary
build/flash_survey/results.json, and the reports docs/bootloader_flash_survey.md
and build/flash_survey/report.html.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import struct
import sys
import time
import traceback
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))

import ali_packet                               # noqa: E402
import lzo1x                                    # noqa: E402
import maciej_uart                              # noqa: E402

OUT_DIR = ROOT / "build" / "flash_survey"
REPORT_MD = ROOT / "docs" / "bootloader_flash_survey.md"
BANNER = b"ELEKTRODA ALI M3801 TEST FOR MACIEJ"
APP_VERSION = "survey"
HEADER_SIZE = 128
SECTOR = 0x10000
NO_CRC = 0x4E435243                             # 'NCRC': a chunk without a CRC
LINE_TIME = 11 / 115200                          # one byte at 115200 8E1 (start, 8 data, parity, stop)
CAPTURE_LIMIT = 150.0                            # emulated seconds of paced 'c' before giving up
BOOT_LIMIT = 150.0                               # emulated seconds for the new application to appear
DEFAULT_LOAD = 0x80000200


# --------------------------------------------------------------------------
# CRC-32/MPEG-2 fast: zlib's reflected CRC-32 over bit-reversed bytes
# --------------------------------------------------------------------------
_REV = bytes(int(f"{b:08b}"[::-1], 2) for b in range(256))


def _rev32(v: int) -> int:
    return int(f"{v:032b}"[::-1], 2)


def crc32_mpeg2(data: bytes, initial: int = 0xFFFFFFFF) -> int:
    """ALi MG_Table_Driven_CRC (poly 04C11DB7, no reflection, no final xor),
    computed by zlib: equal to maciej_uart.crc32_mpeg2, a thousand times faster."""
    if initial != 0xFFFFFFFF:
        return maciej_uart.crc32_mpeg2(data, initial)
    return _rev32(zlib.crc32(data.translate(_REV)) ^ 0xFFFFFFFF)


# --------------------------------------------------------------------------
# The serial line as the emulated box sees it
# --------------------------------------------------------------------------
class EmulatorError(RuntimeError):
    """The emulator itself stopped (a fault it cannot run past, a stall, the wall-clock guard)."""


class Wire:
    """Host <-> guest UART at 115200 baud.  Host bytes go into the 16550's
    16-byte receive FIFO at line rate.  Protocol data waits for room in the
    FIFO (the emulated CPU runs slower than the real 675 MHz part, so a loader
    that keeps up on the box can fall behind here; the maciej_uart tests pace
    the same way); the paced capture probes (send_probe) are lost when they
    arrive at a full FIFO, as on the wire (.overruns).  The guest's
    transmitted bytes are collected in .rx.  read() timeouts are emulated
    seconds; wall_deadline (time.monotonic()) bounds the whole run."""

    FIFO = 16

    def __init__(self, sim, wall_deadline: float):
        self.sim = sim
        self.tx = bytearray()
        self.tx_pos = 0
        self.rx = bytearray()
        self.rx_pos = 0
        self.log = bytearray()
        self.overruns = 0
        self.fifo_full_waits = 0
        self.sent = 0
        self.wall_deadline = wall_deadline
        # debug lines a loader prints between protocol bytes (handshake() finds
        # them): dropped from what reads see; .log keeps everything
        self.noise: list[bytes] = []
        self.noise_dropped = 0
        self._clean_upto = 0
        sim.uart_tx_native = True                   # bulk transmit (C++ engine); same emulated timing
        sim.uart_bulk_callback = self._on_bulk
        sim.setUartHandler(self._on_char)

    def _on_char(self, ch):
        b = ord(ch) & 0xFF
        self.rx.append(b)
        self.log.append(b)

    def _on_bulk(self, data: bytes):
        self.rx += data
        self.log += data

    # -- host -> guest
    def write(self, data: bytes) -> int:
        self.tx += data
        self.sent += len(data)
        return len(data)

    def pending(self) -> int:
        return len(self.tx) - self.tx_pos

    def _deliver(self) -> float:
        """Put the bytes the line brings now into the FIFO; the emulated time
        they take on the wire (0: nothing to send)."""
        pending = self.pending()
        if not pending:
            if self.tx_pos:
                del self.tx[:self.tx_pos]
                self.tx_pos = 0
            return 0.0
        free = self.FIFO - len(self.sim._uart_rx_queue)
        n = min(pending, free)
        if n > 0:
            chunk = bytes(self.tx[self.tx_pos:self.tx_pos + n])
            self.tx_pos += n
            self.sim.setUartReceiveData(chunk, delay_instructions=0)
            return n * LINE_TIME
        self.fifo_full_waits += 1                   # the FIFO is full: the next byte waits
        return LINE_TIME

    def send_probe(self, byte: bytes) -> bool:
        """One paced byte that is lost if it arrives while the FIFO is full."""
        if len(self.sim._uart_rx_queue) >= self.FIFO:
            self.overruns += 1
            return False
        self.sim.setUartReceiveData(byte, delay_instructions=0)
        self.sent += 1
        return True

    def run_until(self, vt_end: float) -> None:
        sim = self.sim
        while True:
            now = sim._vtime()
            if now >= vt_end:
                return
            if time.monotonic() > self.wall_deadline:
                raise EmulatorError("wall-clock budget for this image exhausted")
            step = self._deliver()
            target = vt_end if step == 0 else min(vt_end, now + step)
            before = (sim.instruction_count, now)
            try:
                sim.run(max_instructions=sim.instruction_count + 10 ** 11, max_vtime=target)
            except Exception as exc:                # a fault the emulator stopped on
                raise EmulatorError(f"emulator stopped: {exc!r}"[:300]) from exc
            if (sim.instruction_count, sim._vtime()) == before:
                raise EmulatorError(f"no progress at vtime {now:.3f}")

    # -- guest -> host
    def available(self) -> int:
        if self.noise:
            hold = self._drop_noise()                # (first: it shortens rx)
            return len(self.rx) - self.rx_pos - hold
        return len(self.rx) - self.rx_pos

    def _drop_noise(self) -> int:
        """Remove whole noise lines from the unread bytes (only the new ones
        are scanned); the number of trailing bytes to hold back because they
        may start a noise line (read() and read_exact() hand them over after
        all when the guest stops sending: then they were data)."""
        longest = max(len(line) for line in self.noise)
        start = max(self.rx_pos, self._clean_upto - longest + 1)
        region = bytes(self.rx[start:])
        cleaned = region
        for line in self.noise:
            if line in cleaned:
                self.noise_dropped += cleaned.count(line)
                cleaned = cleaned.replace(line, b"")
        if cleaned != region:
            self.rx[start:] = cleaned
        self._clean_upto = len(self.rx)
        hold = 0
        for line in self.noise:
            for k in range(min(len(line) - 1, len(cleaned)), 0, -1):
                if cleaned.endswith(line[:k]):
                    hold = max(hold, k)
                    break
        return hold

    def _take(self, size: int, timed_out: bool) -> bytes:
        n = min(size, self.available())
        if n < size and timed_out and self.noise:
            n = min(size, len(self.rx) - self.rx_pos)   # nothing followed: the held bytes were data
        data = bytes(self.rx[self.rx_pos:self.rx_pos + n])
        self.rx_pos += n
        self._consumed()
        return data

    def _consumed(self) -> None:
        if self.rx_pos > (1 << 20):
            del self.rx[:self.rx_pos]
            self._clean_upto = max(0, self._clean_upto - self.rx_pos)
            self.rx_pos = 0

    def read(self, size: int, timeout: float) -> bytes:
        if size <= 0:
            return b""
        sim = self.sim
        deadline = sim._vtime() + timeout
        want = min(size, 0x10000)
        step = 0.002
        while self.available() < want and sim._vtime() < deadline:
            if self.available() and size <= 64:
                break                               # short replies: hand over what came
            if self.available() == 0 and not self.pending():
                step = min(step * 1.5, 0.05)        # idle: back off
            missing = want - self.available()
            span = step if size <= 64 else min(max(missing * 50e-6, 0.002), 0.5)
            self.run_until(min(deadline, sim._vtime() + span))
        return self._take(size, sim._vtime() >= deadline)

    def read_exact(self, size: int, timeout: float) -> bytes:
        """`size` bytes, or what came when `timeout` emulated seconds passed:
        runs the guest for the bytes' line time at a stretch, so a packet
        protocol's small reads cost few emulator calls (tools/ali_packet.py
        uses this when the transport has it)."""
        sim = self.sim
        deadline = sim._vtime() + timeout
        idle = 0.0005
        while self.available() < size and sim._vtime() < deadline:
            before = self.available()
            self.run_until(min(deadline, sim._vtime() + max((size - before) * LINE_TIME, idle)))
            # while the guest prepares its answer nothing comes: wait longer each time (to 5 ms)
            idle = min(idle * 2, 0.005) if self.available() == before else 0.0005
        return self._take(size, sim._vtime() >= deadline)

    def drain(self) -> bytes:
        data = bytes(self.rx[self.rx_pos:])
        self.rx_pos = len(self.rx)
        return data

    def quiet(self, gap: float = 0.3, limit: float = 5.0) -> bool:
        """Read until no byte arrives for `gap` emulated seconds; False if the
        guest is still talking after `limit` seconds."""
        end = self.sim._vtime() + limit
        while self.sim._vtime() < end:
            mark = len(self.rx)
            self.run_until(self.sim._vtime() + gap)
            if len(self.rx) == mark:
                self.drain()
                return True
        self.drain()
        return False


class SurveyClient(maciej_uart.BootloaderClient):
    """The established protocol client with its dump_maciej-only limits
    replaced by the image's own flash size and main code chunk."""

    def __init__(self, transport, flash_size: int, **kw):
        super().__init__(transport, **kw)
        self.flash_size = flash_size

    def dump(self) -> bytes:
        self._command("dump")
        size, = struct.unpack(">I", self._read_exact(4))
        if size != self.flash_size:
            self.transport.write(b"E")
            raise maciej_uart.ProtocolError(f"the loader announces 0x{size:x} bytes; flash is 0x{self.flash_size:x}")
        self.transport.write(b"O")
        data = self._read_exact(size, self.dump_timeout)
        expected, = struct.unpack(">I", self._read_exact(4))
        actual = crc32_mpeg2(data)
        if actual != expected:
            raise maciej_uart.ProtocolError(f"dump CRC mismatch: {actual:08x} != {expected:08x}")
        return data

    def address(self, offset: int) -> None:
        self._address = None
        self._staged = None
        self._command(f"address {offset:d}")        # decimal: ali_atoi has no hex
        self._expect(b"O")
        self._address = offset

    def transfer(self, payload: bytes, retries: int = 2) -> None:
        if self._address is None:
            raise maciej_uart.ProtocolError("address() is required before transfer()")
        try:
            self._command(f"transfer {len(payload):d}")
            self._expect(b"O")
            for offset in range(0, len(payload), maciej_uart.BLOCK_SIZE):
                block = payload[offset:offset + maciej_uart.BLOCK_SIZE]
                wire = block + struct.pack(">I", crc32_mpeg2(block))
                for attempt in range(retries + 1):
                    self.transport.write(wire)
                    answer = self._read_exact(1)
                    if answer == b"O":
                        break
                    if answer != b"E" or attempt == retries:
                        raise maciej_uart.ProtocolError(f"block {offset // maciej_uart.BLOCK_SIZE}: reply {answer!r}")
            self._staged = bytes(payload)
        except Exception:
            self._address = None
            self._staged = None
            raise


# --------------------------------------------------------------------------
# The image: its chunks and how its main code is packed
# --------------------------------------------------------------------------
def parse_chunks(flash: bytes) -> list[dict]:
    """The chunk chain from offset 0, as far as it is consistent."""
    chunks = []
    offset = 0
    while offset + HEADER_SIZE <= len(flash) and len(chunks) < 64:
        cid, length, span, crc = struct.unpack_from(">4I", flash, offset)
        if cid in (0, 0xFFFFFFFF):
            break
        end = offset + 16 + length
        name = flash[offset + 16:offset + 32].split(b"\x00")[0].split(b"\xff")[0].decode("latin-1")
        version = flash[offset + 32:offset + 48].split(b"\x00")[0].split(b"\xff")[0].decode("latin-1")
        load, entry = struct.unpack_from(">2I", flash, offset + 120)
        crc_ok = None
        if crc != NO_CRC and end <= len(flash):
            crc_ok = crc32_mpeg2(flash[offset + 16:end]) == crc
        chunks.append({"offset": offset, "id": cid, "length": length, "span": span, "crc": crc,
                       "crc_ok": crc_ok, "name": name, "version": version, "load": load, "entry": entry})
        if not span or offset + span >= len(flash) or end > len(flash):
            break
        offset += span
    return chunks


def main_code_chunk(chunks: list[dict]):
    for c in chunks:
        if (c["id"] >> 16) == 0x01FE:
            return c
    return None


def stream_format(flash: bytes, chunk: dict) -> dict:
    """How the main code payload is packed: {'kind': 'lzma'|'lzo'|'unknown', ...}."""
    start = chunk["offset"] + HEADER_SIZE
    end = chunk["offset"] + 16 + chunk["length"]
    stream = flash[start:end]
    if len(stream) >= 16:
        csize, usize, a_c, a_u = struct.unpack_from("<4I", stream)
        if 0 < csize <= len(stream) - 16 and 0 < usize < 0x4000000 and \
                lzo1x.adler32(stream[16:16 + csize]) == a_c:
            return {"kind": "lzo", "compressed": csize, "size": usize}
    if len(stream) >= 13 and stream[0] < 225:
        dict_size = int.from_bytes(stream[1:5], "little")
        size = int.from_bytes(stream[5:13], "little")
        if 0x1000 <= dict_size <= 0x4000000 and 0 < size < 0x4000000:
            prop = stream[0]
            try:
                dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{
                    "id": lzma.FILTER_LZMA1, "lc": prop % 9, "lp": (prop // 9) % 5,
                    "pb": prop // 45, "dict_size": dict_size}])
                head = dec.decompress(stream[13:13 + 0x10000], max_length=0x1000)
                if len(head) >= min(0x1000, size):
                    return {"kind": "lzma", "prop": prop, "dict_size": dict_size, "size": size}
            except lzma.LZMAError:
                pass
    return {"kind": "unknown", "head": stream[:16].hex()}


def pack_main_code(flash: bytes, chunk: dict, fmt: dict, application: bytes | None):
    """(new flash, payload): the main code chunk carrying `application` packed
    in the chunk's own format -- or, application=None, the original chunk
    renamed "flash-survey" (a valid chunk whose bytes differ).  The payload is
    the chunk from its header, padded to a 64 KiB sector with the bytes that
    were there; the loader's transfer fills the rest of the chunk's
    allocation from flash."""
    off = chunk["offset"]
    updated = bytearray(flash)
    if application is None:
        name = b"flash-survey".ljust(16, b"\x00")
        updated[off + 16:off + 32] = name
        total = 16 + chunk["length"]
    else:
        if fmt["kind"] == "lzma":
            stream = bytearray(lzma.compress(application, format=lzma.FORMAT_ALONE, filters=[{
                "id": lzma.FILTER_LZMA1, "dict_size": fmt["dict_size"],
                "lc": fmt["prop"] % 9, "lp": (fmt["prop"] // 9) % 5, "pb": fmt["prop"] // 45}]))
            stream[5:13] = len(application).to_bytes(8, "little")      # a known size, as the loader needs
        elif fmt["kind"] == "lzo":
            stream = lzo1x.pack_payload(application)
        else:
            raise ValueError("unknown main code format")
        total = HEADER_SIZE + len(stream)
        if chunk["span"] and total > chunk["span"]:
            raise ValueError("packed application larger than the chunk's allocation")
        updated[off + HEADER_SIZE:off + total] = stream
        struct.pack_into(">I", updated, off + 4, total - 16)
    if chunk["crc"] != NO_CRC:
        struct.pack_into(">I", updated, off + 12, crc32_mpeg2(bytes(updated[off + 16:off + total])))
    size = (total + SECTOR - 1) // SECTOR * SECTOR
    if chunk["span"]:
        size = min(size, chunk["span"])
    payload = bytes(updated[off:off + size])
    return bytes(updated), payload


def static_facts(path: Path, flash_size: int) -> dict:
    data = path.read_bytes()
    flash = (data[:flash_size] + b"\xff" * flash_size)[:flash_size]
    chunks = parse_chunks(flash)
    main = main_code_chunk(chunks)
    facts = {
        "file_size": len(data), "flash_size": flash_size,
        "sha1": hashlib.sha1(data).hexdigest(),
        "chunks": [{k: (f"0x{v:08x}" if k in ("id", "crc", "load", "entry") else v) for k, v in c.items()}
                   for c in chunks],
        "loader": None, "main_code": None, "format": None,
        "shipped_tool_accepts_loader": (len(flash) == maciej_uart.FLASH_SIZE and hashlib.sha256(
            flash[:maciej_uart.LOADER_SIZE]).hexdigest() == maciej_uart.LOADER_SHA256),
    }
    if chunks:
        c0 = chunks[0]
        facts["loader"] = {"id": f"0x{c0['id']:08x}", "span": c0["span"], "name": c0["name"],
                           "version": c0["version"]}
    if main is not None:
        load = main["load"] if main["load"] not in (0, 0xFFFFFFFF) else DEFAULT_LOAD
        entry = main["entry"] if main["entry"] not in (0, 0xFFFFFFFF) else load
        facts["main_code"] = {"offset": main["offset"], "id": f"0x{main['id']:08x}", "length": main["length"],
                              "span": main["span"], "name": main["name"], "crc_ok": main["crc_ok"],
                              "load": f"0x{load:08x}", "entry": f"0x{entry:08x}"}
        facts["format"] = stream_format(flash, main)
    return facts


# --------------------------------------------------------------------------
# The test application, built once per (load address, UART)
# --------------------------------------------------------------------------
def build_test_app(load: int, uart_base: int, cross_prefix=None) -> bytes:
    from firmware.maciej_app.build import build
    out = OUT_DIR / "apps" / f"hello_{load:08x}_{uart_base:08x}"
    binary = out / "app.bin"
    stamp = out / "sources.sha1"
    digest = hashlib.sha1(b"".join((ROOT / "firmware/maciej_app" / f).read_bytes()
                                   for f in ("hello.c", "survey_start.S", "link.ld", "build.py"))).hexdigest()
    if not binary.exists() or not stamp.exists() or stamp.read_text() != digest:
        # (survey_start.S: it also runs where a loader starts the main code at its own default address)
        build(out, APP_VERSION, cross_prefix, sources=("hello.c",), load_address=load,
              defines={"UART_BASE": f"{uart_base:#010x}u"}, start="survey_start.S")
        stamp.write_text(digest)
    return binary.read_bytes()


WDT_BASE = 0x18500                               # the watchdog (count at +0, control at +4)


def watchdog_armed(writes) -> bool:
    """Whether the loader set the watchdog to overflow at once: a count within
    0x100000 of the top, then a control write (the M3503 loader: 0xFFFFF000,
    then 0x67)."""
    count = None
    for addr, value in writes:
        if addr == WDT_BASE:
            count = value
        elif addr == WDT_BASE + 4 and value and count is not None and count >= 0xFFF00000:
            return True
    return False


def uart_base_for(family: str) -> int:
    return 0xB8001300 if family == "M3329" else 0xB8018300


# --------------------------------------------------------------------------
# One image
# --------------------------------------------------------------------------
_TMP_FILES: list[Path] = []                      # this image's restart images, removed when it is done


def _remove_tmp_files():
    while _TMP_FILES:
        try:
            _TMP_FILES.pop().unlink()
        except OSError:
            pass


def _new_sim(path: Path, rom_size: int, image: bytes | None = None, deadline: float = 0.0):
    from simulator import AliMipsSimulator
    sim = AliMipsSimulator(rom_size=rom_size, log_handler=lambda _m: None, engine="cpp")
    sim.keep_main_crc = True                     # the C3505 loaders check the main code's CRC, ours included
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    wire = Wire(sim, deadline)
    if image is None:
        sim.loadFile(str(path))
    else:
        import dump_catalog
        tmp = OUT_DIR / "_tmp" / f"{os.getpid()}_{len(_TMP_FILES)}_{path.name}"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(image)
        _TMP_FILES.append(tmp)
        sidecar = Path(str(path) + ".json")
        if sidecar.exists():                         # the real image's sidecar still describes the board
            dump_catalog.set_override(str(tmp), str(sidecar))
        sim.loadFile(str(tmp))
    return sim, wire


class Step:
    def __init__(self, result: dict, name: str, sim):
        self.result, self.name, self.sim = result, name, sim

    def __enter__(self):
        self.t0, self.v0 = time.monotonic(), self.sim._vtime()
        self.entry = {"step": self.name, "ok": None}
        self.result["steps"].append(self.entry)
        return self.entry

    def __exit__(self, exc_type, exc, tb):
        self.entry["wall_s"] = round(time.monotonic() - self.t0, 2)
        self.entry["vtime_s"] = round(self.sim._vtime() - self.v0, 3)
        if exc is not None:
            self.entry["ok"] = False
            self.entry.setdefault("detail", f"{type(exc).__name__}: {exc}"[:400])
            self.entry["emulator_error"] = isinstance(exc, EmulatorError)
        elif self.entry["ok"] is None:
            self.entry["ok"] = True
        return False


def _step_of(result, name):
    return next((s for s in result["steps"] if s["step"] == name), {})


def capture(wire: Wire, limit: float = CAPTURE_LIMIT) -> dict:
    """Paced 'c' (one every 50 ms, as maciej_uart.capture_boot) until the
    classic shell echoes three in a row.  An emulator stop ends the capture
    (reported with the time it happened)."""
    sim = wire.sim
    streak = 0
    consumed_at = None
    try:
        while sim._vtime() < limit:
            mark = len(wire.rx)
            wire.send_probe(b"c")
            wire.run_until(sim._vtime() + 0.05)
            if consumed_at is None and len(sim._uart_rx_queue) == 0:
                consumed_at = round(sim._vtime(), 3)
            got = bytes(wire.rx[mark:])
            streak = streak + 1 if got.endswith(b"c") else 0
            if streak >= 3:
                return {"captured": True, "vtime": round(sim._vtime(), 3), "uart_read_at": consumed_at}
    except EmulatorError as exc:
        return {"captured": False, "vtime": round(sim._vtime(), 3), "uart_read_at": consumed_at,
                "emulator_error": str(exc)[:300]}
    return {"captured": False, "vtime": round(sim._vtime(), 3), "uart_read_at": consumed_at}


def window_capture(wire: Wire, limit: float = CAPTURE_LIMIT) -> dict:
    """Paced 'c' until the first echo, then 'comtest 2' at once.  For loaders
    that look at the UART only for a moment and boot on unless the word
    'comtest' arrives while they look (the M3602 loader of the Amiko ALI3606
    images: about 0.35 s after its main code check, echoing what came in the
    meantime); the established handshake's '\\r' and pause end that window."""
    sim = wire.sim
    try:
        while sim._vtime() < limit:
            mark = len(wire.log)
            wire.send_probe(b"c")
            wire.run_until(sim._vtime() + 0.05)
            if bytes(wire.log[mark:]).endswith(b"c"):
                at = round(sim._vtime(), 3)
                mark = len(wire.log)
                wire.write(b"comtest 2\r")
                wire.run_until(sim._vtime() + 0.5)
                echo = bytes(wire.log[mark:])
                return {"captured": b"comtest" in echo, "vtime": at, "echo": echo[:40].decode("latin-1")}
    except EmulatorError as exc:
        return {"captured": False, "vtime": round(sim._vtime(), 3), "emulator_error": str(exc)[:300]}
    return {"captured": False, "vtime": round(sim._vtime(), 3)}


UPGREQ_LIMIT = 40.0                              # emulated seconds of paced 'upgreq'


def probe_upgreq(wire: Wire, limit: float = UPGREQ_LIMIT) -> dict:
    """The word 'upgreq' every 50 ms from power-on.  The AB CryptoBox loaders
    ignore 'c' and look for this word instead: they answer one byte, 0x80,
    stop booting and wait silently for a binary upgrade protocol."""
    sim = wire.sim
    try:
        while sim._vtime() < limit:
            mark = len(wire.log)
            for b in b"upgreq":
                wire.send_probe(bytes([b]))
            wire.run_until(sim._vtime() + 0.05)
            got = bytes(wire.log[mark:])
            if got.endswith(b"\x80"):
                at = round(sim._vtime(), 3)
                mark = len(wire.log)
                wire.run_until(sim._vtime() + 2.0)      # and then nothing: the loader waits
                if len(wire.log) == mark:
                    return {"answered": True, "reply": "80", "vtime": at}
    except EmulatorError as exc:
        return {"answered": False, "vtime": round(sim._vtime(), 3), "emulator_error": str(exc)[:300]}
    return {"answered": False, "vtime": round(sim._vtime(), 3)}


def handshake(wire: Wire) -> dict:
    """maciej_uart's handshake bytes ('comtest 2\\r', then 'XX'), classifying the answer."""
    wire.write(b"\r")
    wire.quiet()
    wire.write(b"comtest 2\r")
    echo = b""
    while len(echo) < 10:
        part = wire.read(10 - len(echo), 3.0)
        if not part:
            break
        echo += part
    if echo != b"comtest 2\r":
        return {"protocol": "none", "echo": echo.decode("latin-1")}
    wire.write(b"XX")
    reply = b""
    while len(reply) < 2:
        part = wire.read(2 - len(reply), 3.0)
        if not part:
            break
        reply += part
    if reply == b"XX":
        return {"protocol": "classic"}
    if reply == bytes([0xFF - ord("X")] * 2):
        return {"protocol": "packet", "reply": reply.hex()}
    # A loader whose drivers print debug lines between the protocol's bytes (the
    # Opticum AX 502 Combo's front-panel driver prints "pan_FD650K_display" when
    # comtest puts "conn" on the panel): text lines, then the echo.  Such lines
    # are dropped from then on (Wire.noise); the shipped client would stop here.
    end = wire.sim._vtime() + 3.0
    while not reply.endswith(b"XX") and wire.sim._vtime() < end and len(reply) < 400:
        reply += wire.read(1, 0.5)                  # (one at a time: what follows the echo stays unread)
    text = reply[:-2]
    lines = [line + b"\r\n" for line in text.split(b"\r\n")[:-1]]
    if (reply.endswith(b"XX") and text.endswith(b"\r\n") and lines and
            all(len(line) >= 6 and all(32 <= c < 127 for c in line[:-2]) for line in lines)):
        wire.noise = sorted(set(lines), key=len, reverse=True)
        # (bytes sent while such a driver is still busy -- bit-banging the panel -- are lost:
        # the next command waits until the loader has gone quiet)
        wire.quiet()
        return {"protocol": "classic", "noise": [line.decode("ascii").strip() for line in wire.noise]}
    return {"protocol": "other", "reply": reply[:40].hex()}


def _handshake_detail(hs: dict) -> str:
    if hs["protocol"] == "classic" and hs.get("noise"):
        return ("the classic shell, but its drivers print debug lines between the protocol's bytes ("
                + ", ".join(repr(line) for line in hs["noise"]) + "): dropped from the stream from here on")
    if hs["protocol"] == "classic":
        return "the classic shell: 'comtest 2' echoed, 'XX' answered 'XX'"
    if hs["protocol"] == "packet":
        return "the loader answers comtest with 0xFF - byte: it speaks only the packet (format 3) protocol"
    if hs["protocol"] == "other":
        return f"'comtest 2' echoed, but the handshake bytes 'XX' came back as {hs.get('reply')}"
    return f"no classic comtest echo (received {hs.get('echo', '')!r})"


class PacketSurveyClient:
    """The procedure's steps in ALi's packet protocol (tools/ali_packet.py),
    for the loaders that speak only that one: the same commands, each in a
    CRC-checked packet; dump reads 1024-byte packets the host asks for."""

    def __init__(self, wire: Wire, flash_size: int):
        self.flash_size = flash_size
        self.packets = ali_packet.PacketClient(wire, timeout=10.0, clock=wire.sim._vtime)

    def handshake(self):
        self.packets.handshake()

    def dump(self) -> bytes:
        return self.packets.dump(0, self.flash_size)

    def address(self, offset: int):
        self.packets.address(offset)

    def transfer(self, payload: bytes):
        self.packets.transfer(payload)

    def burn(self):
        return self.packets.burn(timeout=600.0)

    def reboot(self):
        self.packets.reboot()


def version_table(client) -> dict:
    if isinstance(client, PacketSurveyClient):
        body = client.packets.chunk_table()          # the packet protocol's 'chunk': no CRC of its own
        crc = crc32_mpeg2(body)
    else:
        client._command("version")
        n, = struct.unpack(">H", client._read_exact(2))
        body = client._read_exact(n)
        crc, = struct.unpack(">I", client._read_exact(4))
    chunks = []
    for i in range((len(body) - 2) // 128):
        h = body[2 + 128 * i:2 + 128 * (i + 1)]
        cid, ln, off, ccrc = struct.unpack(">4I", h[:16])
        chunks.append({"id": f"0x{cid:08x}", "length": ln, "span": off,
                       "name": h[16:32].split(b"\x00")[0].decode("latin-1")})
    return {"crc_ok": crc32_mpeg2(body) == crc, "flash_id": body[0], "crc_bad": body[1], "chunks": chunks}


def wait_for_app(wire: Wire, limit: float = BOOT_LIMIT, start: int | None = None) -> dict:
    """The test application's banner (in the UART output from log index
    `start`, default now) within `limit` emulated seconds, then its pong."""
    sim = wire.sim
    end = sim._vtime() + limit
    marker = BANNER + b"\r\nVersion: " + APP_VERSION.encode() + b"\r\n"
    if start is None:
        start = len(wire.log)
    while sim._vtime() < end:
        wire.run_until(min(end, sim._vtime() + 0.25))
        if marker in wire.log[start:]:
            break
    seen = bytes(wire.log[start:])
    if marker not in seen:
        return {"banner": False, "output": seen[-400:].decode("latin-1")}
    wire.drain()
    wire.write(b"p")
    pong = b""
    t_end = sim._vtime() + 5
    while b"pong survey\r\n" not in pong and sim._vtime() < t_end:
        pong += wire.read(64, 0.5)
    return {"banner": True, "at_vtime": round(sim._vtime(), 2), "pong": b"pong survey\r\n" in pong}


def survey_image(job: dict) -> dict:
    path = Path(job["path"])
    out = Path(job["out"])
    out.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    deadline = started + job["wall_budget"]
    result = {"image": job["rel"], "kind": job.get("kind"), "family": job.get("family"),
              "catalog_boots": job.get("boots"), "steps": [], "verdict": None, "reason": "",
              "loader_key": job.get("loader_key"), "group_size": job.get("group_size"),
              "uart_dumps": job.get("dumps", True), "dump_representative": job.get("dump_representative"),
              "security_ic": job.get("security_ic", False)}
    wire = None
    try:
        from simulator import flash_size_for
        rom_size = flash_size_for(str(path))
        facts = static_facts(path, rom_size)
        result["facts"] = facts
        if job.get("boots") is False:
            result["verdict"] = "n/a"
            result["reason"] = "the emulator does not boot this image (catalog: boots = no)"
            return result
        if job.get("kind") == "test program":
            result["verdict"] = "n/a"
            result["reason"] = "a test program, not a flash image with a bootloader"
            return result
        if not facts["chunks"]:
            result["verdict"] = "n/a"
            result["reason"] = "no ALi chunk chain at flash offset 0 (not a flash image)"
            return result
        sim, wire = _new_sim(path, rom_size, deadline=deadline)
        family = type(sim.chip).__name__
        result["emulated_family"] = family
        flash0 = bytes(sim.rom_image[:rom_size])

        with Step(result, "capture", sim) as st:
            cap = capture(wire)
            st.update(cap)
            st["boot_output"] = bytes(wire.log[:600]).decode("latin-1")
            if not cap["captured"]:
                st["ok"] = False
                st["output_tail"] = bytes(wire.log[-400:]).decode("latin-1")
                if cap.get("emulator_error"):
                    st["detail"] = (f"the emulator stopped after {cap['vtime']:.1f} s of paced 'c', with no echo "
                                    f"yet: {cap['emulator_error']}")
                else:
                    st["detail"] = ("no classic shell echo within %.0f s of paced 'c'; %s" %
                                    (CAPTURE_LIMIT, "the firmware read the UART" if cap["uart_read_at"] is not None
                                     else "nothing read the UART"))
        if not cap["captured"]:
            alt = None
            if cap["uart_read_at"] is not None:
                # another loader's request word, on a fresh machine
                sim, wire = _new_sim(path, rom_size, deadline=deadline)
                with Step(result, "upgreq request", sim) as st:
                    alt = probe_upgreq(wire)
                    st.update(alt)
                    st["ok"] = alt["answered"]
            if alt and alt["answered"]:
                result["verdict"] = "other protocol"
                result["reason"] = (f"the loader ignores the paced 'c'; it answers the word 'upgreq' with 0x80 "
                                    f"(at {alt['vtime']:.1f} s) and waits silently for a binary upgrade protocol")
            else:
                result["verdict"] = "no capture"
                result["reason"] = _step_of(result, "capture")["detail"]
            return result

        with Step(result, "handshake", sim) as st:
            hs = handshake(wire)
            st.update(hs)
            st["ok"] = hs["protocol"] in ("classic", "packet")
            st["detail"] = _handshake_detail(hs)
        if hs["protocol"] == "none":
            # the echo did not last: 'comtest 2' straight after the first echo, on a fresh machine
            first = st
            sim, wire = _new_sim(path, rom_size, deadline=deadline)
            with Step(result, "window capture", sim) as st:
                win = window_capture(wire)
                st.update(win)
                st["ok"] = win["captured"]
                if not win["captured"]:
                    st["detail"] = (f"{first['detail']}; 'comtest 2' sent straight after the first echo was not "
                                    f"echoed either" + (f" ({win['emulator_error']})" if win.get("emulator_error")
                                                        else ""))
            if win["captured"]:
                result["capture_mode"] = "window"
                first["superseded"] = "by the window capture"
                with Step(result, "handshake", sim) as st:
                    hs = handshake(wire)
                    st.update(hs)
                    st["ok"] = hs["protocol"] in ("classic", "packet")
                    st["detail"] = (f"held only by 'comtest' straight after its first echo (at "
                                    f"{win['vtime']:.1f} s); then {_handshake_detail(hs)}")
        if hs["protocol"] not in ("classic", "packet"):
            result["verdict"] = "no handshake"
            result["reason"] = result["steps"][-1]["detail"]
            return result

        result["protocol"] = hs["protocol"]
        if hs["protocol"] == "classic":
            client = SurveyClient(wire, rom_size, timeout=10, burn_timeout=600, dump_timeout=4000)
        else:
            # the same procedure in ALi's packet protocol (the loader's only one)
            client = PacketSurveyClient(wire, rom_size)
            with Step(result, "packet handshake", sim) as st:
                try:
                    client.handshake()
                    st["ok"] = True
                except (TimeoutError, maciej_uart.ProtocolError) as exc:
                    st["ok"] = False
                    st["detail"] = f"the packet protocol's handshake failed: {type(exc).__name__}: {exc}"[:300]
            if not st["ok"]:
                result["verdict"] = "packet protocol only"
                result["reason"] = st["detail"]
                return result
        with Step(result, "backup dump", sim) as st:
            if not job.get("dumps", True):
                # (the group's representative dumps; this image's flash is the emulator's)
                backup = flash0
                st["skipped"] = f"same bootloader as {job['dump_representative']}, whose UART dumps are checked"
            else:
                backup = client.dump()
            st["bytes"] = len(backup)
            st["matches_flash"] = backup == flash0
            file_bytes = path.read_bytes()[:rom_size]
            st["matches_file"] = backup[:len(file_bytes)] == file_bytes
            st["ok"] = st["matches_flash"]
            if not st["ok"]:
                st["detail"] = "the dump differs from the emulated flash"
        if not st["ok"]:
            result["verdict"] = "dump differs"
            result["reason"] = st["detail"]
            return result

        # (diagnostic, not part of the procedure: the loader's own chunk table)
        with Step(result, "version", sim) as st:
            try:
                st.update(version_table(client))
                st["ok"] = bool(st.get("crc_ok"))
            except EmulatorError:
                raise
            except Exception as exc:
                st["ok"] = False
                st["detail"] = f"{type(exc).__name__}: {exc}"[:300]
                wire.quiet()
                client.handshake()                   # back in step for the next command

        main = main_code_chunk(parse_chunks(backup))
        fmt = stream_format(backup, main) if main else {"kind": "none"}
        application = None
        with Step(result, "package", sim) as st:
            if main is None:
                st["ok"] = False
                st["detail"] = "no main code chunk (ID 0x01FExxxx) in the chunk chain"
            else:
                load = main["load"] if main["load"] not in (0, 0xFFFFFFFF) else DEFAULT_LOAD
                st["format"] = fmt["kind"]
                st["load"] = f"0x{load:08x}"
                if fmt["kind"] in ("lzma", "lzo"):
                    application = build_test_app(load, uart_base_for(family), job.get("cross_prefix"))
                    st["application_bytes"] = len(application)
                    st["uart_base"] = f"0x{uart_base_for(family):08x}"
                else:
                    st["detail"] = "main code format not recognised: write test with the original chunk renamed"
                expected, payload = pack_main_code(backup, main, fmt, application)
                st["payload_bytes"] = len(payload)
                st["address"] = main["offset"]
        if main is None:
            result["verdict"] = "no main code chunk"
            result["reason"] = st["detail"]
            return result

        with Step(result, "transfer + burn", sim) as st:
            client.address(main["offset"])
            client.transfer(payload)
            st["burn_progress"] = client.burn()
            st["flash_after_burn_matches"] = bytes(sim.rom_image[:rom_size]) == expected
            # (the written chunk's own CRC, as a loader that checks it computes it)
            _cid, length, _span, crc = struct.unpack_from(">4I", expected, main["offset"])
            st["written_chunk_crc_ok"] = crc == NO_CRC or crc == crc32_mpeg2(
                expected[main["offset"] + 16:main["offset"] + 16 + length])
            st["ok"] = st["flash_after_burn_matches"] and st["written_chunk_crc_ok"]
            if not st["ok"]:
                changed = sum(1 for a, b in zip(sim.rom_image[:rom_size], expected) if a != b)
                st["detail"] = f"emulated flash differs from the expected image in {changed} bytes"

        with Step(result, "readback dump", sim) as st:
            try:
                if not job.get("dumps", True):
                    st["skipped"] = f"same bootloader as {job['dump_representative']}: written flash compared directly"
                    after = bytes(sim.rom_image[:rom_size])
                else:
                    after = client.dump()
                st["matches_expected"] = after == expected
                st["ok"] = st["matches_expected"]
                if not st["ok"]:
                    st["detail"] = "the readback differs from the expected flash"
            except (TimeoutError, maciej_uart.ProtocolError) as exc:
                st["ok"] = False
                st["detail"] = f"{type(exc).__name__}: {exc}"[:300]
                st["note"] = "some loaders reboot by themselves after burn (SYS_SDRAM_SIZE == 2 builds)"

        readback_failed = not result["steps"][-1]["ok"]
        with Step(result, "reboot + application", sim) as st:
            wdt = []
            wdt_hook = sim.add_mmio_hook("write", lambda uc, a, addr, size, value, u=None:
                                         wdt.append(((addr & 0xFFFFFF), value & 0xFFFFFFFF)), WDT_BASE, WDT_BASE + 0xF)
            reboot_mark = len(wire.log)
            target, target_wire = sim, wire
            try:
                if not readback_failed:
                    client.reboot()
                if application is not None:
                    got = wait_for_app(wire, limit=20.0, start=reboot_mark)
                    if not got.get("banner") and watchdog_armed(wdt):
                        # the loader armed its watchdog for an immediate reset and spins: the
                        # emulator has no watchdog, so the harness restarts the machine from the
                        # flash the loader wrote -- what the chip-wide reset does
                        st["watchdog_reset"] = [f"0x{a:06x}={v:08x}" for a, v in wdt[-4:]]
                        target, target_wire = _new_sim(path, rom_size, image=bytes(sim.rom_image[:rom_size]),
                                                       deadline=deadline)
                        got = wait_for_app(target_wire)
                    elif not got.get("banner"):
                        got = wait_for_app(wire, limit=BOOT_LIMIT - 20.0, start=reboot_mark)
                    st.update(got)
                    st["ok"] = bool(st.get("banner") and st.get("pong"))
                    if not st["ok"]:
                        st["detail"] = "the test application did not answer after the loader's reboot"
                else:
                    end = sim._vtime() + 30
                    mark = len(wire.log)
                    wire.run_until(end)
                    if len(wire.log) == mark and watchdog_armed(wdt):
                        st["watchdog_reset"] = [f"0x{a:06x}={v:08x}" for a, v in wdt[-4:]]
                        target, target_wire = _new_sim(path, rom_size, image=bytes(sim.rom_image[:rom_size]),
                                                       deadline=deadline)
                        target_wire.run_until(30)
                        st["output"] = bytes(target_wire.log[:400]).decode("latin-1")
                        st["ok"] = len(target_wire.log) > 0
                    else:
                        st["output"] = bytes(wire.log[mark:mark + 400]).decode("latin-1")
                        st["ok"] = len(wire.log) > mark
                    st["detail"] = "rebooted into the renamed original main code (its output above)"
            except EmulatorError as exc:
                st["ok"] = False
                st["emulator_error"] = True
                st["detail"] = f"the emulator stopped while the loader started the new main code: {exc}"[:300]
            sim.remove_mmio_hook(wdt_hook)
            if target_wire is not wire:
                (out / "uart_after_watchdog.log").write_bytes(bytes(target_wire.log))
        reboot_ok = st["ok"]

        with Step(result, "cold boot from written flash", sim) as st:
            flash_now = bytes(sim.rom_image[:rom_size])
            cold_sim, cold_wire = _new_sim(path, rom_size, image=flash_now, deadline=deadline)
            try:
                if application is not None:
                    st.update(wait_for_app(cold_wire))
                    st["ok"] = bool(st.get("banner") and st.get("pong"))
                else:
                    cold_wire.run_until(30)
                    st["output"] = bytes(cold_wire.log[:400]).decode("latin-1")
                    st["ok"] = len(cold_wire.log) > 0
            except EmulatorError as exc:
                st["ok"] = False
                st["emulator_error"] = True
                st["detail"] = f"the emulator stopped while the loader started the new main code: {exc}"[:300]
            (out / "uart_cold.log").write_bytes(bytes(cold_wire.log))

        counted = [s for s in result["steps"] if s["step"] != "version" and not s.get("superseded")]
        ok_all = all(s["ok"] for s in counted)
        packet = result.get("protocol") == "packet"
        if application is not None and ok_all:
            result["verdict"] = "works, packet protocol" if packet else "works"
            result["reason"] = "backup, burn, readback, reboot and cold boot of the test application"
            if packet:
                result["reason"] += " in ALi's packet protocol, the loader's only one"
            if _step_of(result, "reboot + application").get("watchdog_reset"):
                result["reason"] += " (the loader's reboot arms the watchdog; the emulator restarts the machine)"
            if result.get("capture_mode") == "window":
                result["reason"] += " (held by 'comtest' straight after the loader's first echo)"
            if _step_of(result, "handshake").get("noise"):
                result["reason"] += (" (its debug lines between the protocol's bytes dropped: the shipped "
                                     "client would stop at the handshake)")
        elif application is None and ok_all:
            result["verdict"] = "write path works"
            result["reason"] = "main code format unknown: the renamed original chunk was burned, verified and booted"
            if packet:
                result["reason"] += " (packet protocol)"
        else:
            failed = [s for s in counted if not s["ok"]]
            result["verdict"] = "partial"
            result["reason"] = "; ".join(f"{s['step']}: {s.get('detail', 'failed')}" for s in failed)[:500]
            if job.get("security_ic") and {s["step"] for s in failed} <= {"reboot + application",
                                                                         "cold boot from written flash"}:
                result["reason"] = ("backup, burn and readback work, but the loader has the board's security IC "
                                    "decrypt the first KB of the main code before unpacking it (catalog note): "
                                    "without the chip's key no new main code starts; " + result["reason"])[:500]
        result["reboot_ok"] = reboot_ok
    except EmulatorError as exc:
        result["verdict"] = "emulator error"
        result["reason"] = str(exc)[:400]
    except Exception as exc:
        result["verdict"] = "error"
        result["reason"] = f"{type(exc).__name__}: {exc}"[:400]
        result["traceback"] = traceback.format_exc()[-3000:]
    finally:
        _remove_tmp_files()
        result["wall_s"] = round(time.monotonic() - started, 1)
        if wire is not None:
            (out / "uart.log").write_bytes(bytes(wire.log))
            result["uart_bytes_sent"] = wire.sent
            result["probe_bytes_lost"] = wire.overruns
            result["fifo_full_waits"] = wire.fifo_full_waits
            if wire.noise:
                result["noise_lines_dropped"] = wire.noise_dropped
        (out / "result.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    return result


# --------------------------------------------------------------------------
# Every image
# --------------------------------------------------------------------------
def safe_name(rel: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", rel)[:150]


def loader_key(path: str, rom_size: int) -> str:
    """The identity of an image's bootloader for the dump grouping: the bytes of
    its first chunk (the first 64 KB without a chain) and the flash size."""
    data = Path(path).read_bytes()[:rom_size]
    chunks = parse_chunks((data + b"\xff" * rom_size)[:rom_size])
    span = chunks[0]["span"] if chunks and chunks[0]["span"] else 0x10000
    return f"{hashlib.sha1(data[:span]).hexdigest()[:16]}-{rom_size:x}"


def catalog_jobs(filters, wall_budget, cross_prefix, all_dumps=False):
    import dump_catalog
    from simulator import DUMPS_DIR, flash_size_for
    jobs = []
    for image in dump_catalog.images():
        rel = os.path.relpath(image, DUMPS_DIR).replace(os.sep, "/")
        side = dump_catalog.load(image) or {}
        key = loader_key(image, flash_size_for(image))
        jobs.append({
            "path": str(image), "rel": rel, "out": str(OUT_DIR / safe_name(rel)),
            "kind": (side.get("image") or {}).get("kind"),
            "family": (side.get("device") or {}).get("family"),
            "soc": (side.get("device") or {}).get("soc"),
            "box": " ".join(x for x in ((side.get("device") or {}).get("brand"),
                                         (side.get("device") or {}).get("model")) if x),
            "boots": (side.get("simulator") or {}).get("boots"),
            # the board's security IC decrypts the main code (the Ferguson Ariva 102E / 103 / 153 / 52E)
            "security_ic": "security ic" in ((side.get("simulator") or {}).get("note") or "").lower(),
            "wall_budget": wall_budget, "cross_prefix": cross_prefix,
            "loader_key": key, "dumps": True, "dump_representative": None,
        })
    # The UART dumps run on every flash dump read from a box, and on one
    # representative of each other bootloader group: dump_maciej.bin for its
    # own group, else a dump read from a box if the group has one, else the
    # first image by path.
    groups = {}
    for job in jobs:
        groups.setdefault(job["loader_key"], []).append(job)
    for members in groups.values():
        rep_job = next((j for j in members if j["rel"] == "dump_maciej.bin"),
                       next((j for j in members if j["kind"] == "dump"), members[0]))
        for job in members:
            job["group_size"] = len(members)
            if not all_dumps and job is not rep_job and job["kind"] != "dump":
                job["dumps"] = False
                job["dump_representative"] = rep_job["rel"]
    if filters:
        jobs = [j for j in jobs if any(f.lower() in j["rel"].lower() for f in filters)]
    return jobs


def run_all(jobs, n_jobs):
    results = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=n_jobs, max_tasks_per_child=1) as pool:
        futures = {pool.submit(survey_image, job): job for job in jobs}
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            job = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:                 # a worker that died (native crash)
                res = {"image": job["rel"], "verdict": "emulator error", "steps": [],
                       "reason": f"worker process failed: {exc!r}"[:300]}
                Path(job["out"]).mkdir(parents=True, exist_ok=True)
                (Path(job["out"]) / "result.json").write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
            res.setdefault("box", job.get("box"))
            res.setdefault("soc", job.get("soc"))
            results.append(res)
            print(f"[{i}/{len(jobs)}] {res['verdict']:<22} {res.get('wall_s', 0):>7}s  {job['rel']}", flush=True)
    return results


def dump_gaps(jobs):
    """Group members that rely on a representative which never got to its UART
    dumps (it was not captured, say): for each such group, one member that
    works runs the procedure again with its own dumps."""
    def saved(rel):
        p = OUT_DIR / safe_name(rel) / "result.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    redo, covered = [], set()
    for job in jobs:
        rep = job.get("dump_representative")
        if job.get("dumps", True) or not rep or rep in covered:
            continue
        rep_result = saved(rep) or {}
        if any(s.get("step") == "backup dump" and s.get("ok") and not s.get("skipped")
               for s in rep_result.get("steps", ())):
            continue
        mine = saved(job["rel"]) or {}
        if any(s.get("step") == "backup dump" and s.get("ok") and not s.get("skipped")
               for s in mine.get("steps", ())):
            covered.add(rep)                            # (it ran its own dumps already)
            continue
        if str(mine.get("verdict", "")).startswith("works"):
            covered.add(rep)
            redo.append(dict(job, dumps=True, dump_representative=None))
    return redo


def load_results(jobs):
    results = []
    for job in jobs:
        p = Path(job["out"]) / "result.json"
        if p.exists():
            r = json.loads(p.read_text(encoding="utf-8"))
            r.setdefault("box", job.get("box"))
            r.setdefault("soc", job.get("soc"))
            results.append(r)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-k", action="append", default=[], help="only images whose path contains this (repeatable)")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--wall-budget", type=float, default=1800, help="wall-clock seconds per image")
    parser.add_argument("--cross-prefix", help="MIPS GCC prefix (default: MIPS_CROSS_COMPILE / PATH)")
    parser.add_argument("--report-only", action="store_true", help="re-render the reports from saved results")
    parser.add_argument("--skip-done", action="store_true", help="keep images that already have a result")
    parser.add_argument("--rerun", action="append", default=[], metavar="VERDICT",
                        help="survey the images without a result and again those whose saved result is this "
                             "verdict (repeatable)")
    parser.add_argument("--all-dumps", action="store_true",
                        help="run the two UART dumps on every image, not once per bootloader group")
    args = parser.parse_args()
    from firmware.maciej_app.build import find_prefix
    prefix = None if args.report_only else find_prefix(args.cross_prefix)   # (reports need no compiler)
    jobs = catalog_jobs(args.k, args.wall_budget, prefix, args.all_dumps)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not args.report_only:
        todo = jobs
        if args.skip_done or args.rerun:
            # the images without a result, and with --rerun those whose saved verdict is one of these
            def saved_verdict(job):
                p = Path(job["out"]) / "result.json"
                return json.loads(p.read_text(encoding="utf-8")).get("verdict") if p.exists() else None
            todo = [j for j in jobs if saved_verdict(j) in [None] + args.rerun]
        # build the common test applications before the workers start
        build_test_app(DEFAULT_LOAD, 0xB8018300, prefix)
        build_test_app(DEFAULT_LOAD, 0xB8001300, prefix)
        print(f"Surveying {len(todo)} of {len(jobs)} images with {args.jobs} workers", flush=True)
        run_all(todo, args.jobs)
        gaps = dump_gaps(jobs)
        if gaps:
            print(f"Again with their own UART dumps (their group's representative never dumped): "
                  f"{', '.join(j['rel'] for j in gaps)}", flush=True)
            run_all(gaps, args.jobs)
    results = load_results(jobs)
    (OUT_DIR / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    import flash_survey_report
    flash_survey_report.write_reports(results, REPORT_MD, OUT_DIR / "report.html")
    print(f"Reports: {REPORT_MD} and {OUT_DIR / 'report.html'}")


if __name__ == "__main__":
    main()
