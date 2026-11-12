"""Classic ALi UART updater used by dump_maciej.bin (Opticum HD N2).

The serial settings are 115200 8E1. The protocol is ASCII commands with echo,
1024-byte data blocks and
CRC-32/MPEG-2 in big-endian order. This client deliberately only writes the
maincode chunk at 0x50000..0x28ffff, preserving the original recovery loader.
See refs/BootLoader/SRC/lib/libapplet/libbootupg3/lib_ashcmd.c, *_old handlers.

Transports implement write(bytes) and read(size, timeout_seconds). No hardware
is opened by importing this module. The CLI requires an explicit serial port.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct
import time
from typing import Protocol

FLASH_SIZE = 0x400000
MAIN_OFFSET = 0x50000
MAIN_SPAN = 0x240000
MAIN_ID = 0x01FE0101
BLOCK_SIZE = 1024
# Excludes the HDCP-key chunk at 0x4fe00, which can differ between units.
LOADER_SIZE = 0x4FE00
LOADER_SHA256 = "6e1489a037dfe702a775912ee8eaabc14030b8f3cd65397792b3f217f6f29fa4"


def _crc_table() -> tuple[int, ...]:
    table = []
    for value in range(256):
        crc = value << 24
        for _ in range(8):
            crc = ((crc << 1) ^ (0x04C11DB7 if crc & 0x80000000 else 0)) & 0xFFFFFFFF
        table.append(crc)
    return tuple(table)


_CRC_TABLE = _crc_table()


def crc32_mpeg2(data: bytes, initial: int = 0xFFFFFFFF) -> int:
    """ALi MG_Table_Driven_CRC: poly 04c11db7, nonreflected, xorout=0."""
    crc = initial
    for value in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _CRC_TABLE[((crc >> 24) ^ value) & 0xFF]
    return crc


class Transport(Protocol):
    def write(self, data: bytes) -> object: ...
    def read(self, size: int, timeout: float) -> bytes: ...


class ProtocolError(RuntimeError):
    """Unexpected reply, CRC mismatch, or unsafe update request."""


def validate_maincode(payload: bytes, offset: int = MAIN_OFFSET) -> int:
    """Validate the chunk and the *effective* burn range; return chunk span.

    The loader advances its staging pointer by header.offset, not by the number
    of transferred bytes. A corrupt header could otherwise erase the loader or
    adjacent settings even when the UART transfer itself is short.
    """
    if offset != MAIN_OFFSET:
        raise ValueError(f"only maincode offset 0x{MAIN_OFFSET:x} is writable")
    if not 128 <= len(payload) <= MAIN_SPAN:
        raise ValueError("expected a maincode chunk payload, not a full flash image")
    chunk_id, length, span, expected_crc = struct.unpack_from(">4I", payload)
    if chunk_id != MAIN_ID or span != MAIN_SPAN:
        raise ValueError("maincode chunk ID/span does not match dump_maciej.bin")
    if length < 112 or length + 16 > len(payload):
        raise ValueError("payload does not contain the complete maincode chunk")
    actual_crc = crc32_mpeg2(payload[16:16 + length])
    if actual_crc != expected_crc:
        raise ValueError(f"maincode CRC mismatch: {actual_crc:08x} != {expected_crc:08x}")
    return span


def validate_target_flash(data: bytes) -> None:
    """Require the exact loader studied here before using its write protocol."""
    if len(data) != FLASH_SIZE:
        raise ValueError("target flash must be exactly 4 MiB")
    if hashlib.sha256(data[:LOADER_SIZE]).hexdigest() != LOADER_SHA256:
        raise ValueError("target bootloader differs from dump_maciej.bin; refusing to flash")
    chunk_id, _, span = struct.unpack_from(">3I", data, MAIN_OFFSET)
    if chunk_id != MAIN_ID or span != MAIN_SPAN:
        raise ValueError("target maincode partition does not match the supported layout")


class BootloaderClient:
    """Client for an already interrupted bootloader, with bounded retries.

    handshake() selects/checks the classic protocol. Boot entry is separate:
    send ASCII 'c' during the loader's boot window. Simulator tests queue it
    before running the reset vector; on a board use capture_boot() while cycling
    power, or while the v3 application is already running. Calling dump() never modifies flash.
    """

    def __init__(self, transport: Transport, timeout: float = 10,
                 burn_timeout: float = 120, dump_timeout: float = 600):
        self.transport = transport
        self.timeout = timeout
        self.burn_timeout = burn_timeout
        self.dump_timeout = dump_timeout
        self._address: int | None = None
        self._staged: bytes | None = None

    def _read_exact(self, size: int, timeout: float | None = None) -> bytes:
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        result = bytearray()
        while len(result) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"UART timeout: expected {size} bytes, received {len(result)}")
            part = self.transport.read(size - len(result), remaining)
            if not part:
                raise TimeoutError(f"UART timeout: expected {size} bytes, received {len(result)}")
            if len(part) > size - len(result):
                raise ProtocolError("transport returned more bytes than requested")
            result.extend(part)
        return bytes(result)

    def _expect(self, expected: bytes, timeout: float | None = None) -> None:
        actual = self._read_exact(len(expected), timeout)
        if actual != expected:
            raise ProtocolError(f"expected {expected!r}, received {actual!r}")

    def _command(self, command: str) -> None:
        raw = command.encode("ascii") + b"\r"
        self.transport.write(raw)
        self._expect(raw)

    def capture_boot(self, seconds: float = 5) -> bytes:
        """Send paced 'c' for startup or v3 software capture, then clear echoes.

        This helper uses wall time and is for serial transports, not simulated
        time. It does not toggle power, reset lines, DTR, or RTS.
        """
        if not 0 < seconds <= 60:
            raise ValueError("boot capture must be between 0 and 60 seconds")
        # Capture normally accompanies a power cycle, so previously staged RAM
        # cannot be trusted even if capture or its eventual handshake fails.
        self._address = None
        self._staged = None
        deadline = time.monotonic() + seconds
        received = bytearray()
        while time.monotonic() < deadline:
            probe_started = time.monotonic()
            self.transport.write(b"c")
            received.extend(self.transport.read(4096, 0.05))
            # SerialTransport returns promptly when an echo is available. A
            # read timeout alone therefore does not pace probes and can flood
            # the loader's command buffer as soon as it starts echoing.
            pause = min(deadline, probe_started + 0.05) - time.monotonic()
            if pause > 0:
                time.sleep(pause)
        self.transport.write(b"\r")
        drain_deadline = time.monotonic() + 2.0
        while time.monotonic() < drain_deadline:
            data = self.transport.read(4096, 0.2)
            if not data:
                break
            received.extend(data)
        else:
            raise ProtocolError("UART did not become quiet after boot capture")
        return bytes(received)

    def handshake(self) -> None:
        self._address = None
        self._staged = None
        # Two bytes also satisfy SDK variants that inspect the first two bytes
        # to choose old/new transfer format. '@' would select the HEAD protocol.
        self._command("comtest 2")
        self.transport.write(b"XX")
        self._expect(b"XX")

    def dump(self) -> bytes:
        self._command("dump")
        size, = struct.unpack(">I", self._read_exact(4))
        if size != FLASH_SIZE:
            # Decline the dump before its long binary stream begins.
            self.transport.write(b"E")
            raise ProtocolError(f"unexpected flash size 0x{size:x}; expected 4 MiB")
        self.transport.write(b"O")
        data = self._read_exact(size, self.dump_timeout)
        expected, = struct.unpack(">I", self._read_exact(4))
        actual = crc32_mpeg2(data)
        if actual != expected:
            raise ProtocolError(f"dump CRC mismatch: {actual:08x} != {expected:08x}")
        return data

    def address(self, offset: int = MAIN_OFFSET) -> None:
        if offset != MAIN_OFFSET:
            raise ValueError(f"only maincode offset 0x{MAIN_OFFSET:x} is writable")
        self._address = None
        self._staged = None
        # Firmware ali_atoi is decimal-only: '0x50000' would mean ZERO.
        self._command(f"address {offset:d}")
        self._expect(b"O")
        self._address = offset

    def transfer(self, payload: bytes, retries: int = 2) -> None:
        if not 0 <= retries <= 2:
            raise ValueError("retries must be between 0 and 2")
        if self._address is None:
            raise ProtocolError("address() is required before transfer()")
        if self._staged is not None:
            raise ProtocolError("call address() again before staging another image")
        validate_maincode(payload, self._address)
        try:
            self._command(f"transfer {len(payload):d}")
            self._expect(b"O")
            for offset in range(0, len(payload), BLOCK_SIZE):
                block = payload[offset:offset + BLOCK_SIZE]
                wire = block + struct.pack(">I", crc32_mpeg2(block))
                for attempt in range(retries + 1):
                    self.transport.write(wire)
                    answer = self._read_exact(1)
                    if answer == b"O":
                        break
                    if answer != b"E" or attempt == retries:
                        raise ProtocolError(f"block {offset // BLOCK_SIZE}: reply {answer!r}")
                # Each O acknowledges this block and requests the next, except
                # the final O which announces completed staging.
            self._staged = bytes(payload)
        except Exception:
            # State after a partial transfer is uncertain; prohibit burning it.
            self._address = None
            self._staged = None
            raise

    def burn(self) -> list[str]:
        if self._address is None or self._staged is None:
            raise ProtocolError("a complete validated transfer is required before burn()")
        # Invalidate before transmitting: an absent ACK does not prove that
        # erase/program did not begin, so an ambiguous burn must never retry.
        self._address = None
        self._staged = None
        self._command("burn")
        self._expect(b"O")
        progress: list[str] = []
        line = bytearray()
        deadline = time.monotonic() + self.burn_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("burn did not send final F")
            value = self._read_exact(1, remaining)
            if value == b"F" and not line:
                if any(item.startswith("E") for item in progress):
                    raise ProtocolError("flash program/verify error: " + ", ".join(progress))
                return progress
            line.extend(value)
            if len(line) > 128:
                raise ProtocolError(f"invalid burn progress: {bytes(line)!r}")
            if value == b"\n":
                entry = bytes(line).decode("ascii", errors="replace").rstrip("\r\n")
                if not entry.startswith(("B", "E")):
                    raise ProtocolError(f"unexpected burn progress: {entry!r}")
                progress.append(entry)
                line.clear()

    def flash(self, offset: int, payload: bytes) -> list[str]:
        validate_maincode(payload, offset)
        self.address(offset)
        self.transfer(payload)
        return self.burn()

    def reboot(self) -> None:
        self._address = None
        self._staged = None
        self._command("reboot")
        self._expect(b"O")


class SerialTransport:
    """Optional pyserial adapter; the port is opened only on construction."""

    def __init__(self, port: str, baud: int = 115200):
        try:
            import serial
        except ImportError as error:
            raise RuntimeError("serial CLI requires pyserial: python -m pip install pyserial") from error
        self.serial = serial.Serial(port=None, baudrate=baud,
                                    bytesize=serial.EIGHTBITS, parity=serial.PARITY_EVEN,
                                    stopbits=serial.STOPBITS_ONE, timeout=1,
                                    write_timeout=10, rtscts=False, dsrdtr=False)
        self.serial.dtr = False
        self.serial.rts = False
        self.serial.port = port
        self.serial.open()

    def write(self, data: bytes) -> None:
        if self.serial.write(data) != len(data):
            raise ProtocolError("short serial write")
        self.serial.flush()

    def read(self, size: int, timeout: float) -> bytes:
        self.serial.timeout = timeout
        # Return currently available data promptly; the client assembles reads.
        return self.serial.read(min(size, max(1, self.serial.in_waiting)))

    def close(self) -> None:
        self.serial.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="explicit port, e.g. COM3")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--capture-boot", type=float, default=0, metavar="SECONDS",
                        help="send paced 'c'; running Maciej v3 restarts automatically, older firmware needs power cycling")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("probe", help="check the classic comtest echo only")
    dump_parser = sub.add_parser("dump", help="read and CRC-check the full 4 MiB flash")
    dump_parser.add_argument("output", type=Path)
    flash_parser = sub.add_parser("flash", help="replace only maincode, dump-verify, and reboot")
    flash_parser.add_argument("payload", type=Path)
    flash_parser.add_argument("--backup", type=Path, required=True,
                              help="save a complete CRC-checked backup before flashing")
    flash_parser.add_argument("--stay", action="store_true", help="remain in bootloader after verification")
    args = parser.parse_args()
    payload = None
    if args.action == "flash":
        payload = args.payload.read_bytes()
        validate_maincode(payload)
        if args.backup.exists():
            parser.error("backup path already exists; choose a new path to preserve it")
    if args.action == "dump" and args.output.exists():
        parser.error("output already exists; choose a new path")
    transport = SerialTransport(args.port, args.baud)
    try:
        client = BootloaderClient(transport)
        if args.capture_boot:
            print(f"Capturing boot for {args.capture_boot:g} seconds. Running Maciej v3 restarts automatically; otherwise power on or power-cycle the tuner now.", flush=True)
            client.capture_boot(args.capture_boot)
        client.handshake()
        print("Classic bootloader handshake OK", flush=True)
        if args.action == "dump":
            print("Reading 4 MiB flash and CRC (about 7 minutes at 115200 8E1)...", flush=True)
            data = client.dump()
            with args.output.open("xb") as output:
                output.write(data)
            print(f"Saved {len(data)} bytes; CRC {crc32_mpeg2(data):08x}")
        elif args.action == "flash":
            print("Reading the backup and checking loader identity (about 7 minutes at 115200 8E1)...", flush=True)
            before = client.dump()
            validate_target_flash(before)
            with args.backup.open("xb") as backup:
                backup.write(before)
            print(f"Backup saved to {args.backup}; transferring and burning maincode...", flush=True)
            for line in client.flash(MAIN_OFFSET, payload):
                print(line)
            print("Reading all 4 MiB back for verification (about 7 minutes at 115200 8E1)...", flush=True)
            after = client.dump()
            expected = bytearray(before)
            expected[MAIN_OFFSET:MAIN_OFFSET + len(payload)] = payload
            if after != expected:
                raise ProtocolError("readback differs from expected flash; device left in bootloader")
            print("Full flash readback verified; loader and settings unchanged.")
            if not args.stay:
                client.reboot()
    finally:
        transport.close()


if __name__ == "__main__":
    main()
