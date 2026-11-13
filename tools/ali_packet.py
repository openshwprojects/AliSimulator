"""ALi's packet ("format 3") UART upgrade protocol, host side.

The SDK's boot loader shell (refs/BootLoader/SRC/lib/libapplet/libbootupg3:
Packet.c, lib_ash.c, lib_ashcmd.c) speaks two protocols after 'comtest N':
the classic ASCII one (tools/maciej_uart.py) when the first handshake byte is
not '@', and this packet protocol when it is.  Loaders built with
TRANSFER_FORMAT3_ONLY speak only this one: they answer every handshake byte
with 0xFF - byte, whatever it is.

  packet   "HEAD" type(1) blank(1) index(4) repeat(1) length(4) hcrc(4)
           data(length bytes; 4 for a blank DATA packet) dcrc(4)
  hcrc     CRC-32/MPEG-2 (MG_Table_Driven_CRC from 0xFFFFFFFF) of the 11
           bytes type..length; dcrc the same of the data; numbers big-endian
  types    0 COMMAND  a command line, "dump 0 4194304\\r"
           1 DATA     BE32 packet number + bytes (blank 1: the bytes are all
                      0xFF and only the number is sent; blank 2: all 0x00)
           2 REQUEST  BE32 packet number
           3 STATUS   status byte (0 OK, 1 ERROR, 2 RUNNING, 3 EXECUTED,
                      4 CANCEL) + BE32 code
  index    a command packet carries a new non-zero index, and the packets of
           its exchange (requests, data, status) the same one; a command
           packet sent again with the same index asks for its state (STATUS
           with the last status: EXECUTED once it finished)

Commands (cmd_* in lib_ashcmd.c):
  address <offset>       STATUS OK
  transfer <length>      STATUS OK; DATA 1..n from the host, each answered
                         by STATUS OK n
  burn                   STATUS OK; DATA 0 "B####K\\n" (or "E#######\\n") for
                         every sector it programs; DATA 0 "FINISH"
  dump <start> <length>  STATUS OK; REQUEST 0 -> DATA 0 with BE32 length,
                         REQUEST k -> DATA k (1024 bytes of flash each)
  chunk                  DATA 0: flash id, CRC-bad flag, the chunk headers
  version                DATA 0: BE32 0x31
  reboot                 STATUS OK, then a watchdog reset

Transports implement write(bytes) and read(size, timeout) like
maciej_uart's; `clock` is the time base of the timeouts (time.monotonic on a
serial port, the emulator's time in the emulator).
"""
from __future__ import annotations

from dataclasses import dataclass
import struct
import time

from maciej_uart import ProtocolError, crc32_mpeg2

HEAD = b"HEAD"
COMMAND, DATA, REQUEST, STATUS = range(4)
OK, ERROR, RUNNING, EXECUTED, CANCEL = range(5)
STATUS_NAMES = {OK: "OK", ERROR: "ERROR", RUNNING: "RUNNING", EXECUTED: "EXECUTED", CANCEL: "CANCEL"}
BLOCK = 1024                                    # the loader's PACKAGE_SIZE
MAX_DATA = 2048 - 4                             # MAX_PACKET_SIZE less the data CRC the loader reads into it


@dataclass
class Packet:
    type: int
    index: int
    data: bytes
    blank: int = 0
    repeat: int = 0

    @property
    def number(self) -> int:
        """A DATA / REQUEST packet's packet number."""
        return struct.unpack(">I", self.data[:4])[0]

    @property
    def payload(self) -> bytes:
        """A DATA packet's bytes after its number."""
        return self.data[4:]

    @property
    def status(self) -> tuple[int, int]:
        """A STATUS packet's (status, code)."""
        return self.data[0], struct.unpack(">I", self.data[1:5])[0]


def encode(ptype: int, index: int, data: bytes, blank: int = 0, repeat: int = 0) -> bytes:
    head = HEAD + struct.pack(">BBIBI", ptype, blank, index, repeat, len(data))
    body = data[:4] if (blank and ptype == DATA) else data
    return (head + struct.pack(">I", crc32_mpeg2(head[4:])) +
            body + struct.pack(">I", crc32_mpeg2(body)))


class PacketClient:
    def __init__(self, transport, timeout: float = 10.0, clock=time.monotonic):
        self.transport = transport
        self.timeout = timeout
        self.clock = clock
        self.index = 0
        self.skipped = bytearray()               # bytes seen while hunting for "HEAD"

    # -- bytes
    def _read_exact(self, size: int, timeout: float) -> bytes:
        exact = getattr(self.transport, "read_exact", None)
        if exact is not None:                    # (the emulator's wire: one call per field)
            data = exact(size, timeout)
            if len(data) < size:
                raise TimeoutError(f"UART timeout: expected {size} bytes, received {len(data)}")
            return data
        deadline = self.clock() + timeout
        out = bytearray()
        while len(out) < size:
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise TimeoutError(f"UART timeout: expected {size} bytes, received {len(out)}")
            part = self.transport.read(size - len(out), remaining)
            if not part and self.clock() >= deadline:
                raise TimeoutError(f"UART timeout: expected {size} bytes, received {len(out)}")
            out += part
        return bytes(out)

    # -- packets
    def send(self, ptype: int, data: bytes, index: int | None = None) -> None:
        self.transport.write(encode(ptype, self.index if index is None else index, data))

    def receive(self, timeout: float | None = None) -> Packet:
        timeout = self.timeout if timeout is None else timeout
        deadline = self.clock() + timeout
        hunt = bytearray(self._read_exact(4, timeout))
        while not hunt.endswith(HEAD):            # the sync word
            remaining = deadline - self.clock()
            if remaining <= 0:
                self.skipped += hunt
                raise TimeoutError(f"no packet within {timeout} s")
            hunt += self._read_exact(1, remaining)
        self.skipped += hunt[:-4]
        head = self._read_exact(15, self.timeout)
        ptype, blank, index, repeat, length, hcrc = struct.unpack(">BBIBII", head)
        if crc32_mpeg2(head[:11]) != hcrc:
            raise ProtocolError(f"packet header CRC mismatch ({head.hex()})")
        n = 4 if (blank and ptype == DATA) else length
        if n > MAX_DATA + 4:
            raise ProtocolError(f"packet length {length} too large")
        body = self._read_exact(n + 4, self.timeout)
        data, dcrc = body[:n], struct.unpack(">I", body[n:])[0]
        if crc32_mpeg2(data) != dcrc:
            raise ProtocolError(f"packet data CRC mismatch (type {ptype}, {n} bytes)")
        if ptype == DATA and blank in (1, 2):
            data = data[:4] + (b"\xFF" if blank == 1 else b"\x00") * (length - 4)
        return Packet(ptype, index, data, blank, repeat)

    def expect_status(self, timeout: float | None = None, code: int | None = None) -> Packet:
        """The next STATUS packet of the current exchange; ProtocolError on ERROR."""
        while True:
            p = self.receive(timeout)
            if p.type != STATUS or p.index != self.index:
                continue                          # (a stale packet of an earlier exchange)
            status, value = p.status
            if status == ERROR:
                raise ProtocolError(f"the loader reports an error, code 0x{value:x}")
            if code is None or value == code:
                return p

    # -- the shell
    def handshake(self) -> None:
        """'comtest 2' (echoed), then '@' and one more byte, each answered
        with 0xFF - byte: the packet protocol from here on."""
        self.transport.write(b"comtest 2\r")
        echo = self._read_exact(10, self.timeout)
        if echo != b"comtest 2\r":
            raise ProtocolError(f"expected the comtest echo, received {echo!r}")
        self.transport.write(b"@X")
        reply = self._read_exact(2, self.timeout)
        if reply != bytes([0xFF - 0x40, 0xFF - 0x58]):
            raise ProtocolError(f"expected the packet protocol's handshake reply bf a7, received {reply.hex()}")
        self.index = 0

    def command(self, line: str) -> None:
        """Send a command line in a COMMAND packet with a new index."""
        self.index = self.index % 0xFFFFFFFF + 1
        self.send(COMMAND, line.encode("ascii") + b"\r")

    def address(self, offset: int) -> None:
        self.command(f"address {offset}")
        self.expect_status()

    def transfer(self, data: bytes, block: int = BLOCK, retries: int = 5) -> None:
        self.command(f"transfer {len(data)}")
        self.expect_status(code=0)
        for number, pos in enumerate(range(0, len(data), block), 1):
            packet = struct.pack(">I", number) + data[pos:pos + block]
            for attempt in range(retries):
                self.send(DATA, packet)
                try:
                    self.expect_status(code=number)
                    break
                except (TimeoutError, ProtocolError):
                    if attempt == retries - 1:
                        raise

    def burn(self, timeout: float = 600.0) -> list[str]:
        """Program what transfer staged; the loader's progress records."""
        self.command("burn")
        self.expect_status(code=0)
        progress = []
        while True:
            p = self.receive(timeout)
            if p.index != self.index:
                continue
            if p.type == STATUS and p.status[0] == ERROR:
                raise ProtocolError(f"burn failed, code 0x{p.status[1]:x} ({progress})")
            if p.type == DATA:
                text = p.payload.decode("latin-1")
                if text == "FINISH":
                    return progress
                progress.append(text.strip())
                if text.startswith("E"):
                    raise ProtocolError(f"burn reports {text.strip()} ({progress})")

    def dump(self, start: int, length: int, timeout: float | None = None, retries: int = 5) -> bytes:
        self.command(f"dump {start} {length}")
        self.expect_status(code=0)
        total = self._request(0, timeout, retries)
        total = struct.unpack(">I", total.payload[:4])[0]
        if total != length:
            raise ProtocolError(f"the loader offers {total} bytes, {length} asked for")
        out = bytearray()
        number = 1
        while len(out) < total:
            p = self._request(number, timeout, retries)
            out += p.payload
            number += 1
        return bytes(out[:total])

    def _request(self, number: int, timeout: float | None, retries: int) -> Packet:
        for attempt in range(retries):
            self.send(REQUEST, struct.pack(">I", number))
            try:
                while True:
                    p = self.receive(timeout)
                    if p.type == DATA and p.index == self.index and p.number == number:
                        return p
            except (TimeoutError, ProtocolError):
                if attempt == retries - 1:
                    raise
        raise AssertionError("unreachable")

    def chunk_table(self) -> bytes:
        """The loader's 'chunk' reply: flash id, CRC-bad flag, the chunk headers."""
        self.command("chunk")
        while True:
            p = self.receive()
            if p.index == self.index and p.type == DATA:
                return p.payload
            if p.index == self.index and p.type == STATUS and p.status[0] == ERROR:
                raise ProtocolError(f"chunk failed, code 0x{p.status[1]:x}")

    def reboot(self) -> None:
        self.command("reboot")
        self.expect_status()
