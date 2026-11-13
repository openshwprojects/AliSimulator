#!/usr/bin/env python3
"""
tools/ali_packet.py (ALi's packet "format 3" UART upgrade protocol, host side)
against a model of the loader side written from the SDK's sources
(refs/BootLoader/SRC/lib/libapplet/libbootupg3: Packet.c, lib_ash.c,
lib_ashcmd.c), without the emulator:

  framing   - a packet's bytes: "HEAD", the header fields, both CRC-32/MPEG-2
              sums, big-endian numbers; a corrupted header or data CRC is
              refused; a blank DATA packet (blank flag 1) is 0xFF-filled
  handshake - 'comtest 2' echoed, '@X' answered bf a7
  dump      - REQUEST 0 gives the length, REQUEST k the k-th 1024 bytes;
              all-0xFF blocks arrive as blank packets
  write     - address + transfer (DATA packets, each acknowledged with its
              number) + burn (progress records, FINISH) change exactly the
              transferred range; a lost acknowledgement is retried
  errors    - a STATUS ERROR fails the command
The emulator runs of the real loaders are in tools/bootloader_flash_survey.py
(tests/run_flash_survey_sample.py, tests/run_packet_protocol_amiko.py).
"""
import os
import struct
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "tools"))

import ali_packet as ap                                  # noqa: E402
from maciej_uart import ProtocolError, crc32_mpeg2       # noqa: E402

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}", flush=True)
    if not ok:
        failures.append(text)


class FakeLoader:
    """The loader's side of the protocol, as lib_ashcmd.c's cmd_* handlers
    answer it (synchronously: every host write is answered at once)."""

    def __init__(self, flash: bytes):
        self.flash = bytearray(flash)
        self.out = bytearray()
        self.inbuf = bytearray()
        self.index = 0                      # g_packet_index
        self.mode = None                    # the running command's loop
        self.start = None
        self.staged = bytearray()
        self.expected = 0
        self.received = 0
        self.dump_len = 0
        self.drop_next_ack = False
        self.fail_address = False
        self.comtest = False

    # host -> loader
    def write(self, data):
        self.inbuf += data
        while self._step():
            pass
        return len(data)

    def read(self, size, timeout):
        n = min(size, len(self.out))
        data = bytes(self.out[:n])
        del self.out[:n]
        return data

    def _status(self, status, code):
        self.out += ap.encode(ap.STATUS, self.index, bytes([status]) + struct.pack(">I", code))

    def _data(self, number, payload):
        blank = 1 if payload and all(b == 0xFF for b in payload) else 0
        self.out += ap.encode(ap.DATA, self.index, struct.pack(">I", number) + payload, blank=blank)

    def _step(self):
        buf = self.inbuf
        if self.comtest:                    # cmd_comtest: 0xFF - byte, twice
            if len(buf) < 2:
                return False
            self.out += bytes([0xFF - buf[0], 0xFF - buf[1]])
            del buf[:2]
            self.comtest = False
            self.index = 0
            return True
        if buf.startswith(b"comtest 2\r"):
            self.out += b"comtest 2\r"
            del buf[:10]
            self.comtest = True
            return True
        if len(buf) < 19 or not buf.startswith(b"HEAD"):
            return False
        ptype, blank, index, repeat, length, hcrc = struct.unpack(">BBIBII", bytes(buf[4:19]))
        assert crc32_mpeg2(bytes(buf[4:15])) == hcrc, "host header CRC"
        n = 4 if (blank and ptype == ap.DATA) else length
        if len(buf) < 19 + n + 4:
            return False
        data = bytes(buf[19:19 + n])
        assert crc32_mpeg2(data) == struct.unpack(">I", bytes(buf[19 + n:23 + n]))[0], "host data CRC"
        del buf[:23 + n]
        self._packet(ptype, index, data)
        return True

    def _packet(self, ptype, index, data):
        if ptype == ap.COMMAND and index != self.index:
            self.index = index
            words = data.rstrip(b"\r\n").decode().split()
            cmd = words[0]
            if cmd == "address":
                if self.fail_address:
                    self._status(ap.ERROR, 0x12)
                    return
                self.start = int(words[1])
                self.staged = bytearray()
                self._status(ap.OK, 0)
            elif cmd == "transfer":
                self.expected, self.received, self.mode = int(words[1]), 0, "transfer"
                self._status(ap.OK, 0)
            elif cmd == "burn":
                self._status(ap.OK, 0)
                end = self.start + len(self.staged)
                for sector in range(self.start & ~0xFFFF, end, 0x10000):
                    self._data(0, f"B{sector >> 10:04d}K\n".encode())
                self.flash[self.start:end] = self.staged
                self._data(0, b"FINISH")
            elif cmd == "dump":
                self.start, self.dump_len, self.mode = int(words[1]), int(words[2]), "dump"
                self._status(ap.OK, 0)
            elif cmd == "reboot":
                self._status(ap.OK, 0)
            return
        if index != self.index:
            return
        if self.mode == "transfer" and ptype == ap.DATA:
            number = struct.unpack(">I", data[:4])[0]
            if number == self.received + 1:
                self.received += 1
                self.staged += data[4:]
            if self.drop_next_ack:          # the acknowledgement is lost on the line
                self.drop_next_ack = False
                return
            self._status(ap.OK, self.received)
        elif self.mode == "dump" and ptype == ap.REQUEST:
            number = struct.unpack(">I", data[:4])[0]
            if number == 0:
                self._data(0, struct.pack(">I", self.dump_len))
            else:
                pos = self.start + (number - 1) * ap.BLOCK
                self._data(number, bytes(self.flash[pos:min(pos + ap.BLOCK, self.start + self.dump_len)]))


print("=== tools/ali_packet.py: the packet protocol against a model of the SDK's loader ===")

# framing
pkt = ap.encode(ap.COMMAND, 7, b"dump 0 1024\r")
head = pkt[:19]
check(head[:4] == b"HEAD" and head[4] == ap.COMMAND and head[5] == 0 and
      struct.unpack(">I", head[6:10])[0] == 7 and struct.unpack(">I", head[11:15])[0] == 12,
      "a COMMAND packet: HEAD, type 0, blank 0, BE32 index 7, BE32 length 12")
check(struct.unpack(">I", head[15:19])[0] == crc32_mpeg2(head[4:15]) and
      struct.unpack(">I", pkt[-4:])[0] == crc32_mpeg2(b"dump 0 1024\r"),
      "header CRC over type..length, data CRC over the data (CRC-32/MPEG-2)")
check(crc32_mpeg2(b"123456789") == 0x0376E6E7, "CRC-32/MPEG-2 check value 0376e6e7")


class Bytes:
    def __init__(self, data):
        self.data = bytearray(data)

    def write(self, data):
        return len(data)

    def read(self, size, timeout):
        part = bytes(self.data[:size])
        del self.data[:size]
        return part


blank = ap.encode(ap.DATA, 3, struct.pack(">I", 5) + b"\xFF" * 1024, blank=1)
check(len(blank) == 19 + 4 + 4, "a blank DATA packet carries only its number (27 bytes)")
p = ap.PacketClient(Bytes(b"noise" + blank), timeout=1).receive()
check(p.type == ap.DATA and p.number == 5 and p.payload == b"\xFF" * 1024,
      "received: noise before HEAD skipped, the blank packet's 1024 bytes filled with 0xFF")
bad = bytearray(ap.encode(ap.STATUS, 1, b"\x00\x00\x00\x00\x00"))
bad[8] ^= 1
try:
    ap.PacketClient(Bytes(bad), timeout=1).receive()
    check(False, "a corrupted header is refused")
except ProtocolError:
    check(True, "a corrupted header is refused (header CRC)")
bad = bytearray(ap.encode(ap.STATUS, 1, b"\x00\x00\x00\x00\x00"))
bad[20] ^= 1
try:
    ap.PacketClient(Bytes(bad), timeout=1).receive()
    check(False, "corrupted data is refused")
except ProtocolError:
    check(True, "corrupted data is refused (data CRC)")

# the shell
flash = bytes((i * 7) & 0xFF for i in range(0x30000)) + b"\xFF" * 0x10000
loader = FakeLoader(flash)
client = ap.PacketClient(loader, timeout=1)
client.handshake()
check(loader.index == 0 and not loader.comtest, "handshake: 'comtest 2' echoed, '@X' answered bf a7")
data = client.dump(0, len(flash))
check(data == flash, f"dump of {len(flash)} bytes: REQUEST 0 = length, then {len(flash) // 1024} packets, "
                     f"the 0xFF tail as blank packets")
check(client.index == 1, "the dump command carried index 1, its requests the same")
payload = bytes(range(256)) * 20 + b"tail"
client.address(0x20000)
loader.drop_next_ack = True
client.transfer(payload)
check(bytes(loader.staged) == payload and loader.received == (len(payload) + 1023) // 1024,
      "transfer: 6 DATA packets, each acknowledged with its number; a lost acknowledgement is retried")
progress = client.burn()
expected = bytearray(flash)
expected[0x20000:0x20000 + len(payload)] = payload
check(progress == ["B0128K"] and bytes(loader.flash) == bytes(expected),
      "burn: one progress record (B0128K), FINISH; the flash changed exactly in the transferred range")
check(client.dump(0x20000, len(payload)) == payload, "a readback dump of the written range")
client.reboot()
check(client.index == 6, "reboot answered; each command had a new index (dump, address, transfer, burn, "
                         "dump, reboot: 1..6)")
loader.fail_address = True
try:
    client.address(0x10000)
    check(False, "a STATUS ERROR fails the command")
except ProtocolError as exc:
    check("0x12" in str(exc), "a STATUS ERROR fails the command (code 0x12)")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] the packet protocol client")
