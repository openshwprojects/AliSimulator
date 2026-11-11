"""Host-side protocol safety and framing tests; no serial port is opened."""
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from maciej_uart import (
    BLOCK_SIZE, BootloaderClient, FLASH_SIZE, MAIN_ID, MAIN_OFFSET, MAIN_SPAN,
    ProtocolError, crc32_mpeg2, validate_maincode, validate_target_flash,
)


def chunk(size=1300):
    body = bytes(index % 251 for index in range(size - 16))
    return struct.pack(">4I", MAIN_ID, len(body), MAIN_SPAN, crc32_mpeg2(body)) + body


class ScriptedTransport:
    """Independent expected wire transcript, with fragmented UART reads."""
    def __init__(self, exchanges):
        self.exchanges = list(exchanges)
        self.pending = bytearray()
        self.writes = []

    def write(self, data):
        self.writes.append(data)
        if not self.exchanges:
            raise AssertionError(f"unexpected write {data!r}")
        expected, reply = self.exchanges.pop(0)
        if data != expected:
            raise AssertionError(f"wire mismatch: {data!r} != {expected!r}")
        self.pending.extend(reply)

    def read(self, size, timeout):
        part = bytes(self.pending[:min(size, 137)])
        del self.pending[:len(part)]
        return part


class MaciejUartTests(unittest.TestCase):
    def test_crc_known_vectors_and_real_capture(self):
        self.assertEqual(crc32_mpeg2(b"123456789"), 0x0376E6E7)
        raw = (ROOT / "dumps" / "dump_maciej.bin").read_bytes()
        self.assertEqual(len(raw), FLASH_SIZE + 4)
        self.assertEqual(crc32_mpeg2(raw[:-4]), 0x5FE32852)
        self.assertEqual(raw[-4:], bytes.fromhex("5fe32852"))
        validate_target_flash(raw[:-4])

    def test_decimal_commands_short_final_block_retry_and_burn(self):
        payload = chunk()
        first, last = payload[:1024], payload[1024:]
        first_wire = first + struct.pack(">I", crc32_mpeg2(first))
        last_wire = last + struct.pack(">I", crc32_mpeg2(last))
        transport = ScriptedTransport([
            (b"comtest 2\r", b"comtest 2\r"), (b"XX", b"XX"),
            (b"address 327680\r", b"address 327680\rO"),
            (b"transfer 1300\r", b"transfer 1300\rO"),
            (first_wire, b"E"), (first_wire, b"O"), (last_wire, b"O"),
            (b"burn\r", b"burn\rOB0320K\nF"),
            (b"reboot\r", b"reboot\rO"),
        ])
        client = BootloaderClient(transport)
        client.handshake()
        self.assertEqual(client.flash(MAIN_OFFSET, payload), ["B0320K"])
        client.reboot()
        self.assertFalse(transport.exchanges)
        self.assertFalse(transport.pending)

    def test_safety_checks_before_any_write(self):
        transport = ScriptedTransport([])
        client = BootloaderClient(transport)
        for offset in (0, 0x10000, MAIN_OFFSET - 1, 0x290000):
            with self.assertRaises(ValueError):
                client.flash(offset, chunk())
        bad_span = bytearray(chunk())
        struct.pack_into(">I", bad_span, 8, 0x400000)
        bad_crc = bytearray(chunk())
        bad_crc[-1] ^= 1
        for payload in (bytes(bad_span), bytes(bad_crc), b"X" * FLASH_SIZE):
            with self.assertRaises(ValueError):
                client.flash(MAIN_OFFSET, payload)
        with self.assertRaises(ProtocolError):
            client.burn()
        self.assertFalse(transport.writes)

    def test_failed_transfer_cannot_burn(self):
        payload = chunk(128)
        wire = payload + struct.pack(">I", crc32_mpeg2(payload))
        transport = ScriptedTransport([
            (b"address 327680\r", b"address 327680\rO"),
            (b"transfer 128\r", b"transfer 128\rO"),
            (wire, b"E"), (wire, b"E"), (wire, b"E"),
        ])
        client = BootloaderClient(transport)
        client.address()
        with self.assertRaises(ProtocolError):
            client.transfer(payload)
        with self.assertRaises(ProtocolError):
            client.burn()
        self.assertFalse(transport.exchanges)

    def test_failed_transfer_command_requires_new_address(self):
        for reply in (b"wrong command!", b"transfer 128\r"):
            with self.subTest(reply=reply):
                transport = ScriptedTransport([
                    (b"address 327680\r", b"address 327680\rO"),
                    (b"transfer 128\r", reply),
                ])
                client = BootloaderClient(transport)
                client.address()
                with self.assertRaises((ProtocolError, TimeoutError)):
                    client.transfer(chunk(128))
                with self.assertRaisesRegex(ProtocolError, "address"):
                    client.transfer(chunk(128))
                with self.assertRaises(ProtocolError):
                    client.burn()
                self.assertFalse(transport.exchanges)

    def test_failed_handshake_or_reboot_invalidates_staged_image(self):
        payload = chunk(128)
        for method, command in (("handshake", b"comtest 2\r"),
                                ("reboot", b"reboot\r")):
            with self.subTest(method=method):
                transport = ScriptedTransport([
                    (b"address 327680\r", b"address 327680\rO"),
                    (b"transfer 128\r", b"transfer 128\rO"),
                    (payload + struct.pack(">I", crc32_mpeg2(payload)), b"O"),
                    (command, b""),
                ])
                client = BootloaderClient(transport)
                client.address()
                client.transfer(payload)
                with self.assertRaises(TimeoutError):
                    getattr(client, method)()
                with self.assertRaises(ProtocolError):
                    client.burn()
                self.assertFalse(transport.exchanges)

    def test_capture_paces_immediate_echoes_and_invalidates_staging(self):
        payload = chunk(128)
        transport = ScriptedTransport([
            (b"address 327680\r", b"address 327680\rO"),
            (b"transfer 128\r", b"transfer 128\rO"),
            (payload + struct.pack(">I", crc32_mpeg2(payload)), b"O"),
        ])
        client = BootloaderClient(transport)
        client.address()
        client.transfer(payload)

        # A serial adapter may return an echo immediately; it must not let
        # that accelerate capture probes into an unbounded command stream.
        now = [0.0]
        sent = []
        pending = bytearray()

        def write(data):
            sent.append((now[0], data))
            pending.extend(data)

        def read(size, timeout):
            if not pending:
                now[0] += timeout
            else:
                # Model finite wire time so a missing pacing guard fails the
                # assertion below instead of making this regression hang.
                now[0] += 0.001
            result = bytes(pending[:size])
            del pending[:len(result)]
            return result

        def sleep(seconds):
            now[0] += seconds

        with patch.object(transport, "write", side_effect=write), \
                patch.object(transport, "read", side_effect=read), \
                patch("maciej_uart.time.monotonic", side_effect=lambda: now[0]), \
                patch("maciej_uart.time.sleep", side_effect=sleep):
            self.assertEqual(client.capture_boot(0.2), b"cccc\r")
        probes = [when for when, data in sent if data == b"c"]
        self.assertEqual(len(probes), 4)
        self.assertTrue(all(b - a >= 0.049 for a, b in zip(probes, probes[1:])))
        self.assertEqual(sent[-1][1], b"\r")
        with self.assertRaises(ProtocolError):
            client.burn()

    def test_burn_reports_device_verify_failure(self):
        payload = chunk(128)
        transport = ScriptedTransport([
            (b"address 327680\r", b"address 327680\rO"),
            (b"transfer 128\r", b"transfer 128\rO"),
            (payload + struct.pack(">I", crc32_mpeg2(payload)), b"O"),
            (b"burn\r", b"burn\rOE0327680\nF"),
        ])
        client = BootloaderClient(transport)
        with self.assertRaisesRegex(ProtocolError, "verify error"):
            client.flash(MAIN_OFFSET, payload)
        with self.assertRaises(ProtocolError):
            client.burn()

    def test_lost_burn_ack_cannot_retry(self):
        payload = chunk(128)
        transport = ScriptedTransport([
            (b"address 327680\r", b"address 327680\rO"),
            (b"transfer 128\r", b"transfer 128\rO"),
            (payload + struct.pack(">I", crc32_mpeg2(payload)), b"O"),
            (b"burn\r", b"burn\r"),
        ])
        client = BootloaderClient(transport)
        with self.assertRaises(TimeoutError):
            client.flash(MAIN_OFFSET, payload)
        with self.assertRaises(ProtocolError):
            client.burn()
        self.assertFalse(transport.exchanges)

    def test_dump_crc_and_exact_binary_framing(self):
        raw = (ROOT / "dumps" / "dump_maciej.bin").read_bytes()
        transport = ScriptedTransport([
            (b"dump\r", b"dump\r" + struct.pack(">I", FLASH_SIZE)),
            (b"O", raw),
        ])
        self.assertEqual(BootloaderClient(transport).dump(), raw[:-4])
        self.assertFalse(transport.pending)

    def test_dump_declines_unrecognized_size(self):
        transport = ScriptedTransport([
            (b"dump\r", b"dump\r" + struct.pack(">I", 0x800000)), (b"E", b""),
        ])
        with self.assertRaisesRegex(ProtocolError, "flash size"):
            BootloaderClient(transport).dump()

    def test_target_loader_mismatch_refused(self):
        raw = bytearray((ROOT / "dumps" / "dump_maciej.bin").read_bytes()[:-4])
        raw[0x1000] ^= 1
        with self.assertRaisesRegex(ValueError, "bootloader differs"):
            validate_target_flash(raw)

    def test_short_or_wrong_echo_fails_closed(self):
        for echo in (b"comtest 2\r"[:-1], b"wrong echo"):
            transport = ScriptedTransport([(b"comtest 2\r", echo)])
            with self.assertRaises((TimeoutError, ProtocolError)):
                BootloaderClient(transport).handshake()


if __name__ == "__main__":
    unittest.main()
