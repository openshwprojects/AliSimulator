#!/usr/bin/env python3
"""Run the distributed UART ZIP's real CLI twice against dump_maciej.bin.

Only the pyserial device is replaced by an adapter to the emulator's UART.
The extracted updater runs its own capture, SerialTransport, backup, burn,
full readback, and reboot code with the exact relative paths from its README.
No guest CPU, RAM, or flash is patched. No physical serial port is opened.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import types
from unittest.mock import patch
import uuid
import zipfile

from run_maciej_bootloader_update import SimulatorTransport

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "firmware/maciej_app/bin"
PAYLOAD = "elektroda_ali_m3801_maciej_v2.maincode.bin"


@contextmanager
def working_directory(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class EmulatedSerial:
    """pyserial boundary, leaving the production SerialTransport unchanged."""

    def __init__(self, transport, **options):
        assert options == dict(port=None, baudrate=115200, bytesize=8,
                               parity="E", stopbits=1, timeout=1,
                               write_timeout=10, rtscts=False, dsrdtr=False), options
        self.transport = transport
        self.port = options["port"]
        self.timeout = options["timeout"]
        self.dtr = self.rts = True
        self.opened = self.closed = False
        self.writes = []
        self.flushes = 0
        self.reboot_mark = None
        self._last_io = time.monotonic()

    def _resume(self):
        # A physical tuner keeps executing while the host sleeps between 'c'
        # probes or calculates a CRC. Account for that idle host time, excluding
        # time spent executing the emulator itself, before the next operation.
        elapsed = time.monotonic() - self._last_io
        deadline = self.transport.sim._vtime() + elapsed
        while self.transport.sim._vtime() < deadline:
            self.transport._advance(deadline)
        self._last_io = time.monotonic()

    def open(self):
        assert self.port == "SIMULATED_UART"
        assert self.dtr is False and self.rts is False
        self.opened = True
        self._last_io = time.monotonic()

    @property
    def in_waiting(self):
        self._resume()
        return len(self.transport.pending)

    def write(self, data):
        assert self.opened and not self.closed
        self._resume()
        self.writes.append(data)
        if data == b"comtest 2\r":
            # Recovery of the large stock image can use the existing HLE.
            # Every boot of the small supplied app uses the native decoder.
            self.transport.sim.lzma_hle = False
        if data == b"reboot\r":
            self.reboot_mark = len(self.transport.received)
        result = self.transport.write(data)
        self._last_io = time.monotonic()
        return result

    def flush(self):
        self._resume()
        self.flushes += 1
        # Finish UART transmission, as pyserial.flush() does, before allowing
        # the host to read responses. The simulator paces bytes at 115200 8E1.
        while self.transport.transmitting:
            self.transport._advance(self.transport.sim._vtime() + 0.02)
        self._last_io = time.monotonic()

    def read(self, size):
        assert self.opened and not self.closed
        self._resume()
        result = self.transport.read(size, self.timeout)
        self._last_io = time.monotonic()
        return result

    def close(self):
        self.closed = True


def run(args):
    started = time.monotonic()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    extracted = output / ("extracted_" + uuid.uuid4().hex)
    extracted.mkdir()
    sources = {"maciej_uart.py": ROOT / "tools/maciej_uart.py",
               PAYLOAD: BIN / PAYLOAD,
               "README_UART.txt": BIN / "README_UART.txt"}
    with zipfile.ZipFile(BIN / "maciej_uart_v2.zip") as bundle:
        assert bundle.testzip() is None, "Broken ZIP CRC"
        assert sorted(bundle.namelist()) == sorted(sources), "Unexpected ZIP contents"
        for name, source in sources.items():
            assert bundle.read(name) == source.read_bytes(), f"Stale ZIP member: {name}"
            (extracted / name).write_bytes(bundle.read(name))
    (extracted / "README_UART.txt").read_bytes().decode("ascii")
    help_result = subprocess.run([sys.executable, "-I", str(extracted / "maciej_uart.py"),
                                  "--help"], cwd=extracted, capture_output=True,
                                 text=True, check=True)
    assert "--capture-boot" in help_result.stdout and "flash" in help_result.stdout
    spec = importlib.util.spec_from_file_location("bundled_maciej_uart", extracted / "maciej_uart.py")
    updater = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(updater)
    payload = (extracted / PAYLOAD).read_bytes()
    updater.validate_maincode(payload)
    manifest = json.loads((BIN / "elektroda_ali_m3801_maciej_v2.json").read_text())
    assert hashlib.sha256(payload).hexdigest() == manifest["payload_sha256"]
    print("[PASS] ZIP contents, checksums, standalone CLI and payload validation", flush=True)

    source = ROOT / "dumps/dump_maciej.bin"
    original_dump = source.read_bytes()
    before = original_dump[:updater.FLASH_SIZE]
    ready_image = (BIN / "elektroda_ali_m3801_maciej_v2.bin").read_bytes()
    assert hashlib.sha256(ready_image).hexdigest() == manifest["flash_sha256"]
    current_path = source
    report = {"engine": args.engine, "zip": str(BIN / "maciej_uart_v2.zip"),
              "zip_sha256": hashlib.sha256((BIN / "maciej_uart_v2.zip").read_bytes()).hexdigest(),
              "payload_sha256": manifest["payload_sha256"], "updates": []}

    for cycle in (1, 2):
        print(f"[cycle {cycle}] running extracted CLI: capture, backup, burn, readback, reboot", flush=True)
        transport = SimulatorTransport(current_path, engine=args.engine, native_lzma=False)
        ports = []

        def serial_factory(**options):
            port = EmulatedSerial(transport, **options)
            ports.append(port)
            return port

        serial_module = types.SimpleNamespace(Serial=serial_factory, EIGHTBITS=8,
                                             PARITY_EVEN="E", STOPBITS_ONE=1)
        backup_name = f"before-maciej-v2-{cycle}.bin"
        argv = ["maciej_uart.py", "--port", "SIMULATED_UART", "--capture-boot", "60",
                "flash", PAYLOAD, "--backup", backup_name]
        try:
            with working_directory(extracted), patch.dict(sys.modules, {"serial": serial_module}), \
                    patch.object(sys, "argv", argv):
                updater.main()
        finally:
            (output / f"uart_bundle_{cycle}.log").write_bytes(transport.received)
        assert len(ports) == 1
        port = ports[0]
        assert port.opened and port.closed, "CLI did not close the serial port"
        assert port.flushes == len(port.writes)
        assert port.writes[0] == b"c", "CLI did not exercise boot capture"
        assert port.writes.count(b"dump\r") == 2, "Expected backup and verification over UART"
        assert port.writes.count(b"burn\r") == 1
        assert port.writes.count(b"address 327680\r") == 1
        assert port.reboot_mark is not None
        assert (extracted / backup_name).read_bytes() == before, "Backup differs from pre-update flash"
        actual = bytes(transport.sim.rom_image[:updater.FLASH_SIZE])
        expected = bytearray(before)
        expected[updater.MAIN_OFFSET:updater.MAIN_OFFSET + len(payload)] = payload
        assert actual == bytes(expected) == ready_image, "Flash differs from distributed image"
        reboot = transport.check_application("v2")
        reboot_log = bytes(transport.received[port.reboot_mark:])
        assert b"bl_verify_sw" in reboot_log and b"success!" in reboot_log
        assert not reboot["lzma_hle"]
        assert bytes(transport.sim.rom_image[:updater.FLASH_SIZE]) == actual
        snapshot = output / f"dump_maciej_bundle_{cycle}.bin"
        snapshot.write_bytes(actual)
        (output / f"uart_bundle_{cycle}.log").write_bytes(transport.received)
        cold = SimulatorTransport(snapshot, engine=args.engine)
        cold_boot = cold.check_application("v2")
        assert not cold_boot["lzma_hle"]
        assert bytes(cold.sim.rom_image[:updater.FLASH_SIZE]) == actual
        (output / f"uart_bundle_{cycle}_cold.log").write_bytes(cold.received)

        # A repeated command with the same backup must fail before opening a
        # serial port, preserving the recovery copy even after a valid update.
        with working_directory(extracted), patch.object(sys, "argv", argv), \
                patch.object(updater, "SerialTransport", side_effect=AssertionError("Opened UART")), \
                redirect_stdout(io.StringIO()), patch("sys.stderr", new_callable=io.StringIO):
            try:
                updater.main()
            except SystemExit as error:
                assert error.code == 2
            else:
                raise AssertionError("Existing backup was not refused")
        assert (extracted / backup_name).read_bytes() == before
        report["updates"].append({"cycle": cycle, "backup": str(extracted / backup_name),
                                  "backup_sha256": hashlib.sha256(before).hexdigest(),
                                  "flash_sha256": hashlib.sha256(actual).hexdigest(),
                                  "uart_full_dumps": 2, "capture_boot_seconds": 60,
                                  "existing_backup_refused": True,
                                  "reboot": reboot, "cold_boot": cold_boot})
        before, current_path = actual, snapshot
        print(f"[PASS] ZIP CLI cycle {cycle}: full backup/readback, native reboot/cold boot, p/v", flush=True)

    assert source.read_bytes() == original_dump, "Original dump changed"
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report_path = output / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"[PASS] Distributed ZIP installed twice through its actual CLI; report: {report_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("cpp", "unicorn"),
                        default=os.environ.get("ALISIM_ENGINE", "cpp"))
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.engine != "cpp":
        # Keep the distributed CLI's real hardware deadlines unchanged. The
        # slower Unicorn interpreter needs extended UART dump timeouts, as in
        # run_maciej_bootloader_update; this regression targets the C++ core.
        print("[NOT APPLICABLE] Portable CLI timing regression requires the C++ engine")
        return
    if args.output_dir is None:
        args.output_dir = ROOT / "build/maciej_app/selftest" / args.engine / "bundle"
    run(args)


if __name__ == "__main__":
    main()
