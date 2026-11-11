#!/usr/bin/env python3
"""Flash two RAM applications through dump_maciej's original UART bootloader.

No guest PC, RAM, or flash is patched. The only inputs to the running machine
are UART bytes. Flash snapshots are read back after the guest's own burn
command and loaded into fresh machines to check persistence across power loss.
"""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from simulator import AliMipsSimulator, resolve_dump
from maciej_image import package_image
from maciej_uart import BootloaderClient

APP_BANNER = "ELEKTRODA ALI M3801 TEST FOR MACIEJ"


class SimulatorTransport:
    """The byte transport shared by the hardware client and this integration.

    Read timeouts are in simulated seconds; a separate wall-clock guard makes
    a stalled emulator fail instead of hanging the test indefinitely.
    """

    def __init__(self, image, *, engine="cpp", wall_timeout=180, native_lzma=True):
        self.sim = AliMipsSimulator(log_handler=lambda _message: None, engine=engine)
        self.sim.setSPIDump(False)
        self.sim.setI2CDump(False)
        # These tiny applications must exercise the actual LZMA decoder.
        self.sim.lzma_hle = not native_lzma
        self.pending = deque()
        self.transmitting = deque()
        self.received = bytearray()
        self.sent_bytes = 0
        self.wall_timeout = wall_timeout
        self.sim.setUartHandler(self._receive)
        self.sim.loadFile(str(image))

    def _receive(self, chars):
        data = chars.encode("latin-1")
        self.pending.extend(data)
        self.received.extend(data)

    def write(self, data):
        self.transmitting.extend(data)
        self.sent_bytes += len(data)
        return len(data)

    def _advance(self, deadline):
        # Real 115200 8E1 sends only about 10 KiB/s. Delivering a complete
        # packet instantaneously can overflow the firmware's software FIFO.
        count = min(16, len(self.transmitting))
        if count:
            self.sim.setUartReceiveData(bytes(self.transmitting.popleft() for _ in range(count)),
                                        delay_instructions=0)
        step = count * 11 / 115200 if count else 0.02
        self.sim.run(max_instructions=self.sim.instruction_count + 1_000_000,
                     max_vtime=min(deadline, self.sim._vtime() + step))

    def read(self, size, timeout):
        if size <= 0:
            return b""
        deadline = self.sim._vtime() + timeout
        wall_deadline = time.monotonic() + self.wall_timeout
        while not self.pending and self.sim._vtime() < deadline:
            if time.monotonic() >= wall_deadline:
                raise TimeoutError("Simulator exceeded its wall-clock guard")
            self._advance(deadline)
        return bytes(self.pending.popleft() for _ in range(min(size, len(self.pending))))

    def wait_for(self, expected, timeout=60):
        result = bytearray()
        deadline = self.sim._vtime() + timeout
        while expected not in result:
            remaining = deadline - self.sim._vtime()
            if remaining <= 0:
                raise AssertionError(f"UART did not produce {expected!r}; received {bytes(result[-400:])!r}")
            data = self.read(4096, remaining)
            if not data:
                raise AssertionError(f"UART timed out waiting for {expected!r}; received {bytes(result[-400:])!r}")
            result.extend(data)
        return bytes(result)

    def enter_bootloader(self):
        self.write(b"c")
        self._advance(self.sim._vtime() + 0.02)
        # bl_verify_sw is printed before the stock image CRC is checked.
        # Give that real verification loop time to complete before sending a
        # command: the loader discards bytes sent during its initialization.
        self.sim.run(max_instructions=30_000_000)
        assert b"bl_verify_sw" in self.received, "Original bootloader did not reach verification"
        self.pending.clear()
        assert b"success!" not in self.received, "Boot interruption missed the original bootloader"

    def check_application(self, version):
        expected = f"{APP_BANNER}\r\nVersion: {version}\r\n".encode("ascii")
        ready = expected + b"RAM app via original bootloader\r\nCommands: v=version p=ping\r\n"
        boot = self.wait_for(ready)
        assert b"runtime init failed" not in boot, "Application runtime initialization failed"
        assert b"bl_verify_sw" in self.received, "Application did not pass through the original bootloader"
        self.pending.clear()
        self.write(b"p")
        response = self.wait_for(f"pong {version}\r\n".encode("ascii"), 5)
        self.pending.clear()
        self.write(b"v")
        version_response = self.wait_for(expected, 5)
        return {"banner": APP_BANNER, "version": version,
                "boot_tail": boot[-400:].decode("latin-1"),
                "ping": response.decode("latin-1"),
                "version_response": version_response.decode("latin-1"),
                "lzma_hle": self.sim.lzma_hle}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def run(args):
    source = Path(resolve_dump(args.dump)).resolve()
    source_bytes = source.read_bytes()
    original = source_bytes[:0x400000]
    assert len(original) == 0x400000, "Expected a complete 4 MiB flash dump"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    current_path = source
    current_flash = original
    report = {"source": str(source), "source_sha256": sha256(source_bytes),
              "engine": args.engine, "updates": []}
    started = time.monotonic()

    for version, application_path in (("v1", args.app_v1), ("v2", args.app_v2)):
        package = package_image(current_flash, application_path.read_bytes())
        print(f"[{version}] entering original bootloader and sending {len(package.payload)} bytes", flush=True)
        transport = SimulatorTransport(current_path, engine=args.engine, native_lzma=False)
        transport.enter_bootloader()
        # UART dump deadlines are wall-clock based; the Unicorn interpreter
        # needs more time than the native C++ core for the same 4 MiB stream.
        client = BootloaderClient(transport, timeout=10, burn_timeout=120,
                                  dump_timeout=3000 if args.engine == "unicorn" else 600)
        client.handshake()
        print(f"[{version}] bootloader handshake passed", flush=True)
        progress = client.flash(package.flash_offset, package.payload)
        actual = bytes(transport.sim.rom_image[:len(original)])
        assert actual == package.flash, "Guest flash contents differ from the packaged image after burn"
        assert actual[:package.flash_offset] == original[:package.flash_offset], "Original bootloader changed"
        assert actual[package.flash_offset + len(package.payload):] == current_flash[package.flash_offset + len(package.payload):], "Bytes outside the transferred region changed"
        print(f"[{version}] flash readback matches; rebooting through original bootloader", flush=True)
        if version == "v2":
            print(f"[{version}] verifying full 4 MiB dump through the UART protocol", flush=True)
            assert client.dump() == actual, "Wire dump readback differs from flash after the second update"
        transport.pending.clear()
        reboot_mark = len(transport.received)
        transport.sim.lzma_hle = False
        client.reboot()
        reboot_result = transport.check_application(version)
        reboot_output = bytes(transport.received[reboot_mark:])
        assert b"bl_verify_sw" in reboot_output and b"success!" in reboot_output, "Reboot did not verify the application through the original bootloader"
        assert bytes(transport.sim.rom_image[:len(original)]) == actual, "Application unexpectedly modified flash"

        snapshot = args.output_dir / f"dump_maciej_{version}.bin"
        snapshot.write_bytes(actual)
        (args.output_dir / f"uart_{version}.log").write_bytes(transport.received)
        print(f"[{version}] checking a fresh power-on from persisted flash", flush=True)
        cold = SimulatorTransport(snapshot, engine=args.engine)
        cold_result = cold.check_application(version)
        assert bytes(cold.sim.rom_image[:len(original)]) == actual
        (args.output_dir / f"uart_{version}_cold.log").write_bytes(cold.received)
        report["updates"].append({"version": version, "application": str(application_path.resolve()),
                                  "flash_offset": package.flash_offset,
                                  "transferred_bytes": len(package.payload),
                                  "flash_sha256": sha256(actual), "snapshot": str(snapshot.resolve()),
                                  "reboot": reboot_result, "cold_boot": cold_result,
                                  "uart_bytes_sent": transport.sent_bytes,
                                  "wire_dump_verified": version == "v2",
                                  "burn_progress": progress,
                                  "package": package.manifest})
        current_flash, current_path = actual, snapshot
        print(f"[PASS] {version}: UART burn, bootloader preservation, reboot, cold boot, and ping", flush=True)

    assert source.read_bytes() == source_bytes, "The original dump file was modified"
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report_path = args.output_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"[PASS] Two successive updates completed; report: {report_path.resolve()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", default="dump_maciej.bin")
    parser.add_argument("--app-v1", type=Path, default=ROOT / "build/maciej_app/v1/app.bin")
    parser.add_argument("--app-v2", type=Path, default=ROOT / "build/maciej_app/v2/app.bin")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build/maciej_app/integration")
    parser.add_argument("--engine", choices=("cpp", "unicorn"), default="cpp")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
