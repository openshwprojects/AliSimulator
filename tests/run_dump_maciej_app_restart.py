#!/usr/bin/env python3
"""Re-enter the original UART bootloader from the running Maciej RAM app.

One emulator instance boots native application code, ignores unrelated UART
bytes, restarts normally twice, and installs two updates via the production
CLI's existing paced 'c' capture. The only inputs after power-on are UART
bytes. No test writes guest registers, RAM, flash, or reset state.
The slower Unicorn engine checks native restart, capture and loader reboot;
the C++ engine additionally performs the two full CLI updates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import types
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from firmware.maciej_app.build import build, find_prefix


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def run_smoke(args, prefix):
    from maciej_image import package_image
    import maciej_uart as updater
    from run_maciej_bootloader_update import SimulatorTransport
    from run_dump_maciej_uart_bundle import EmulatedSerial

    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    application = build(output / "restart_smoke", "restart_smoke", prefix)
    package = package_image((ROOT / "dumps/dump_maciej.bin").read_bytes(), application.read_bytes())
    image = output / "initial.bin"
    image.write_bytes(package.flash)
    transport = SimulatorTransport(image, engine=args.engine)
    result = {"engine": args.engine, "mode": "restart/capture smoke",
              "flash_sha256": sha256(package.flash), "restarts": []}
    try:
        result["cold_boot"] = transport.check_application("restart_smoke")
        for cycle in (1, 2):
            transport.pending.clear()
            mark = len(transport.received)
            transport.write(b"r")
            result["restarts"].append(transport.check_application("restart_smoke"))
            assert b"bl_verify_sw" in bytes(transport.received[mark:])
            assert bytes(transport.sim.rom_image[:updater.FLASH_SIZE]) == package.flash
            print(f"[PASS] {args.engine} native 'r' restart {cycle}, flash unchanged", flush=True)
        ports = []

        def serial_factory(**options):
            port = EmulatedSerial(transport, **options)
            ports.append(port)
            return port

        serial_module = types.SimpleNamespace(Serial=serial_factory, EIGHTBITS=8,
                                              PARITY_EVEN="E", STOPBITS_ONE=1)
        argv = ["maciej_uart.py", "--port", "SIMULATED_UART", "--capture-boot", "10", "probe"]
        transport.pending.clear()
        mark = len(transport.received)
        with patch.dict(sys.modules, {"serial": serial_module}), patch.object(sys, "argv", argv):
            updater.main()
        assert len(ports) == 1 and ports[0].closed
        assert ports[0].writes[0] == b"c"
        assert b"comtest 2\r" in ports[0].writes and b"XX" in ports[0].writes
        assert b"bl_verify_sw" in bytes(transport.received[mark:])
        updater.BootloaderClient(transport).reboot()
        result["loader_reboot"] = transport.check_application("restart_smoke")
        assert bytes(transport.sim.rom_image[:updater.FLASH_SIZE]) == package.flash
        assert not transport.sim.lzma_hle
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        result["passed"] = True
        (output / "report.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"[PASS] {args.engine} native restart/capture/comtest/loader reboot: {output}", flush=True)
    finally:
        (output / "uart_restart.log").write_bytes(transport.received)


def run(args, prefix):
    # Import only after verifying prerequisites, as in the source-build test.
    from maciej_image import package_image
    import maciej_uart as updater
    from run_maciej_bootloader_update import SimulatorTransport
    from run_dump_maciej_uart_bundle import EmulatedSerial

    started = time.monotonic()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    first_app = build(output / "restart1", "restart1", prefix)
    next_app = build(output / "restart2", "restart2", prefix)
    source = ROOT / "dumps/dump_maciej.bin"
    source_bytes = source.read_bytes()
    original = source_bytes[:updater.FLASH_SIZE]
    initial = package_image(original, first_app.read_bytes())
    initial_path = output / "initial.bin"
    initial_path.write_bytes(initial.flash)
    transport = SimulatorTransport(initial_path, engine=args.engine)
    report = {"engine": args.engine, "initial_flash_sha256": sha256(initial.flash),
              "simulator_instances": 1, "guest_state_patched": False,
              "updates": [], "source_sha256": sha256(source_bytes)}

    def assert_original_boot(mark):
        log = bytes(transport.received[mark:])
        assert b"bl_verify_sw" in log and b"success!" in log, \
            "Restart bypassed the original loader verification"
        assert not transport.sim.lzma_hle, "Application used high-level LZMA emulation"

    def check_ignored_input(version, flash):
        transport.pending.clear()
        mark = len(transport.received)
        # None contains a defined lower-case command. In particular, a newline
        # or a long unknown string must not accidentally request a restart.
        samples = (b"\x00\xff?!\r\n\t", b"BOOTLOADER", b"xyz0123456789", b"x" * 128)
        for data in samples:
            transport.write(data)
            assert not transport.read(4096, 0.1), "Unrecognized UART input produced output"
        assert bytes(transport.received[mark:]) == b"", "Unrecognized input restarted the app"
        transport.write(b"p")
        assert transport.wait_for(f"pong {version}\r\n".encode("ascii"), 5) == \
            f"pong {version}\r\n".encode("ascii")
        assert bytes(transport.sim.rom_image[:updater.FLASH_SIZE]) == flash
        return [data.hex() for data in samples]

    current_flash, current_version = initial.flash, "restart1"
    try:
        report["initial_boot"] = transport.check_application(current_version)
        assert_original_boot(0)
        assert "r=restart" in report["initial_boot"]["commands"]
        assert "c=" in report["initial_boot"]["commands"]
        print("[PASS] Native startup exposes version, ping, restart and boot capture commands", flush=True)

        for cycle, target_version, target_app in ((1, "restart2", next_app),
                                                  (2, "restart1", first_app)):
            ignored = check_ignored_input(current_version, current_flash)
            transport.pending.clear()
            restart_mark = len(transport.received)
            transport.write(b"r")
            restart = transport.check_application(current_version)
            assert_original_boot(restart_mark)
            assert bytes(transport.sim.rom_image[:updater.FLASH_SIZE]) == current_flash
            print(f"[cycle {cycle}] 'r' restarted through the original loader; flash unchanged", flush=True)

            package = package_image(current_flash, target_app.read_bytes())
            payload_path = output / f"update_{cycle}.maincode.bin"
            payload_path.write_bytes(package.payload)
            backup_path = output / f"before_update_{cycle}.bin"
            # The production tool deliberately refuses an existing backup.
            # Each invocation of this regression must get a fresh output dir.
            if backup_path.exists():
                raise FileExistsError(f"Use a fresh --output-dir; backup already exists: {backup_path}")
            ports = []

            def serial_factory(**options):
                port = EmulatedSerial(transport, **options)
                ports.append(port)
                return port

            serial_module = types.SimpleNamespace(Serial=serial_factory, EIGHTBITS=8,
                                                  PARITY_EVEN="E", STOPBITS_ONE=1)
            argv = ["maciej_uart.py", "--port", "SIMULATED_UART", "--capture-boot", "5",
                    "flash", str(payload_path), "--backup", str(backup_path)]
            transport.pending.clear()
            capture_mark = len(transport.received)
            instruction_mark = transport.sim.instruction_count
            print(f"[cycle {cycle}] running CLI capture/backup/burn/readback from the running app", flush=True)
            with patch.dict(sys.modules, {"serial": serial_module}), patch.object(sys, "argv", argv):
                updater.main()
            assert len(ports) == 1
            port = ports[0]
            assert port.opened and port.closed, "CLI failed to close the serial port"
            assert port.flushes == len(port.writes)
            assert port.writes[0] == b"c", "CLI bypassed ordinary boot capture"
            assert port.writes.count(b"c") >= 2, "CLI did not exercise repeated capture probes"
            assert port.writes.count(b"dump\r") == 2, "Expected full backup and verification over UART"
            assert port.writes.count(b"burn\r") == 1
            assert port.writes.count(b"address 327680\r") == 1
            assert port.reboot_mark is not None
            assert b"bl_verify_sw" in bytes(transport.received[capture_mark:port.reboot_mark]), \
                "Capture did not return through the original loader"
            assert transport.sim.instruction_count > instruction_mark
            assert backup_path.read_bytes() == current_flash
            actual = bytes(transport.sim.rom_image[:updater.FLASH_SIZE])
            assert actual == package.flash, "Flash differs from the packaged image"
            assert actual != current_flash, "Each cycle must change the installed application"
            offset, end = package.flash_offset, package.flash_offset + len(package.payload)
            assert actual[:offset] == current_flash[:offset] == original[:offset]
            assert actual[end:] == current_flash[end:], "Update changed bytes outside its payload"
            application = transport.check_application(target_version)
            assert_original_boot(port.reboot_mark)
            assert bytes(transport.sim.rom_image[:updater.FLASH_SIZE]) == actual
            report["updates"].append({
                "cycle": cycle, "from_version": current_version, "to_version": target_version,
                "ignored_input_hex": ignored, "normal_restart": restart,
                "capture_probes": port.writes.count(b"c"), "uart_full_dumps": 2,
                "backup_sha256": sha256(current_flash), "flash_sha256": sha256(actual),
                "native_reboot": application, "bytes_outside_payload_unchanged": True,
            })
            current_flash, current_version = actual, target_version
            print(f"[PASS] Cycle {cycle}: software capture, full backup/readback, native reboot and p/v", flush=True)
        assert source.read_bytes() == source_bytes, "Original dump was modified"
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["passed"] = True
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"[PASS] Two software-triggered updates in one continuously running simulator: {output}", flush=True)
    finally:
        (output / "uart_restart.log").write_bytes(transport.received)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cross-prefix", help="compiler prefix, including the final dash")
    parser.add_argument("--engine", choices=("cpp", "unicorn"),
                        default=os.environ.get("ALISIM_ENGINE", "cpp"))
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--smoke-only", action="store_true",
                        help="check restart/capture without flash writes (always used with Unicorn)")
    parser.add_argument("--require-toolchain", action="store_true",
                        default=os.environ.get("GITHUB_ACTIONS", "").lower() == "true")
    args = parser.parse_args()
    try:
        prefix = find_prefix(args.cross_prefix)
    except SystemExit as error:
        if args.require_toolchain:
            raise
        print(f"[NOT APPLICABLE] {error}", flush=True)
        return
    missing = [prefix + tool for tool in ("gcc", "objcopy", "objdump")
               if not shutil.which(prefix + tool)]
    if missing:
        raise SystemExit("Incomplete MIPS toolchain: " + ", ".join(missing))
    if args.output_dir is None:
        # Avoid replacing backups on local reruns; CI uploads this parent.
        args.output_dir = ROOT / "build/maciej_app/selftest" / args.engine / "restart" / \
            (time.strftime("%Y%m%dT%H%M%S") + "_" + uuid.uuid4().hex[:8])
    if args.smoke_only or args.engine == "unicorn":
        run_smoke(args, prefix)
    else:
        run(args, prefix)


if __name__ == "__main__":
    main()
