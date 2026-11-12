#!/usr/bin/env python3
"""Check shipped v3 artifacts and native restart/recovery without a compiler.

Boot the checked-in image, issue three UART restarts, capture its original
loader with paced 'c', and reboot through that loader. No guest registers,
RAM, flash, or reset state are patched, and no serial port is opened.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from maciej_image import extract_application, validate_image
from maciej_uart import BootloaderClient, FLASH_SIZE, MAIN_OFFSET, validate_maincode
from run_maciej_bootloader_update import APP_BANNER, SimulatorTransport

BIN = ROOT / "firmware/maciej_app/bin"
STEM = "elektroda_ali_m3801_maciej_v3"
EXPECTED_FLASH_SHA256 = "3564d45b5354989f90f704c7bbf4ce1869182675a91bc3f158c6303da40c46c6"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check_artifacts():
    manifest = json.loads((BIN / (STEM + ".json")).read_text(encoding="utf-8"))
    image = (BIN / (STEM + ".bin")).read_bytes()
    payload = (BIN / (STEM + ".maincode.bin")).read_bytes()
    flash, chunks, trailer = validate_image(image)
    application = extract_application(flash)
    assert trailer is None
    assert manifest["format"] == "maciej-maincode-v1"
    assert manifest["application_version"] == "v3"
    assert manifest["banner"] == APP_BANNER
    assert manifest["uart"] == "115200 8E1"
    for name, data in (("flash", flash), ("payload", payload), ("application", application)):
        assert len(data) == manifest[name + "_size"], name + " size mismatch"
        assert sha256(data) == manifest[name + "_sha256"], name + " SHA-256 mismatch"
    assert sha256(flash) == EXPECTED_FLASH_SHA256, "Shipped v3 bytes changed"
    assert len(flash) == FLASH_SIZE
    assert manifest["flash_offset"] == MAIN_OFFSET == 0x50000
    assert manifest["load_address"] == manifest["entry_address"] == 0x80000200
    assert manifest["chunk"] == chunks[2].as_dict()
    assert manifest["compressed_size"] == chunks[2].data_end - MAIN_OFFSET - 128
    validate_maincode(payload)
    assert payload == flash[MAIN_OFFSET:MAIN_OFFSET + len(payload)]

    original = (ROOT / "dumps/dump_maciej.bin").read_bytes()
    original_flash, _, original_crc = validate_image(original)
    assert manifest["input_sha256"] == sha256(original)
    assert manifest["input_uart_crc"] == original_crc
    assert flash[:MAIN_OFFSET] == original_flash[:MAIN_OFFSET]
    assert flash[MAIN_OFFSET + len(payload):] == original_flash[MAIN_OFFSET + len(payload):]
    assert manifest["preserved_prefix_sha256"] == sha256(flash[:MAIN_OFFSET])
    assert manifest["preserved_suffix_sha256"] == sha256(flash[MAIN_OFFSET + chunks[2].span:])

    sources = {"maciej_uart.py": ROOT / "tools/maciej_uart.py",
               STEM + ".maincode.bin": BIN / (STEM + ".maincode.bin"),
               "README_UART.txt": BIN / "README_UART_v3.txt"}
    with zipfile.ZipFile(BIN / "maciej_uart_v3.zip") as bundle:
        assert bundle.testzip() is None, "Broken ZIP CRC"
        assert sorted(bundle.namelist()) == sorted(sources), "Unexpected ZIP members"
        for name, source in sources.items():
            assert bundle.read(name) == source.read_bytes(), "Stale ZIP member: " + name
        bundle.read("README_UART.txt").decode("ascii")
    print("[PASS] Shipped v3 manifest, flash/payload/app hashes, preservation, and ZIP bytes", flush=True)
    return flash, manifest


def run(args):
    started = time.monotonic()
    flash, manifest = check_artifacts()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    transport = SimulatorTransport(BIN / (STEM + ".bin"), engine=args.engine,
                                   native_lzma=True, wall_timeout=60)
    report = {"engine": args.engine, "flash_sha256": manifest["flash_sha256"],
              "payload_sha256": manifest["payload_sha256"],
              "application_sha256": manifest["application_sha256"],
              "passed": False, "restarts": []}

    def unchanged():
        assert bytes(transport.sim.rom_image[:FLASH_SIZE]) == flash, "Flash changed during restart"
        assert not transport.sim.lzma_hle, "New app must use the original native LZMA decoder"

    def check_boot():
        result = transport.check_application("v3")
        assert "r=restart" in result["commands"]
        assert "c=bootloader capture" in result["commands"]
        unchanged()
        return result

    try:
        report["cold_boot"] = check_boot()
        for cycle in (1, 2, 3):
            transport.pending.clear()
            mark = len(transport.received)
            transport.write(b"r")
            report["restarts"].append(check_boot())
            text = bytes(transport.received[mark:])
            assert b"Restarting via original bootloader\r\n" in text
            assert b"bl_verify_sw" in text and b"success!" in text
            print(f"[PASS] Shipped v3 native restart {cycle}, commands and flash preservation", flush=True)

        # Pace probes at 20 Hz in guest time. An available echo must not turn
        # this into an unbounded flood of characters into the loader buffer.
        transport.pending.clear()
        mark = len(transport.received)
        deadline = transport.sim._vtime() + 5
        while transport.sim._vtime() < deadline:
            transport.write(b"c")
            next_probe = min(deadline, transport.sim._vtime() + .05)
            while transport.sim._vtime() < next_probe:
                transport.read(4096, next_probe - transport.sim._vtime())
        transport.write(b"\r")
        for _ in range(20):
            if not transport.read(4096, .2):
                break
        else:
            raise AssertionError("UART did not become quiet after capture")
        client = BootloaderClient(transport)
        client.handshake()
        captured = bytes(transport.received[mark:])
        assert b"Restarting via original bootloader\r\n" in captured
        assert b"bl_verify_sw" in captured
        unchanged()
        report["capture_handshake"] = True
        client.reboot()
        report["loader_reboot"] = check_boot()
        report["passed"] = True
        print("[PASS] Shipped v3 c capture/comtest/loader reboot; all flash bytes unchanged", flush=True)
    except Exception as exc:
        report["error"] = repr(exc)
        raise
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        (output / "uart_ready_v3.log").write_bytes(transport.received)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("cpp", "unicorn"),
                        default=os.environ.get("ALISIM_ENGINE", "cpp"))
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    args.output_dir = args.output_dir or ROOT / "build/maciej_app/selftest" / args.engine / "ready_v3"
    run(args)


if __name__ == "__main__":
    main()
