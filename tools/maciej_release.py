#!/usr/bin/env python3
"""Package a built Maciej application as release files in firmware/maciej_app/bin:
the 4 MiB flash image (dump_maciej.bin with the new main code), the UART
payload (.maincode.bin, what tools/maciej_uart.py flashes), a manifest
(.json: sizes, addresses, SHA-256, commands) and the portable ZIP
(maciej_uart.py, the payload and README_UART.txt), with fixed timestamps so
the same inputs give the same bytes.

  python firmware/maciej_app/build.py --version v4 --demo
  python tools/maciej_release.py --version v4 --app build/maciej_app/v4/app.bin \\
      --readme firmware/maciej_app/bin/README_UART_v4.txt
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import maciej_image                                  # noqa: E402

BIN = ROOT / "firmware" / "maciej_app" / "bin"
BANNER = "ELEKTRODA ALI M3801 TEST FOR MACIEJ"
ZIP_TIME = (2026, 11, 12, 12, 0, 0)

# what each release answers on the UART (v4: whole command lines)
COMMANDS = {
    "v4": {
        "help": "list of commands", "version": "banner and version", "ping": "answers pong",
        "info": "chip, clock, memory layout, uptime", "uptime": "time since start",
        "echo": "prints its arguments", "md": "dump memory", "mr": "read a 32-bit word",
        "mw": "write a 32-bit word (RAM, registers)",
        "screen": "draw on the TV picture: demo|bars|clear|text|rect|on|off",
        "panel": "front panel digits, brightness (boards with the TM1650)",
        "keys": "front panel key state; without a TM1650 (Comsat TE 1050 HD) its two buttons on GPIO 31 / 9",
        "ir": "remote control receiver (raw timing on|off)",
        "usb": "USB port state, the descriptors of its device and, through a hub, of every device behind it; "
               "reset, init, kbd [report|interrupt|raw on|off] (a USB keyboard types into the command line, "
               "read from its interrupt endpoint), mouse (a USB mouse moves a pointer on the TV and paints with "
               "its left button), reg <offset> [byte], ctl <type> <request> <value> <index> <length> [device] "
               "(a control request)",
        "lsusb": "the USB devices, one line each (with the hub and port of those behind a hub)",
        "disks": "USB disks (sticks, card readers): their size, partitions and file systems",
        "ls": "[n:][/path]: a directory on a USB disk's FAT12 / FAT16 / FAT32 volume (n: the disk's device "
              "number as lsusb lists it)",
        "cat": "[n:]/path: a text file on a USB disk (Ctrl-C stops it)",
        "sector": "[n:]<number>: one sector of a USB disk in hex",
        "watchdog": "the chip's watchdog, running from the start: a demo stopped for 8 s restarts the box; "
                    "test (stop feeding it), off, on",
        "clear": "clear the terminal",
        "video": "the original firmware's display and HDMI set-up, per board and chip revision "
                 "(init [opticum|comsat] [rev0|rev1]); the demo runs this board's at start, before USB",
        "reboot": "restart through the original bootloader", "restart": "the same as reboot",
        "bootloader": "restart into the original bootloader; hold 'c' (or run the updater) to stay in it",
        "ccc": "three 'c' on an empty line: restart for the UART updater's boot capture",
        "/": "every command may also be written with '/' in front (/restart)",
    },
}


def stem(version: str) -> str:
    return f"elektroda_ali_m3801_maciej_{version}"


def release(version: str, app_path: Path, readme: Path, out_dir: Path = BIN) -> dict:
    original = (ROOT / "dumps" / "dump_maciej.bin").read_bytes()
    application = app_path.read_bytes()
    package = maciej_image.package_image(original, application)
    name = stem(version)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{name}.bin").write_bytes(package.flash)
    (out_dir / f"{name}.maincode.bin").write_bytes(package.payload)
    manifest = dict(package.manifest)
    manifest.update({"application_version": version, "banner": BANNER, "uart": "115200 8E1",
                     "commands": COMMANDS.get(version, {})})
    (out_dir / f"{name}.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
                                         newline="\r\n")   # (CRLF, as the v1-v3 manifests)
    readme_bytes = readme.read_bytes()
    readme_bytes.decode("ascii")                     # the ZIP's instructions are plain ASCII
    members = [("maciej_uart.py", (ROOT / "tools" / "maciej_uart.py").read_bytes()),
               (f"{name}.maincode.bin", package.payload),
               ("README_UART.txt", readme_bytes)]
    with zipfile.ZipFile(out_dir / f"maciej_uart_{version}.zip", "w", zipfile.ZIP_DEFLATED) as bundle:
        for member, data in members:
            info = zipfile.ZipInfo(member, date_time=ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            bundle.writestr(info, data)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True)
    parser.add_argument("--app", type=Path, required=True, help="the built application (app.bin)")
    parser.add_argument("--readme", type=Path, required=True, help="the ZIP's README_UART.txt (ASCII)")
    parser.add_argument("--out-dir", type=Path, default=BIN)
    args = parser.parse_args()
    manifest = release(args.version, args.app, args.readme, args.out_dir)
    print(f"{stem(args.version)}: application {manifest['application_size']} bytes, "
          f"payload {manifest['payload_size']} bytes at 0x{manifest['flash_offset']:x}, "
          f"flash SHA-256 {manifest['flash_sha256']}")


if __name__ == "__main__":
    main()
