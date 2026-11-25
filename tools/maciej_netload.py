#!/usr/bin/env python3
"""Run a new build of the v4 demo on the box from RAM, over Ethernet -- no flash
(the flash keeps the old demo: a reset, or a new image that hangs and lets the
watchdog reset the box, brings that one back).

The demo listens on TCP port 6464 (firmware/maciej_app/demo/net.c): this sends
"M4LD", the image's length and its CRC-32 (zlib's), both 32-bit little-endian,
then the image (app.bin, linked at 0x80000200), and prints the box's one-line
answer ("OK ..." -- it then starts the image -- or "ERR ...").

  python firmware/maciej_app/build.py --version v4 --demo
  python tools/maciej_netload.py <box-ip> [build/maciej_app/v4/app.bin]

The box's address: 'ifconfig' on its command line (DHCP).
"""
from __future__ import annotations

import argparse
from pathlib import Path
import socket
import struct
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_APP = ROOT / "build" / "maciej_app" / "v4" / "app.bin"
PORT = 6464
MAGIC = b"M4LD"
START = struct.pack("<I", 0x40086000)          # start.S's first instruction: mfc0 $t0, $12


def netload(host: str, image: bytes, port: int = PORT, timeout: float = 15.0) -> str:
    """Send the image; the box's answer line."""
    header = MAGIC + struct.pack("<II", len(image), zlib.crc32(image) & 0xFFFFFFFF)
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(header + image)
        answer = bytearray()
        while not answer.endswith(b"\n"):
            chunk = s.recv(256)
            if not chunk:
                break
            answer += chunk
    return answer.decode("ascii", "replace").strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", help="the box's IPv4 address (or name)")
    parser.add_argument("app", nargs="?", type=Path, default=DEFAULT_APP, help=f"the image (default {DEFAULT_APP})")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    image = args.app.read_bytes()
    if not image.startswith(START):
        print(f"{args.app}: does not start as the demo's start.S does (mfc0 $t0, $12): not sent", file=sys.stderr)
        return 2
    print(f"{args.app}: {len(image)} bytes, CRC-32 {zlib.crc32(image) & 0xFFFFFFFF:08x} -> {args.host}:{args.port}")
    t0 = time.monotonic()
    try:
        # (the box itself gives an image 10 s + 1 ms per 100 bytes -- 45 s for 3.5 MB; a fixed 15 s here gave up
        #  on a slow link while the box was still receiving, and the box then started nothing)
        answer = netload(args.host, image, args.port, timeout=15.0 + len(image) / 100000.0)
    except OSError as e:
        print(f"failed: {e}", file=sys.stderr)
        return 1
    print(f"box ({time.monotonic() - t0:.2f} s): {answer or '(no answer)'}")
    return 0 if answer.startswith("OK") else 1


if __name__ == "__main__":
    sys.exit(main())
