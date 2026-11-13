"""
Test: tools/lzo1x.py, the LZO1X main code format of the vic.wang M3801
bootloaders (dump.bin, srt8115.BIN, the Cabletech URZ0083Q / URZ0194S, the
Strong Prima VIII).

  stock     - every such image's main code chunk unpacks: the 16-byte header's
              Adler-32 of the compressed stream and of the result both match,
              and the result starts with the application's first instruction
  round     - compress() output decodes back to its input for edge cases and
              random data (literal runs of every length class, matches of
              every distance class, runs of zeros)
  payload   - pack_payload() pads to a multiple of 4 (the loader copies the
              payload to 0x81E80000 - length and reads the header with word
              loads) and unpacks again
"""
import os
import random
import struct
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import lzo1x                                             # noqa: E402

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== LZO1X main code format (tools/lzo1x.py) ===")
IMAGES = ["dump.bin", "srt8115.BIN", os.path.join("CABLETECH URZ0083Q", "Cabletech URZ0083Q", "EN25Q32B.bin"),
          "CABLETECH_urz0194s_v1_0_8.bin", os.path.join("STRONG PRIMA VIII", "GD25Q32B_20190128_141501.BIN")]
for name in IMAGES:
    image = open(os.path.join(ROOT, "dumps", name), "rb").read()
    off = 0x20000
    cid, length = struct.unpack_from(">2I", image, off)
    payload = image[off + 128:off + 16 + length]
    try:
        app = lzo1x.unpack_payload(payload)
        csize, usize = struct.unpack_from("<2I", payload)
        check(cid >> 16 == 0x01FE and len(app) == usize and app[:4] == bytes.fromhex("00800840"),
              f"{os.path.basename(name)}: {csize} -> {usize} bytes, both Adler-32 match, starts with mfc0 $t0, Status")
    except lzo1x.LzoError as exc:
        check(False, f"{os.path.basename(name)}: {exc}")

random.seed(7)
cases = [b"", b"a", b"ab", b"abc", b"abcd", bytes(19), bytes(range(256)) * 300, b"\x00" * 70000, os.urandom(4096),
         b"xy" * 40000 + os.urandom(300) + b"xy" * 30]
for _ in range(150):
    alphabet = random.choice([b"ab\x00", b"abcdefgh", bytes(range(256))])
    cases.append(bytes(random.choice(alphabet) for _ in range(random.randint(1, 3000))))
bad = [len(c) for c in cases if lzo1x.decompress(lzo1x.compress(c), len(c)) != c]
check(not bad, f"compress -> decompress gives the input back ({len(cases)} cases)")
far = os.urandom(0x5000) + b"PATTERN-FAR-AWAY" * 2 + os.urandom(0x6000) + b"PATTERN-FAR-AWAY" * 2
check(lzo1x.decompress(lzo1x.compress(far), len(far)) == far, "matches farther than 0x4000 bytes (M4) round-trip")

for size in (1, 2, 3, 4, 5, 700, 4097):
    data = os.urandom(size)
    packed = lzo1x.pack_payload(data)
    if len(packed) % 4 or lzo1x.unpack_payload(packed) != data:
        check(False, f"pack_payload of {size} bytes")
        break
else:
    check(True, "pack_payload pads to a multiple of 4 and unpacks again")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] all LZO1X checks")
