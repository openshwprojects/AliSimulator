#!/usr/bin/env python3
"""
ALi's packet ("format 3") UART upgrade protocol (tools/ali_packet.py) on a
loader that speaks only that one: the Amiko HD8200 Series image's, built
with the SDK's TRANSFER_FORMAT3_ONLY.

  handshake - captured by the paced 'c' (after its main code check, about a
              minute of emulated time), its loader answers the classic
              handshake bytes with 0xFF - byte; '@X' gives bf a7
  chunk     - the packet 'chunk' command: the loader's chunk table
  dump      - the first 64 KB in 1024-byte packets, equal to the flash
  procedure - the flash survey's whole procedure in the packet protocol
              (tools/bootloader_flash_survey.py, as a member of its
              bootloader group: no full dumps): address + transfer + burn of
              a main code chunk carrying the test application, the loader's
              reboot into it, a cold boot -- "works, packet protocol"
Needs a MIPS GCC for the test application (NOT APPLICABLE without one).
"""
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import ali_packet                                      # noqa: E402
import bootloader_flash_survey as survey               # noqa: E402
from simulator import flash_size_for                   # noqa: E402

IMAGE = "AMIKO HD8200 SERIES/AMIKO_HD8200_Series_1.6.96_emu.abs"
failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}", flush=True)
    if not ok:
        failures.append(text)


print("=== The packet protocol on the Amiko HD8200 Series loader ===")
try:
    from firmware.maciej_app.build import find_prefix
    prefix = find_prefix(None)
except SystemExit as exc:
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        raise
    print(f"[NOT APPLICABLE] the procedure builds its test application: {exc}")
    sys.exit(0)

t0 = time.monotonic()
path = ROOT / "dumps" / IMAGE
survey.OUT_DIR = ROOT / "build" / "packet_protocol_test"
rom = flash_size_for(str(path))
sim, wire = survey._new_sim(path, rom, deadline=time.monotonic() + 1800)
flash = bytes(sim.rom_image[:rom])
cap = survey.capture(wire)
check(cap["captured"], f"the paced 'c' capture the loader ({cap['vtime']:.0f} emulated s)")
hs = survey.handshake(wire)
check(hs["protocol"] == "packet" and hs.get("reply") == "a7a7",
      "the classic handshake's 'XX' come back as a7 a7: the packet protocol only")
packets = ali_packet.PacketClient(wire, timeout=10.0, clock=sim._vtime)
packets.handshake()
check(True, "the packet handshake: 'comtest 2' echoed, '@X' answered bf a7")
table = packets.chunk_table()
names = [table[2 + 128 * i + 16:2 + 128 * i + 32].split(b"\0")[0] for i in range((len(table) - 2) // 128)]
check(names[:2] == [b"bootloader", b"maincode(AV)"] and len(names) == 13,
      f"chunk: the loader's table of {len(names)} chunks (bootloader, maincode(AV), ...)")
data = packets.dump(0, 0x10000)
check(data == flash[:0x10000], "dump 0 65536: 64 packets of 1024 bytes, equal to the flash")

job = {"path": str(path), "rel": IMAGE, "out": str(survey.OUT_DIR / survey.safe_name(IMAGE)),
       "kind": "image", "boots": True, "wall_budget": 1800, "cross_prefix": prefix, "dumps": False,
       "dump_representative": "(this test: the group's dumps are not run)"}
result = survey.survey_image(job)
steps = {s["step"]: s for s in result["steps"]}
check(result["verdict"] == "works, packet protocol", f"the survey's procedure: {result['verdict']} ({result['reason'][:120]})")
burn = steps.get("transfer + burn", {})
check(burn.get("flash_after_burn_matches") and burn.get("written_chunk_crc_ok") and burn.get("burn_progress"),
      f"transfer + burn: the flash is the expected image, the chunk's CRC right ({burn.get('burn_progress')})")
check(steps.get("reboot + application", {}).get("pong") and steps.get("cold boot from written flash", {}).get("pong"),
      "the loader's reboot and a cold boot start the test application (banner, pong)")
print(f"\n{time.monotonic() - t0:.1f} s")
if failures:
    print(f"[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("[PASS] the packet protocol flashes the Amiko HD8200 Series loader")
