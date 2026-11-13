#!/usr/bin/env python3
"""
The bootloader flash survey (tools/bootloader_flash_survey.py) on three flash
dumps that cover its three paths, each with the whole procedure -- capture,
handshake, CRC-checked backup 'dump', transfer + burn of the test
application, readback 'dump', reboot, cold boot:

  dump_maciej.bin   jessie.wei loader, LZMA-alone main code, reboot by jump
  srt8115.BIN       vic.wang loader, LZO1X main code (tools/lzo1x.py)
  Echosonic ESR-250 M3510A (M3503 family), its reboot arms the watchdog,
                    which the harness turns into a restart

All three must come out "works".  Takes several minutes (two full UART dumps
of 4 MB each).
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import bootloader_flash_survey as survey               # noqa: E402

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}", flush=True)
    if not ok:
        failures.append(text)


print("=== Bootloader flash survey: three representative dumps ===")
try:
    from firmware.maciej_app.build import find_prefix
    prefix = find_prefix(None)
except SystemExit as exc:
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        raise
    print(f"[NOT APPLICABLE] the survey builds its test application: {exc}")
    sys.exit(0)

survey.OUT_DIR = ROOT / "build" / "flash_survey_sample"
for rel in ("dump_maciej.bin", "srt8115.BIN",
            "other/Echosonic_Mini_ESR-250__GD25Q32B--DVBS2-M3510A-A3__OK--OK.BIN"):
    path = ROOT / "dumps" / rel
    job = {"path": str(path), "rel": rel, "out": str(survey.OUT_DIR / survey.safe_name(rel)),
           "kind": "dump", "boots": True, "wall_budget": 1800, "cross_prefix": prefix, "dumps": True}
    result = survey.survey_image(job)
    steps = {s["step"]: s for s in result["steps"]}
    check(result["verdict"] == "works", f"{rel}: {result['verdict']} ({result['reason'][:150]})")
    if rel == "srt8115.BIN":
        check(steps.get("package", {}).get("format") == "lzo", "srt8115: main code packed as LZO1X")
    if rel.startswith("other/"):
        check(bool(steps.get("reboot + application", {}).get("watchdog_reset")),
              "Echosonic: its reboot arms the watchdog (restart by the harness)")
if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] the established flash procedure works on all three")
