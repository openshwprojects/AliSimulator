#!/usr/bin/env python3
"""Build and repeatedly flash the ELEKTRODA ALI M3801 TEST FOR MACIEJ app.

Compiles v1 and v2 from the checked-in C/assembly sources, then exercises the
original dump_maciej.bin UART bootloader: two updates, complete flash readback,
bootloader preservation, native LZMA decoding, reboot, cold boot, and commands.
GitHub Actions requires the cross compiler; local runs without one are marked
not applicable. Set MIPS_CROSS_COMPILE or pass --cross-prefix to select it.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from firmware.maciej_app.build import build, find_prefix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cross-prefix", help="compiler prefix, including the final dash")
    parser.add_argument("--engine", choices=("cpp", "unicorn"),
                        default=os.environ.get("ALISIM_ENGINE", "cpp"))
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--require-toolchain", action="store_true",
                        default=os.environ.get("GITHUB_ACTIONS", "").lower() == "true",
                        help="fail instead of skipping if the MIPS compiler is unavailable (always on GitHub)")
    args = parser.parse_args()

    try:
        prefix = find_prefix(args.cross_prefix)
    except SystemExit as exc:
        if args.require_toolchain:
            raise
        print(f"[NOT APPLICABLE] {exc}", flush=True)
        return
    # An explicitly configured but broken toolchain is a configuration error,
    # not a reason to silently pass the regression.
    missing = [prefix + tool for tool in ("gcc", "objcopy", "objdump")
               if not shutil.which(prefix + tool)]
    if missing:
        raise SystemExit("Incomplete MIPS toolchain: " + ", ".join(missing))

    output = (args.output_dir or ROOT / "build/maciej_app/selftest" / args.engine).resolve()
    app_v1 = build(output / "v1", "v1", prefix)
    app_v2 = build(output / "v2", "v2", prefix)
    print("[PASS] Both application versions compiled from source", flush=True)

    # Import the simulator only after checking the compiler so a lightweight
    # local discovery run can report the missing prerequisite cleanly.
    from run_maciej_bootloader_update import run

    run(argparse.Namespace(dump="dump_maciej.bin", app_v1=app_v1, app_v2=app_v2,
                           output_dir=output / "integration", engine=args.engine))


if __name__ == "__main__":
    main()
