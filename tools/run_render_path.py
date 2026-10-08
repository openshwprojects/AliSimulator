"""
Explore the setup wizard key path on dump_maciej.bin:
Captures the screens as we navigate through the wizard steps.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

import numpy as np

from simulator import AliMipsSimulator

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wizard_screens")
os.makedirs(OUT_DIR, exist_ok=True)

BOOT_LIMIT_S = 15 * 60
KEY_LIMIT_S = 2 * 60


def main():
    print("=== Navigating dump_maciej setup wizard key path ===")
    sim = AliMipsSimulator(log_handler=lambda msg: None)
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    sim.setUartHandler(lambda c: None)
    sim.loadFile("dump_maciej.bin")
    start = time.time()

    def run_until_drawn(min_ops, limit):
        last, quiet, t = sim.ge_ops, 0, time.time()
        while time.time() - t < limit:
            sim.run(max_instructions=sim.instruction_count + 5_000_000)
            if sim.ge_ops != last:
                last, quiet = sim.ge_ops, 0
            elif sim.ge_ops >= min_ops:
                quiet += 1
                if quiet >= 6:
                    return True
        return False

    def snap(name):
        path = os.path.join(OUT_DIR, f"{name}.png")
        rgb = sim.capture_screen(path)
        print(f"[{time.time() - start:6.1f}s] saved {path} ({sim.ge_ops} GE ops)")
        return rgb

    # 1. Wait for wizard step 1
    if not run_until_drawn(300, BOOT_LIMIT_S):
        print(f"[FAIL] wizard not drawn (GE commands: {sim.ge_ops})")
        sys.exit(1)

    print(f"[{time.time() - start:6.1f}s] Step 1 drawn")
    before = snap("step1_start_polish")

    # Sequence of keys to explore:
    # 1. DOWN -> selects German
    # 2. OK   -> advances to Step 2 (Aspect Ratio)
    # 3. DOWN -> selects 16:9 Wide screen (from 4:3 Letter box)
    # 4. OK   -> advances to Step 3!
    # 5. OK   -> advances to Step 4 (or confirms)!
    steps = [
        ("DOWN", "step1_german"),
        ("OK",   "step2_aspect_ratio"),
        ("DOWN", "step2_16x9_selected"),
        ("OK",   "step3_next"),
        ("OK",   "step4_next"),
    ]

    for key, name in steps:
        ops = sim.ge_ops
        try:
            addr, cmd = sim.press_key(key)
        except Exception as e:
            print(f"[FAIL] press_key({key}): {e}")
            break
        drawn = run_until_drawn(ops + 1, KEY_LIMIT_S)
        after = snap(name)
        changed = int((after != before).any(axis=2).sum())
        print(f"[{time.time() - start:6.1f}s] {key} -> {name}: {sim.ge_ops - ops} ops, {changed} px changed")
        before = after

    print(f"[DONE] Completed in {time.time() - start:.0f}s")


if __name__ == "__main__":
    main()
