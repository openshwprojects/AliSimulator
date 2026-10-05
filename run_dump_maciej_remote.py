"""
Remote-control regression for dump_maciej.bin (slow, about 8 minutes): boots
the firmware to its first-install wizard, then drives it with IR remote keys
and checks that the OSD reacts.

The keys travel the real path: sim.press_key() looks the key up in the UI's
own key table in RAM, encodes it as an NEC frame and feeds it to the emulated
M6303 IR receiver (run-length FIFO + interrupt line 19); the firmware's ISR,
NEC decoder, pan buffer and key task turn it into a UI key message, and the
redraw goes through the GE model (see ir_remote.py, ge_m36f.py).

  DOWN  -> the language highlight moves (and the UI switches language)
  OK    -> the wizard goes to its step 2, the aspect-ratio list
  DOWN  -> the aspect-ratio highlight moves
  OK    -> step 3, the channel search, starts: its progress screen is drawn
           and then keeps changing (the GE never goes quiet while it scans),
           which the last check verifies 40 s later

Usage: python run_dump_maciej_remote.py [out_dir]
Exit code 0 if every step changed the screen as expected.
"""
import os
import sys
import time

import numpy as np

import report_artifacts
from front_panel import make_panel
from simulator import AliMipsSimulator

BOOT_LIMIT_S = 15 * 60
KEY_LIMIT_S = 3 * 60


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else report_artifacts.out_dir()
    print("=== dump_maciej: drive the OSD with the IR remote ===")
    sim = AliMipsSimulator(log_handler=lambda msg: None)
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    sim.setUartHandler(lambda c: None)
    panel, _keys, _desc = make_panel("dump_maciej.bin", log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    sim.loadFile("dump_maciej.bin")
    start = time.time()

    def run_until_drawn(min_ops, limit, quiet_needed=6):
        """Run until the GE has executed min_ops commands and then stayed idle
        for quiet_needed slices (0: as soon as min_ops are done, for a screen
        that keeps redrawing)."""
        last, quiet, t = sim.ge_ops, 0, time.time()
        while time.time() - t < limit:
            sim.run(max_instructions=sim.instruction_count + 5_000_000)
            if sim.ge_ops >= min_ops and quiet_needed == 0:
                return True
            if sim.ge_ops != last:
                last, quiet = sim.ge_ops, 0
            elif sim.ge_ops >= min_ops:
                quiet += 1
                if quiet >= quiet_needed:
                    return True
        return False

    def run_for(seconds):
        t = time.time()
        while time.time() - t < seconds:
            sim.run(max_instructions=sim.instruction_count + 5_000_000)

    def snap(name):
        rgb = sim.capture_screen()
        if out:
            os.makedirs(out, exist_ok=True)
            path = os.path.join(out, f"remote_{name}.png")
            sim.capture_screen(path)
            report_artifacts.image(path, f"screen: {name} ({sim.ge_ops} GE commands)")
        return rgb

    if not run_until_drawn(300, BOOT_LIMIT_S):
        print(f"[FAIL] the wizard was not drawn (GE commands: {sim.ge_ops})")
        sys.exit(1)
    print(f"[{time.time() - start:6.1f}s] wizard drawn ({sim.ge_ops} GE commands)")
    before = snap("0_start")
    ok = True
    # (key, minimum changed pixels, GE commands to wait for, quiet slices needed)
    steps = (("DOWN", 2000, 1, 6),        # step 1: language highlight
             ("OK", 20000, 1, 6),         # step 2: aspect-ratio list
             ("DOWN", 1500, 1, 6),        # its highlight moves
             ("OK", 20000, 40, 0))        # step 3: channel search, redraws continuously
    for i, (key, min_px, min_ops, quiet) in enumerate(steps, 1):
        try:
            addr, cmd = sim.press_key(key)
        except Exception as e:
            print(f"[FAIL] press_key({key!r}): {e}")
            sys.exit(1)
        ops = sim.ge_ops
        drawn = run_until_drawn(ops + min_ops, KEY_LIMIT_S, quiet)
        after = snap(f"{i}_{key}")
        changed = int((after != before).any(axis=2).sum())
        print(f"[{time.time() - start:6.1f}s] {key} (NEC 0x{addr:02X}/0x{cmd:02X}): "
              f"{sim.ge_ops - ops} GE commands, {changed} pixels changed")
        if not drawn or changed < min_px:
            print(f"[FAIL] the OSD did not react to {key} (step {i})")
            ok = False
            break
        before = after
    if ok:
        # the channel search is running: its progress screen keeps changing
        ops = sim.ge_ops
        run_for(40)
        after = snap("5_search_progress")
        changed = int((after != before).any(axis=2).sum())
        print(f"[{time.time() - start:6.1f}s] channel search 40 s later: {sim.ge_ops - ops} GE commands, "
              f"{changed} pixels changed")
        if sim.ge_ops - ops < 10 or changed < 200:
            print("[FAIL] the channel-search progress screen did not advance")
            ok = False
    report_artifacts.panel(panel.digits, "front panel (TM1650) at the end", panel.get_display_text())
    if not ok:
        sys.exit(1)
    print(f"[PASS] the firmware's menus follow the IR remote ({time.time() - start:.0f}s total)")
    sys.exit(0)


if __name__ == "__main__":
    main()
