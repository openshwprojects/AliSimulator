"""
Screen survey: boot every firmware image under dumps/ -- or those whose path
contains one of the given words -- each in its own Python process, until its
screen shows something (at least MIN_COLOURS colours in sim.capture_screen():
a blank screen has one, the Thomson THT501's flat wizard seven), and report
how many instructions that took, the graphics engine's command count and what
the front panel showed on the way (a text held for two slices, not one caught
half rewritten).  An image whose sidecar
says "display": true but that draws nothing within the budget (or the other
way round) is flagged.  The screen regressions under tests/ check one image
per family in depth; this checks that every image still gives a screen, in
about half an hour for all of them with --jobs 3 (2026-10-19: 98 of 100 draw,
within 10-130 s each; ali_sdk.bin has no display, the R265 Lite's M3822P.bin
dump a damaged main code) -- not part of run_all_tests.py.

  python tools/screen_survey.py                      every image, one at a time
  python tools/screen_survey.py --jobs 2 URZ0083 KM0183   these only, two at a time
  python tools/screen_survey.py --out shots          also save each first screen there
  python tools/screen_survey.py --budget 600         instruction budget per image, millions

The boot runs in 5 M instruction slices with the dump's front panel decoder
and tuner model attached, as the screen regressions do; the screen is looked
at every 10 M instructions.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))   # the simulator's modules

MIN_COLOURS = 4
SLICE = 5_000_000
PROBE_EVERY = 10_000_000


def survey_one(path, budget_m, out_dir):
    """Boot one image (in this process) and print its result as one JSON line."""
    import numpy as np
    from unicorn.mips_const import UC_MIPS_REG_PC
    import gma_capture
    from front_panel import make_panel
    from simulator import AliMipsSimulator, flash_size_for

    sim = AliMipsSimulator(rom_size=flash_size_for(path), log_handler=lambda m: None)
    sim.setSPIDump(False)
    sim.setUartHandler(lambda c: None)
    panel, _keys, _desc = make_panel(path, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    result = {"path": path, "drawn_at": None, "colours": 0, "ge_ops": 0, "panel": [], "error": None}
    start = time.time()
    try:
        sim.loadFile(path)
        try:
            sim.attach_tuner()
        except Exception:
            pass                                    # no tuner model for this dump
        next_probe = PROBE_EVERY
        previous_text = None
        while sim.instruction_count < budget_m * 1_000_000:
            before = sim.instruction_count
            sim.run(max_instructions=sim.instruction_count + SLICE)
            text = panel.get_display_text()
            # a text the firmware is still writing digit by digit would show up mixed: keep a text
            # only once it has been on the display at the end of two slices in a row
            if text == previous_text and text.strip() and (not result["panel"] or result["panel"][-1] != text):
                result["panel"].append(text)
            previous_text = text
            if sim.instruction_count >= next_probe or sim.instruction_count <= before or (sim.mu.reg_read(UC_MIPS_REG_PC) & ~1) == 0:
                next_probe = sim.instruction_count + PROBE_EVERY
                rgb = sim.capture_screen()
                px = rgb.reshape(-1, 3).astype(np.uint32)     # (one word per pixel: unique sorts it fast)
                colours = len(np.unique((px[:, 0] << 16) | (px[:, 1] << 8) | px[:, 2]))
                if colours >= MIN_COLOURS:
                    result.update(drawn_at=sim.instruction_count, colours=colours)
                    if out_dir:
                        name = os.path.splitext(os.path.basename(path))[0] + ".png"
                        gma_capture.save_png(os.path.join(out_dir, name), rgb)
                    break
                if (sim.mu.reg_read(UC_MIPS_REG_PC) & ~1) == 0:
                    result["error"] = "jump to NULL"
                    break
                if sim.instruction_count <= before:
                    result["error"] = "CPU stalled"
                    break
    except Exception as e:                          # a crash is a result too
        result["error"] = f"{type(e).__name__}: {e}"[:200]
    result.update(ge_ops=sim.ge_ops, instructions=sim.instruction_count, seconds=round(time.time() - start))
    print("RESULT " + json.dumps(result))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("words", nargs="*", help="only images whose path contains one of these (case-insensitive)")
    ap.add_argument("--jobs", type=int, default=1, help="images booted at a time")
    ap.add_argument("--budget", type=float, default=450, help="instruction budget per image, millions")
    ap.add_argument("--out", help="directory for each image's first drawn screen")
    ap.add_argument("--one", help=argparse.SUPPRESS)        # the child process: survey this image
    args = ap.parse_args()
    if args.out:
        os.makedirs(args.out, exist_ok=True)
    if args.one:
        survey_one(args.one, args.budget, args.out)
        return

    import dump_catalog
    entries = [(p, d) for p, d in dump_catalog.catalog()
               if not args.words or any(w.lower() in p.lower() for w in args.words)]
    print(f"{len(entries)} image(s), budget {args.budget:.0f} M instructions each, {args.jobs} at a time")

    def run_child(entry):
        path, data = entry
        expected = bool(data and data.get("simulator", {}).get("display"))
        cmd = [sys.executable, os.path.abspath(__file__), "--one", path, "--budget", str(args.budget)]
        if args.out:
            cmd += ["--out", args.out]
        result = None
        for _attempt in range(2 if expected else 1):
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=600).stdout
            except subprocess.TimeoutExpired:
                out = ""
            line = next((l for l in out.splitlines() if l.startswith("RESULT ")), None)
            result = json.loads(line[7:]) if line else {"path": path, "drawn_at": None, "error": "no result (crashed?)"}
            if result.get("drawn_at") is not None:
                break
        drawn = result.get("drawn_at") is not None
        flag = "" if drawn == expected else ("  <-- sidecar says display: " + ("true" if expected else "false"))
        rel = os.path.relpath(path, dump_catalog.DUMPS_DIR)
        what = (f"drawn at {result['drawn_at'] / 1e6:.0f} M ({result['colours']} colours, {result['ge_ops']} GE)"
                if drawn else f"nothing drawn ({result.get('error') or 'budget used up'})")
        panel = " -> ".join(f"[{t}]" for t in result.get("panel") or []) or "-"
        print(f"{'OK  ' if drawn else 'NONE'} {rel}: {what}, panel {panel}, {result.get('seconds', '?')} s{flag}",
              flush=True)
        return drawn, flag

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        results = list(pool.map(run_child, entries))
    print(f"\n{sum(d for d, _ in results)} of {len(results)} image(s) draw; "
          f"{sum(1 for _, f in results if f)} disagree with their sidecar")


if __name__ == "__main__":
    main()
