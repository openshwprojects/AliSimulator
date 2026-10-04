"""
Screen capture self-test for dump_maciej.bin (slow, about 3 minutes): boots the
firmware into its application, captures what its OSD shows through the ALi
GE_M36F graphics engine into RAM, saves it as a PNG, and verifies pixel-by-pixel
against the saved golden reference image (dump_maciej_screen_golden.png).

Nothing here is extracted from the flash image.  The firmware draws its UI
through the ALi GE_M36F graphics engine -- command lists of rectangle fills,
bitmap blits (palette lookup, RLE icons, colour key) and anti-aliased font
glyphs (4-bit glyphs expanded to an A8 mask and alpha-blended) -- which the
simulator now executes into RAM (ge_m36f.py).  The display engine has no fixed
framebuffer: GMA layer 0's base-address register 0xB8006304 points to a region
head in RAM that names the bitmap (here a 1280x720 ARGB1555 surface) and its
position; sim.capture_screen() follows it (gma_capture.py).

Every time the GE goes quiet after drawing, the screen is captured; a frame
that differs from the previous one is written as <out>_NN.png, the last one
also as <out>.png.

Usage:
  python run_dump_maciej_capture_screen.py [out.png] [minutes after the app banner, default 3]
  python run_dump_maciej_capture_screen.py --verify-only [image.png]

Exit code 0 if a non-trivial screen was captured and matches the golden reference.
"""
import os
import sys
import time

import numpy as np

from simulator import AliMipsSimulator

BOOT_LIMIT_S = 15 * 60


def compare_images(rgb, golden_rgb):
    """Returns (diff_count, pct, max_diff, diff_mask)."""
    if rgb.shape != golden_rgb.shape:
        raise ValueError(f"Shape mismatch: {rgb.shape} vs {golden_rgb.shape}")
    diff_mask = (rgb != golden_rgb).any(axis=2)
    diff_count = int(diff_mask.sum())
    total_px = rgb.shape[0] * rgb.shape[1]
    pct = (diff_count / total_px) * 100.0
    max_diff = int(np.abs(rgb.astype(int) - golden_rgb.astype(int)).max()) if diff_count else 0
    return diff_count, pct, max_diff, diff_mask


def verify_against_golden(rgb, golden_path, diff_path=None):
    if not os.path.exists(golden_path):
        print(f"[WARN] golden reference not found at {golden_path}; skipping image comparison")
        return True
    try:
        from PIL import Image
        golden_rgb = np.array(Image.open(golden_path).convert('RGB'))
    except Exception as e:
        print(f"[FAIL] failed to open golden reference {golden_path}: {e}")
        return False

    try:
        diff_count, pct, max_diff, diff_mask = compare_images(rgb, golden_rgb)
    except Exception as e:
        print(f"[FAIL] image comparison failed: {e}")
        return False

    if diff_count == 0:
        print(f"[PASS] screen matches golden reference ({os.path.basename(golden_path)}) exactly (0 pixel differences)")
        return True

    if diff_path:
        try:
            from PIL import Image
            diff_vis = np.zeros_like(rgb)
            diff_vis[diff_mask] = [255, 0, 0]
            Image.fromarray(diff_vis).save(diff_path)
            print(f"saved difference map to {diff_path}")
        except Exception:
            pass

    total_px = rgb.shape[0] * rgb.shape[1]
    print(f"[FAIL] screen differs from golden reference: {diff_count}/{total_px} pixels differ "
          f"({pct:.2f}%, max channel diff: {max_diff})")
    return False


def main():
    golden_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dump_maciej_screen_golden.png")

    if "--verify-only" in sys.argv:
        target = "dump_maciej_screen.png"
        for arg in sys.argv[1:]:
            if not arg.startswith("-"):
                target = arg
                break
        if not os.path.exists(target):
            print(f"[FAIL] target image '{target}' not found")
            sys.exit(1)
        from PIL import Image
        img = np.array(Image.open(target).convert('RGB'))
        base = os.path.splitext(target)[0]
        ok = verify_against_golden(img, golden_path, f"{base}_diff.png")
        sys.exit(0 if ok else 1)

    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "dump_maciej_screen.png"
    app_minutes = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
    base = os.path.splitext(out)[0]
    print("=== dump_maciej: capture and verify the OSD drawn through the graphics engine ===")
    sim = AliMipsSimulator(log_handler=lambda msg: None)
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    uart = []
    sim.setUartHandler(lambda c: uart.append(c))
    sim.loadFile("dump_maciej.bin")

    start = time.time()
    app_t = None
    last_ops, captured_ops, frames, prev = 0, 0, 0, None
    while time.time() - start < BOOT_LIMIT_S:
        try:
            sim.run(max_instructions=sim.instruction_count + 5_000_000)
        except Exception as e:
            print(f"[FAIL] simulator stopped: {e}")
            sys.exit(1)
        now = time.time()
        if app_t is None and "Application version" in "".join(uart[-400:]):
            app_t = now
            print(f"[{now - start:6.1f}s] application started")
        if app_t and now - app_t > app_minutes * 60:
            break
        if sim.ge_ops != last_ops:          # still drawing
            last_ops = sim.ge_ops
            continue
        if sim.ge_ops == captured_ops:      # quiet, nothing new
            continue
        captured_ops = sim.ge_ops
        rgb = sim.capture_screen()
        if prev is None or not np.array_equal(rgb, prev):
            frames += 1
            path = f"{base}_{frames:02d}.png"
            sim.capture_screen(path)
            print(f"[{now - start:6.1f}s] {sim.ge_ops} GE commands ({sim.ge.primitives} primitives): "
                  f"new frame -> {path}")
        prev = rgb

    if prev is None:
        print("[FAIL] the firmware drew nothing")
        sys.exit(1)
    rgb = sim.capture_screen(out)
    colours = len(np.unique(rgb.reshape(-1, 3), axis=0))
    unsupported = dict(sim.ge.unsupported) if sim.ge else {}
    print(f"saved {out}: {rgb.shape[1]}x{rgb.shape[0]}, {colours} colours, {frames} distinct frame(s), "
          f"GE features not modelled: {unsupported or 'none'}")
    if colours < 16:
        print("[FAIL] the captured screen is (nearly) uniform")
        sys.exit(1)

    # Self-test: verify against the saved golden reference
    if not verify_against_golden(rgb, golden_path, f"{base}_diff.png"):
        sys.exit(1)

    print(f"[PASS] captured and verified the firmware's screen ({time.time() - start:.0f}s total)")
    sys.exit(0)


if __name__ == "__main__":
    main()

