"""
Unit test (fast): verifies integrity of the saved golden screen reference
(golden/dump_maciej_screen_golden.png) and tests the self-test image comparison logic.
"""
import hashlib
import os
import sys

import numpy as np
from PIL import Image

import report_artifacts
import run_dump_maciej_capture_screen as capture_mod

EXPECTED_SHA256 = "94b48dc3e8a01a79569a681dc8bc3dab897f36c36d0e66d13bfcdbe6e69d5702"
EXPECTED_SHAPE = (720, 1280, 3)

fails = []


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


def main():
    print("=== Unit test: dump_maciej golden screen reference integrity ===")
    golden_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden", "dump_maciej_screen_golden.png")

    check(os.path.exists(golden_path), f"golden image file exists ({os.path.basename(golden_path)})")
    if not os.path.exists(golden_path):
        sys.exit(1)

    img = np.array(Image.open(golden_path).convert("RGB"))
    report_artifacts.image(golden_path, "the golden reference (dump_maciej's first wizard screen)")
    check(img.shape == EXPECTED_SHAPE, f"image resolution is {EXPECTED_SHAPE[1]}x{EXPECTED_SHAPE[0]} (got {img.shape})")

    pixel_hash = hashlib.sha256(img.tobytes()).hexdigest()
    check(pixel_hash == EXPECTED_SHA256, f"raw pixel SHA256 matches baseline ({pixel_hash[:16]}...)")

    colours = len(np.unique(img.reshape(-1, 3), axis=0))
    check(colours >= 16, f"image contains rich UI elements ({colours} unique colours)")

    # Test image comparison logic
    diff_count, pct, max_diff, _ = capture_mod.compare_images(img, img)
    check(diff_count == 0 and pct == 0.0 and max_diff == 0, "compare_images on identical image returns 0 diff")

    # Test mismatch detection
    mutated = img.copy()
    mutated[100, 100] = (255 - mutated[100, 100, 0], 0, 0)
    diff_count, pct, max_diff, _ = capture_mod.compare_images(img, mutated)
    check(diff_count == 1 and max_diff > 0, f"compare_images detects pixel mutations (diff: {diff_count})")

    try:
        capture_mod.compare_images(img, img[:100, :100])
        check(False, "compare_images on mismatched shape should raise ValueError")
    except ValueError:
        check(True, "compare_images rejects mismatched shape with ValueError")

    if fails:
        print(f"\n[FAIL] {len(fails)} check(s) failed")
        sys.exit(1)
    print("\n[PASS] golden screen reference and self-test comparison logic verified")
    sys.exit(0)


if __name__ == "__main__":
    main()
