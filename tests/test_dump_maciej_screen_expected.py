"""
Unit test (fast): verifies integrity of the saved expected screen
(tests/expected/dump_maciej_screen.png) and the screen regressions' image
comparison (screen_regression.compare).
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import hashlib

import numpy as np
from PIL import Image

import report_artifacts
import screen_regression

EXPECTED_SHA256 = "94b48dc3e8a01a79569a681dc8bc3dab897f36c36d0e66d13bfcdbe6e69d5702"
EXPECTED_SHAPE = (720, 1280, 3)

fails = []


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


def main():
    print("=== Unit test: dump_maciej expected screen integrity ===")
    expected_path = os.path.join(screen_regression.EXPECTED_DIR, "dump_maciej_screen.png")

    check(os.path.exists(expected_path), f"expected screen file exists ({os.path.basename(expected_path)})")
    if not os.path.exists(expected_path):
        sys.exit(1)

    img = np.array(Image.open(expected_path).convert("RGB"))
    report_artifacts.image(expected_path, "the expected screen (dump_maciej's first wizard screen)")
    check(img.shape == EXPECTED_SHAPE, f"image resolution is {EXPECTED_SHAPE[1]}x{EXPECTED_SHAPE[0]} (got {img.shape})")

    pixel_hash = hashlib.sha256(img.tobytes()).hexdigest()
    check(pixel_hash == EXPECTED_SHA256, f"raw pixel SHA256 matches baseline ({pixel_hash[:16]}...)")

    colours = len(np.unique(img.reshape(-1, 3), axis=0))
    check(colours >= 16, f"image contains rich UI elements ({colours} unique colours)")

    # Test image comparison logic
    diff_count, pct, max_diff, _ = screen_regression.compare(img, img)
    check(diff_count == 0 and pct == 0.0 and max_diff == 0, "compare on identical image returns 0 diff")

    # Test mismatch detection
    mutated = img.copy()
    mutated[100, 100] = (255 - mutated[100, 100, 0], 0, 0)
    diff_count, pct, max_diff, _ = screen_regression.compare(img, mutated)
    check(diff_count == 1 and max_diff > 0, f"compare detects pixel mutations (diff: {diff_count})")

    try:
        screen_regression.compare(img, img[:100, :100])
        check(False, "compare on mismatched shape should raise ValueError")
    except ValueError:
        check(True, "compare rejects mismatched shape with ValueError")

    if fails:
        print(f"\n[FAIL] {len(fails)} check(s) failed")
        sys.exit(1)
    print("\n[PASS] expected screen reference and the screen comparison verified")
    sys.exit(0)


if __name__ == "__main__":
    main()
