"""
Attach rendered images and front-panel displays to the self-test report.

A test that draws something calls image() with a PNG it saved (an OSD screen
capture, a difference map, ...) and panel() with the segment bytes of a
front-panel LED display; run_all_tests.py picks these up from the test's
output and shows them in report/index.html (report.py).  Both print one
machine-readable line to stdout:

  [REPORT_IMAGE] <path>\t<caption>
  [REPORT_PANEL] <hex segment bytes>\t<text>\t<caption>

so a test needs nothing but this module, and run on its own the lines are
just two more log lines.  out_dir() is where a test should save such files:
run_all_tests.py sets ALISIM_REPORT_DIR to a per-test directory under report/
(a plain run uses the current directory).
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

IMAGE_TAG = "[REPORT_IMAGE]"
PANEL_TAG = "[REPORT_PANEL]"


def out_dir(*sub):
    """Directory for a test's image files (created): $ALISIM_REPORT_DIR or '.'."""
    d = os.path.join(os.environ.get("ALISIM_REPORT_DIR") or ".", *sub)
    os.makedirs(d, exist_ok=True)
    return d


def path(name):
    """Full path for an image file `name` in out_dir()."""
    return os.path.join(out_dir(), name)


def image(file_path, caption=""):
    """Report a saved image (PNG) with a one-line caption."""
    print(f"{IMAGE_TAG} {os.path.abspath(file_path)}\t{_one_line(caption)}", flush=True)


def panel(digits, caption="", text=None):
    """Report a front-panel display: `digits` are the segment bytes of the 4
    digits (bit 0..6 = segments a..g, bit 7 = DP, as the TM1650 / TM1628
    decoders' .digits give them), `text` the decoded characters if known."""
    hexes = " ".join(f"{int(d) & 0xFF:02X}" for d in digits)
    print(f"{PANEL_TAG} {hexes}\t{_one_line(text or '')}\t{_one_line(caption)}", flush=True)


def _one_line(s):
    return " ".join(str(s).split())
