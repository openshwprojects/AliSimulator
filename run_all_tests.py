"""
Unified test runner for all MIPS simulator tests.

Runs every test script of the project (test_*.py unit tests and the
run_dump_*.py firmware regressions), each in its own Python process, prints
their output as it comes, and reports aggregate results.  Individual test files
can still be run directly.

It also writes report/index.html (report.py): one page with every test's
verdict, timing, description (the script's docstring), its [PASS] / [FAIL]
assertions and full output, and the images the test attached through
report_artifacts.py -- the OSD screens it rendered and the front-panel LED
displays it decoded.  The GitHub Actions workflow publishes that page to
GitHub Pages after every push.

  python run_all_tests.py            the default suite (a few minutes)
  python run_all_tests.py --slow     plus the multi-minute firmware runs
  python run_all_tests.py -k remote  only scripts whose name contains 'remote'
  python run_all_tests.py --timeout 1800   kill a test after 30 minutes
  python run_all_tests.py --slow --jobs 2  two tests at a time (output per test, not streamed)
"""

import ast
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import report
import report_artifacts

ROOT = Path(__file__).parent
REPORT_DIR = ROOT / "report"

# Scripts whose name does not say which dump they run: look for it in the source
DUMPS = [("dump_maciej.bin", "dump_maciej.bin"), ("dump.bin", "dump.bin"),
         ("SRT_Prima", "SRT Prima VIII"), ("Globo", "Globo N3"), ("URZ0083Q", "Cabletech URZ0083Q"),
         ("urz0195", "Cabletech URZ0195"), ("urz0194", "Cabletech URZ0194S"), ("srt8115", "Strong SRT 8115"),
         ("ali_sdk.bin", "ali_sdk.bin")]
SLOW_TESTS = ("run_dump_maciej_to_main_app.py", "run_dump_maciej_capture_screen.py",
              "run_dump_maciej_remote.py", "run_dump_globo_capture_screen.py",
              "run_dump_cabletech_capture_screen.py", "run_dump_capture_screen.py",
              "run_dump_srt8115_capture_screen.py", "run_dump_urz0194s_capture_screen.py",
              "run_dump_urz0195_capture_screen.py")


def discover_test_files(include_slow=False):
    """All test scripts: test_*.py (except util modules) plus the regression runs."""
    test_files = []
    for file_path in ROOT.glob("test_*.py"):
        if "util" not in file_path.stem:
            test_files.append(str(file_path))
    regressions = [
        "run_dump_to_print_bl_flash_init.py", "run_dump_maciej_to_print_bl_flash_init.py",
        "run_dump_to_print_check_program.py", "run_dump_with_bad_flash_id.py",
        "run_dump_maciej_to_bl_verify_sw.py", "run_dump_Prima_to_check_program.py",
        "run_dump_Prima_to_print_success.py", "run_dump_maciej_to_I2C_display_ON.py",
        "run_dump_maciej_to_verify_uart_buffer.py", "run_dump_maciej_without_uart_interrupt.py",
        "run_dump_maciej_to_check_uart_overflow.py", "run_dump_no_main_app.py",
        # the firmware boots into its main application, whose RTOS runs on CP0
        # timer ticks (about 20 s each)
        "run_dump_to_main_app.py", "run_dump_Prima_to_main_app.py",
    ]
    if include_slow:
        regressions += list(SLOW_TESTS)       # minutes each
    for name in regressions:
        if (ROOT / name).exists():
            test_files.append(str(ROOT / name))
    return sorted(test_files)


def _description(path):
    """The script's module docstring (shown in the report)."""
    try:
        return (ast.get_docstring(ast.parse(Path(path).read_text(encoding="utf-8"))) or "").strip()
    except Exception:
        return ""


def _tags(path, result):
    name = os.path.basename(path)
    try:
        source = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        source = ""
    tags = []
    for needle, label in DUMPS:
        if needle.lower() in name.lower() or needle in source:
            if not any(t["name"] == label for t in tags):
                tags.append({"group": "dump", "name": label})
    if name.startswith("test_"):
        tags.append({"group": "kind", "name": "unit"})
    else:
        tags.append({"group": "kind", "name": "regression"})
    if name in SLOW_TESTS:
        tags.append({"group": "kind", "name": "slow"})
    if result["images"] or result["panels"]:
        tags.append({"group": "data", "name": "renders"})
    if result["crashed"]:
        tags.append({"group": "data", "name": "crashed"})
    if result["timed_out"]:
        tags.append({"group": "data", "name": "timed out"})
    return tags


def _collect_artifact(line, result, img_dir):
    """A [REPORT_IMAGE] / [REPORT_PANEL] line from the test: record it (the
    image file is copied next to the report).  Returns True if it was one."""
    if line.startswith(report_artifacts.IMAGE_TAG):
        body = line[len(report_artifacts.IMAGE_TAG):].strip()
        path, _, caption = body.partition("\t")
        entry = {"path": path, "caption": caption, "missing": not os.path.isfile(path)}
        if not entry["missing"]:
            try:
                os.makedirs(img_dir, exist_ok=True)
                dest = os.path.join(img_dir, os.path.basename(path))
                if os.path.abspath(dest) != os.path.abspath(path):
                    shutil.copyfile(path, dest)
                entry["path"] = dest
            except OSError:
                pass
        result["images"].append(entry)
        return True
    if line.startswith(report_artifacts.PANEL_TAG):
        body = line[len(report_artifacts.PANEL_TAG):].strip()
        hexes, _, rest = body.partition("\t")
        text, _, caption = rest.partition("\t")
        try:
            digits = [int(h, 16) for h in hexes.split()]
        except ValueError:
            digits = []
        result["panels"].append({"digits": digits, "text": text, "caption": caption})
        return True
    return False


_print_lock = threading.Lock()


def run_test_file(test_file_path, timeout=None, stream=True):
    """Run a single test file and return its result record.  Its output is
    streamed as it comes (stream=True) or printed as one block at the end
    (parallel runs)."""
    test_name = os.path.basename(test_file_path)
    stem = os.path.splitext(test_name)[0]
    img_dir = str(REPORT_DIR / "img" / stem)

    if stream:
        print(f"\n{'=' * 80}")
        print(f"Running: {test_name}")
        print(f"{'=' * 80}\n", flush=True)

    # Each test runs in its own Python process: a test that crashes the
    # interpreter (a native fault inside Unicorn) fails on its own instead of
    # ending the whole run without a summary.  Unbuffered, so its output up to
    # a crash is not lost, and with faulthandler, which prints the Python stack
    # of a native crash.  ALISIM_REPORT_DIR tells report_artifacts where to put
    # the images the test renders.
    env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONFAULTHANDLER="1", PYTHONIOENCODING="utf-8",
               ALISIM_REPORT_DIR=img_dir)
    result = {"name": test_name, "script": test_name, "description": _description(test_file_path),
              "passed": False, "elapsed": 0.0, "exit_code": None, "crashed": False, "timed_out": False,
              "checks": [], "output": "", "images": [], "panels": []}
    lines = []
    start = time.time()
    proc = subprocess.Popen([sys.executable, test_file_path], cwd=str(ROOT), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace", bufsize=1)

    def reader():
        for line in proc.stdout:
            if _collect_artifact(line.rstrip("\r\n"), result, img_dir):
                continue
            lines.append(line)
            if stream:
                sys.stdout.write(line)
                sys.stdout.flush()

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        result["timed_out"] = True
        proc.kill()
        proc.wait()
        print(f"\n{test_name} killed after {timeout:.0f}s (timeout)", flush=True)
    th.join(timeout=5)
    exit_code = proc.returncode
    result["elapsed"] = time.time() - start
    result["exit_code"] = exit_code
    result["output"] = "".join(lines)
    result["crashed"] = exit_code not in (0, 1) and not result["timed_out"]
    if result["crashed"]:
        print(f"\n{test_name} exited with code {exit_code} (0x{exit_code & 0xFFFFFFFF:08X}): "
              f"crashed?", flush=True)
    for line in lines:
        m = re.search(r"\[(PASS|FAIL)\]\s*(.*)", line)
        if m:
            result["checks"].append({"ok": m.group(1) == "PASS", "text": m.group(2).strip()})
    result["passed"] = exit_code == 0
    result["tags"] = _tags(test_file_path, result)
    if not stream:
        with _print_lock:
            print(f"\n{'=' * 80}\n{test_name}: {'PASS' if result['passed'] else 'FAIL'} "
                  f"({result['elapsed']:.0f}s)\n{'=' * 80}\n{result['output']}", flush=True)
    return result


def write_report(results, note=""):
    """Emit report/index.html; never fails the run itself."""
    try:
        run_id = os.environ.get("GITHUB_RUN_ID")
        run_url = None
        if run_id:
            run_url = "%s/%s/actions/runs/%s" % (os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
                                                  os.environ.get("GITHUB_REPOSITORY", ""), run_id)
        meta = {
            "total_time": sum(r["elapsed"] for r in results),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "commit": os.environ.get("GITHUB_SHA"),
            "repo": os.environ.get("GITHUB_REPOSITORY"),
            "run_url": run_url,
            "note": note,
        }
        path = report.generate(results, meta, str(REPORT_DIR / "index.html"))
        print(f"HTML report written: {path}")
    except Exception as e:
        print(f"WARN: could not write the HTML report: {e!r}")


def main():
    """Main test runner function."""
    args = sys.argv[1:]
    include_slow = "--slow" in args
    timeout = None
    if "--timeout" in args:
        timeout = float(args[args.index("--timeout") + 1])
    jobs = int(args[args.index("--jobs") + 1]) if "--jobs" in args else 1
    patterns = [a.lower() for i, a in enumerate(args) if i > 0 and args[i - 1] == "-k"]

    print("\n" + "=" * 80)
    print("MIPS Simulator Test Suite - Running All Tests")
    print("=" * 80)

    test_files = discover_test_files(include_slow)
    if patterns:
        test_files = [t for t in test_files if any(p in os.path.basename(t).lower() for p in patterns)]
    if not include_slow:
        print("(slow regressions skipped; run with --slow to include " + ", ".join(SLOW_TESTS) + ")")
    if not test_files:
        print("No test files found!")
        sys.exit(1)

    print(f"\nFound {len(test_files)} test file(s):")
    for test_file in test_files:
        print(f"  - {os.path.basename(test_file)}")

    if jobs > 1:
        # Parallel: the simulations are CPU bound and independent (firmware time
        # follows each emulation thread's own CPU time), so N at once on N cores
        # cuts the wall time of the slow suite; outputs are printed per test.
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(lambda t: run_test_file(t, timeout, stream=False), test_files))
    else:
        results = [run_test_file(t, timeout) for t in test_files]

    print("\n" + "=" * 80)
    print("Test Summary")
    print("=" * 80)
    for r in results:
        status = "\033[92mPASS\033[0m" if r["passed"] else "\033[91mFAIL\033[0m"
        extra = " (crashed)" if r["crashed"] else (" (timed out)" if r["timed_out"] else "")
        print(f"  {status} - {r['name']}{extra}  {r['elapsed']:.0f}s")
    print("\n" + "-" * 80)

    note = ("default suite" if not include_slow else "with --slow") + (f", {jobs} jobs" if jobs > 1 else "")
    if patterns:
        note += ", filtered: " + ", ".join(patterns)
    write_report(results, note)

    total = len(results)
    failed = sum(1 for r in results if not r["passed"])
    if failed == 0:
        print(f"\033[92mAll {total} test(s) passed!\033[0m")
        sys.exit(0)
    print(f"\033[91m{failed} of {total} test(s) failed\033[0m")
    sys.exit(1)


if __name__ == "__main__":
    main()
