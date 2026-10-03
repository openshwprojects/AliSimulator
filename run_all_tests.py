"""
Unified test runner for all MIPS simulator tests.

This script runs all test files in the project and reports aggregate results.
Individual test files can still be run directly via their own files.
"""

import sys
import os
import subprocess
from pathlib import Path


def run_test_file(test_file_path):
    """
    Run a single test file and capture its result.
    
    Args:
        test_file_path: Path to the test file
        
    Returns:
        Tuple of (test_name, passed) where passed is True if test succeeded
    """
    test_name = os.path.basename(test_file_path)

    print(f"\n{'=' * 80}")
    print(f"Running: {test_name}")
    print(f"{'=' * 80}\n", flush=True)

    # Each test runs in its own Python process: a test that crashes the
    # interpreter (a native fault inside Unicorn) fails on its own instead of
    # ending the whole run without a summary.  Unbuffered, so its output up to
    # a crash is not lost, and with faulthandler, which prints the Python stack
    # of a native crash.
    env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONFAULTHANDLER="1")
    exit_code = subprocess.call([sys.executable, test_file_path],
                                cwd=os.path.dirname(os.path.abspath(test_file_path)), env=env)
    if exit_code not in (0, 1):
        print(f"\n{test_name} exited with code {exit_code} (0x{exit_code & 0xFFFFFFFF:08X}): "
              f"crashed?", flush=True)

    # Check if test passed (exit code 0 means success)
    return test_name, exit_code == 0


def discover_test_files(include_slow=False):
    """
    Discover all test files in the current directory.
    
    Returns:
        List of test file paths
    """
    current_dir = Path(__file__).parent
    test_files = []
    
    # Find all test_*.py files except utility modules
    for file_path in current_dir.glob("test_*.py"):
        # Skip utility modules
        if "util" not in file_path.stem:
            test_files.append(str(file_path))
    
    # Also include the specific regression tests
    reg_test = current_dir / "run_dump_to_print_bl_flash_init.py"
    if reg_test.exists():
        test_files.append(str(reg_test))
    
    reg_test_maciej = current_dir / "run_dump_maciej_to_print_bl_flash_init.py"
    if reg_test_maciej.exists():
        test_files.append(str(reg_test_maciej))
    
    reg_test_check_program = current_dir / "run_dump_to_print_check_program.py"
    if reg_test_check_program.exists():
        test_files.append(str(reg_test_check_program))
    
    reg_test_bad_flash = current_dir / "run_dump_with_bad_flash_id.py"
    if reg_test_bad_flash.exists():
        test_files.append(str(reg_test_bad_flash))
    
    reg_test_maciej_verify = current_dir / "run_dump_maciej_to_bl_verify_sw.py"
    if reg_test_maciej_verify.exists():
        test_files.append(str(reg_test_maciej_verify))
    
    reg_test_prima = current_dir / "run_dump_Prima_to_check_program.py"
    if reg_test_prima.exists():
        test_files.append(str(reg_test_prima))
    
    reg_test_success = current_dir / "run_dump_Prima_to_print_success.py"
    if reg_test_success.exists():
        test_files.append(str(reg_test_success))
    
    reg_test_i2c_display = current_dir / "run_dump_maciej_to_I2C_display_ON.py"
    if reg_test_i2c_display.exists():
        test_files.append(str(reg_test_i2c_display))

    reg_test_uart_buffer = current_dir / "run_dump_maciej_to_verify_uart_buffer.py"
    if reg_test_uart_buffer.exists():
        test_files.append(str(reg_test_uart_buffer))

    reg_test_uart_negative = current_dir / "run_dump_maciej_without_uart_interrupt.py"
    if reg_test_uart_negative.exists():
        test_files.append(str(reg_test_uart_negative))

    reg_test_uart_overflow = current_dir / "run_dump_maciej_to_check_uart_overflow.py"
    if reg_test_uart_overflow.exists():
        test_files.append(str(reg_test_uart_overflow))

    reg_test_no_main_app = current_dir / "run_dump_no_main_app.py"
    if reg_test_no_main_app.exists():
        test_files.append(str(reg_test_no_main_app))

    # The firmware boots into its main application, whose RTOS runs on CP0
    # timer ticks (about 20 s each)
    for name in ("run_dump_to_main_app.py", "run_dump_Prima_to_main_app.py"):
        if (current_dir / name).exists():
            test_files.append(str(current_dir / name))

    # Slow regressions (minutes): only with --slow
    if include_slow:
        reg_test_main_app = current_dir / "run_dump_maciej_to_main_app.py"
        if reg_test_main_app.exists():
            test_files.append(str(reg_test_main_app))

    return sorted(test_files)


def main():
    """Main test runner function."""
    print("\n" + "=" * 80)
    print("MIPS Simulator Test Suite - Running All Tests")
    print("=" * 80)
    
    # Discover all test files (--slow adds the multi-minute regressions)
    include_slow = "--slow" in sys.argv[1:]
    test_files = discover_test_files(include_slow)
    if not include_slow:
        print("(slow regressions skipped; run with --slow to include run_dump_maciej_to_main_app.py)")
    
    if not test_files:
        print("No test files found!")
        sys.exit(1)
    
    print(f"\nFound {len(test_files)} test file(s):")
    for test_file in test_files:
        print(f"  - {os.path.basename(test_file)}")
    
    # Run all tests
    results = []
    for test_file in test_files:
        test_name, passed = run_test_file(test_file)
        results.append((test_name, passed))
    
    # Print summary
    print("\n" + "=" * 80)
    print("Test Summary")
    print("=" * 80)
    
    passed_count = 0
    failed_count = 0
    
    for test_name, passed in results:
        if passed:
            status = "\033[92mPASS\033[0m"
            passed_count += 1
        else:
            status = "\033[91mFAIL\033[0m"
            failed_count += 1
        print(f"  {status} - {test_name}")
    
    print("\n" + "-" * 80)
    
    total = len(results)
    if failed_count == 0:
        print(f"\033[92mAll {total} test(s) passed!\033[0m")
        sys.exit(0)
    else:
        print(f"\033[91m{failed_count} of {total} test(s) failed\033[0m")
        sys.exit(1)


if __name__ == "__main__":
    main()
