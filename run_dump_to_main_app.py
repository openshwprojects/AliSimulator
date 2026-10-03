"""
Regression test: dump.bin boots through the bootloader into the main
application, whose RTOS runs on CP0 timer ticks and prints its init banner.

Before the CP0 timer interrupt existed, the application parked forever in the
RTOS idle task (`b .` at 0x802B1254) right after the bootloader's 'success!'.
The whole UART output is compared byte for byte, so duplicated or lost
characters (e.g. a device access replayed after an asynchronous slice stop)
fail the test.  About 10 s.
"""
import sys

from app_reach_check import run_to_app_banner, report

FIRMWARE = "dump.bin"
EXPECTED = (b"\x01APP  init!\r\nbl_flash_init!\r\nbl_verify_sw\r\ncheck_program!\r\nsuccess!\r\n"
            b"\x01MC: APP  init ok\r\r\n<< SDK4.0ba.4.0_20101217 >>\r\n\r\r\n"
            b"Libcore version 8.1c.0@SDK4.0bd.8.7_20121127(gcc version 3.4.4 mipssde-6.06.01-20070420)"
            b"(vic.wang@ Fri Nov 30 11:35:29 2012)\r\n\r\r\n"
            b"Application version 1.0.0@SDK4.0bd.8.7_20121127byUSER\r\n\r\r\n")


def main():
    print(f"=== Regression Test: {FIRMWARE} boots into the main application ===")
    try:
        res = run_to_app_banner(FIRMWARE, len(EXPECTED))
    except FileNotFoundError:
        print(f"{FIRMWARE} not found")
        sys.exit(1)
    sys.exit(0 if report(f"{FIRMWARE} main application started", res, EXPECTED) else 1)


if __name__ == "__main__":
    main()
