"""
Regression test: SRT_Prima_VIII boots through the bootloader into the main
application, whose RTOS runs on CP0 timer ticks and prints its init banner.

Before the CP0 timer interrupt existed, the application parked forever in the
RTOS idle task (`b .` at 0x802EA124) right after the bootloader's 'success!'.
The whole UART output is compared byte for byte (the Libcore line carries a
UTF-8 date), so duplicated or lost characters fail the test.  The init then
has to get past the PMU handshake (0xB8018D02) and the VCAP busy bit
(0xB800F04B), see app_reach_check.py.  About 15 s.
"""
import sys

from app_reach_check import run_to_app_banner, report

FIRMWARE = "SRT_Prima_VIII_V1.0.6_20160114.abs"
EXPECTED = (b"\x01APP  init!\r\nbl_flash_init!\r\nbl_verify_sw\r\ncheck_program!\r\nsuccess!\r\n"
            b"\x01MC: APP  init ok\r\r\n<< SDK4.0ba.4.0_20101217 >>\r\n\r\r\n"
            b"Libcore version 8.32.0@SDK4.0bd.8.32_20141126(gcc version 3.4.4 mipssde-6.06.01-20070420)"
            b"(edwindle.zhang@ 2014\xe5\xb9\xb411\xe6\x9c\x8824\xe6\x97\xa5 10:23:28)\r\n\r\r\n"
            b"Application version 1.0.0@SDK4.0bd.8.32_20141126byAdministrator\r\n\r\r\n")


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
