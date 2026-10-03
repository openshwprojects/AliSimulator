"""
Regression test (slow, about 5 minutes): dump_maciej.bin boots through the
whole bootloader and starts the main application.

  1. the UART shows the boot sequence up to the bootloader's 'success!',
  2. execution reaches the application entry (chunk header codestart, default
     0x80000200) in MIPS32 mode,
  3. expand() decompressed the main-code chunk correctly: the RAM at the entry
     equals an offline LZMA decompression of the chunk found in the flash
     image (7 MB compared byte for byte),
  4. the application's RTOS runs: it takes CP0 timer interrupts (IP7 ticks)
     and its main task gets past its first sleep and prints the init banner
     ('MC: APP  init ok').  Before the timer existed the application parked
     forever in the idle task's `b .`.

Included in run_all_tests.py only with --slow.
"""
import lzma
import struct
import sys
import time

from simulator import AliMipsSimulator
from unicorn.mips_const import UC_MIPS_REG_PC

EXPECTED_STRINGS = ["APP  init!", "bl_panel_init!", "bl_flash_init!", "bl_verify_sw", "success!"]
CHUNKID_MAINCODE, CHUNKID_MAINCODE_MASK = 0x01FE0000, 0xFFFF0000
BOOT_LIMIT_S = 15 * 60
APP_LIMIT_S = 120


def find_main_code(flash):
    """Walk the chunk chain (big-endian longs) like sto_chunk_goto() does."""
    p = 0
    while p + 128 <= len(flash):
        cid, length, off = struct.unpack_from('>III', flash, p)
        if cid in (0, 0xFFFFFFFF):
            break
        if (cid & CHUNKID_MAINCODE_MASK) == CHUNKID_MAINCODE:
            codestart = struct.unpack_from('>I', flash, p + 120)[0]
            entry = struct.unpack_from('>I', flash, p + 124)[0]
            if codestart in (0, 0xFFFFFFFF):
                codestart = 0x80000200
            if entry in (0, 0xFFFFFFFF):
                entry = codestart
            return p, length, codestart, entry
        if off == 0:
            break
        p += off
    return None


def main():
    print("=== Regression Test: dump_maciej boots into the main application (slow) ===")
    try:
        flash = open("dump_maciej.bin", "rb").read()[:4 * 1024 * 1024]
    except FileNotFoundError:
        print("dump_maciej.bin not found")
        sys.exit(1)
    found = find_main_code(flash)
    if not found:
        print("[FAIL] main-code chunk not found in the flash image")
        sys.exit(1)
    off, length, codestart, entry = found
    image = lzma.decompress(flash[off + 128: off + 128 + length], format=lzma.FORMAT_ALONE)
    print(f"main-code chunk @0x{off:06X} len 0x{length:X}, decompresses to 0x{len(image):X} bytes, "
          f"codestart 0x{codestart:08X} entry 0x{entry:08X}")

    sim = AliMipsSimulator(log_handler=lambda msg: None)
    sim.setSPIDump(False)
    uart, seen_success = [], [False]

    def on_uart(char):
        uart.append(char)
        if not seen_success[0] and "success!" in "".join(uart[-12:]):
            seen_success[0] = True
            sim.mu.emu_stop()

    sim.setUartHandler(on_uart)
    sim.loadFile("dump_maciej.bin")

    # 1. boot until 'success!' (wall-clock guarded: instruction counts are estimates in fast mode)
    start = time.time()
    while not seen_success[0] and time.time() - start < BOOT_LIMIT_S:
        try:
            sim.run(max_instructions=sim.instruction_count + 20_000_000)
        except Exception as e:
            print(f"[FAIL] simulator stopped: {e}")
            sys.exit(1)
    text = "".join(uart)
    print(f"boot phase: {time.time() - start:.0f}s, UART: {text.encode('ascii', 'replace').decode()!r}")
    ok = True
    for s in EXPECTED_STRINGS:
        if s in text:
            print(f"  [PASS] '{s}' found in UART output")
        else:
            print(f"  [FAIL] '{s}' NOT found in UART output")
            ok = False
    if not ok:
        sys.exit(1)

    # 2. reach the application entry
    sim.stop_instr = entry
    t = time.time()
    while sim.mu.reg_read(UC_MIPS_REG_PC) != entry and time.time() - t < 120:
        sim.run(max_instructions=sim.instruction_count + 5_000_000)
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    if pc != entry or sim.is_mips16_mode():
        print(f"  [FAIL] did not reach the entry 0x{entry:08X} in MIPS32 (PC=0x{pc:08X}, "
              f"{'MIPS16' if sim.is_mips16_mode() else 'MIPS32'})")
        sys.exit(1)
    print(f"  [PASS] reached the application entry 0x{entry:08X} in MIPS32 after {time.time() - t:.0f}s")
    sim.stop_instr = None

    # 3. the decompressed image in RAM matches the offline decompression
    ram = bytes(sim.mu.mem_read(codestart, len(image)))
    if ram != image:
        bad = sum(1 for a, b in zip(ram, image) if a != b)
        print(f"  [FAIL] RAM at 0x{codestart:08X} differs from the decompressed chunk in {bad} bytes")
        sys.exit(1)
    print(f"  [PASS] expand() output matches the LZMA decompression ({len(image)} bytes)")

    # 4. the RTOS takes timer ticks and the main task prints its init banner
    ticks0, uart0 = sim.timer_irq_count, len(uart)
    t = time.time()
    while time.time() - t < APP_LIMIT_S and "MC: APP  init ok" not in "".join(uart[uart0:]):
        sim.run(max_instructions=sim.instruction_count + 5_000_000)
    app_text = "".join(uart[uart0:])
    ticks = sim.timer_irq_count - ticks0
    print(f"  application: {ticks} timer interrupts in {time.time() - t:.0f}s, "
          f"UART: {app_text.encode('ascii', 'replace').decode()[:120]!r}")
    if ticks == 0:
        print("  [FAIL] the application took no timer interrupts")
        sys.exit(1)
    if "MC: APP  init ok" not in app_text:
        pc = sim.mu.reg_read(UC_MIPS_REG_PC)
        print(f"  [FAIL] 'MC: APP  init ok' not printed within {APP_LIMIT_S}s (PC=0x{pc:08X})")
        sys.exit(1)
    print(f"  [PASS] the RTOS runs on timer ticks and the application printed 'MC: APP  init ok'")
    print(f"\n[PASS] main application started ({time.time() - start:.0f}s total)")
    sys.exit(0)


if __name__ == "__main__":
    main()
