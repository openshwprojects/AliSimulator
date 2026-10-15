"""
Test: the ALi bootloaders' LZMA decoder run in Python (simulator._hook_lzma).

The SDK's boot library unpacks the main code with the LZMA SDK 4.0x
LzmaDecode() compiled without optimisation; emulated, dump_maciej's 7.3 MB
took ~29 M instructions (40 s), the Ferguson T750i's two streams ~48 M.  The
simulator finds the routine by its first 43 instructions (_LZMA_DECODE_SIG),
decodes the stream with Python's lzma module at its entry and returns to the
caller, charging lzma_insns_per_byte of the instruction count for it.

  signature  - the routine is in the flash images of the families it runs
  decode     - dump_maciej: one decode, 0x6F37C0 bytes to 0x80000200, equal
               to the image's LZMA stream decoded on its own (its 13-byte
               header and all), and the bootloader's 'success!' at about the
               instruction count the emulated decoder reached it (29.9 M)
  no_time    - lzma_insns_per_byte = 0 (tv_gui): 'success!' right after it
  disabled   - lzma_hle = False: the emulated decoder runs (no decode recorded,
               the CPU inside it a few million instructions later)
"""
import lzma
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from unicorn.mips_const import UC_MIPS_REG_PC
from simulator import AliMipsSimulator, flash_size_for, resolve_dump

fails = []


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


def boot(dump, until=None, max_m=40.0, **settings):
    """Boot `dump` until `until` is on its UART (or max_m million instructions):
    (simulator, UART text, instruction count when `until` appeared or None)."""
    path = resolve_dump(dump)
    sim = AliMipsSimulator(rom_size=flash_size_for(path), log_handler=lambda m: None)
    for k, v in settings.items():
        setattr(sim, k, v)
    sim.setSPIDump(False)
    uart, seen = [], [None]

    def on_uart(ch):
        uart.append(ch)
        if until and seen[0] is None and "".join(uart[-len(until) - 4:]).find(until) >= 0:
            seen[0] = sim.instruction_count
            sim.mu.emu_stop()
    sim.setUartHandler(on_uart)
    sim.loadFile(path)
    while sim.instruction_count < max_m * 1e6 and seen[0] is None:
        sim.run(max_instructions=sim.instruction_count + 1_000_000)
    return sim, "".join(uart), seen[0]


print("--- signature: LzmaDecode in the flash images")
for name in ("dump_maciej.bin", "dump.bin", "Ferguson_T750i_V1.20B2_18092019.abs", "URZ0086_V1.2.1.abs",
             "Sw_Globo_HD-XS2_SmartHD_1.3.5_2015-05-08.abs", "ArivaT50_20111118_V102B214.abs"):
    image = open(resolve_dump(name), "rb").read()
    check(AliMipsSimulator._LZMA_DECODE_SIG in image, f"{name} carries the routine")

print("--- decode: dump_maciej.bin")
sim, text, at = boot("dump_maciej.bin", until="success!")
check(len(sim.lzma_decodes) == 1, f"one LzmaDecode call decoded in Python ({len(sim.lzma_decodes)})")
if sim.lzma_decodes:
    entry, src, dst, n = sim.lzma_decodes[0]
    check((dst, n) == (0x80000200, 0x6F37C0), f"0x{n:X} bytes to 0x{dst:08X} (0x6F37C0 to 0x80000200 wanted)")
    header = bytes(sim.mu.mem_read(src - 13, 13))
    stream = bytes(sim.mu.mem_read(src - 13, 0x400000))
    expected = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(stream, max_length=n)
    check(bytes(sim.mu.mem_read(dst, n)) == expected,
          f"the RAM holds the stream decoded on its own (props 0x{header[0]:02X}, size 0x{int.from_bytes(header[5:13], 'little'):X})")
check(at is not None and 25e6 <= at <= 36e6,
      f"'success!' at {(at or 0) / 1e6:.1f} M instructions (the emulated decoder: 29.9 M; 25-36 M wanted)")

print("--- no_time: lzma_insns_per_byte = 0")
sim, text, at = boot("dump_maciej.bin", until="success!", lzma_insns_per_byte=0)
check(at is not None and at < 5e6, f"'success!' at {(at or 0) / 1e6:.1f} M instructions (under 5 M wanted)")

print("--- disabled: lzma_hle = False")
sim, text, at = boot("dump_maciej.bin", max_m=4, lzma_hle=False)
pc = sim.mu.reg_read(UC_MIPS_REG_PC) & ~1
check(not sim.lzma_decodes and "success!" not in text,
      f"no decode in Python, no 'success!' yet ({len(sim.lzma_decodes)} decodes)")
check(0x81E90000 <= pc < 0x81E92000, f"the emulated decoder runs (PC 0x{pc:08X} in 0x81E90000..0x81E92000)")

print()
if fails:
    print(f"\033[91m{len(fails)} LZMA check(s) failed\033[0m")
    sys.exit(1)
print("\033[92mAll LZMA checks passed\033[0m")
