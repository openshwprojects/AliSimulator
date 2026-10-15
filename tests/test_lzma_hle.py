"""
Test: the ALi bootloaders' LZMA decoder run in Python (simulator._hook_lzma).

The SDK's boot library unpacks the main code with the LZMA SDK 4.0x
LzmaDecode() compiled without optimisation; emulated, dump_maciej's 7.3 MB
took ~29 M instructions (40 s), the Ferguson T750i's two streams ~48 M.  The
simulator finds the routine by its first 43 instructions (_LZMA_DECODE_SIG),
decodes the stream with Python's lzma module at its entry and returns to the
caller, charging lzma_insns_per_byte of the instruction count for it.

  hook       - the hook itself, on a synthetic call (the routine's bytes at an
               entry, a raw LZMA1 stream, the arguments in a0..a3 and on the
               stack): the output written, *outSizeProcessed, v0 = 0, back at
               $ra, the time charged; a stream with an end marker shorter than
               outSize; no time with lzma_insns_per_byte = 0 -- and every
               fallback leaving the call to the emulated decoder untouched: a
               stream the module rejects, the input cut short, a probability
               buffer too small, output outside the RAM, lzma_hle off, exact
               mode, a breakpoint or the stop address in the decoder, other
               code at the entry
  scan       - a RAM chunk's scan hooks the routine in both views (KSEG0, KSEG1)
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


ENTRY, SRC, DST, DONE, BUF, SP, RA = 0x80200000, 0x80300000, 0x80400000, 0x80500000, 0x80600000, 0x80700000, \
    0x80123450
DATA = bytes(range(256)) * 64 + b"AliSimulator " * 500


def call(data=DATA, stream=None, lc=0, lp=2, pb=2, buf_size=None, in_size=None, out=DST, out_size=None, **settings):
    """A simulator stopped at the entry of a call LzmaDecode(BUF, buf_size, lc,
    lp, pb, SRC, in_size, out, out_size, DONE), the routine's bytes there; then
    the hook, as Unicorn would run it.  Returns the simulator."""
    import struct
    from unicorn.mips_const import UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3, UC_MIPS_REG_RA, \
        UC_MIPS_REG_SP
    sim = AliMipsSimulator(log_handler=lambda m: None)
    for k, v in settings.items():
        setattr(sim, k, v)
    if stream is None:
        stream = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[
            {"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": 1 << 16}])
    sim.mu.mem_write(ENTRY, AliMipsSimulator._LZMA_DECODE_SIG)
    sim.mu.mem_write(SRC, stream)
    for reg, v in ((UC_MIPS_REG_A0, BUF), (UC_MIPS_REG_A1, buf_size or (0x736 + (0x300 << (lc + lp))) * 2),
                   (UC_MIPS_REG_A2, lc), (UC_MIPS_REG_A3, lp), (UC_MIPS_REG_SP, SP), (UC_MIPS_REG_RA, RA),
                   (UC_MIPS_REG_PC, ENTRY)):
        sim.mu.reg_write(reg, v)
    sim.mu.mem_write(SP + 16, struct.pack("<6I", pb, SRC, in_size or len(stream), out,
                                          len(data) if out_size is None else out_size, DONE))
    if settings.get("hook_every_instruction"):
        sim._sync_hooks()                       # (the exact per-instruction hook installed)
    sim._hook_lzma(sim.mu, ENTRY, 4, None)
    return sim


def applied(sim, n=len(DATA)):
    """Whether the hook decoded the call: the output, *outSizeProcessed, v0, the PC."""
    from unicorn.mips_const import UC_MIPS_REG_V0
    return (bytes(sim.mu.mem_read(DST, n)) == DATA[:n] and int.from_bytes(sim.mu.mem_read(DONE, 4), "little") == n
            and sim.mu.reg_read(UC_MIPS_REG_V0) == 0 and sim.mu.reg_read(UC_MIPS_REG_PC) == RA
            and sim.lzma_decodes == [(ENTRY, SRC, DST, n)])


def untouched(sim):
    return (sim.mu.reg_read(UC_MIPS_REG_PC) == ENTRY and not sim.lzma_decodes and sim.busy_pending == 0
            and not any(sim.mu.mem_read(DST, 64)))


print("--- hook: a synthetic LzmaDecode call")
sim = call()
check(applied(sim) and abs(sim.busy_pending - len(DATA) * sim.lzma_insns_per_byte / sim._insn_rate) < 1e-9,
      f"decoded {len(DATA)} bytes, back at $ra, {sim.busy_pending * sim._insn_rate:.0f} instructions charged")
stream = lzma.compress(DATA[:5000], format=lzma.FORMAT_RAW,
                       filters=[{"id": lzma.FILTER_LZMA1, "lc": 0, "lp": 2, "pb": 2, "dict_size": 1 << 16}])
sim = call(stream=stream, out_size=len(DATA))
check(applied(sim, 5000), "a stream whose end marker comes before outSize: *outSizeProcessed = 5000")
sim = call(lzma_insns_per_byte=0)
check(applied(sim) and sim.busy_pending == 0, "lzma_insns_per_byte = 0: decoded, no time charged")
bad = bytearray(lzma.compress(DATA, format=lzma.FORMAT_RAW, filters=[
    {"id": lzma.FILTER_LZMA1, "lc": 0, "lp": 2, "pb": 2, "dict_size": 1 << 16}]))
bad[0] = 0xFF                                   # (a range coder's first byte is 0)
cases = (("a stream the module rejects", dict(stream=bytes(bad))),
         ("the input cut short", dict(in_size=200)),
         ("a probability buffer too small", dict(buf_size=100)),
         ("output outside the RAM", dict(out=0x8F000000)),
         ("lzma_hle off", dict(lzma_hle=False)),
         ("exact mode", dict(hook_every_instruction=True)),
         ("a breakpoint in the decoder", dict(breakpoints={ENTRY + 0x200})),
         ("the stop address in the decoder", dict(stop_instr=ENTRY - 0x300)))
for what, kw in cases:
    check(untouched(call(**kw)), f"{what}: left to the emulated decoder")
sim = AliMipsSimulator(log_handler=lambda m: None)
sim.mu.mem_write(ENTRY, AliMipsSimulator._LZMA_DECODE_SIG[:8] + b"\0\0\0\0" + AliMipsSimulator._LZMA_DECODE_SIG[12:])
sim.mu.reg_write(UC_MIPS_REG_PC, ENTRY)
sim._hook_lzma(sim.mu, ENTRY, 4, None)
check(untouched(sim), "other code at the entry: left alone")

print("--- scan: the routine in a RAM chunk")
sim = AliMipsSimulator(log_handler=lambda m: None)
sim.mu.mem_write(0x80A00100, AliMipsSimulator._LZMA_DECODE_SIG)
sim._rescan_cp0_sites([(0x80A00000, 0x100000)])
check({0x80A00100, 0xA0A00100} <= set(sim._lzma_hooks), f"hooked at {[hex(a) for a in sim._lzma_hooks]}")

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
