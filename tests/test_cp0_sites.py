"""
Test: fast mode's CP0 sites -- the scan that finds them, the rescans that keep
them current, the hook's reads of their code -- and the direct register access
the hooks use.

  scan       - planted MFC0 / MTC0 / ERET words among random data: the numpy
               scan (the words' top bytes) and the regex scan find exactly the
               aligned ones -- not misaligned copies, not other CP0 registers --,
               with MFC0 Status a site only under the forced ERL
  vector     - the timer interrupt's vector page is scanned again only when its
               bytes changed, not at every tick
  periodic   - code written later into a chunk that already ran is hooked by the
               periodic rescan (which counts the instructions the CPU ran: no
               code runs in skipped idle time)
  flash      - CP0 instructions executed from the flash window (the hook reads
               them through Unicorn, not the RAM buffer): Count advances, EPC
               round-trips
  registers  - _reg_write / _reg_read write and read what they are given (32
               bits)
"""
import os
import random
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_S1, UC_MIPS_REG_T0, UC_MIPS_REG_T1
import simulator
from simulator import AliMipsSimulator
from mips_asm import (COUNT, EPC, ERET, IDLE, MAIN, NOP, STATUS, T0, T1, T2, T3, T4, T6, addiu, b, bne, li, load,
                      mfc0, mtc0, tick_handler, timer_prologue)

fails = []


class ForcedErl(AliMipsSimulator):
    native_status = False


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


print("--- scan")
rng = random.Random(1015)
data = bytearray(rng.getrandbits(8) for _ in range(0x10000))
for i in range(0, len(data), 4):                   # no accidental CP0 words in the noise
    if data[i + 3] in (0x40, 0x42):
        data[i + 3] = 0x41
planted = [mfc0(T0, COUNT), mtc0(T1, 11), mfc0(T2, STATUS), mtc0(T2, STATUS), mfc0(T3, 13), mtc0(T4, 13),
           mfc0(T0, EPC), mtc0(T1, EPC), mfc0(T2, 15, 1), mtc0(T3, 15, 1), ERET]
others = [mfc0(T0, 16), mtc0(T0, 16), mfc0(T0, STATUS, 2), mtc0(T0, 15, 0), 0x42000020]    # Config, SRSCtl, EBase sel 0, WAIT
aligned = {}
for w in planted + others:
    for _ in range(3):
        at = rng.randrange(0, len(data) // 4 - 1) * 4
        data[at:at + 4] = struct.pack("<I", w)
        aligned[at] = w
        mis = rng.randrange(0, len(data) // 4 - 2) * 4 + rng.choice((1, 2, 3))
        if not any(a in aligned for a in range(mis - 3, mis + 4)):
            data[mis:mis + 4] = struct.pack("<I", w)               # misaligned: never a site
for cls in (AliMipsSimulator, ForcedErl):
    sim = cls(log_handler=lambda m: None)
    every = struct.unpack(f"<{len(data) // 4}I", bytes(data))                    # (brute force: every aligned word)
    want = {0x1000 + 4 * i for i, w in enumerate(every) if w == ERET or (w & 0xFFE0FFFF) in sim._site_words}
    present = {0x1000 + a for a, w in aligned.items() if struct.unpack_from("<I", data, a)[0] == w
               and (w == ERET or (w & 0xFFE0FFFF) in sim._site_words)}
    check(present and present <= want, f"the planted sites are among them ({len(present)})")
    with_np = sim._find_cp0_sites(bytes(data), 0x1000)
    saved, simulator._np = simulator._np, None
    try:
        with_re = sim._find_cp0_sites(bytes(data), 0x1000)
    finally:
        simulator._np = saved
    status_sites = {a for a in want if (struct.unpack_from("<I", data, a - 0x1000)[0] & 0xFFE0FFFF) == 0x40006000}
    name = "forced ERL" if cls is ForcedErl else "native Status"
    check(with_np == want == with_re and (bool(status_sites) == (cls is ForcedErl)),
          f"{name}: numpy {len(with_np)} / regex {len(with_re)} sites, {len(want)} wanted "
          f"(MFC0 Status {'among them' if status_sites else 'not a site'})")

print("--- vector / periodic")
sim = AliMipsSimulator(log_handler=lambda m: None)
sim.exact_count_threshold = 0
sim.calibration_slices = 0
sim.rescan_interval = 300_000
load(sim, timer_prologue(0x100000, 0x100000, 0x10008001) + IDLE, tick_handler())
page_scans = [0]
orig = sim._rescan_cp0_sites


def counting(ranges=None):
    if ranges == [(0x80000000, 0x1000)]:
        page_scans[0] += 1
    return orig(ranges)


sim._rescan_cp0_sites = counting


def run_ticks(n):
    target = sim.mu.reg_read(UC_MIPS_REG_S1) + n
    for _ in range(200):
        sim.run(max_instructions=sim.instruction_count + 500_000)
        if sim.mu.reg_read(UC_MIPS_REG_S1) >= target:
            return


run_ticks(10)
first = page_scans[0]
sim.mu.mem_write(0x80000800, struct.pack("<I", 0x00000021))       # (addu zero, zero, zero: not run)
run_ticks(3)
check(first == 1 and page_scans[0] == 2,
      f"the vector page is scanned once over 10 ticks ({first}), again after it changed ({page_scans[0]})")
late = MAIN + 0x800
sim.mu.mem_write(late, struct.pack("<I", mfc0(T6, COUNT)))
sim.idle_skip = False                    # (the rescan interval counts the instructions run, not skipped time)
run_ticks(40)
check(late in sim._cp0_site_hooks, f"an MFC0 Count written later at 0x{late:08X} is hooked by the periodic rescan")

print("--- flash")
sim = AliMipsSimulator(log_handler=lambda m: None)
code = [mfc0(T0, COUNT), addiu(T3, 0, 200), addiu(T3, T3, -1), bne(T3, 0, -2), NOP, mfc0(T1, COUNT)] + \
    li(T2, 0x80123456) + [mtc0(T2, EPC), mfc0(T4, EPC)] + IDLE
blob = struct.pack(f"<{len(code)}I", *code)
sim.rom_image[0:len(blob)] = blob
sim._rom_write(0, blob)
sim._rescan_all()
sim.mu.reg_write(UC_MIPS_REG_PC, 0xBFC00000)
end = 0xBFC00000 + 4 * (len(code) - 2)
for _ in range(20):
    sim.run(max_instructions=sim.instruction_count + 100_000)
    if sim.mu.reg_read(UC_MIPS_REG_PC) == end:
        break
t0, t1, t4 = (sim.mu.reg_read(sim.gpr_map[r]) for r in (T0, T1, T4))
check(0xBFC00000 in sim._cp0_site_hooks and t1 > t0 and t4 == 0x80123456,
      f"from the flash window: Count 0x{t0:08X} -> 0x{t1:08X}, EPC round-trips 0x{t4:08X}")

print("--- registers")
sim = AliMipsSimulator(log_handler=lambda m: None)
sim._reg_write(UC_MIPS_REG_T0, 0x89ABCDEF)
sim._reg_write(UC_MIPS_REG_T1, 0x01234567)
sim.mu.reg_write(sim.gpr_map[T2], 0xFFFFFFFF)
check((sim.mu.reg_read(UC_MIPS_REG_T0), sim._reg_read(UC_MIPS_REG_T1), sim._reg_read(sim.gpr_map[T2])) ==
      (0x89ABCDEF, 0x01234567, 0xFFFFFFFF), "the direct register writes and reads")
check(sim._live_env and sim._env_u32 is not None, "CPUMIPSState direct register array (_env_u32) is calibrated")
for r in range(1, 32):
    sim._reg_write(sim.gpr_map[r], (0xA5000000 | (r * 0x10101)) & 0xFFFFFFFF)
snap = struct.unpack("<32I", sim._gpr_snapshot())
check(all(sim.mu.reg_read(sim.gpr_map[r]) == snap[r] == sim._env_u32[r] == ((0xA5000000 | (r * 0x10101)) & 0xFFFFFFFF)
          for r in range(1, 32)),
      "all 31 GPRs ($1..$31) match across _reg_write, mu.reg_read, _env_u32, and _gpr_snapshot")
sim._reg_write(sim.gpr_map[0], 0xDEADBEEF)
check(sim._reg_read(sim.gpr_map[0]) == 0 and sim.mu.reg_read(sim.gpr_map[0]) == 0 and sim._env_u32[0] == 0,
      "$zero ($0) stays 0 after _reg_write")
sim._write_pc(0x80234568)
check(sim.mu.reg_read(UC_MIPS_REG_PC) == 0x80234568 and sim._env_u32[32] == 0x80234568,
      "_write_pc updates Unicorn PC and _env_u32[32]")

# Fast-mode CP0 site round-trips for Compare (11), Cause (13), Status (12), EBase (15,1), and MFC0 $zero, Count
sim = AliMipsSimulator(log_handler=lambda m: None)
sim.exact_count_threshold = 0
sim.calibration_slices = 0
cp0_prog = (
    li(T0, 0x12345678) + [mtc0(T0, 11), mfc0(T1, 11)] +
    li(T0, 0x00000300) + [mtc0(T0, 13), mfc0(T2, 13)] +
    li(T0, 0x80004000) + [mtc0(T0, 15, 1), mfc0(T3, 15, 1)] +
    [mfc0(0, COUNT), b(-1), NOP]
)
load(sim, cp0_prog)
done_pc = MAIN + 4 * (len(cp0_prog) - 2)
sim.stop_instr = done_pc
sim.run(max_instructions=100_000)
check(sim.mu.reg_read(UC_MIPS_REG_PC) == done_pc
      and sim._reg_read(sim.gpr_map[T1]) == 0x12345678
      and (sim._reg_read(sim.gpr_map[T2]) & 0x300) == 0x300
      and (sim._reg_read(sim.gpr_map[T3]) & 0xFFFFF000) == 0x80004000
      and sim._reg_read(sim.gpr_map[0]) == 0,
      "CP0 site hooks round-trip Compare, Cause IP0/IP1, EBase, and keep $zero == 0 on MFC0 $zero, Count")

print("--- long blocks")
sim = AliMipsSimulator(log_handler=lambda m: None)
chunk = bytearray(0x4000)
insn = struct.pack("<I", addiu(T0, T0, 1))
jr_ra = struct.pack("<I", 0x03E00008)
# 1) Block at offset 0..350*4 followed by jr ra
chunk[0:350 * 4] = insn * 350
chunk[350 * 4:351 * 4] = jr_ra
# 2) Interior block at 1000*4..1320*4 bounded by jr ra
chunk[999 * 4:1000 * 4] = jr_ra
chunk[1000 * 4:1320 * 4] = insn * 320
chunk[1320 * 4:1321 * 4] = jr_ra
# 3) Block at the end of the chunk (last 310 words) preceded by jr ra
end_w = len(chunk) // 4
chunk[(end_w - 311) * 4:(end_w - 310) * 4] = jr_ra
chunk[(end_w - 310) * 4:end_w * 4] = insn * 310
sim._find_long_blocks(bytes(chunk), 0x400000, (0x80000000,))
check((0x80400000, 0x80400000 + 350 * 4 - 1) in sim._long_block_hooks,
      "straight-line block starting at chunk offset 0 is hooked")
check((0x80400000 + 1000 * 4, 0x80400000 + 1320 * 4 - 1) in sim._long_block_hooks,
      "interior straight-line block is hooked")
check((0x80400000 + (end_w - 310) * 4, 0x80400000 + end_w * 4 - 1) in sim._long_block_hooks,
      "straight-line block ending at chunk boundary is hooked")

# Verify _LONG_BLK_BRK_MASK candidate probing and full scan reject blocks broken at any offset
breakers = [
    ("BEQ", bne(T0, T1, 4)),
    ("JAL", 0x0C100000),
    ("JR", 0x03E00008),
    ("ERET", ERET),
    ("zero word", 0x00000000),
    ("0xFFFFFFFF", 0xFFFFFFFF),
]
probe_offsets = (75, 1, 2, 3, 37, 112, 200)
rejected_all = True
for idx, (bname, bword) in enumerate(breakers):
    off = probe_offsets[idx % len(probe_offsets)]
    sim_b = AliMipsSimulator(log_handler=lambda m: None)
    buf = bytearray(insn * 300)
    struct.pack_into("<I", buf, off * 4, bword)
    sim_b._find_long_blocks(bytes(buf), 0x500000, (0x80000000,))
    if sim_b._long_block_hooks:
        rejected_all = False
check(rejected_all, "300-word runs broken at probe/interior offsets by branches, jumps, ERET, 0, or 0xFFFFFFFF are not hooked")

print()
if fails:
    print(f"\033[91m{len(fails)} CP0-site check(s) failed\033[0m")
    sys.exit(1)
print("\033[92mAll CP0-site checks passed\033[0m")
