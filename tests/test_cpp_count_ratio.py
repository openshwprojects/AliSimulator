"""Native Count arithmetic retains fractional ratios and unsigned wraparound.

Check host reads and executed MFC0 instructions against an independent integer
oracle, including ratio changes, frozen clocks and 64-bit multiplication wrap.
All guest instructions execute; no idle/spin/poll acceleration is enabled.
"""
import math
import os
import random
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from engine_check import CPP, not_applicable

if not CPP:
    not_applicable("native Count ratio arithmetic")

import cpp_core as cc

MASK32, MASK64 = (1 << 32) - 1, (1 << 64) - 1
RATIOS = ((0, 1), (1, 1), (2, 1), (7, 1), (1, 3), (3, 2), (6, 3),
          (MASK64, 1), (MASK64, 2), (MASK64 - 1, MASK64), (1, MASK64))


def count(base, origin, tick, num, den):
    return (base + ((((tick - origin) & MASK64) * num & MASK64) // den)) & MASK32


def arithmetic():
    rng = random.Random(0xC017)
    core = cc.CppUc()
    try:
        core.set(cc.F_TIMER_ENABLED, 0)
        base, origin, tick, num, den = 0, 0, 0, 2, 1
        for index in range(2000):
            if index % 5 == 0:
                new_num, new_den = rng.choice(RATIOS + ((23, 0),))
                core._lib.ali_set_count_ratio(core.handle, new_num, new_den)
                if new_den:
                    base = count(base, origin, tick, num, den)
                    origin = tick
                    gcd = math.gcd(new_num, new_den)
                    num, den = new_num // gcd, new_den // gcd
                assert (core.get(cc.F_CNUM), core.get(cc.F_CDEN)) == (num, den)
            elif index % 5 == 1:
                base, origin = rng.getrandbits(32), tick
                core.set(cc.F_COUNT, base)
            else:
                tick = rng.choice((0, 1, MASK64, MASK64 - 1, rng.getrandbits(64)))
                core.set(cc.F_ICOUNT, tick)
            expected = count(base, origin, tick, num, den)
            assert core.get(cc.F_COUNT) == expected, (index, num, den, tick, expected)
            assert core._lib.ali_cp0_read(core.handle, 9, 0) == expected
            assert core.get(cc.F_COUNT_OBSERVED) == expected
            assert core.get(cc.F_COUNT_OBSERVED_VALID) == 1
    finally:
        core.__del__()


def guest_trace(blocks, ratio, base, armed):
    core = cc.CppUc()
    try:
        core.mem_map(0, 0x4000)
        for field, value in ((cc.F_EXACT, 1), (cc.F_IDLE_SKIP, 0), (cc.F_SPIN_SKIP, 0),
                             (cc.F_HOST_ACCESS_COST, 0), (cc.F_BLOCKS_ON, int(blocks))):
            core.set(field, value)
        core._lib.ali_set_count_ratio(core.handle, *ratio)
        core.set(cc.F_COUNT, base)
        core.set(cc.F_STATUS, 0)  # Observe timer latching without taking a handler.
        if armed:
            core.set(cc.F_COMPARE_WRITE, (base + 11) & MASK32)
        # MFC0 t0,Count; SW t0,offset(s0), repeated with no skipped instructions.
        words = []
        for index in range(24):
            words.extend((0x40084800, 0xAE080000 | (4 * index)))
        words.extend((0x10000001, 0))
        core.reg_write(18, 0x80002000)
        core.mem_write(0x1000, struct.pack(f"<{len(words)}I", *words))
        core.emu_start(0x80001000, 0x80001000 + len(words) * 4, count=len(words))
        actual = struct.unpack("<24I", core.mem_read(0x2000, 96))
        gcd = math.gcd(*ratio)
        num, den = ratio[0] // gcd, ratio[1] // gcd
        assert actual == tuple(count(base, 0, 2 * i, num, den) for i in range(24))
        assert core.get(cc.F_COUNT) == count(base, 0, len(words), num, den)
        assert core.get(cc.F_EXECUTED) == core.get(cc.F_ICOUNT) == len(words)
        assert all(core.get(field) == 0 for field in
                   (cc.F_IDLE_SKIPPED, cc.F_SPIN_SKIPPED, cc.F_POLL_SKIPPED, cc.F_FF_SKIPPED))
        return actual, tuple(core.get(field) for field in
                             (cc.F_COUNT, cc.F_COMPARE, cc.F_TI, cc.F_TIMER_ANCHOR,
                              cc.F_TIMER_CHECK_AT, cc.F_COUNT_OBSERVED, cc.F_COUNT_OBSERVED_VALID))
    finally:
        core.__del__()


def addiu(rt, rs, value=1):
    return 0x24000000 | rs << 21 | rt << 16 | (value & 0xFFFF)


def timer_delivery(blocks, ratio, base, words, compare, before_handler, registers):
    """A six-instruction handler records the boundary and returns to address zero."""
    core = cc.CppUc()
    start, vector = 0x80001000, 0x80000180
    try:
        core.mem_map(0, 0x4000)
        for field, value in ((cc.F_EXACT, 1), (cc.F_IDLE_SKIP, 0), (cc.F_SPIN_SKIP, 0),
                             (cc.F_HOST_ACCESS_COST, 0), (cc.F_BLOCKS_ON, int(blocks)),
                             (cc.F_TIMER_ENABLED, 1)):
            core.set(field, value)
        core._lib.ali_set_count_ratio(core.handle, *ratio)
        core.set(cc.F_COUNT, base)
        core.set(cc.F_STATUS, 0x8001)  # IE and IM7; ordinary vector, no EXL/ERL.
        if compare is not None:
            core.set(cc.F_COMPARE_WRITE, compare)
        core.reg_write(2 + 9, (base + 1) & MASK32)  # t1 for guest MTC0 Compare cases.
        # MFC0 s3,EPC; MFC0 s4,Cause; MFC0 s5,Count; ADDIU s1,1; JR zero; NOP.
        handler = [0x40137000, 0x40146800, 0x40154800, addiu(17, 17), 8, 0]
        core.mem_write(vector & 0x1FFFFFFF, struct.pack("<6I", *handler))
        core.mem_write(start & 0x1FFFFFFF, struct.pack(f"<{len(words)}I", *words))
        core.emu_start(start, 0, count=80)
        expected_epc = start + registers.get("epc_offset", before_handler * 4)
        assert core.get(cc.F_EPC) == core.reg_read(2 + 19) == expected_epc
        cause = core.reg_read(2 + 20)
        assert cause & 0xC000807C == 0x40008000, hex(cause)  # TI/IP7, no BD or exception.
        assert core.reg_read(2 + 17) == core.get(cc.F_TIMER_IRQS) == 1
        assert core.get(cc.F_EXECUTED) == core.get(cc.F_ICOUNT) == before_handler + 6
        assert core.reg_read(2 + 21) == count(base, 0, before_handler + 2, *ratio)
        assert core.get(cc.F_COUNT) == count(base, 0, before_handler + 6, *ratio)
        for reg, expected in registers.items():
            if isinstance(reg, int):
                assert core.reg_read(2 + reg) == expected, (ratio, base, reg, expected)
        assert all(core.get(field) == 0 for field in
                   (cc.F_IDLE_SKIPPED, cc.F_SPIN_SKIPPED, cc.F_POLL_SKIPPED, cc.F_FF_SKIPPED))
    finally:
        core.__del__()


def exact_timer_boundaries():
    # Explicit expectations: floor(3*2)=6 crosses5, floor(4*3/2)=6 crosses5,
    # and floor(6/3)=2 crosses2. The same five-tick distance crosses Count wrap.
    straight = [addiu(16, 16)] * 16 + [8, 0]
    for blocks in (False, True):
        for ratio, base, distance, boundary in (
                ((2, 1), 0, 5, 3), ((3, 2), 0, 5, 4), ((1, 3), 0, 2, 6),
                ((2, 1), MASK32 - 3, 5, 3), ((3, 2), MASK32 - 3, 5, 4)):
            timer_delivery(blocks, ratio, base, straight, (base + distance) & MASK32,
                           boundary, {16: boundary})
        # Count crosses Compare after the branch. Its delay-slot marker must run
        # before delivery, and EPC must be the branch target, never the delay slot.
        branch = [0x10000002, addiu(18, 18), addiu(16, 16), addiu(16, 16), 8, 0]
        for ratio in ((2, 1), (3, 2)):
            timer_delivery(blocks, ratio, 0, branch, 1, 2,
                           {16: 0, 18: 1, "epc_offset": 12})
        # A recent MFC0 observation precedes Compare=observed+1, written after
        # crossing it. The write must latch immediately, before the next marker.
        late = [0x40084800, addiu(16, 16), 0x40895800, addiu(18, 18), 8, 0]
        for ratio, base in (((2, 1), 0), ((3, 2), 0), ((2, 1), MASK32)):
            timer_delivery(blocks, ratio, base, late, None, 3, {16: 1, 18: 0})
        # The recent-observation window includes exactly 0x40000000 ticks.
        # Just beyond it, Compare=1 is behind current Count and waits for wrap:
        # 8*0x20000001 wraps 32 bits to 8, so the IRQ occurs after eight instructions.
        threshold = [0x40084800, addiu(16, 16), 0x40895800] + [addiu(18, 18)] * 10 + [8, 0]
        timer_delivery(blocks, (0x20000000, 1), 0, threshold, None, 3, {16: 1, 18: 0})
        timer_delivery(blocks, (0x20000001, 1), 0, threshold, None, 8, {16: 1, 18: 5})


arithmetic()
print("[PASS] 2000 Count reads, ratio changes, zero denominators and unsigned wrap cases")
for armed in (False, True):
    for ratio in RATIOS:
        for base in (0, MASK32 - 7):
            assert guest_trace(True, ratio, base, armed) == guest_trace(False, ratio, base, armed)
    print(f"[PASS] guest Count traces match integer oracle and scalar execution; timer armed={armed}")
exact_timer_boundaries()
print("[PASS] exact timer IRQ boundaries, integer/fractional ratios, Count wrap, delay slots and late Compare")
