"""
Fast check of the M3801's real-time clock model (rtc_m36.py), no firmware:

The SDK's RTC driver loads the time with a word store to 0xB8018A00 (bit 31
set, then the year's two low bits, month, day, weekday, hour, minute,
second) and reads the running time at 0xB8018A04 in the same layout; the
Comsat TE 1050 HD's UI shows its local time from it.  Checks: the layout
(pack / unpack); advance() carries the seconds into the day, the day into
the month (29 February only when the year's low bits are 0) and the month
into the year, the weekday counting 1..7; and on a simulator, a small MIPS
program reads 0 before the first load, its loaded time right after it, and
that time one second on once a second of emulation time has passed --
31 December 23:59:59 turning into 1 January 00:00:00 of the next year.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from test_cp0_timer_interrupt import ZERO, T1, T2, T3, S0, S6, S7, ERET, NOP, addiu, sw, beq, li, make_sim, run_until
from unicorn.mips_const import UC_MIPS_REG_S0, UC_MIPS_REG_S6, UC_MIPS_REG_S7

import rtc_m36
from rtc_m36 import advance, pack, unpack

S5 = 21
ok = True


def lw(rt, off, base): return 0x8C000000 | base << 21 | rt << 16 | (off & 0xFFFF)


def check(cond, msg):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    ok &= bool(cond)


print("=== Test: real-time clock 0xB8018A00 (rtc_m36.py) ===")
t = (2, 10, 10, 6, 12, 34, 56)                  # 10/10 (year % 4 = 2, Saturday) 12:34:56
check(unpack(pack(*t)) == t and pack(*t) == (2 << 29) | (10 << 25) | (10 << 20) | (6 << 17) | (12 << 12) | (34 << 6) | 56,
      f"pack / unpack: 0x{pack(*t):08X}")
check(advance(t, 0) == t and advance(t, 4) == (2, 10, 10, 6, 12, 35, 0), "advance: seconds carry into the minute")
check(advance((2, 10, 10, 6, 23, 59, 50), 15) == (2, 10, 11, 7, 0, 0, 5), "the time of day into the next day, Saturday -> Sunday (7)")
check(advance((2, 10, 11, 7, 12, 0, 0), 86400) == (2, 10, 12, 1, 12, 0, 0), "Sunday (7) -> Monday (1)")
check(advance((0, 2, 28, 1, 12, 0, 0), 86400)[1:3] == (2, 29), "28 February -> 29 February when year % 4 = 0")
check(advance((1, 2, 28, 1, 12, 0, 0), 86400)[1:3] == (3, 1), "28 February -> 1 March otherwise")
check(advance((2, 4, 30, 4, 12, 0, 0), 86400)[1:3] == (5, 1), "30 April -> 1 May")
check(advance((3, 12, 31, 3, 23, 59, 59), 1) == (0, 1, 1, 4, 0, 0, 0), "31 December 23:59:59 -> 1 January, year % 4 3 -> 0")

# on a simulator: read +04 before the load, load, read, wait for the next second, read
loaded = pack(3, 12, 31, 3, 23, 59, 59)
main = li(T1, 0xB8018A00) + [lw(S5, 4, T1)] + li(T2, 0x80000000 | loaded) + [
    sw(T2, 0, T1),
    lw(S6, 4, T1),
    lw(T3, 4, T1), beq(T3, S6, -2), NOP,         # until the second changes
    lw(S7, 4, T1),
    addiu(S0, ZERO, 1), beq(ZERO, ZERO, -1), NOP]
sim = make_sim('fast', main, [ERET, NOP])
check(isinstance(getattr(sim.chip, "rtc", None), rtc_m36.Rtc), "the M3801 family has the RTC model")
run_until(sim, 'fast', 0, lambda s: s.mu.reg_read(UC_MIPS_REG_S0) == 1, wall=10.0)
before = sim.mu.reg_read(sim.gpr_map[S5])
s6, s7 = sim.mu.reg_read(UC_MIPS_REG_S6), sim.mu.reg_read(UC_MIPS_REG_S7)
check(before == 0, f"+04 reads 0 before the first load (0x{before:08X})")
check(s6 == loaded, f"+04 right after the load: the loaded time (0x{s6:08X}, loaded 0x{loaded:08X})")
check(sim.mu.reg_read(UC_MIPS_REG_S0) == 1 and unpack(s7) == (0, 1, 1, 4, 0, 0, 0),
      f"a second later: 1 January 00:00:00, year % 4 = 0, weekday 4 ({unpack(s7)})")
print(f"\n[{'PASS' if ok else 'FAIL'}] real-time clock")
sys.exit(0 if ok else 1)
