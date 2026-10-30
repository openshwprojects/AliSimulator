"""Test the C++ guest-instruction profiler without changing execution semantics.

Completed instructions must be counted exactly once across partial MMIO blocks,
callback and code-hook stops, redirected hooks, faults (including delay slots),
MIPS16 blocks, ERET and native single-step. Faulting or unexecuted instructions
must not be counted. Profiled and unprofiled runs must leave identical CPU,
memory, interrupt and callback state. These short programs disable all skips.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from engine_check import CPP, not_applicable

if not CPP:
    not_applicable("the C++ core's guest-instruction profiler")

import cpp_core as cc
from unicorn import UcError, UC_HOOK_CODE
from unicorn.mips_const import UC_MIPS_REG_PC

CODE = 0x80001000
TARGET = 0x80001100
DATA = 0x80002000
MMIO = 0xB8000000
NOP = 0
ERET = 0x42000018
fails = []


def check(condition, message):
    print(f"  [{'PASS' if condition else 'FAIL'}] {message}")
    if not condition:
        fails.append(message)


def addiu(rt, rs, imm):
    return 0x24000000 | rs << 21 | rt << 16 | (imm & 0xFFFF)


def lw(rt, rs, offset=0):
    return 0x8C000000 | rs << 21 | rt << 16 | (offset & 0xFFFF)


def sw(rt, rs, offset=0):
    return 0xAC000000 | rs << 21 | rt << 16 | (offset & 0xFFFF)


def bne(rs, rt, offset):
    return 0x14000000 | rs << 21 | rt << 16 | (offset & 0xFFFF)


def finish(body):
    # A transfer ends the decoded block; its target is the emu_start end address.
    return body + [0x10000001, NOP]


def execute(program, blocks, profile, *, mode16=False, base=DATA,
            mmio=False, stop_on_store=False, hook=None, eret=False, steps=None,
            budget=1024, until_offset=None):
    core = cc.CppUc()
    core.mem_map(0, 0x4000)
    core.mem_write(CODE & 0x1FFFFFFF, struct.pack("<" + ("H" if mode16 else "I") * len(program), *program))
    for field, value in ((cc.F_EXACT, 1), (cc.F_IDLE_SKIP, 0), (cc.F_SPIN_SKIP, 0),
                         (cc.F_HOST_ACCESS_COST, 0), (cc.F_BLOCKS_ON, int(blocks)),
                         (cc.F_STATUS, 4 if eret else 0)):
        core.set(field, value)
    core.reg_write(2 + 16, base)
    core.reg_write(2 + 12, 4)
    if eret:
        core.set(cc.F_ERROR_EPC, TARGET | 1)
    callbacks = []
    device = [0]
    if mmio:
        def read(uc, offset, size, user):
            callbacks.append(("read", offset, size, device[0]))
            return device[0]

        def write(uc, offset, size, value, user):
            device[0] = value
            callbacks.append(("write", offset, size, value))
            if stop_on_store:
                uc.emu_stop()

        core.mmio_map(0x18000000, 0x1000, read, None, write, None)
    if hook:
        offset = 8 if hook == "stop" else 4

        def on_code(uc, address, size, user):
            callbacks.append(("hook", address, size))
            if hook == "stop":
                uc.emu_stop()
            else:
                uc.reg_write(UC_MIPS_REG_PC, CODE + 12)

        core.hook_add(UC_HOOK_CODE, on_code, begin=CODE + offset, end=CODE + offset)
    core.prof(profile)
    error = None
    begin = CODE | int(mode16)
    if steps is None:
        until = TARGET if eret else CODE + len(program) * (2 if mode16 else 4)
        if until_offset is not None:
            until = CODE + until_offset
        try:
            core.emu_start(begin, until, count=budget)
        except UcError as exc:
            error = exc.errno
    else:
        core.reg_write(UC_MIPS_REG_PC, begin)
        for _ in range(steps):
            error = core._lib.ali_step_one(core.handle) or None
            if error:
                break
    fields = (cc.F_ICOUNT, cc.F_EXECUTED, cc.F_COUNT, cc.F_STATUS, cc.F_CAUSE,
              cc.F_EPC, cc.F_M16, cc.F_DS_ACTIVE, cc.F_DS_TARGET, cc.F_DS_M16,
              cc.F_FAULT_PC, cc.F_FAULT_ADDR, cc.F_FAULT_ACCESS, cc.F_STOP_REASON,
              cc.F_IDLE_SKIPPED, cc.F_SPIN_SKIPPED, cc.F_POLL_SKIPPED, cc.F_FF_SKIPPED)
    result = {
        "state": {
            "gpr": [core.reg_read(2 + r) for r in range(32)],
            "pc": core.reg_read(UC_MIPS_REG_PC),
            "hi_lo": [core.reg_read(129), core.reg_read(130)],
            "fields": {f: core.get(f) for f in fields},
            "memory": bytes(core.mem_read(DATA & 0x1FFFFFFF, 16)),
            "callbacks": callbacks,
            "device": device[0],
            "error": error,
        },
        # All programs contain fewer than 256 distinct instruction addresses.
        "profile": dict(core.prof_top(0, 256)),
        "blocks": core.get(cc.F_BLOCK_RUNS),
    }
    core.__del__()
    return result


def scenario(name, program, completed, *, blocks=(True, False), expected_error=False,
             expected_pc=None, expected_profile=None, inspect=None, **kwargs):
    for enabled in blocks:
        plain = execute(program, enabled, False, **kwargs)
        profiled = execute(program, enabled, True, **kwargs)
        state, counts = profiled["state"], profiled["profile"]
        label = f"{name}, blocks {'on' if enabled else 'off'}"
        check(state == plain["state"], f"{label}: profiling preserves CPU, memory and callback state")
        check(sum(counts.values()) == state["fields"][cc.F_EXECUTED] == completed,
              f"{label}: profile and executed count are {completed} ({sum(counts.values())} profiled)")
        check(bool(state["error"]) == expected_error,
              f"{label}: {'fault' if expected_error else 'normal stop'} is preserved (error {state['error']})")
        if expected_pc is not None:
            check(state["pc"] == expected_pc, f"{label}: PC is 0x{expected_pc:08X}")
        if expected_profile is not None:
            check(counts == expected_profile, f"{label}: instruction PC and ISA attribution are exact ({counts})")
        if inspect:
            check(inspect(profiled), f"{label}: scenario-specific architectural effects are correct")
        check(not any(state["fields"][f] for f in
                      (cc.F_IDLE_SKIPPED, cc.F_SPIN_SKIPPED, cc.F_POLL_SKIPPED, cc.F_FF_SKIPPED)),
              f"{label}: no instructions were skipped")


# A read and a write force separate partial returns within each decoded loop.
scenario("MMIO partial blocks", [addiu(8, 8, 1), sw(8, 16), addiu(9, 9, 1),
                                 lw(10, 16), addiu(11, 11, 1), bne(8, 12, -6), NOP],
         28, base=MMIO, mmio=True, expected_pc=CODE + 28,
         inspect=lambda r: len(r["state"]["callbacks"]) == 8 and r["state"]["device"] == 4
         and r["state"]["gpr"][8:12] == [4, 4, 4, 4])
scenario("MMIO callback stop", finish([addiu(8, 0, 7), sw(8, 16), addiu(9, 0, 9)]),
         2, base=MMIO, mmio=True, stop_on_store=True, expected_pc=CODE + 8,
         inspect=lambda r: r["state"]["device"] == 7 and r["state"]["gpr"][9] == 0
         and r["state"]["fields"][cc.F_STOP_REASON] == cc.STOP_REQUEST)
scenario("code hook stop before instruction", finish([addiu(8, 0, 1), addiu(9, 0, 2), addiu(10, 0, 3)]),
         2, hook="stop", expected_pc=CODE + 8,
         inspect=lambda r: r["state"]["gpr"][10] == 0 and CODE + 8 not in r["profile"])
scenario("code hook redirect", finish([addiu(8, 0, 1), addiu(9, 0, 2),
                                      addiu(10, 0, 3), addiu(11, 0, 4)]),
         4, hook="redirect", expected_pc=CODE + 24,
         inspect=lambda r: r["state"]["gpr"][8:12] == [1, 0, 0, 4])
scenario("count budget inside decoded block", finish([addiu(8, 0, 1), addiu(9, 0, 2), addiu(10, 0, 3)]),
         2, budget=2, expected_pc=CODE + 8,
         inspect=lambda r: r["state"]["gpr"][10] == 0
         and r["state"]["fields"][cc.F_STOP_REASON] == cc.STOP_COUNT)
scenario("until address inside decoded block", finish([addiu(8, 0, 1), addiu(9, 0, 2), addiu(10, 0, 3)]),
         2, until_offset=8, expected_pc=CODE + 8,
         inspect=lambda r: r["state"]["gpr"][10] == 0
         and r["state"]["fields"][cc.F_STOP_REASON] == cc.STOP_UNTIL)
scenario("annulled likely-branch delay slot", finish([addiu(8, 0, 1), 0x51000001,
                                                     addiu(9, 0, 2), addiu(10, 0, 3)]),
         5, expected_pc=CODE + 24,
         inspect=lambda r: r["state"]["gpr"][8:11] == [1, 0, 3])

for label, base in (("unaligned load", DATA + 1), ("unmapped load", 0xBEE00000)):
    scenario(label, finish([addiu(8, 0, 1), lw(9, 16), addiu(10, 0, 3)]),
             1, base=base, expected_error=True, expected_pc=CODE + 4,
             expected_profile={CODE: 1})
scenario("fault before any instruction completes", finish([lw(9, 16)]),
         0, base=DATA + 1, expected_error=True, expected_pc=CODE, expected_profile={})
scenario("trap after completed prefix", finish([addiu(8, 0, 1), 0x00000034, addiu(10, 0, 3)]),
         1, expected_error=True, expected_pc=CODE + 4, expected_profile={CODE: 1})
scenario("fault in branch delay slot", [addiu(8, 0, 1), 0x10000002, lw(9, 16), NOP, NOP],
         2, base=DATA + 1, expected_error=True, expected_pc=CODE + 8,
         inspect=lambda r: r["state"]["fields"][cc.F_DS_ACTIVE] == 1
         and r["state"]["fields"][cc.F_DS_TARGET] == CODE + 16)
scenario("fetch fault after completed block", [addiu(8, 0, 1), 0x02000008, NOP],
         3, base=0xBEE00000, expected_error=True, expected_pc=0xBEE00000)
scenario("MIPS16 block", [0x6801, 0x4801, 0x1000], 3, mode16=True,
         expected_pc=CODE + 6, inspect=lambda r: r["state"]["gpr"][16] == 2
         and all(pc & 1 for pc in r["profile"]))
scenario("ERET keeps source PC and ISA", [ERET], 1, eret=True,
         expected_pc=TARGET, expected_profile={CODE: 1},
         inspect=lambda r: r["state"]["fields"][cc.F_M16] == 1)
scenario("native single-step stops at fault", [addiu(8, 0, 1), addiu(9, 0, 2), lw(10, 16)],
         2, base=DATA + 1, steps=3, blocks=(False,), expected_error=True, expected_pc=CODE + 8,
         expected_profile={CODE: 1, CODE + 4: 1})
scenario("native single-step ERET", [ERET], 1, eret=True, steps=1, blocks=(False,),
         expected_pc=TARGET, expected_profile={CODE: 1},
         inspect=lambda r: r["state"]["fields"][cc.F_M16] == 1)

print(f"\n[{'PASS' if not fails else 'FAIL'}] C++ profiler accounting ({len(fails)} failed checks)")
sys.exit(bool(fails))
