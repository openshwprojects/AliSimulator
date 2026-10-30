"""Native device stores retain every side effect and exact interrupt boundary.

Ordinary register bytes may keep the existing event deadline. IRQ enables,
doorbells, callbacks, executable pointer aliases and modeled access latency
must still take effect before the following guest instruction. Compare strict
decoded-block runs with the instruction-at-a-time path, including access widths.
"""
import ctypes
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from engine_check import CPP, not_applicable

if not CPP:
    not_applicable("native device event scheduling")

import cpp_core as cc
from unicorn import (UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_READ_UNMAPPED,
                     UC_HOOK_MEM_WRITE, UC_HOOK_MEM_WRITE_UNMAPPED,
                     UC_HOOK_MEM_FETCH_PROT)

CODE, VECTOR, DEVICE = 0x80001000, 0x80000180, 0xB8000000
T0, T1, T2, S0, S1 = 8, 9, 10, 16, 17


def addiu(rt, rs, value):
    return 0x24000000 | rs << 21 | rt << 16 | (value & 0xFFFF)


def store(width, offset=0):
    return {1: 0xA0000000, 2: 0xA4000000, 4: 0xAC000000}[width] | S0 << 21 | T0 << 16 | offset


class Board:
    def __init__(self, blocks=True, device=True):
        self.core = cc.CppUc()
        self.buffer = ctypes.create_string_buffer(0x50000)
        self.callbacks = []
        self.core.mem_map(0, 0x10000)
        for f, v in ((cc.F_EXACT, 1), (cc.F_IDLE_SKIP, 0), (cc.F_SPIN_SKIP, 0),
                     (cc.F_HOST_ACCESS_COST, 0), (cc.F_BLOCKS_ON, int(blocks))):
            self.core.set(f, v)
        if device:
            self.install_device()
        self.put(VECTOR, [addiu(S1, S1, 1), 0x00000008, 0])  # handler: count; jr $0; nop

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.core.__del__()

    def install_device(self, callback=None):
        if callback is not None:
            callback = cc._DEV_CB(callback)
            self.callbacks.append(callback)
        self.core._lib.ali_set_device_window(self.core.handle, 0x18000000, self.buffer,
                                            len(self.buffer), callback, None)

    def put(self, address, words):
        self.core.mem_write(address & 0x1FFFFFFF, struct.pack(f"<{len(words)}I", *words))

    def reg(self, reg, value=None):
        if value is None:
            return self.core.reg_read(2 + reg)
        self.core.reg_write(2 + reg, value)

    def irq(self, lines=0, status=0x30, enable=0x38, base=0x30):
        self.core._lib.ali_set_ic(self.core.handle, status, enable, base)
        self.core.set(cc.F_IC_LINES, lines)
        self.core.set(cc.F_STATUS, 0x801)

    def run_store(self, width=4, offset=0x100, value=1, delay_slot=False):
        self.reg(S0, DEVICE + offset)
        self.reg(T0, value)
        words = [store(width), addiu(T1, T1, 1), 0x1000FFFD, 0]
        if delay_slot:
            words = [0x10000001, store(width), addiu(T1, T1, 1), 0x1000FFFC, 0]
        self.put(CODE, words)
        self.core.emu_start(CODE, 0, count=32)

    def check_irq(self, epc=CODE + 4, instructions=4, access_cost=0):
        c = self.core
        assert self.reg(S1) == 1 and self.reg(T1) == 0, "IRQ must precede the next instruction"
        assert c.get(cc.F_EPC) == epc, (hex(c.get(cc.F_EPC)), hex(epc))
        assert c.get(cc.F_EXECUTED) == instructions
        assert c.get(cc.F_ICOUNT) == instructions + access_cost
        assert c.get(cc.F_COUNT) == 2 * (instructions + access_cost)
        self.check_no_skip()

    def check_no_skip(self):
        assert all(self.core.get(f) == 0 for f in
                   (cc.F_IDLE_SKIPPED, cc.F_SPIN_SKIPPED, cc.F_POLL_SKIPPED, cc.F_FF_SKIPPED))


def plain_store_state(width, blocks):
    with Board(blocks) as b:
        b.reg(S0, DEVICE + 0x100)
        b.reg(T0, 0x8F123456)
        # store; load the complete word; count a pass; branch; delay slot
        b.put(CODE, [store(width), 0x8E0A0000, addiu(T1, T1, 1), 0x1000FFFC, 0])
        b.core.emu_start(CODE, 0, count=500)
        b.check_no_skip()
        value = 0x8F123456 & ((1 << (8 * width)) - 1)
        assert b.reg(T1) == 100 and b.reg(T2) == value
        assert b.core.get(cc.F_EXECUTED) == b.core.get(cc.F_ICOUNT) == 500
        return (tuple(b.reg(i) for i in range(32)), b.core.reg_read(1),
                b.core.get(cc.F_COUNT), b.buffer.raw[0x100:0x108])


def test_plain_and_widths():
    for width in (1, 2, 4):
        assert plain_store_state(width, True) == plain_store_state(width, False)


def test_ic_enables_and_delay_slot():
    for status, enable, base in ((0x30, 0x38, 0x30), (0x38, 0x3C, 0x30),
                                  (0x40030, 0x40038, 0x40030)):
        for word in (0, 1):
            for width in (1, 2, 4):
                with Board() as b:
                    b.irq(1 << (32 * word + 31), status, enable, base)
                    b.run_store(width, enable + 4 * word + 4 - width, 1 << (8 * width - 1))
                    b.check_irq()
    with Board() as b:
        b.irq(1)
        b.run_store(4, 0x38, 1, delay_slot=True)
        b.check_irq(CODE + 8, instructions=5)


def test_doorbell_and_mask():
    for ring, shift, bit in ((0x206, 0, 0x80), (0x207, 4, 0x08)):
        for width in (1, 2, 4):
            with Board() as b:
                b.irq(enable=0x120)  # mask byte is independent of the enable words
                b.core._lib.ali_set_doorbell(b.core.handle, ring, shift)
                b.buffer[0x3F] = 0x80
                offset = ring & -width
                b.run_store(width, offset, bit << (8 * (ring - offset)))
                b.check_irq()
    for width in (1, 2, 4):
        with Board() as b:
            b.irq(enable=0x120)
            b.core._lib.ali_set_doorbell(b.core.handle, 0x207, 4)
            b.buffer[0x207] = 0x08
            b.run_store(width, 0x40 - width, 0x80 << (8 * (width - 1)))
            b.check_irq()


def test_doubleword_store_boundary():
    # SDC1 is one guest instruction implemented as two word stores. An enable
    # in either half takes effect after both halves, never between the writes.
    for enable, value in ((0x38, 0x89ABCDEF00000001), (0x3C, 0x0000000112345678)):
        with Board() as b:
            b.irq(1, status=0x200, enable=enable)
            b.core.set(cc.F_STATUS, 0x24000801)  # CU1, FR=1, IM3, IE
            b.core.reg_write(cc.REG_F0, value)
            b.reg(S0, DEVICE + 0x38)
            b.put(CODE, [0xF4000000 | S0 << 21, addiu(T1, T1, 1), 0x1000FFFD, 0])
            b.core.emu_start(CODE, 0, count=32)
            b.check_irq()
            assert struct.unpack_from("<Q", b.buffer, 0x38)[0] == value


def test_self_removing_memory_hook():
    with Board() as b:
        b.irq(1)
        seen = []
        handle = [None]

        def hook(uc, access, address, size, value, user):
            seen.append((address, size, value))
            uc.hook_del(handle[0])
            # Deliberately update shared bytes without a native setter/poke.
            struct.pack_into("<I", b.buffer, 0x38, 1)

        handle[0] = b.core.hook_add(UC_HOOK_MEM_WRITE, hook, begin=0x18000100, end=0x18000103)
        b.run_store()
        b.check_irq()
        assert seen == [(0x18000100, 4, 1)]


def test_unmapped_callback():
    with Board(device=False) as b:
        b.irq(1)
        seen = []

        def hook(uc, access, address, size, value, user):
            seen.append(address)
            b.install_device()
            struct.pack_into("<I", b.buffer, 0x38, 1)
            return True

        b.core.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook)
        b.run_store()
        b.check_irq()
        assert seen == [0x18000100]


def test_callbacks_before_plain_store():
    # A prior callback may change shared IRQ bytes without calling a setter.
    # Preserve the original boundary: the following ordinary store causes the
    # IRQ check, before the addiu. Merely poking at callback exit would change it.
    kinds = ("code", "read", "ram_write", "read_unmapped", "fetch_protected",
             "chunk", "flash_read")
    for blocks in (True, False):
        for kind in kinds:
            with Board(blocks) as b:
                b.irq(1)
                b.reg(S0, DEVICE + 0x100)
                b.reg(T0, 1)
                b.reg(18, 0x80003000)
                seen, handle = [], [None]

                def callback(*args):
                    seen.append(kind)
                    if kind in ("code", "read", "ram_write"):
                        b.core.hook_del(handle[0])
                    if kind == "read_unmapped":
                        b.core.mem_map(0x20000, 0x1000)
                    struct.pack_into("<I", b.buffer, 0x38, 1)
                    return True

                prefix = []
                if kind == "code":
                    handle[0] = b.core.hook_add(UC_HOOK_CODE, callback, begin=CODE, end=CODE)
                elif kind == "read":
                    handle[0] = b.core.hook_add(UC_HOOK_MEM_READ, callback,
                                                begin=0x18000104, end=0x18000107)
                    prefix = [0x8E0A0004]  # lw t2,4(s0)
                elif kind == "ram_write":
                    handle[0] = b.core.hook_add(UC_HOOK_MEM_WRITE, callback,
                                                begin=0x3000, end=0x3003)
                    prefix = [0xAC000000 | 18 << 21 | T0 << 16]  # sw t0,0(s2)
                elif kind == "read_unmapped":
                    b.reg(18, 0x80020000)
                    b.core.hook_add(UC_HOOK_MEM_READ_UNMAPPED, callback)
                    prefix = [0x8C000000 | 18 << 21 | T2 << 16]
                elif kind == "fetch_protected":
                    b.core.mem_protect(0x1000, 0x1000, 3)
                    b.core.hook_add(UC_HOOK_MEM_FETCH_PROT, callback)
                else:
                    event = cc._MACHINE_EVENT(callback)
                    b.callbacks.append(event)
                    b.core._lib.ali_set_event_cb(b.core.handle, event, None)
                    if kind == "chunk":
                        b.core._lib.ali_set_chunks(b.core.handle, 12, 16)
                        b.core._lib.ali_chunk_mark(b.core.handle, 0, 1)  # IRQ vector
                    else:
                        windows = (ctypes.c_uint32 * 1)(0)
                        b.core._lib.ali_set_flash_cmd(b.core.handle, 1, windows, 1)
                        prefix = [0x8C000000 | 18 << 21 | T2 << 16]
                b.put(CODE, prefix + [store(4), addiu(T1, T1, 1), 0x00000008, 0])
                b.core.emu_start(CODE, 0, count=32)
                b.check_irq(CODE + 4 * (len(prefix) + 1), instructions=len(prefix) + 4)
                assert seen == [kind], (kind, blocks, seen)


def test_nested_callback_keeps_pending_shared_write():
    for blocks in (True, False):
        with Board(blocks) as b:
            b.irq(1)
            b.reg(S0, DEVICE + 0x100)
            b.reg(T0, 1)
            seen = []

            def callback(uc, address, size, user):
                # This zero-instruction nested run reconsiders events and returns
                # to the same PC. The outer callback changes shared bytes after it.
                uc.emu_start(CODE, CODE, count=32)
                struct.pack_into("<I", b.buffer, 0x38, 1)
                seen.append(address)

            b.core.hook_add(UC_HOOK_CODE, callback, begin=CODE, end=CODE)
            # The nested run resets the until address; explicitly stop at the
            # common return target of the main program and interrupt handler.
            b.core.hook_add(UC_HOOK_CODE, lambda uc, *args: uc.emu_stop(), begin=0, end=0)
            b.put(CODE, [store(4), addiu(T1, T1, 1), 0x00000008, 0])
            b.core.emu_start(CODE, 0, count=32)
            b.check_irq()
            assert seen == [CODE]


def test_device_callback_latency_and_stop():
    for stop in (False, True):
        with Board() as b:
            b.irq(1)
            seen = []

            def callback(user, write, offset, size, value):
                seen.append((write, offset, size, value))
                struct.pack_into("<I", b.buffer, offset, value)
                if stop:
                    b.core.emu_stop()
                else:
                    struct.pack_into("<I", b.buffer, 0x38, 1)
                return 0

            b.install_device(callback)
            b.core._lib.ali_set_dev_flags(b.core.handle, 0x100, 4, cc.DF_WRITE)
            b.core.set(cc.F_HOST_ACCESS_COST, 7)
            b.run_store()
            assert seen == [(1, 0x100, 4, 1)]
            if stop:
                assert b.reg(T1) == b.reg(S1) == 0
                assert b.core.get(cc.F_EXECUTED) == 1 and b.core.get(cc.F_ICOUNT) == 8
                assert b.core.reg_read(1) == CODE + 4
            else:
                b.check_irq(access_cost=7)


def test_gpio_sequence_and_latency():
    with Board() as b:
        edges = []

        def gpio(user, pairs, count):
            edges.extend((pairs[2 * i], pairs[2 * i + 1]) for i in range(count))

        cb = cc._GPIO_CB(gpio)
        b.callbacks.append(cb)
        b.core._lib.ali_set_gpio_cb(b.core.handle, cb, None)
        b.core._lib.ali_set_dev_flags(b.core.handle, 0x100, 4, cc.DF_GPIO_DO)
        struct.pack_into("<I", b.buffer, 0x104, 0xFFFFFFFF)
        b.core.set(cc.F_HOST_ACCESS_COST, 5)
        b.reg(S0, DEVICE + 0x100)
        b.reg(T0, 7)
        b.put(CODE, [store(4), addiu(T0, T0, 1), store(4), 0x00000008, 0])
        b.core.emu_start(CODE, 0, count=100)
        assert edges == [(0x100, 7), (0x100, 8)]
        assert b.core.get(cc.F_EXECUTED) == 5 and b.core.get(cc.F_ICOUNT) == 15
        b.check_no_skip()


def test_executable_aliases_and_remapping():
    with Board() as b:
        for offset, alias in ((0, 0x20000), (0x1000, 0x30000), (0x2000, 0x20000)):
            b.core.mem_map_ptr(alias, 0x1000, 7, ctypes.addressof(b.buffer) + offset)
            b.reg(S0, DEVICE + offset + 4)
            b.reg(T0, addiu(T1, T1, 9))
            b.reg(T1, 0)
            b.put(alias, [store(4), addiu(T1, T1, 1), 0x00000008, 0])
            b.core.emu_start(0x80000000 | alias, 0, count=20)
            assert b.reg(T1) == 9, "device alias must update the next decoded instruction"
            b.core.mem_unmap(alias, 0x1000)
        b.check_no_skip()


def test_timer_and_uart_boundaries():
    with Board() as b:
        b.core.set(cc.F_STATUS, 0x8001)
        b.core.set(cc.F_COMPARE_WRITE, 2)
        b.run_store()
        b.check_irq()
        assert b.core.get(cc.F_TIMER_IRQS) == 1
    with Board() as b:
        b.irq()
        b.core._lib.ali_uart_arm(b.core.handle, 1, 1)
        b.run_store()
        b.check_irq()
        assert b.core.get(cc.F_UART_IRQS) == 1


if __name__ == "__main__":
    tests = (test_plain_and_widths, test_ic_enables_and_delay_slot, test_doorbell_and_mask,
             test_doubleword_store_boundary,
             test_self_removing_memory_hook, test_unmapped_callback,
             test_callbacks_before_plain_store, test_nested_callback_keeps_pending_shared_write,
             test_device_callback_latency_and_stop, test_gpio_sequence_and_latency,
             test_executable_aliases_and_remapping, test_timer_and_uart_boundaries)
    for test in tests:
        test()
        print(f"[PASS] {test.__name__}", flush=True)
    print(f"[PASS] {len(tests)} native device event scenarios")
