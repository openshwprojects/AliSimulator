"""Guest UART reads expose THRE and TEMT after synchronous byte delivery."""
import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from simulator import AliMipsSimulator
from mips_asm import IDLE, T0, T1, T2, T3, T4, T5, lbu, li, load


def sb(rt, offset, base):
    return 0xA0000000 | base << 21 | rt << 16 | (offset & 0xFFFF)


def run(engine):
    for uart in (0xB8018300, 0x98018300, 0x18018300):
        for receive in (False, True):
            sim = AliMipsSimulator(engine=engine, log_handler=lambda _message: None)
            delivered = []
            sim.setUartHandler(delivered.append)
            # Exercise the C++ idle-register fast path with no pending RX, as
            # well as the Python device path while an RX byte is available.
            program = li(T0, uart) + [lbu(T1, 5, T0)] + li(T2, ord("Z")) + \
                [sb(T2, 0, T0), lbu(T3, 5, T0), lbu(T4, 0, T0), lbu(T5, 5, T0)] + IDLE
            load(sim, program)
            if receive:
                sim.setUartReceiveData(b"Q", delay_instructions=0)
            sim.run(max_instructions=500)
            registers = [sim.mu.reg_read(sim.gpr_map[reg]) for reg in (T1, T3, T4, T5)]
            expected_status = 0x61 if receive else 0x60
            assert registers[0:2] == [expected_status] * 2, (hex(uart), receive, registers)
            assert registers[3] == 0x60, (hex(uart), receive, registers)
            if receive:
                assert registers[2] == ord("Q"), (hex(uart), registers)
            assert "".join(delivered) == "Z", "TX callback did not receive exactly one byte"
            print(f"[PASS] {engine} UART {uart:08x}, RX={receive}: THRE/TEMT and synchronous TX")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("cpp", "unicorn"),
                        default=os.environ.get("ALISIM_ENGINE", "cpp"))
    run(parser.parse_args().engine)
