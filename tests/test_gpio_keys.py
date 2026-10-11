"""
Fast check of the front-panel buttons on GPIO inputs (gpio_keys.py), no firmware:

The Strong Prima VIII's application switches GPIO 31 and 9 to inputs, reads
the bank's DI register (0xB8000050) and takes a pin that reads 0 twice, 50 ms
apart, for a pressed key.  The simulator answers a DI read with the decoder's
di_override() for the input bits and the DO register for the output bits
(simulator._hook_gpio_di_read, its default for an undriven input being 0).
Checks: both key pins read high (released) by default; press_key(pin) holds
that pin low for hold_reads reads, then releases it; output bits, other pins
and other banks are left alone; front_panel gives the Prima VIII and the
Comsat TE 1050 HD (dump.bin, the same SDK key task on the same pins) this model.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

import front_panel
from gpio_keys import GpioKeys

DI = 0x050                  # bank 0's DI register (DO 0x054, DIR 0x058)
ok = True


def check(cond, msg):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    ok &= bool(cond)


def read(dec, do=0, dirs=0):
    """A DI read of bank 0 as the simulator answers it: inputs from the decoder, outputs from DO."""
    return dec.di_override(DI, do & dirs) & ~dirs | (do & dirs)


print("=== Test: front-panel buttons on GPIO inputs (gpio_keys.py) ===")
keys = GpioKeys((31, 9))
check(read(keys) == (1 << 31) | (1 << 9), "idle: both key pins read high (released), the other inputs low")
v = read(keys, do=1 << 5, dirs=(1 << 5) | (1 << 9))
check(v == (1 << 31) | (1 << 5), "output pins follow DO -- GPIO 9 as an output driven low, GPIO 5 high -- "
                                 f"GPIO 31 still released (0x{v:08X})")
keys.press_key(9)
seen = [read(keys) >> 9 & 1 for _ in range(4)]
check(seen == [0, 0, 0, 1], f"press_key(9): three reads see GPIO 9 low, the fourth released ({seen})")
keys.press_key(31, hold_reads=1)
v = read(keys)
check(v >> 31 & 1 == 0 and v >> 9 & 1 == 1, "press_key(31): GPIO 31 low while GPIO 9 stays released")
check(keys.di_override(0x0D0, 0) == 0, "another bank's reads are left alone")
panel, panel_keys, desc = front_panel.make_panel("STRONG PRIMA VIII/GD25Q32B_20190128_141501.BIN")
check(isinstance(panel, GpioKeys) and panel.pins == (31, 9) and not panel.has_display
      and [code for _label, code in panel_keys] == [31, 9],
      f"front_panel gives the Strong Prima VIII its two GPIO keys, no display ({desc})")
panel, panel_keys, desc = front_panel.make_panel("dump.bin")
check(isinstance(panel, GpioKeys) and panel_keys == [("UP", 31), ("DOWN", 9)],
      f"and the Comsat TE 1050 HD (dump.bin) the same pins, its virtual keys UP / DOWN ({panel_keys})")
print(f"\n[{'PASS' if ok else 'FAIL'}] GPIO keys")
sys.exit(0 if ok else 1)
