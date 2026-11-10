#!/usr/bin/env python3
"""The Opticum AX 502 Combo V1.28B22 update (an ALi M3516 / M3503 rev B, chips/m3503.py)
boots from the flash window with its stack in the cache-as-RAM range until DDR is up,
parks the SEE co-processor at 0xA1018804 (chips/see.py), unpacks the LZO1X-compressed
seecode and maincode chunks and starts the application at 0x80000200, which moves its
exception vectors (EBase 0x80002000), starts the SEE's program at 0x86000200 on the
second core (EBase 0x86002001), initializes the FD650K front panel on GPIO 134/135,
exchanges remote calls with the SEE core and executes GE commands.
"""
import see_regression

see_regression.run(
    "AX502Combo_HSJU_V1.28B22_PVR+mcas+sharing_170410..abs",
    "the Opticum AX 502 Combo (M3516 / M3503 rev B) unpacks LZO1X maincode/seecode and runs its application",
    family="M3503", starts=[(0xA1018804, "parked"), (0x86000200, "run on the SEE core")],
    calls=50, see_calls=10, limit=60_000_000,
    uart=("i2c_gpio_set id:0 sda:134 scl:135", "pan_FD650K_display", "MC: APP  init ok", "SDK4.0ba.4"),
    ebase=0x80002000, see_ebase=0x86002001,
    wait_for=lambda run: run.sim.ge_ops >= 5,
    checks=[
        lambda run: (sum(m.startswith("[CAR]") for m in run.logs) == 1,
                     "the bootloader keeps its stack in the cache-as-RAM range, then runs from RAM"),
        lambda run: (run.sim.ge_ops >= 5,
                     f"the application executes GE drawing commands ({run.sim.ge_ops} ops)"),
    ],
)
