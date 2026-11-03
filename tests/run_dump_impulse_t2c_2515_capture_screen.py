"""
Screen regression for the Amiko Impulse T2/C firmware v2.5.15 emu (System ID
22000A88, slow): a compact Full HD DVB-T2/C terrestrial and cable receiver on
the ALi M3821A SoC with 128 MB DDR3, 8 MB SPI flash, and MaxLinear MxL603 tuner
(chips/m3821.py).  Its XIP "M3821A 1.1.1" bootloader runs through cache-as-RAM,
unpacks seecode ("M3606 SEE") and maincode(AV) ("22000A882515"), and starts both
cores (SEE at 0xA6000200).  The application drives its CH455 4-digit LED panel
on GPIO 128 / 129 (" ON " -> " on ") and renders its 1280 x 720 OSD dialog
through GE_M36F, captured and compared with impulse_t2c_2515_screen.png.

Usage: python run_dump_impulse_t2c_2515_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO IMPULSE T2C/AMIKO_Impluse_T2C_2.5.15_emu.abs",
    expected="impulse_t2c_2515_screen.png",
    boot_limit_s=5 * 60,
    settle_s=5,
    min_ge_ops=4,
    min_colours=3,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko Impulse T2/C (firmware v2.5.15 emu)",
    retries=2,
)
