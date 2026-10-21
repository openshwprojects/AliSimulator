"""
Screen regression for the Opticum HD X110p update 1.0.11C MCAS+EMU (slow,
about 2 minutes): the single-tuner sister model of the Opticum X110TS on the
dual-CPU ALi M3606 SoC (the M3602 family, chips/m3602.py, chip ID 0x3603).
Its bootloader header has byte 0x43 = 0x80 (the EuP standby-on-AC-power-up
flag, bypassed by $fp = 0xDEADBEAD in M3602.start()), and during startup its
application probes the Airoha AV2011 DVB-S2 silicon tuner at I2C 0x63
(tuners.py, device.tunerModel) before opening the UI -- without the AV2011
acknowledging that check, it shut down into standby after 4 retries.  With
the SEE co-processor's program running on the second core (chips/see.py) and
the AV2011 model attached, it opens its main menu with the TM1650-compatible
front panel on GPIO 9 / 8 showing "noCH" (x110p_screen.png); the remote's
DOWN moves the highlight down to "Installation" (x110p_nav.png).

Usage: python run_dump_x110p_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

FEATURED = {"device": "Opticum HD X110p (update 1.0.11C MCAS+EMU)",
            "chips": ["ALi M3606 (C3603)", "AV2011", "S3501"],
            "shows": ["boots to screen", "second CPU (SEE)", "tuner I2C", "remote navigation"]}

screen_regression.run(
    dump="OPTICUM X110P/Opticum_X110p_M3606_MCAS+EMU_VER1.0.11C_20110715.abs",
    expected="x110p_screen.png",
    boot_limit_s=20 * 60,
    settle_s=30,
    min_ge_ops=12,            # the main menu is complete at 13 commands
    panel_text="noCH",
    max_diff_pct=1.0,
    title="Opticum HD X110p (update 1.0.11C MCAS+EMU)",
    retries=1,
    navigation=[("DOWN", 2000)],
)
