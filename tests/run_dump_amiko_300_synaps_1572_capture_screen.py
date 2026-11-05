"""
Screen regression for the Amiko STHD-8800 Combo / GI 300 Black Synaps firmware
1.5.72 by gisclub.tv (System ID 06000A00): a Full HD DVB-S2 + DVB-T Combo receiver
on the single-CPU ALi M3602A SoC (chips/m3602.py).

Usage: python run_dump_amiko_300_synaps_1572_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko STHD-8800 Combo / GI 300 Black Synaps (v1.5.72)",
    "chips": ["ALi M3602A", "S3501", "AV2011", "PT6311 VFD"],
    "shows": ["boots to screen", "Lemontree VFD", "front panel"],
}

screen_regression.run(
    dump="AMIKO STHD-8800 COMBO/amiko_300_black synaps_gi_1.5.72_gisclub.tv.abs",
    expected="amiko_300_synaps_1574_screen.png",
    boot_limit_s=4 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    panel_text="GISCLUB ",
    max_diff_pct=1.0,
    title="Amiko STHD-8800 Combo / GI 300 Black Synaps (v1.5.72)",
    retries=1,
)
