"""
Screen regression for the Opticum / Globo 7000CR MultiView firmware
(ALI3329C_05000200_globo_cr_amstar_led_multiroom_1.3.26.abs, ALi M3329C / M3101,
chips/m3329.py).

Usage: python run_dump_opticum_7000cr_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Opticum / Globo 7000CR MultiView (Amstar LED Multiroom 1.3.26)",
    "chips": ["ALi M3329C (M3101)", "74HC164 multiplexed LED panel"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="OPTICUM 7000CR/ALI3329C_05000200_globo_cr_amstar_led_multiroom_1.3.26.abs",
    expected="opticum_7000cr_screen.png",
    boot_limit_s=60,
    settle_s=0,
    probe_s=0,
    min_ge_ops=0,
    min_colours=4,
    ge=False,
    title="Opticum / Globo 7000CR MultiView",
    retries=1,
)
