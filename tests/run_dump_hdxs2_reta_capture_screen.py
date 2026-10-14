"""
Screen regression for the Globo HD-XS2 / Opticum Blue XS65 update 1.3.5
"Reta" (Polish, slow, about 6 minutes): the same ALi M3503 pack as the
SmartHD image (run_dump_hdxs2_capture_screen.py), which hashes its code on
the SEE's crypto engine (crypto_engine.py) before it goes on.  Its
first-install wizard ("Wybierz język") is captured and compared with
hdxs2_reta_screen.png; the remote's DOWN picks German, and the whole wizard
switches to it ("Auswahl Sprache"), compared with hdxs2_reta_nav.png.

Usage: python run_dump_hdxs2_reta_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

FEATURED = {"device": "Globo HD-XS2 (update 1.3.5 Reta)", "chips": ["ALi M3503"],
            "shows": ["boots to screen", "remote navigation"]}

screen_regression.run(
    dump="GLOBO HD-XS2/Sw_Globo_HD-XS2_Reta_pol_1.3.5_2015-06-22.abs",
    expected="hdxs2_reta_screen.png",
    boot_limit_s=20 * 60,
    settle_s=30,
    min_ge_ops=240,           # the wizard's first page is complete at 241 commands
    panel_text="Strt",        # its TM1650-type panel (GPIO 135 / 134)
    title="Globo HD-XS2 (update 1.3.5 Reta)",
    retries=1,
    navigation=[("DOWN", 20000)],
)
