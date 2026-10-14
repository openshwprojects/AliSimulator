"""
Screen regression for the Globo HD-XS2 / Opticum Blue XS65 satellite update
1.3.5 "SmartHD" (slow, about 6 minutes): an ALi M3503 (chips/m3503.py),
dual-CPU, whose application asks the SEE (HLD_DSC.16) to hash its own code
with the crypto engine's DMA and SHA-256 unit (crypto_engine.py) before it
goes on -- without that engine the call never returned and nothing was
drawn.  Its main menu ("Edycja kanałów", "Instalacja anteny", ...) is
captured and compared with hdxs2_screen.png; the remote's RIGHT moves the
highlight to "Instalacja anteny", compared with hdxs2_nav.png.

Usage: python run_dump_hdxs2_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

FEATURED = {"device": "Globo HD-XS2 (update 1.3.5 SmartHD)", "chips": ["ALi M3503"],
            "shows": ["boots to screen", "remote navigation"]}

screen_regression.run(
    dump="GLOBO HD-XS2/Sw_Globo_HD-XS2_SmartHD_1.3.5_2015-05-08.abs",
    expected="hdxs2_screen.png",
    boot_limit_s=20 * 60,
    settle_s=30,
    min_ge_ops=360,           # the main menu is complete at 363 commands
    panel_text="noCH",        # its TM1650-type panel (GPIO 135 / 134): no channels yet
    title="Globo HD-XS2 (update 1.3.5 SmartHD)",
    retries=1,
    navigation=[("RIGHT", 20000)],
)
