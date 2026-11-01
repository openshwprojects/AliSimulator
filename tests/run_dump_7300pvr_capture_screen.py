"""
Screen regression for the Opticum 7300 PVR CI2CX 4 MB SPI flash dump (firmware
1.0.78, ALi M3329E, chips/m3329.py, slow).  The 3329EA 1.1.2 bootloader reads
from SPI flash through SF_INS / SF_FMT (0xB8000098) and unpacks its 3.94 MB
LZMA maincode into SDRAM; the application decodes its boot logo through
M3329E's VideoEngine at 0xB8013200, drives its 8-character 14-segment PT6312
VFD on GPIO 3 / 2 / 4 ("  BOOT  " -> "   ON   " -> "--------" -> "1PLUS1  "),
and draws the channel 0001 ("1PLUS1") info banner through GE_M36 at 0xB800E000
into OSD_S36 regions in the second 8 MB SDRAM segment (7300pvr_screen.png).
Pressing OK and DOWN opens the channel list ("Список телеканалів") and moves
the selection bar to channel 0002 ("$Inter") (7300pvr_nav.png).

Usage: python run_dump_7300pvr_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Opticum 7300 PVR CI2CX (firmware 1.0.78)",
    "chips": ["ALi M3329E", "PT6312 14-segment VFD"],
    "shows": ["boots to screen", "front panel", "remote navigation"],
}

screen_regression.run(
    dump="OPTICUM 7300 PVR/7300PVR.bin",
    expected="7300pvr_screen.png",
    boot_limit_s=5 * 60,
    settle_s=0,
    probe_s=0,
    slice_instructions=2_500_000,
    min_ge_ops=5,
    min_colours=80,
    max_diff_pct=0.5,
    nav_diff_pct=0.5,
    panel_text="1PLUS1  ",
    title="Opticum 7300 PVR CI2CX (firmware 1.0.78)",
    retries=1,
    navigation=[("OK", 200000), ("DOWN", 10000)],
)
