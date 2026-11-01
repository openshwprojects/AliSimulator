"""
Screen regression for the Opticum 4000A / Globo 7010A 2 MB parallel-NOR flash
dump (maincode 2008-03-19, ALi M3329C / M3101, chips/m3329.py, slow).  The
1.1.2 bootloader unpacks maincode(AV) from parallel NOR into SDRAM; because the
JTAG dump's userdb(64+64) was captured in standby, PAN_COMMON_0 multiplexes the
74HC164 4-digit panel on GPIO 16..21 to the saved clock "1737".  Sending IR
POWER (NEC 0x807F00FF from its 76-entry 8-byte {nec32, vkey} table) writes the
active state to parallel NOR, resets VPO_M3327, and soft-reboots to channel
"OOO1", where OSD_M3327_0 draws the 720x576 8 bpp CLUT "Информация - Нет
сигнала!" dialog (opticum_4000a_screen.png).  MENU then opens the illustrated
"Главное меню" and DOWN highlights "Инсталляция" (opticum_4000a_nav.png).

Usage: python run_dump_opticum_4000a_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Opticum 4000A / Globo 7010A (2008-03-19)",
    "chips": ["ALi M3329C (M3101)", "74HC164 multiplexed LED panel"],
    "shows": ["boots to screen", "front panel", "reacts to remote"],
}

screen_regression.run(
    dump="OPTICUM 4000A/DumpFlash Opticum4000a(Globo7xxx)4,5w.bin",
    expected="opticum_4000a_screen.png",
    boot_limit_s=5 * 60,
    settle_s=15,
    min_ge_ops=0,
    min_colours=32,
    ge=False,
    wake_on=("1737", "POWER"),
    panel_text="OOO1",
    title="Opticum 4000A / Globo 7010A (2008-03-19)",
    retries=1,
    navigation=[("MENU", 100000), ("DOWN", 5000)],
)
