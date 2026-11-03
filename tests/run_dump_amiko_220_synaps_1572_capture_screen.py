"""
Screen regression for the Amiko SHD-8000 / GI 220 Black Synaps firmware 1.5.72
by gisclub.tv (System ID 06020A00, slow): a Full HD DVB-S2 satellite receiver on
the single-CPU ALi M3602B SoC (chips/m3602.py).  Its "M3602B 1.1.6" bootloader
communicates with the external Lemontree EuP standby and 4-digit LED front-panel
microcontroller at I2C 0x28 on bit-banged GPIO 62 / 171 (lemontree_decoder.py:
CRC-16/XMODEM display frames " ON " -> "    " -> "9iSC") and unpacks
maincode(AV) to 0x80008000.  The application configures its ALi S3501 DVB-S2
demodulator at I2C 0x33 and Airoha AV2011 tuner at I2C 0x60 and draws its Black
Synaps GI OSD dialog through GeM3602, captured and compared with
amiko_220_synaps_1572_screen.png.

Usage: python run_dump_amiko_220_synaps_1572_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO SHD-8000/amiko_220_black synaps_gi_1.5.72_gisclub.tv.abs",
    expected="amiko_220_synaps_1572_screen.png",
    boot_limit_s=4 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko SHD-8000 / GI 220 Black Synaps (firmware v1.5.72)",
    retries=2,
)
