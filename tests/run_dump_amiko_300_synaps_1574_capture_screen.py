"""
Screen regression for the Amiko STHD-8800 Combo / GI 300 Black Synaps firmware
1.5.74 by gisclub.tv (System ID 06000A00, slow): a Full HD DVB-S2 + DVB-T Combo
receiver on the single-CPU ALi M3602A SoC (chips/m3602.py).  Its "M3602A 1.1.6"
bootloader communicates with the external Lemontree EuP standby and 8-character
14-segment PT6311 VFD front-panel microcontroller at I2C 0x28 on bit-banged GPIO
62 / 171 (lemontree_decoder.py: 38-byte CRC-16/XMODEM VFD frames "  BOOT  " ->
"        " -> "GISCLUB ") and unpacks maincode(AV) to 0x80008000.  The
application configures its ALi S3501 DVB-S2 demodulator at I2C 0x33 and Airoha
AV2011 tuner at I2C 0x60 and draws its Black Synaps GI OSD dialog through
GeM3602, captured and compared with amiko_300_synaps_1574_screen.png.

Usage: python run_dump_amiko_300_synaps_1574_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO STHD-8800 COMBO/amiko_300_black synaps_gi_1.5.74_gisclub.tv.abs",
    expected="amiko_300_synaps_1574_screen.png",
    boot_limit_s=4 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    panel_text="GISCLUB ",
    max_diff_pct=1.0,
    title="Amiko STHD-8800 Combo / GI 300 Black Synaps (firmware v1.5.74)",
    retries=2,
)
