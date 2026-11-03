"""
Screen regression for the Amiko HD8840 Combo / Galaxy Innovations Black Synaps
firmware v1.7.01 EMU (System ID 0A050A00, slow): a Full HD DVB-S2 + DVB-T2/C
Combo receiver on the ALi M3606C / C3603 dual-core SoC (chips/m3602.py with chip
ID 0x3603).  Its "M3606C 1.1.3" bootloader maps the 8 MB SPI flash in the 16 MB
window at 0xAF000000, parks the SEE boot stub at 0xA1E8F9B8, unpacks maincode(AV)
to 0x80000200, and starts "M3606 SEE" at 0xA7000200.  The application
communicates with the external Lemontree EuP standby and front-panel
microcontroller at I2C 0x28 on bit-banged GPIO 103 / 102 (" on "), configures
its ALi S3501 DVB-S2 demodulator at I2C 0x33 and Airoha AV2011 tuner at I2C 0x60
and renders its 1280x720 Black Synaps OSD dialog on GMA layer 0 (9 GE commands,
30 colours), compared with amiko_0a050a00_gi_1701_screen.png.

Usage: python run_dump_amiko_0a050a00_gi_1701_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO HD8840/amiko_0A050A00_black synaps_gi_1.7.01_gisclub.tv.abs",
    expected="amiko_0a050a00_gi_1701_screen.png",
    boot_limit_s=4 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    panel_text="9iSC",
    max_diff_pct=1.0,
    title="Amiko HD8840 Combo (GI Black Synaps firmware v1.7.01)",
    retries=2,
)
