#!/usr/bin/env python3
"""
chips.detect() picks each firmware image's chip family from its chunk chain:
the R265 Lite images' "M3821b" bootloader version makes them M3821 -- and so
does the T750i's XIP bootloader on a dual-CPU image whose main code drives
the M3821's demodulator (NIM_S3821) -- the T760i's
boot-ROM bootloader with a SEE program and a main code that names the chip
C3505, the Globo HD-XS2's "M3503" bootloader M3503 -- and so does the
Echosonic ESR-250's "3510-" one (an M3510A) --, the M36xx update images
(HDCPKey "Demo s3602", a maincode named after the M3602 / M3606 demo
projects, or a main-code chunk whose version names the M3601S / M3606) M3602,
and everything else -- the M3801 dumps among them -- falls back to the M3801.
Also checks chunk_chain() on one image's known layout.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

import chips
from chips.base import chunk_chain
from simulator import resolve_dump

EXPECTED = [
    ("dump.bin", "M3801"),
    ("Ali_3801_Globo_DVBT_dump SPI 4mb.bin", "M3801"),
    ("T650i_V1.13B4_20160721.abs", "M3801"),
    ("M3822P.bin", "M3821"),
    ("T2GEN265_1.2.0-2023-03-17.abs", "M3821"),
    ("URZ0083_V1.2.5.abs", "M3602"),             # HDCPKey "Demo s3602", maincode "Demo M3606"
    ("THT501_V1.1.5a_20120925.abs", "M3602"),    # HDCPKey "Demo s3602", maincode "501"
    ("URZ0086_V1.2.1.abs", "M3602"),             # maincode "M3606 2Tuner"
    ("ArivaT50_20111118_V102B214.abs", "M3602"),  # no HDCPKey chunk: maincode "Demo M3602"
    ("Ferguson_T760i_V1.5B4-14092021.abs", "C3505"),  # boot-ROM bootloader, SEE program, main code names ALI_C3505
    ("Ferguson_T760i_V1.4B8_28072020.abs", "C3505"),
    ("A104_20190910_V1.3B1.abs", "C3505"),            # boot-ROM bootloader ($sp in KSEG1 0xBFE0), SEE program, ALI_C3505
    ("A104_20190926_V1.3B1_PATCH.abs", "C3505"),
    ("Ferguson_T750i_V1.20B2_18092019.abs", "M3821"),  # XIP bootloader, SEE program, main code drives NIM_S3821
    ("Sw_Globo_HD-XS2_SmartHD_1.3.5_2015-05-08.abs", "M3503"),  # bootloader "M3503---0.1.0"
    ("Sw_Globo_HD-XS2_Reta_pol_1.3.5_2015-06-22.abs", "M3503"),
    ("140_M3511-RETAIL_PL.abs", "M3503"),                       # M3511 package, bootloader "M3503---0.1.0"
    ("Software_GER_RETA_NETWORK_1.2.8_REV.778_RC1_2014-11-28.abs", "M3503"),
    ("Echosonic_Mini_ESR-250__GD25Q32B--DVBS2-M3510A-A3__OK--OK.BIN", "M3503"),   # bootloader "3510-r1362"
    ("Software_UNI_S60_1.0.4.1_PVR_2012-08-28.abs", "M3602"),   # main-code chunk version "M3601S"
    ("Software_S50_1.1.4.1_PVR1_2012-09-26.abs", "M3602"),      # main-code chunk version "M3601S"
    ("Opticum_X110p_M3606_MCAS_NOEMU_VER1.0.11B_20110715.abs", "M3602"),  # maincode "M3606 "
    ("Opticum_X110p_M3606_MCAS+EMU_VER1.0.11C_20110715.abs", "M3602"),   # maincode "M3606 "
    ("Software_mcas_x110p_1.2.0B_2012-04-13.abs", "M3602"),
    ("Software_patch_x110p_1.2.0C_2012-04-13.abs", "M3602"),
    ("Software_mcas_x110p_1.23B_2012-07-12.abs", "M3602"),
    ("Software_mcas_x110p_1.23C_2012-07-12.abs", "M3602"),
    ("Software_patch_x110p_1.24C_PVR_2012-09-06.abs", "M3602"),
    ("Software_mcas_x110p_1.2.5B_2012-10-10.abs", "M3602"),
    ("Software_Conax_X110p_PL_SMART_HD+_1.3.4_RC3_2015-01-23.abs", "M3602"),   # maincode "M3606 "
    ("Software_Patch_X110TS_X110TSE_1.4.0C_PVR_UNI_ENG_2015-05-04.abs", "M3602"),   # "M3606 2Tuner"
    ("Software_Conax_X110TS_1.1.0_PL SMART_HD+_2013-06-10.abs", "M3602"),
    ("Software_Conax_X110TS_1.1.3_PVR_PL_2013-07-29.abs", "M3602"),
    ("Software_Conax_X110TS_1.1.6_PL_SMART_HD+_2013-12-17.abs", "M3602"),
    ("Software_Conax_X110TS_1.17_PVR_UNI_ENG_2014-02-05.abs", "M3602"),
    ("Software_Conax_X110TS_1.1.8_RC3-REV243_PVR_ENG_2014-02-21.abs", "M3602"),
    ("Software_Conax_X110TS_1.1.8_RC4-REV243_PVR_POL_SMART_HD+_2014-02-21.abs", "M3602"),
    ("Software_Conax_X110TS_1.1.9_PL SMART_HD+_2014-04-07.abs", "M3602"),
    ("Software_X110TS_X110TSE_temp_Tiles_to_Sabbat.abs", "M3602"),
    ("Software_S50_special_temp_NPVR_to_PVR_1.1.4.1.abs", "M3602"),
    ("software_S60_special_temp_nopvr_to_pvr_v1.0.4.1.abs", "M3602"),
    ("software_X110p_special_temp_nopvr_to_pvr_v1.2.4.abs", "M3602"),
    ("S16_CHN_2.8.abs", "M3602"),                                # Openbox S16: main-code chunk version "M3601S"
    ("ALI3606_0A010A00_gui_edision_1.6.89.abs", "M3602"),        # Amiko ALI3606: maincode "M3606 "
    ("OPTIMUSS_underline_official_hd_1.5.87.abs", "M3602"),      # Edision Optimuss Underline: maincode "M3606 "
    ("miniplus_highspeed_official_hd_1.5.87.abs", "M3602"),      # Edision Miniplus Highspeed: maincode "M3606 "
    ("A204_20190903_V1.3B1.abs", "C3505"),                       # Ferguson Ariva 204: boot-ROM bootloader, SEE program, ALI_C3505
    ("A204_20190925_V1.3B1_PATCH.abs", "C3505"),
    ("A204_V1.3B2_31072020.abs", "C3505"),
    ("Ferguson_A204_V1.3B3.abs", "C3505"),
    ("A154Combo_10102018_V1.29B8.abs", "C3505"),                 # Ferguson Ariva 154 Combo: boot-ROM bootloader, SEE program, ALI_C3505
    ("FERGUSON_A154Combo_V1.29B8_10102018_PATCH.abs", "C3505"),
    ("A154Combo_20190305_V1.30B0.abs", "C3505"),
    ("A154Combo_20190305_V1.30B0_PATCH.abs", "C3505"),
    ("A154Combo_20190719_V1.32B1.abs", "C3505"),
    ("Ferguson_A154_V.132B1_24092019_PATCH.abs", "C3505"),
    ("A154_V1.32B4_26082020.abs", "C3505"),
    ("A254Combo_09102018_V1.29B7.abs", "C3505"),                 # Ferguson Ariva 254 Combo: boot-ROM bootloader, SEE program, ALI_C3505
    ("FERGUSON_A254Combo_V1.29B7_10102018_PATCH.abs", "C3505"),
    ("A254Combo_01032019_V1.30B0.abs", "C3505"),
    ("FERGUSON_A254Combo_V1.30B0_01032019_PATCH.abs", "C3505"),
    ("A254Combo_20190719_V1.32B1.abs", "C3505"),
    ("A254Combo_20190924_V1.32B1_PATCH.abs", "C3505"),
    ("254Combo_20200423_V1.32B3.abs", "C3505"),
    ("A254Combo_01062020_V1.32B2.abs", "C3505"),
    ("A254Combo_27072020_V1.32B3.abs", "C3505"),
    ("STB_HD_T90_N2-3_1.3.2PVR_2014-01-05.abs", "M3801"),
]

print("=== Test: chips.detect() picks each image's chip family ===")
failures = 0
for dump, family in EXPECTED:
    with open(resolve_dump(dump), "rb") as f:
        got = chips.detect(f.read()).__name__
    ok = got == family
    failures += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {dump}: {got}" + ("" if ok else f" (expected {family})"))

with open(resolve_dump("URZ0083_V1.2.5.abs"), "rb") as f:
    chain = chunk_chain(f.read())
want = [(0x000000, "bootloader", "DVBT---0.1.0"), (0x01FE00, "HDCPKey", "Demo s3602"),
        (0x020000, "maincode", "Demo M3606"), (0x170000, "Radioback", "1.0.0"),
        (0x177200, "countryband", "1.0.0"), (0x17FF80, "userdb", "1.0.0")]
ok = chain == want
failures += not ok
print(f"  [{'PASS' if ok else 'FAIL'}] chunk_chain(URZ0083_V1.2.5.abs): "
      + ", ".join(f"{name}@0x{off:06X} ({version})" for off, name, version in chain))

print(f"\n[{'PASS' if not failures else 'FAIL'}] chip family detection")
sys.exit(1 if failures else 0)
