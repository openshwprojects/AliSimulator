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
import dump_catalog
from simulator import resolve_dump

EXPECTED = [
    ("dump.bin", "M3801"),
    ("Ali_3801_Globo_DVBT_dump SPI 4mb.bin", "M3801"),
    ("T650i_V1.13B4_20160721.abs", "M3801"),
    ("M3822P.bin", "M3821"),
    ("T2GEN265_1.2.0-2023-03-17.abs", "M3821"),
    ("URZ0083_V1.2.5.abs", "M3602"),             # HDCPKey "Demo s3602", maincode "Demo M3606"
    ("THT501_V1.1.5a_20120925.abs", "M3602"),    # HDCPKey "Demo s3602", maincode "501"
    ("THT501-V1.0.9.abs", "M3602"),
    ("KM00183_V1.0.8.abs", "M3602"),             # Kruger&Matz KM0183: HDCPKey "Demo s3602"
    ("KM00186_V1.1.1.abs", "M3602"),             # Kruger&Matz KM0186: maincode "M3606 2Tuner"
    ("URZ0086_V1.2.1.abs", "M3602"),             # maincode "M3606 2Tuner"
    ("ArivaT50_20111118_V102B214.abs", "M3602"),  # no HDCPKey chunk: maincode "Demo M3602"
    ("A52E_20160812_V1.31B2.abs", "M3602"),       # Ferguson bootloader "HSJ2", version "37019-01047"
    ("Ferguson_T760i_V1.5B4-14092021.abs", "C3505"),  # boot-ROM bootloader, SEE program, main code names ALI_C3505
    ("Ferguson_T760i_V1.4B8_28072020.abs", "C3505"),
    ("A104_20190910_V1.3B1.abs", "C3505"),            # boot-ROM bootloader ($sp in KSEG1 0xBFE0), SEE program, ALI_C3505
    ("A104_20190926_V1.3B1_PATCH.abs", "C3505"),
    ("Ferguson_T750i_V1.20B2_18092019.abs", "M3821"),  # XIP bootloader, SEE program, main code drives NIM_S3821
    ("AMIKO_T58_1.0.60_fta.abs", "M3821"),             # Amiko T58: single-CPU XIP M3821, HDCPKey "M3821", MainCode drives NIM_S3821_0
    ("AMIKO_ECO_TC-200_2.3.09_emu.abs", "M3821"),      # Amiko Eco TC-200: dual-CPU XIP M3821A ("M3821A 1.1.1" + "M3606 SEE"), NIM_S3821_0
    ("Sw_Globo_HD-XS2_SmartHD_1.3.5_2015-05-08.abs", "M3503"),  # bootloader "M3503---0.1.0"
    ("Sw_Globo_HD-XS2_Reta_pol_1.3.5_2015-06-22.abs", "M3503"),
    ("140_M3511-RETAIL_PL.abs", "M3503"),                       # M3511 package, bootloader "M3503---0.1.0"
    ("140_M3515-COMBO-RETAIL-PL.abs", "M3503"),                 # Opticum XS65 Combo: uppercase BOOTLOADER "M3503---0.1.0", 256 MB M3515
    ("140_TWIN_RETAIL_PL.abs", "M3503"),                        # Opticum XS65 Twin: uppercase BOOTLOADER "M3503---0.1.0", 256 MB twin DVB-S2
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
    ("Edision.vip3.0A050800_emu_1.6.60.abs", "M3602"),           # Edision Argus VIP3: bootloader "M3606c 1.1.3", seecode "M3606 SEE"
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
    ("Ferguson_A255_V1.32B4.abs", "C3505"),                       # Ferguson Ariva 255 Combo: 256 MB DDR3 C3505 (SEE at 0xAE000200)
    ("Ferguson_A255 Slim_V1.30B4_20231103_EU.abs", "C3505"),      # Ferguson Ariva 255 Combo S: 256 MB DDR3 C3505 (HASG4, RDA5816 + R840)
    ("AMIKO 8155 Edision_v.1453.abs", "C3505"),                   # Amiko HD8155: 128 MB DDR3 C3505, maincode(AV) + seecode "M3606 SEE" at 0xA6000200
    ("AMIKO_Impluse_H265_T2C_1.3.87_emu.abs", "C3505"),           # Amiko Impulse H.265 T2/C: 128 MB DDR3 M3626A / C3505, seecode "M3606 SEE" at 0xA6000200
    ("Amiko_HD8140C_SE_1.1.04_emu.abs", "C3505"),                 # Amiko HD8140C SE: 128 MB DDR3 M3712A / C3505 DVB-C, DECV_HEVC_0 + seecode at 0xA6000200
    ("Amiko_HD8142_Twin-C_1.1.11_conax.abs", "C3505"),            # Amiko HD8142 Twin-C: 128 MB DDR3 M3716A / C3505 dual DVB-C, DECV_HEVC_0 + seecode at 0xA6000200
    ("AMIKO 8265+ Edision_v.1529.abs", "C3505"),                  # Amiko HD8265+: 256 MB DDR3 C3505, maincode(AV) + seecode "M3606 SEE" at 0xAE000200
    ("Amiko_HD8275_1.2.02_emu.abs", "C3505"),                     # Amiko HD8275+: 256 MB DDR3 M3529A / C3505 combo, maincode(AV) + seecode "M3606 SEE" at 0xAE000200
    ("AMIKO_XFinder_III_1.0.49_emu.abs", "C3505"),                # Amiko X-Finder 3: 256 MB DDR3 M3529F / C3505 handheld meter, seecode "M3505 SEE" at 0xAE000200
    ("8260_Edision_Piccollo_ v.2468.abs", "M3503"),               # Amiko HD8260+: 16 MB SPI flash, 256 MB DDR3 M3516A / M3503, bootloader "M3516A 1.2.1"
    ("OPTICUM_HD_X4_220_ps_lemontree_1.3.37.abs", "M3602"),       # Opticum HD X4 220: bootloader "M3602B 1.1.5", Lemontree EuP MCU
    ("Opticum HD X402p-403p_220_ps_synaps_rc2_1.5.48_by dreamer1983.abs", "M3602"),  # Opticum HD X402p / X403p: bootloader "M3602B 1.1.6", Lemontree EuP MCU
    ("amstar_yumatu_1.5.25_x4_newoldremote.abs", "M3602"),         # Yumatu Full HD Amstar: 4 MB SPI M3602B, bootloader "M3602B 1.1.6", Lemontree EuP MCU
    ("Opticum_HD_x7_galaxy_UPC_synaps_1.5.24.VI.abs", "M3602"),   # Opticum HD X7 Combo: bootloader "M3602A 1.1.6", Lemontree PT6311 VFD MCU
    ("A53_20190813_V1.33B7.abs", "C3503"),                        # Ferguson Ariva 53: boot-ROM bootloader, no SEE, get_clock_3503D (C3503C)
    ("A54_20190926_V1.3B1.abs", "C3503"),                         # Ferguson Ariva 54: boot-ROM bootloader, no SEE, get_clock_3503D (C3503D)
    ("PICCO_S2_v.1248.abs", "C3503"),                             # Edision Picco S2: bootloader "3510DB 1.1.1", no SEE, get_clock_3503D (C3503D)
    ("STB_HD_T90_N2-3_1.3.2PVR_2014-01-05.abs", "M3801"),
    ("Edision.optimuss.underline.3in1.0E06080emu_1.3.79.abs", "M3801"),  # Edision Optimuss Underline 3in1: ALi M3612 (single-CPU S3811, chip ID 0x3811)
    ("srt8115.BIN", "M3801"),
    ("CABLETECH_urz0194s_v1_0_8.bin", "M3801"),
    ("EN25Q32B.bin", "M3801"),
    ("sat_main_ali3329-s15125_dump_eeprom_by_h2h_ok.bin", "M3329"),
    ("dump opticum x80 premium.bin", "M3329"),                    # Opticum X80 Premium: 2 MB SPI M3329C / M3101C (0xE3000010, chip ID 0x3101)
    ("7300PVR.bin", "M3329"),                                     # Opticum 7300 PVR CI2CX: 4 MB SPI M3329E (0xE3000010, chip ID 0x3329)
    ("AMIKO_Mini_Combo_Extra_1.0.46_emu.abs", "C3505"),           # Amiko Mini Combo Extra: 8 MB SPI 256 MB DDR3 M3526A / C3505, bootloader "3526A 1.1.1"
    ("AMIKO_Impulse_SAT_2.3.40_emu.abs", "M3503"),                # Amiko Impulse SAT: 8 MB SPI 128 MB DDR3 M3510B / M3503 rev B, bootloader "M3510B 1.1.1"
    ("AMIKO_HD8150_2.3.40_Synaps_2.3.40_by Dekolte.abs", "M3503"),  # Amiko HD8150: 8 MB SPI 128 MB DDR3 M3511D / M3503 rev B, bootloader "M3511D 1.1.1"
    ("dump bigsat 6500 lux.bin", "M3329"),                        # BigSat DSR 6500 Lux: 2 MB parallel NOR M3329, OSD_M3327 + 74HC164 panel
    ("AMIKO_XFinder2_2.0.48_emu.abs", "M3503"),                   # Amiko X-Finder 2: 16 MB SPI 256 MB DDR3 M3516A / M3503 handheld meter
    ("OPENBOX-S16_Eu1129.abs", "M3602"),                          # Openbox S16 EU: 4 MB SPI dual-CPU S3606H / M3606C (chip ID 0x3603)
    ("DumpFlash Opticum4000a(Globo7xxx)4,5w.bin", "M3329"),       # Opticum 4000A / Globo 7010A: 2 MB parallel NOR M3329 (STO_FLASH_0)
    ("flash ECHOLINK EL700FTA mx29lv160.bin", "M3329"),           # Echolink EL-700 FTA: 2 MB parallel NOR M3329C ("SMT01---0.9.6", PAN_SMTM51_0)
]

print("=== Test: chips.detect() picks each image's chip family ===")
failures = 0
detected_by_path = {}
seen_expected = set()
duplicate_expected = []
for dump, family in EXPECTED:
    resolved = resolve_dump(dump)
    norm = os.path.normcase(os.path.abspath(resolved))
    if norm in seen_expected:
        duplicate_expected.append(dump)
    seen_expected.add(norm)
    with open(resolved, "rb") as f:
        got = chips.detect(f.read()).__name__
    detected_by_path[norm] = got
    ok = got == family
    failures += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {dump}: {got}" + ("" if ok else f" (expected {family})"))

ok_no_dups = not duplicate_expected
failures += not ok_no_dups
print(f"  [{'PASS' if ok_no_dups else 'FAIL'}] EXPECTED has no duplicate entries"
      + ("" if ok_no_dups else f": {duplicate_expected}"))

ok_short = all(chips.detect(buf) is chips.M3801 for buf in (b"", b"\x00" * 64, b"\xFF" * 0x490))
failures += not ok_short
print(f"  [{'PASS' if ok_short else 'FAIL'}] short / empty buffers safely fall back to M3801")

catalog_entries = dump_catalog.catalog()
catalog_mismatches = []
for path, data in catalog_entries:
    if data is None:
        continue
    norm = os.path.normcase(os.path.abspath(path))
    got = detected_by_path.get(norm)
    if got is None:
        with open(path, "rb") as f:
            got = chips.detect(f.read()).__name__
        detected_by_path[norm] = got
    want_fam = data["device"]["family"].split()[0]
    if got != want_fam:
        catalog_mismatches.append((os.path.basename(path), got, want_fam))
ok_all = len(catalog_entries) >= 100 and not catalog_mismatches
failures += not ok_all
print(f"  [{'PASS' if ok_all else 'FAIL'}] all {len(catalog_entries)} catalog dumps match their sidecar chip family"
      + ("" if ok_all else f": {catalog_mismatches}"))

with open(resolve_dump("URZ0083_V1.2.5.abs"), "rb") as f:
    chain = chunk_chain(f.read())
want = [(0x000000, "bootloader", "DVBT---0.1.0"), (0x01FE00, "HDCPKey", "Demo s3602"),
        (0x020000, "maincode", "Demo M3606"), (0x170000, "Radioback", "1.0.0"),
        (0x177200, "countryband", "1.0.0"), (0x17FF80, "userdb", "1.0.0")]
ok = chain == want
failures += not ok
print(f"  [{'PASS' if ok else 'FAIL'}] chunk_chain(URZ0083_V1.2.5.abs): "
      + ", ".join(f"{name}@0x{off:06X} ({version})" for off, name, version in chain))

from chips.m3329 import M3329
for m3329_dump, want_spi in (
    ("sat_main_ali3329-s15125_dump_eeprom_by_h2h_ok.bin", False),
    ("dump bigsat 6500 lux.bin", False),
    ("DumpFlash Opticum4000a(Globo7xxx)4,5w.bin", False),
    ("flash ECHOLINK EL700FTA mx29lv160.bin", False),
    ("dump opticum x80 premium.bin", True),
    ("7300PVR.bin", True),
):
    with open(resolve_dump(m3329_dump), "rb") as f:
        got_spi = M3329._uses_spi_flash(f.read())
    ok = got_spi is want_spi
    failures += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] M3329._uses_spi_flash({m3329_dump}): {got_spi}")

print(f"\n[{'PASS' if not failures else 'FAIL'}] chip family detection")
sys.exit(1 if failures else 0)
