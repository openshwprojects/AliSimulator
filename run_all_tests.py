"""
Unified test runner for all MIPS simulator tests.

Runs every test script of the project (test_*.py unit tests and the
run_dump_*.py firmware regressions), each in its own Python process, prints
their output as it comes, and reports aggregate results.  Individual test files
can still be run directly.

It also writes report/index.html (report.py): one page with every test's
verdict, timing, description (the script's docstring), its [PASS] / [FAIL]
assertions and full output, and the images the test attached through
report_artifacts.py -- the OSD screens it rendered and the front-panel LED
displays it decoded.  A script that declares FEATURED -- the full run of one
box: {"device", "chips", "shows"} -- is shown first, opened.  The results go
to report/results.json too.  The GitHub Actions workflow publishes that page
to GitHub Pages after every push.

  python run_all_tests.py            the default suite (a few minutes)
  python run_all_tests.py --slow     plus the multi-minute firmware runs
  python run_all_tests.py -k remote  only scripts whose name contains 'remote'
  python run_all_tests.py --timeout 1800   kill a test after 30 minutes
  python run_all_tests.py --slow --jobs 2  two tests at a time (output per test, not streamed)
  python run_all_tests.py --report-only    the page again from report/results.json, runs nothing
  python run_all_tests.py --engine unicorn every simulator on the Unicorn engine instead of the
                                           C++ core (simulator_cpp.py: the default, built first by
                                           cpp\\build.bat on Windows, cpp/build.sh elsewhere; its
                                           report goes to report/cpp/).  Unicorn's report goes to
                                           report/; its suite takes about seven times longer
  python run_all_tests.py --link "C++ engine=cpp/index.html"   a link in the page's header (repeatable)
"""

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent
TESTS_DIR = ROOT / "tests"
REPORT_DIR = ROOT / "report"
ENGINE = "cpp"             # the simulator's engine in every test (--engine: cpp, the default, or unicorn)
LINKS = []                 # [label, href] pairs shown in the page's header (--link)
NOT_APPLICABLE = "[NOT APPLICABLE]"
sys.path[:0] = [str(TESTS_DIR), str(ROOT / "src")]     # the report helpers and the simulator's modules

import report                                          # noqa: E402
import report_artifacts                                # noqa: E402

# Scripts whose name does not say which dump they run: look for it in the source
DUMPS = [("dump_maciej.bin", "dump_maciej.bin"), ("dump.bin", "dump.bin"),
         ("SRT_Prima", "SRT Prima VIII"), ("Ali_3801_Globo", "Globo N3"), ("globo_", "Globo N3"), ("URZ0083Q", "Cabletech URZ0083Q"),
         ("URZ0083_V", "Cabletech URZ0083"), ("URZ0083_v", "Cabletech URZ0083"), ("URZ0086", "Cabletech URZ0086"),
         ("KM00183", "Kruger&Matz KM0183"), ("KM00186", "Kruger&Matz KM0186"),
         ("urz0195", "Cabletech URZ0195"), ("urz0194", "Cabletech URZ0194S"), ("srt8115", "Strong SRT 8115"),
         ("prima8", "Strong Prima VIII"), ("T650i", "Ferguson Ariva T650i"), ("T760i", "Ferguson Ariva T760i"),
         ("T750i", "Ferguson Ariva T750i"),
         ("A104", "Ferguson Ariva 104"), ("A154", "Ferguson Ariva 154 Combo"),
         ("A52E", "Ferguson Ariva 52E"), ("A53", "Ferguson Ariva 53"), ("A54", "Ferguson Ariva 54"),
         ("A204", "Ferguson Ariva 204"), ("A254", "Ferguson Ariva 254 Combo"), ("254Combo", "Ferguson Ariva 254 Combo"),
         ("a255_", "Ferguson Ariva 255 Combo"), ("Ferguson_A255_", "Ferguson Ariva 255 Combo"),
         ("a255s_", "Ferguson Ariva 255 Combo S"), ("A255 Slim", "Ferguson Ariva 255 Combo S"),
         ("r265lite", "Opticum Blue R265 Lite"), ("T90", "Opticum HD T90"), ("HD-XS2", "Globo HD-XS2"),
         ("X110TS", "Opticum X110TS"), ("X110p", "Opticum HD X110p"),
         ("UNI_S60", "Opticum HD S60"), ("Software_S50", "Opticum HD S50"), ("S16_CHN", "Openbox S16"),
         ("ALI3606_0A010A00", "Amiko Mini HD"), ("miniplus_highspeed", "Edision Argus Miniplus Highspeed"),
         ("OPTIMUSS_underline", "Edision Optimuss Underline"),
         ("AMIKO 8155", "Amiko HD8155"), ("hd8155", "Amiko HD8155"),
         ("AMIKO 8265", "Amiko HD8265+"), ("hd8265", "Amiko HD8265+"),
         ("8260_Edision", "Amiko HD8260+"), ("hd8260", "Amiko HD8260+"),
         ("OPTICUM_HD_X4", "Opticum HD X4 220"), ("x4_220", "Opticum HD X4 220"),
         ("ArivaT50", "Ferguson Ariva T50"),
         ("ESR-250", "Echosonic Mini ESR-250"), ("ali3329", "M3329 board s15125"), ("THT501", "Thomson THT501"),
         ("M3515-COMBO", "Opticum XS65 Combo"),
         ("xs65_combo", "Opticum XS65 Combo"),
         ("PICCO_S2", "Edision Picco S2"),
         ("picco_s2", "Edision Picco S2"),
         ("Opticum_HD_x7", "Opticum HD X7 Combo"),
         ("x7_", "Opticum HD X7 Combo"),
         ("underline.3in1", "Edision Optimuss Underline 3in1"),
         ("underline_3in1", "Edision Optimuss Underline 3in1"),
         ("dump opticum x80 premium.bin", "Opticum X80 Premium"),
         ("x80_premium_", "Opticum X80 Premium"),
         ("AMIKO_T58_1.0.60_fta.abs", "Amiko T58"),
         ("amiko_t58_", "Amiko T58"),
         ("AMIKO_Impluse_H265_T2C_1.3.87_emu.abs", "Amiko Impulse H.265 T2/C"),
         ("impulse_h265_", "Amiko Impulse H.265 T2/C"),
         ("140_TWIN_RETAIL_PL.abs", "Opticum XS65 Twin"),
         ("xs65_twin", "Opticum XS65 Twin"),
         ("Edision.vip3", "Edision Argus VIP3"),
         ("vip3_", "Edision Argus VIP3"),
         ("7300PVR.bin", "Opticum 7300 PVR CI2CX"),
         ("7300pvr_", "Opticum 7300 PVR CI2CX"),
         ("AMIKO_ECO_TC-200", "Amiko Eco TC-200"),
         ("eco_tc200_", "Amiko Eco TC-200"),
         ("AMIKO_Mini_Combo_Extra", "Amiko Mini Combo Extra"),
         ("mini_combo_extra_", "Amiko Mini Combo Extra"),
         ("AMIKO_Impulse_SAT", "Amiko Impulse SAT"),
         ("impulse_sat_", "Amiko Impulse SAT"),
         ("Opticum HD X402p-403p", "Opticum HD X402p / X403p"),
         ("x403p_", "Opticum HD X402p / X403p"),
         ("bigsat 6500", "BigSat DSR 6500 Lux"),
         ("bigsat_6500", "BigSat DSR 6500 Lux"),
         ("AMIKO_XFinder2", "Amiko X-Finder 2"),
         ("xfinder2", "Amiko X-Finder 2"),
         ("AMIKO_XFinder_III", "Amiko X-Finder 3"),
         ("xfinder3", "Amiko X-Finder 3"),
         ("HD8142_Twin-C", "Amiko HD8142 Twin-C"),
         ("hd8142_twinc", "Amiko HD8142 Twin-C"),
         ("OPENBOX-S16_Eu1129", "Openbox S16 EU"),
         ("s16_eu", "Openbox S16 EU"),
         ("Opticum4000a", "Opticum 4000A / Globo 7010A"),
         ("opticum_4000a", "Opticum 4000A / Globo 7010A"),
         ("HD8140C_SE", "Amiko HD8140C SE"),
         ("hd8140c_se_", "Amiko HD8140C SE"),
         ("HD8275_", "Amiko HD8275+"),
         ("hd8275_", "Amiko HD8275+"),
         ("AMIKO_HD8150", "Amiko HD8150"),
         ("hd8150_", "Amiko HD8150"),
         ("amstar_yumatu", "Yumatu Full HD Amstar"),
         ("yumatu_amstar_", "Yumatu Full HD Amstar"),
         ("amiko_0A040A00", "Amiko HD8240"),
         ("hd8240_", "Amiko HD8240"),
         ("globo_x4_amstar_sab", "SAB Titan I HD 3602"),
         ("sab_titan_amstar_", "SAB Titan I HD 3602"),
         ("piccollo_3in1_PLUS_CI", "Edision Piccollo 3in1 Plus CI"),
         ("piccollo_3in1_", "Edision Piccollo 3in1 Plus CI"),
         ("Amiko_Mini_HD265", "Amiko Mini HD265"),
         ("mini_hd265_", "Amiko Mini HD265"),
         ("bigsat 7035", "BigSat DSR 7035 Plus"),
         ("bigsat_7035", "BigSat DSR 7035 Plus"),
         ("AMIKO_Mira2_wifi", "Amiko Mira2 WiFi"),
         ("mira2_wifi", "Amiko Mira2 WiFi"),
         ("AMIKO_Impulse_T2C", "Amiko Impulse T2/C"),
         ("impulse_t2c", "Amiko Impulse T2/C"),
         ("EDISION PICCOLLINO S2+T2C", "Edision Piccollino S2+T2/C"),
         ("piccollino_S2+T2C", "Edision Piccollino S2+T2/C"),
         ("AMIKO MICRO HD SE", "Amiko Micro HD SE"),
         ("MicroHD SE", "Amiko Micro HD SE"),
         ("GOLDEN MEDIA UNIBOX XWINDOW", "Golden Media Uni-Box 9060/9080 HD"),
         ("xwindow_gm", "Golden Media Uni-Box 9060/9080 HD"),
         ("AMIKO HD9265+", "Amiko HD9265+"),
         ("Amiko_HD9265+", "Amiko HD9265+"),
         ("AMIKO HD8100 SERIES", "Amiko HD8100 Series"),
         ("AMIKO_HD8100", "Amiko HD8100 Series"),
         ("AMIKO MIRA WIFI", "Amiko Mira WiFi"),
         ("AMIKO_Mira_1.1.74", "Amiko Mira WiFi"),
         ("SYNAPS STC-3220", "Synaps STC-3220 Combo"),
         ("STC3220", "Synaps STC-3220 Combo"),
         ("AMIKO HD8140", "Amiko HD8140"),
         ("AMIKO_HD8140_Galaxy", "Amiko HD8140"),
         ("DYNAVISION DAVINCI HD", "Dynavision Davinci / Sparkle Plus HD"),
         ("synaps_dynavision", "Dynavision Davinci / Sparkle Plus HD"),
         ("PROTON HD", "Proton HD"),
         ("lemontree_proton", "Proton HD"),
         ("EDISION PICCOLLINO LED", "Edision Piccollino LED"),
         ("Piccollino_v.", "Edision Piccollino LED"),
         ("AMIKO MINI COMBO HD SE", "Amiko Mini Combo HD SE"),
         ("AMIKO_MiniComboHD_SE", "Amiko Mini Combo HD SE"),
         ("ILTV HD", "ILTV HD"),
         ("iltv_1.5.27_hd", "ILTV HD"),
         ("AMIKO SHD-8360", "Amiko SHD-8360 CI+CA"),
         ("AMIKO_SHD-8360", "Amiko SHD-8360 CI+CA"),
         ("AMIKO MINI HD", "Amiko Mini HD"),
         ("AMIKO_MiniHD_1.6.96", "Amiko Mini HD"),
         ("EDISION PICCOLLO S2+T2C", "Edision Piccollo S2+T2/C"),
         ("piccollo_S2+T2C", "Edision Piccollo S2+T2/C"),
         ("AMIKO HD8270+", "Amiko HD8270+"),
         ("AMIKO_HD8270", "Amiko HD8270+"),
         ("AMIKO STHD-8800 COMBO", "Amiko STHD-8800 Combo"),
         ("AMIKO_STHD-8800", "Amiko STHD-8800 Combo"),
         ("AMIKO CHD8270+", "Amiko CHD8270+"),
         ("AMIKO_CHD8270", "Amiko CHD8270+"),
         ("EDISION PICCOLLINO S2", "Edision Piccollino S2"),
         ("Piccollino_S2_v.", "Edision Piccollino S2"),
         ("AMIKO_HD8840", "Amiko HD8840 Combo"),
         ("hd8840", "Amiko HD8840 Combo"),
         ("AMIKO_SHD-7900-8000", "Amiko SHD-7900 / SHD-8000"),
         ("shd8000", "Amiko SHD-7900 / SHD-8000"),
         ("Amiko_HD8255", "Amiko HD8255+"),
         ("hd8255_plus", "Amiko HD8255+"),
         ("AMIKO HD8200 SERIES", "Amiko HD8200 Series"),
         ("hd8200_series", "Amiko HD8200 Series"),
         ("AMIKO HD8300 SERIES", "Amiko HD8300 Series"),
         ("AMIKO_HD8300_Series", "Amiko HD8300 Series"),
         ("AMIKO_MicroHD_1.5.73", "Amiko Micro HD"),
         ("AMIKO MICRO HD/", "Amiko Micro HD"),
         ("AMIKO MINI HD COMBO", "Amiko Mini HD Combo"),
         ("AMIKO_MiniHD_Combo", "Amiko Mini HD Combo"),
         ("AMIKO MINI HD RE", "Amiko Mini HD RE"),
         ("AMIKO_MiniHD_RE", "Amiko Mini HD RE"),
         ("AMIKO MINI HD T2C", "Amiko Mini HD T2/C"),
         ("AMIKO_MiniHD_T2C", "Amiko Mini HD T2/C"),
         ("AMIKO SHD-8110", "Amiko SHD-8110"),
         ("AMIKO_SHD-8110", "Amiko SHD-8110"),
         ("AMIKO SHD-8140", "Amiko SHD-8140"),
         ("AMIKO_SHD-8140", "Amiko SHD-8140"),
         ("AMIKO STHD-8820", "Amiko STHD-8820 Combo"),
         ("AMIKO_STHD-8820", "Amiko STHD-8820 Combo"),
         ("AMIKO X-FINDER+", "Amiko X-Finder+ handheld meter"),
         ("AMIKO_XFinder_Plus", "Amiko X-Finder+ handheld meter"),
         ("AMIKO HD8140 T2C", "Amiko HD8140 T2/C"),
         ("AMIKO_HD8140_T2C", "Amiko HD8140 T2/C"),
         ("ECHOLINK EL700FTA", "Echolink EL-700 FTA"),
         ("OPENBOX S10", "Openbox S10 HD PVR"),
         ("C2HS2-12-06-18_05E3CMT", "Openbox S10 HD PVR"),
         ("OPENBOX V5S", "Openbox V5S"),
         ("OPENBOX_V5S_", "Openbox V5S"),
         ("OPTICUM XS65", "Opticum XS65"),
         ("140_M3511-RETAIL_PL", "Opticum XS65"),
         ("FERGUSON ARIVA 102E", "Ferguson Ariva 102E"),
         ("A102E_", "Ferguson Ariva 102E"),
         ("OPTICUM AX 502 COMBO", "Opticum AX 502 Combo"),
         ("AX502Combo", "Opticum AX 502 Combo"),
         ("ax502_combo", "Opticum AX 502 Combo"),
         ("FERGUSON ARIVA 103", "Ferguson Ariva 103"),
         ("A103_", "Ferguson Ariva 103"),
         ("a103_", "Ferguson Ariva 103"),
         ("FERGUSON ARIVA 153 COMBO", "Ferguson Ariva 153 Combo"),
         ("A153Combo_", "Ferguson Ariva 153 Combo"),
         ("a153_combo", "Ferguson Ariva 153 Combo"),
         ("OPENBOX V8S/", "Openbox V8S"),
         ("OPENBOX_V8S_", "Openbox V8S"),
         ("openbox_v8s", "Openbox V8S"),
         ("OPENBOX V8SE", "Openbox V8Se"),
         ("OPENBOX_V8SE_", "Openbox V8Se"),
         ("openbox_v8se", "Openbox V8Se"),
         ("AMIKO HD8250+", "Amiko HD8250+"),
         ("AMIKO_HD8250_", "Amiko HD8250+"),
         ("hd8250_plus", "Amiko HD8250+"),
         ("SKYBOX S12", "Skybox S12"),
         ("skybox s12", "Skybox S12"),
         ("skybox_s12", "Skybox S12"),
         ("SKYBOX F4", "Skybox F4"),
         ("skybox_f4", "Skybox F4"),
         ("SKYBOX A3", "Skybox A3 / A4 / M5"),
         ("SKYBOX_A3_", "Skybox A3 / A4 / M5"),
         ("skybox_a3", "Skybox A3 / A4 / M5"),
         ("OPENBOX X3", "Openbox X3 / Q3"),
         ("X3_OPENBOX_", "Openbox X3 / Q3"),
         ("openbox_x3", "Openbox X3 / Q3"),
         ("OPENBOX S9", "Openbox S9 HD PVR"),
         ("openbox_s9", "Openbox S9 HD PVR"),
         ("AMIKO MINI 4K", "Amiko Mini 4K UHD Combo"),
         ("amiko_mini_4k", "Amiko Mini 4K UHD Combo"),
         ("XC406p", "Opticum HD XC406p"),
         ("xc406p", "Opticum HD XC406p"),
         ("500HD", "AB CryptoBox 500HD"),
         ("cryptobox_500hd", "AB CryptoBox 500HD"),
         ("600HD", "AB CryptoBox 600HD Mini"),
         ("cryptobox_600hd", "AB CryptoBox 600HD Mini"),
         ("652HD", "AB CryptoBox 652HD Combo"),
         ("cryptobox_652hd", "AB CryptoBox 652HD Combo"),
         ("AX300", "Opticum AX 300"),
         ("opticum_ax300", "Opticum AX 300"),
         ("HD506", "Opticum HD 506"),
         ("opticum_hd506", "Opticum HD 506"),
         ("ali_sdk.bin", "ali_sdk.bin")]
SLOW_TESTS = ("run_dump_maciej_to_main_app.py", "run_dump_maciej_capture_screen.py",
              "run_dump_maciej_custom_app.py", "run_dump_maciej_uart_bundle.py",
              "run_dump_maciej_app_restart.py",
              "run_dump_maciej_remote.py", "run_dump_globo_capture_screen.py",
              "run_dump_cabletech_capture_screen.py", "run_dump_capture_screen.py",
              "run_dump_srt8115_capture_screen.py", "run_dump_urz0194s_capture_screen.py",
              "run_dump_urz0195_capture_screen.py", "run_dump_prima8_capture_screen.py",
              "run_dump_t650i_capture_screen.py", "run_dump_r265lite_capture_screen.py",
              "run_dump_r265lite_120_capture_screen.py", "run_dump_globo_signal.py",
              "run_dump_r265lite_signal_capture_screen.py", "run_dump_signal_capture_screen.py",
              "run_dump_t90_capture_screen.py", "run_dump_x110ts_capture_screen.py",
              "run_dump_x110p_capture_screen.py",
              "run_dump_t750i_capture_screen.py", "run_dump_t760i_capture_screen.py",
              "run_dump_a104_capture_screen.py",
              "run_dump_a53_capture_screen.py", "run_dump_a54_capture_screen.py",
              "run_dump_a255_capture_screen.py", "run_dump_a255s_capture_screen.py",
              "run_dump_hd8155_capture_screen.py", "run_dump_hd8265_capture_screen.py",
              "run_dump_hd8260_capture_screen.py", "run_dump_x4_220_capture_screen.py",
              "run_dump_prima8_update_capture_screen.py", "run_dump_urz0195_2013_capture_screen.py",
              "run_dump_urz0083_capture_screen.py", "run_dump_urz0086_capture_screen.py",
              "run_dump_s60_capture_screen.py", "run_dump_s50_capture_screen.py",
              "run_dump_s16_capture_screen.py",
              "run_dump_esr250_capture_screen.py",
              "run_dump_t50_capture_screen.py", "run_dump_hdxs2_capture_screen.py",
              "run_dump_hdxs2_reta_capture_screen.py", "run_dump_m3329_capture_screen.py",
              "run_dump_tht501_capture_screen.py",
              "run_dump_xs65_combo_capture_screen.py",
              "run_dump_picco_s2_capture_screen.py",
              "run_dump_x7_capture_screen.py",
              "run_dump_underline_3in1_capture_screen.py",
              "run_dump_x80_premium_capture_screen.py",
              "run_dump_amiko_t58_capture_screen.py",
              "run_dump_impulse_h265_capture_screen.py",
              "run_dump_xs65_twin_capture_screen.py",
              "run_dump_vip3_capture_screen.py",
              "run_dump_7300pvr_capture_screen.py",
              "run_dump_eco_tc200_capture_screen.py",
              "run_dump_mini_combo_extra_capture_screen.py",
              "run_dump_impulse_sat_capture_screen.py",
              "run_dump_x403p_capture_screen.py",
              "run_dump_bigsat_6500_capture_screen.py",
              "run_dump_xfinder2_capture_screen.py",
              "run_dump_xfinder3_capture_screen.py",
              "run_dump_hd8142_twinc_capture_screen.py",
              "run_dump_s16_eu_capture_screen.py",
              "run_dump_opticum_4000a_capture_screen.py",
              "run_dump_hd8140c_se_capture_screen.py",
              "run_dump_hd8275_capture_screen.py",
              "run_dump_hd8150_capture_screen.py",
              "run_dump_hd8240_capture_screen.py",
              "run_dump_sab_titan_amstar_capture_screen.py",
              "run_dump_piccollo_3in1_capture_screen.py",
              "run_dump_mini_hd265_capture_screen.py",
              "run_dump_bigsat_7035_capture_screen.py",
              "run_dump_mira2_wifi_capture_screen.py",
              "run_dump_impulse_t2c_capture_screen.py",
              "run_dump_piccollino_s2_t2c_capture_screen.py",
              "run_dump_micro_hd_se_capture_screen.py",
              "run_dump_gm_unibox_xwindow_capture_screen.py",
              "run_dump_hd8100_series_capture_screen.py",
              "run_dump_mira_wifi_capture_screen.py",
              "run_dump_stc3220_capture_screen.py",
              "run_dump_hd8140_m3612_capture_screen.py",
              "run_dump_dynavision_synaps_capture_screen.py",
              "run_dump_proton_lemontree_capture_screen.py",
              "run_dump_piccollino_led_capture_screen.py",
              "run_dump_minicombo_hd_se_capture_screen.py",
              "run_dump_iltv_hd_capture_screen.py",
              "run_dump_shd8360_capture_screen.py",
              "run_dump_minihd_m3606f_capture_screen.py",
              "run_dump_piccollo_s2_t2c_capture_screen.py",
              "run_dump_hd8270_plus_capture_screen.py",
              "run_dump_sthd8800_combo_capture_screen.py",
              "run_dump_chd8270_plus_capture_screen.py",
              "run_dump_piccollino_s2_capture_screen.py",
              "run_dump_hd8840_capture_screen.py",
              "run_dump_shd8000_capture_screen.py",
              "run_dump_hd8255_plus_capture_screen.py",
              "run_dump_hd8200_series_capture_screen.py",
              "run_dump_hd8300_series_capture_screen.py",
              "run_dump_microhd_capture_screen.py",
              "run_dump_minihd_combo_capture_screen.py",
              "run_dump_minihd_re_capture_screen.py",
              "run_dump_minihd_t2c_capture_screen.py",
              "run_dump_shd8110_capture_screen.py",
              "run_dump_shd8140_capture_screen.py",
              "run_dump_sthd8820_capture_screen.py",
              "run_dump_xfinder_plus_capture_screen.py",
              "run_dump_hd8140_t2c_capture_screen.py",
              "run_dump_hd8155_wifi_capture_screen.py",
              "run_dump_mini_combo_extra_rca_capture_screen.py",
              "run_dump_mira2_wifi_edision_capture_screen.py",
              "run_dump_hd8155_v1440_capture_screen.py",
              "run_dump_hd8265_v1521_capture_screen.py",
              "run_dump_yumatu_amstar_capture_screen.py")
# The per-dump UART console tests (console_regression.ConsoleHarness): every
# firmware with the ODM's interactive console gets its command table walked
# through ("startconsole", each command and what it does); 15-60 s each.
CONSOLE_TESTS = ("run_dump_maciej_console.py", "run_dump_globo_console.py", "run_dump_t90_console.py",
                 "run_dump_r265lite_console.py", "run_dump_r265lite_120_console.py",
                 "run_dump_x110p_console.py", "run_dump_x110ts_116_console.py",
                 "run_dump_x110ts_117_console.py", "run_dump_x110ts_118_rc3_console.py",
                 "run_dump_x110ts_118_rc4_console.py", "run_dump_x110ts_119_console.py",
                 "run_dump_x110ts_tiles_console.py", "run_dump_x110ts_140c_console.py",
                 "run_dump_hdxs2_reta_console.py", "run_dump_hdxs2_smarthd_console.py",
                 "run_dump_hdxs2_ger_console.py", "run_dump_hdxs2_140_console.py")


def discover_test_files(include_slow=False):
    """All test scripts: test_*.py (except util modules) plus the regression runs."""
    test_files = []
    for file_path in TESTS_DIR.glob("test_*.py"):
        if "util" not in file_path.stem:
            test_files.append(str(file_path))
    regressions = [
        "run_dump_to_print_bl_flash_init.py", "run_dump_maciej_to_print_bl_flash_init.py",
        "run_dump_to_print_check_program.py", "run_dump_with_bad_flash_id.py",
        "run_dump_maciej_to_bl_verify_sw.py", "run_dump_maciej_ready_v3.py", "run_dump_Prima_to_check_program.py",
        "run_dump_Prima_to_print_success.py", "run_dump_urz0195_2012_to_print_success.py",
        "run_dump_r265lite_boot.py", "run_dump_r265lite_app_banner.py", "run_dump_r265lite_120_app_banner.py",
        "run_dump_r265lite_panel_on.py", "run_dump_r265lite_remote_key.py",
        "run_dump_urz0083_app_runs.py", "run_dump_urz0086_see_start.py", "run_dump_km0186_see_start.py",
        "run_dump_a52e_security_ic.py", "run_dump_a102e_security_ic.py",
        "run_dump_a103_security_ic.py", "run_dump_a153_combo_security_ic.py",
        "run_dump_ax502_combo_app_starts.py", "run_dump_openbox_v8s_app_starts.py",
        "run_dump_openbox_v8se_app_starts.py", "run_dump_hd8250_plus_app_starts.py",
        "run_dump_skybox_s12_app_starts.py", "run_dump_skybox_f4_app_starts.py",
        "run_dump_skybox_a3_app_starts.py", "run_dump_openbox_x3_app_starts.py",
        "run_dump_a53_app_starts.py", "run_dump_a54_app_starts.py",
        "run_dump_t760i_app_starts.py", "run_dump_a204_app_starts.py",
        "run_dump_a255_app_starts.py", "run_dump_a255s_app_starts.py",
        "run_dump_hd8155_app_starts.py", "run_dump_hd8265_app_starts.py",
        "run_dump_hd8260_app_starts.py", "run_dump_x4_220_app_starts.py",
        "run_dump_t750i_app_starts.py", "run_dump_hdxs2_app_starts.py", "run_dump_x110ts_see_start.py",
        "run_dump_el700_security_mcu.py",
        "run_dump_hd8265_v1521_app_starts.py",
        "run_dump_hd8155_v1440_app_starts.py",
        "run_dump_mira2_wifi_edision_app_starts.py",
        "run_dump_mini_combo_extra_rca_app_starts.py",
        "run_dump_hd8155_wifi_app_starts.py",
        "run_dump_hd8140_t2c_app_starts.py",
        "run_dump_xfinder_plus_app_starts.py",
        "run_dump_sthd8820_app_starts.py",
        "run_dump_shd8140_app_starts.py",
        "run_dump_shd8110_app_starts.py",
        "run_dump_minihd_t2c_app_starts.py",
        "run_dump_minihd_re_app_starts.py",
        "run_dump_minihd_combo_app_starts.py",
        "run_dump_microhd_app_starts.py",
        "run_dump_hd8300_series_app_starts.py",
        "run_dump_hd8200_series_app_starts.py",
        "run_dump_hd8255_plus_app_starts.py",
        "run_dump_shd8000_app_starts.py",
        "run_dump_hd8840_app_starts.py",
        "run_dump_piccollino_s2_app_starts.py",
        "run_dump_chd8270_plus_app_starts.py",
        "run_dump_sthd8800_combo_app_starts.py",
        "run_dump_hd8270_plus_app_starts.py",
        "run_dump_piccollo_s2_t2c_app_starts.py",
        "run_dump_minihd_m3606f_app_starts.py",
        "run_dump_shd8360_app_starts.py",
        "run_dump_iltv_hd_app_starts.py",
        "run_dump_minicombo_hd_se_app_starts.py",
        "run_dump_piccollino_led_app_starts.py",
        "run_dump_proton_lemontree_app_starts.py",
        "run_dump_dynavision_synaps_app_starts.py",
        "run_dump_hd8140_m3612_app_starts.py",
        "run_dump_stc3220_app_starts.py",
        "run_dump_mira_wifi_app_starts.py",
        "run_dump_hd8100_series_app_starts.py",
        "run_dump_hd9265_arm_layout.py",
        "run_dump_gm_unibox_xwindow_app_starts.py",
        "run_dump_micro_hd_se_app_starts.py",
        "run_dump_piccollino_s2_t2c_app_starts.py",
        "run_dump_impulse_t2c_app_starts.py",
        "run_dump_mira2_wifi_app_starts.py",
        "run_dump_bigsat_7035_app_starts.py",
        "run_dump_mini_hd265_app_starts.py",
        "run_dump_piccollo_3in1_app_starts.py",
        "run_dump_sab_titan_amstar_app_starts.py",
        "run_dump_hd8240_app_starts.py",
        "run_dump_yumatu_amstar_app_starts.py",
        "run_dump_hd8150_app_starts.py",
        "run_dump_hd8275_app_starts.py",
        "run_dump_hd8140c_se_app_starts.py",
        "run_dump_opticum_4000a_app_starts.py",
        "run_dump_s16_eu_app_starts.py",
        "run_dump_hd8142_twinc_app_starts.py",
        "run_dump_xfinder3_app_starts.py",
        "run_dump_xfinder2_app_starts.py",
        "run_dump_bigsat_6500_app_starts.py",
        "run_dump_x403p_app_starts.py",
        "run_dump_impulse_sat_app_starts.py",
        "run_dump_mini_combo_extra_app_starts.py",
        "run_dump_eco_tc200_app_starts.py",
        "run_dump_7300pvr_app_starts.py",
        "run_dump_vip3_app_starts.py",
        "run_dump_xs65_twin_app_starts.py",
        "run_dump_impulse_h265_app_starts.py",
        "run_dump_amiko_t58_app_starts.py",
        "run_dump_x80_premium_app_starts.py",
        "run_dump_underline_3in1_app_starts.py",
        "run_dump_x7_app_starts.py",
        "run_dump_picco_s2_app_starts.py",
        "run_dump_xs65_combo_app_starts.py",
        "run_dump_maciej_to_I2C_display_ON.py",
        "run_dump_maciej_to_verify_uart_buffer.py", "run_dump_maciej_without_uart_interrupt.py",
        "run_dump_maciej_to_check_uart_overflow.py", "run_dump_no_main_app.py",
        "run_dump_to_end.py",
        # the firmware boots into its main application, whose RTOS runs on CP0
        # timer ticks (about 20 s each)
        "run_dump_to_main_app.py", "run_dump_Prima_to_main_app.py",
    ]
    for pat in ("run_dump_*_app_starts.py", "run_dump_*_arm_layout.py"):
        for p in sorted(TESTS_DIR.glob(pat)):
            if p.name not in regressions:
                regressions.append(p.name)
    regressions += list(CONSOLE_TESTS)
    if include_slow:
        regressions += list(SLOW_TESTS)       # minutes each
        for p in sorted(TESTS_DIR.glob("run_dump_*_capture_screen.py")):
            if p.name not in regressions:
                regressions.append(p.name)
    for name in regressions:
        if (TESTS_DIR / name).exists():
            test_files.append(str(TESTS_DIR / name))
    return sorted(test_files)


def _description(path):
    """The script's module docstring (shown in the report)."""
    try:
        return (ast.get_docstring(ast.parse(Path(path).read_text(encoding="utf-8"))) or "").strip()
    except Exception:
        return ""


def _featured(path):
    """The script's module-level FEATURED literal, read without running it:
    {"device": the box, "chips": its SoC, panel chip, tuner, "shows": what the
    run shows}.  The report puts such a run first, opened, under the title
    "<device> with <chip> + <chip>".  None for any other script."""
    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "FEATURED" for t in node.targets):
            try:
                value = ast.literal_eval(node.value)
            except ValueError:
                return None
            return value if isinstance(value, dict) and value.get("device") else None
    return None


def _tags(path, result):
    name = os.path.basename(path)
    try:
        source = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        source = ""
    tags = []
    for needle, label in DUMPS:
        if needle.lower() in name.lower() or needle in source:
            if not any(t["name"] == label for t in tags):
                tags.append({"group": "dump", "name": label})
    if name.startswith("test_"):
        tags.append({"group": "kind", "name": "unit"})
    else:
        tags.append({"group": "kind", "name": "regression"})
    if name in SLOW_TESTS or name.endswith("_capture_screen.py"):
        tags.append({"group": "kind", "name": "slow"})
    if name in CONSOLE_TESTS or name == "test_uart_console.py":
        tags.append({"group": "kind", "name": "console"})
    if result["images"] or result["panels"]:
        tags.append({"group": "data", "name": "renders"})
    if result["crashed"]:
        tags.append({"group": "data", "name": "crashed"})
    if result["timed_out"]:
        tags.append({"group": "data", "name": "timed out"})
    if result.get("not_applicable"):
        tags.append({"group": "data", "name": "not applicable"})
    return tags


def _collect_artifact(line, result, img_dir):  # noqa: C901
    """A [REPORT_IMAGE] / [REPORT_PANEL] line from the test: record it (the
    image file is copied next to the report).  Returns True if it was one."""
    if line.startswith(report_artifacts.IMAGE_TAG):
        body = line[len(report_artifacts.IMAGE_TAG):].strip()
        path, _, rest = body.partition("\t")
        caption, _, extra = rest.partition("\t")
        entry = {"path": path, "caption": caption, "missing": not os.path.isfile(path),
                 "order": len(result["images"]) + len(result["panels"])}    # its place among the test's renders
        if extra:
            try:
                extra = json.loads(extra)
            except ValueError:
                extra = {}
            if extra.get("panel"):
                try:
                    entry["panel"] = {"digits": [int(h, 16) for h in extra["panel"].split()],
                                      "text": extra.get("panelText", "")}
                except ValueError:
                    pass
            if extra.get("tuner"):
                entry["tuner"] = extra["tuner"]
        if not entry["missing"]:
            try:
                os.makedirs(img_dir, exist_ok=True)
                dest = os.path.join(img_dir, os.path.basename(path))
                if os.path.abspath(dest) != os.path.abspath(path):
                    shutil.copyfile(path, dest)
                entry["path"] = dest
            except OSError:
                pass
        result["images"].append(entry)
        return True
    if line.startswith(report_artifacts.PANEL_TAG):
        body = line[len(report_artifacts.PANEL_TAG):].strip()
        hexes, _, rest = body.partition("\t")
        text, _, caption = rest.partition("\t")
        try:
            digits = [int(h, 16) for h in hexes.split()]
        except ValueError:
            digits = []
        result["panels"].append({"digits": digits, "text": text, "caption": caption,
                                 "order": len(result["images"]) + len(result["panels"])})
        return True
    return False


_print_lock = threading.Lock()


def run_test_file(test_file_path, timeout=None, stream=True):
    """Run a single test file and return its result record.  Its output is
    streamed as it comes (stream=True) or printed as one block at the end
    (parallel runs)."""
    test_name = os.path.basename(test_file_path)
    stem = os.path.splitext(test_name)[0]
    img_dir = str(REPORT_DIR / "img" / stem)

    if stream:
        print(f"\n{'=' * 80}")
        print(f"Running: {test_name}")
        print(f"{'=' * 80}\n", flush=True)

    # Each test runs in its own Python process: a test that crashes the
    # interpreter (a native fault inside Unicorn) fails on its own instead of
    # ending the whole run without a summary.  Unbuffered, so its output up to
    # a crash is not lost, and with faulthandler, which prints the Python stack
    # of a native crash.  ALISIM_REPORT_DIR tells report_artifacts where to put
    # the images the test renders.
    # the tests import the simulator's modules from src/ and the helpers from tests/
    pythonpath = [str(ROOT / "src"), str(TESTS_DIR)] + ([os.environ["PYTHONPATH"]] if os.environ.get("PYTHONPATH") else [])
    env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONFAULTHANDLER="1", PYTHONIOENCODING="utf-8",
               ALISIM_REPORT_DIR=img_dir, PYTHONPATH=os.pathsep.join(pythonpath), ALISIM_ENGINE=ENGINE)
    result = {"name": test_name, "script": test_name, "description": _description(test_file_path),
              "featured": _featured(test_file_path), "passed": False, "elapsed": 0.0, "exit_code": None, "crashed": False, "timed_out": False,
              "checks": [], "output": "", "images": [], "panels": []}
    lines = []
    start = time.time()
    proc = subprocess.Popen([sys.executable, test_file_path], cwd=str(ROOT), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace", bufsize=1)

    def reader():
        for line in proc.stdout:
            if _collect_artifact(line.rstrip("\r\n"), result, img_dir):
                continue
            lines.append(line)
            if stream:
                sys.stdout.write(line)
                sys.stdout.flush()

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        result["timed_out"] = True
        proc.kill()
        proc.wait()
        print(f"\n{test_name} killed after {timeout:.0f}s (timeout)", flush=True)
    th.join(timeout=5)
    exit_code = proc.returncode
    result["elapsed"] = time.time() - start
    result["exit_code"] = exit_code
    result["output"] = "".join(lines)
    result["crashed"] = exit_code not in (0, 1) and not result["timed_out"]
    if result["crashed"]:
        print(f"\n{test_name} exited with code {exit_code} (0x{exit_code & 0xFFFFFFFF:08X}): "
              f"crashed?", flush=True)
    for line in lines:
        m = re.search(r"\[(PASS|FAIL)\]\s*(.*)", line)
        if m:
            result["checks"].append({"ok": m.group(1) == "PASS", "text": m.group(2).strip()})
    result["passed"] = exit_code == 0
    # a test of one engine's own machinery (e.g. Unicorn's CP0 site hooks) says so
    # on the other engine: "[NOT APPLICABLE] why" (engine_check.py)
    na = [ln for ln in lines if ln.startswith(NOT_APPLICABLE)]
    result["not_applicable"] = na[0][len(NOT_APPLICABLE):].strip() if na else None
    result["tags"] = _tags(test_file_path, result)
    if not stream:
        with _print_lock:
            print(f"\n{'=' * 80}\n{test_name}: {'PASS' if result['passed'] else 'FAIL'} "
                  f"({result['elapsed']:.0f}s)\n{'=' * 80}\n{result['output']}", flush=True)
    return result


def write_report(results, note=""):
    """Emit report/index.html, and the results behind it as
    report/results.json (for --report-only); never fails the run itself."""
    try:
        run_id = os.environ.get("GITHUB_RUN_ID")
        run_url = None
        if run_id:
            run_url = "%s/%s/actions/runs/%s" % (os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
                                                  os.environ.get("GITHUB_REPOSITORY", ""), run_id)
        meta = {
            "total_time": sum(r["elapsed"] for r in results),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "commit": os.environ.get("GITHUB_SHA"),
            "repo": os.environ.get("GITHUB_REPOSITORY"),
            "run_url": run_url,
            "note": note,
            "engine": ENGINE,
            "links": LINKS,
        }
        path = report.generate(results, meta, str(REPORT_DIR / "index.html"))
        print(f"HTML report written: {path}")
        with open(REPORT_DIR / "results.json", "w", encoding="utf-8") as f:
            json.dump({"meta": meta, "results": results}, f, ensure_ascii=False, indent=1)
    except Exception as e:
        print(f"WARN: could not write the HTML report: {e!r}")


def report_only():
    """--report-only: report/index.html again from report/results.json (the
    last run's results), each script's docstring and FEATURED read anew, so a
    change to the page's layout or to a test's description shows without
    running anything."""
    if not (REPORT_DIR / "results.json").exists():
        print(f"No {REPORT_DIR / 'results.json'}: run the tests first.")
        sys.exit(1)
    with open(REPORT_DIR / "results.json", encoding="utf-8") as f:
        saved = json.load(f)
    for r in saved["results"]:
        script = TESTS_DIR / r["script"]
        if script.exists():
            r["description"], r["featured"] = _description(script), _featured(script)
    if LINKS:
        saved["meta"]["links"] = LINKS
    path = report.generate(saved["results"], saved["meta"], str(REPORT_DIR / "index.html"))
    print(f"HTML report written: {path}")


def _parallel_order(test_files):
    """Longest-job-first dispatch order for parallel runs, using the previous
    run's per-script timings from REPORT_DIR/results.json when available (with a
    coarse category fallback on a fresh checkout) so long tests do not start at
    the tail of the queue."""
    prior = {}
    for candidate in (REPORT_DIR / "results.json", ROOT / "report" / "cpp" / "results.json", ROOT / "report" / "results.json"):
        if candidate.exists():
            try:
                with open(candidate, encoding="utf-8") as f:
                    for r in json.load(f).get("results", ()):
                        s = r.get("script")
                        if s and s not in prior:
                            prior[s] = float(r.get("elapsed", 0.0))
            except Exception:
                pass
    slow_set, console_set = set(SLOW_TESTS), set(CONSOLE_TESTS)

    def est(path):
        name = os.path.basename(path)
        if name in prior:
            return prior[name]
        if name in slow_set:
            return 60.0
        if name in console_set or name.startswith("run_dump_"):
            return 20.0
        return 5.0

    return sorted(test_files, key=lambda p: (-est(p), os.path.basename(p)))


def main():
    """Main test runner function."""
    global ENGINE, REPORT_DIR
    args = sys.argv[1:]
    if "--engine" in args:
        ENGINE = args[args.index("--engine") + 1].lower()
        if ENGINE not in ("unicorn", "cpp"):
            print(f"unknown engine {ENGINE!r} (cpp, unicorn)")
            sys.exit(2)
    if ENGINE == "cpp":
        # The default since 2026-11-04: the same suite takes about seven times
        # longer on Unicorn (and needs the crash retries); --engine unicorn still runs it.
        REPORT_DIR = ROOT / "report" / "cpp"
        sys.path.insert(0, str(ROOT / "src"))
        import cpp_core
        if not cpp_core.available() and "--report-only" not in args:
            print(f"the C++ core is not built ({cpp_core.DLL_PATH}): run {cpp_core.BUILD_HINT}")
            sys.exit(2)
    for i, a in enumerate(args[:-1]):
        if a == "--link" and "=" in args[i + 1]:
            label, href = args[i + 1].split("=", 1)
            LINKS.append([label.strip(), href.strip()])
    if "--report-only" in args:
        report_only()
        return
    include_slow = "--slow" in args
    timeout = None
    if "--timeout" in args:
        timeout = float(args[args.index("--timeout") + 1])
    jobs = int(args[args.index("--jobs") + 1]) if "--jobs" in args else 1
    patterns = [a.lower() for i, a in enumerate(args) if i > 0 and args[i - 1] == "-k"]

    print("\n" + "=" * 80)
    print("MIPS Simulator Test Suite - Running All Tests")
    print("=" * 80)

    test_files = discover_test_files(include_slow)
    if patterns:
        test_files = [t for t in test_files if any(p in os.path.basename(t).lower() for p in patterns)]
    if not include_slow:
        print("(slow regressions skipped; run with --slow to include " + ", ".join(SLOW_TESTS) + ")")
    if not test_files:
        print("No test files found!")
        sys.exit(1)

    print(f"\nFound {len(test_files)} test file(s):")
    for test_file in test_files:
        print(f"  - {os.path.basename(test_file)}")

    if jobs > 1:
        # Parallel: the simulations are CPU bound and independent (firmware time
        # follows each emulation thread's own CPU time), so N at once on N cores
        # cuts the wall time of the slow suite; outputs are printed per test.
        # Dispatch longest tests first so slow unit/dump tests do not straggle at
        # the end, then restore discover_test_files() order for the summary/report.
        from concurrent.futures import ThreadPoolExecutor
        work_files = _parallel_order(test_files)
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            by_file = dict(zip(work_files, pool.map(lambda t: run_test_file(t, timeout, stream=False), work_files)))
        results = [by_file[t] for t in test_files]
    else:
        results = [run_test_file(t, timeout) for t in test_files]

    print("\n" + "=" * 80)
    print("Test Summary")
    print("=" * 80)
    for r in results:
        status = "\033[92mPASS\033[0m" if r["passed"] else "\033[91mFAIL\033[0m"
        if r["passed"] and r.get("not_applicable"):
            status = "\033[93mN/A \033[0m"
        extra = " (crashed)" if r["crashed"] else (" (timed out)" if r["timed_out"] else "")
        print(f"  {status} - {r['name']}{extra}  {r['elapsed']:.0f}s")
    print("\n" + "-" * 80)

    note = ("default suite" if not include_slow else "with --slow") + (f", {jobs} jobs" if jobs > 1 else "")
    note += f", engine {ENGINE}"
    if patterns:
        note += ", filtered: " + ", ".join(patterns)
    write_report(results, note)

    total = len(results)
    failed = sum(1 for r in results if not r["passed"])
    na = sum(1 for r in results if r["passed"] and r.get("not_applicable"))
    if na:
        print(f"{na} test(s) check machinery the {ENGINE} engine does not have (not applicable)")
    if failed == 0:
        print(f"\033[92mAll {total - na} applicable test(s) passed!\033[0m" if na else
              f"\033[92mAll {total} test(s) passed!\033[0m")
        sys.exit(0)
    print(f"\033[91m{failed} of {total} test(s) failed\033[0m")
    sys.exit(1)


if __name__ == "__main__":
    main()
