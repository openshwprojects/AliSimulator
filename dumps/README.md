# The firmware images

Rendered by `tools/dump_table.py` from the `<image>.json` sidecar next to each image (`src/dump_catalog.py`; `tests/test_dump_catalog.py` checks them).  Edit the sidecars, not this file.

| Image | Box | SoC | Tuner | Front panel | Boots / app / display | Source |
|---|---|---|---|---|---|---|
| `Ali_3801_Globo_DVBT_dump SPI 4mb.bin` | Globo STB HD N3 | ALi M3801 | Rafael Micro R820T (7-bit I2C address 0x1A, 0x34 as the w... | TM1650 (SCL 31, SDA 9) | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic4156384-30.html#21933067), JacekTorun |
| `ali_sdk.bin` | test program (not a flash dump) | ALi M3801 (it reads the chip id, "chip id raw: 3811") | - | - | yes / - / - | not recorded |
| `CABLETECH URZ0083Q/Cabletech URZ0083Q/EN25Q32B.bin` | Cabletech URZ0083Q | ALi M3801 | MaxLinear MxL603 family at I2C 0x60 on the first hardware... | TM1628-class 3-wire (CLK 31, DIO 9, STB 11) | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic2842886.html#13677891), Fairgrounds |
| `CABLETECH_urz0194s_v1_0_8.bin` | Cabletech URZ0194S | ALi M3801 | MaxLinear MxL603 family at I2C 0x60 on the first hardware... | TM1628-class 3-wire (CLK 31, DIO 9, STB 11) | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic2981605.html#14403424), Krzyś122333 |
| `cableteh_urz0195__w25q32bv.BIN` | Cabletech URZ0195 | ALi M3801 | MaxLinear MxL603 family at I2C 0x60 on the first hardware... | uPD16312-class 3-wire (CLK 31, DIO 9, STB 14) | yes / yes / no | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic2973485.html#14357941), Bell72 |
| `dump.bin` | Comsat TE 1050 HD | ALi M3801 | MaxLinear MxL603 family, by its wake-up: at start the app... | - | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic4155976.html), p.kaczmarek2 |
| `dump_maciej.bin` | Opticum STB HD N2 | ALi M3801 | unknown: the application touches no hardware I2C master i... | TM1650 (SCL 31, SDA 9) | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic4156384.html#21794256), maciej_333 |
| `FERGUSON ARIVA T650i/T650i_V1.13B4_20160721.abs` | Ferguson Ariva T650i | ALi M3801 | MaxLinear MxL603 family at I2C 0x63 (an address strap opt... | FD650K (TM1650-compatible) (SCL 31, SDA 9) | yes / yes / yes | [ferguson-digital.eu](https://ferguson-digital.eu/download/?dir=dvb-t%2Fseries_Ariva%2FAriva_T650i%2Ffirmware), Ferguson |
| `Opticum Blue R265 Lite/M3822P.bin` | Opticum Blue R265 Lite | ALi M3822P | MaxLinear MxL608 (reported for this board; the firmware p... | HD2015 (TM1650-compatible; no display soldered, 3 buttons) (SCL 57, SDA 58) | yes / no / no | [github.com/openshwprojects/FlashDumps](https://github.com/openshwprojects/FlashDumps/tree/main/Sat/Opticum%20Blue%20R265%20Lite), openshwprojects |
| `Opticum Blue R265 Lite/T2GEN265_1.1.5-2022-08-01.abs` | Opticum Blue R265 Lite (also sold as Skymaster STB 2GEN, STB M265 and STB N2) | ALi M3822P | MaxLinear MxL608 (reported for this board; the firmware c... | HD2015 (TM1650-compatible; no display soldered, 3 buttons) (SCL 57, SDA 58) | yes / yes / yes | [update.skymaster.de](https://update.skymaster.de/api/downloadfile?file=sw/SW_Opticum_Blue_R265_Lite_1.2.0-2023-03-17.zip), Skymaster (the Polish distributor) |
| `Opticum Blue R265 Lite/T2GEN265_1.2.0-2023-03-17.abs` | Opticum Blue R265 Lite (also sold as Skymaster STB 2GEN, STB M265 and STB N2) | ALi M3822P | MaxLinear MxL608 (reported for this board; the firmware p... | HD2015 (TM1650-compatible; no display soldered, 3 buttons) (SCL 57, SDA 58) | yes / yes / yes | [update.skymaster.de](https://update.skymaster.de/api/downloadfile?file=sw/SW_Opticum_Blue_R265_Lite_1.2.0-2023-03-17.zip), Skymaster (the Polish distributor) |
| `other/Echosonic_Mini_ESR-250__GD25Q32B--DVBS2-M3510A-A3__OK--OK.BIN` | Echosonic Mini ESR-250 | ALi M3510A | - | - | no / no / no | not recorded |
| `other/sat_main_ali3329-s15125_dump_eeprom_by_h2h_ok.bin` | satellite receiver main board "s15125" | ALi M3329 | - | - | no / no / no | not recorded |
| `srt8115.BIN` | Strong SRT 8115 | ALi M3801 | MaxLinear MxL603 family (MxL603 / pin-compatible MxL608)... | TM1628-class 3-wire (CLK 31, DIO 9, STB 11) | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic3123357.html#15195863) |
| `SRT_Prima_VIII_V1.0.6_20160114.abs` | Strong Prima VIII | ALi M3801 | probably a Silicon Labs Si2144 option: the image's only t... | - | yes / yes / - | not recorded |
| `STRONG PRIMA VIII/GD25Q32B_20190128_141501.BIN` | Strong Prima VIII | ALi M3801 | MaxLinear MxL603 family at I2C 0x60 on the first hardware... | - | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic3549956.html#17756835), bakardjiev |
| `urz0195_full_dump(ESMTF25L3204).bin` | Cabletech URZ0195 | ALi M3801 | MaxLinear MxL5007T (I2C 0x60 on the first hardware I2C ma... | uPD16312-class 3-wire (CLK 31, DIO 9, STB 14) | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic3573829.html#17909725) |

## `Ali_3801_Globo_DVBT_dump SPI 4mb.bin`

* **Box:** Globo STB HD N3
* **Type:** DVB-T set-top box
* **SoC:** ALi M3801 (M3801)
* **Demodulator:** internal (NIM_S3811)
* **Tuner:** Rafael Micro R820T (7-bit I2C address 0x1A, 0x34 as the write address byte, on the first hardware I2C master)
* **Flash:** 4 MB SPI (desoldered and read with a programmer)
* **Front panel:** TM1650 (SCL 31, SDA 9)
* **IR coding:** nec
* **Image:** dump, maincode "M3801 DVBT" 2014-6-23 (name 406000000003002), 2014-06-23, 4194304 bytes, SHA-1 ef46dee13875ce21193b9ffe58c031aebd83c54b
* **Layout:** bootloader 0x000000, HDCPKey 0x04FE00, maincode 0x050000, Radioback 0x290000, defaultdb 0x2A0000, userdb 0x2BFF80 -- the dump_maciej.bin layout and maincode name
* **Source:** [elektroda.pl](https://www.elektroda.pl/rtvforum/topic4156384-30.html#21933067), JacekTorun (2026-07-05) -- login needed. Thread "Jak skompilować i uruchomić własny firmware dla ALI M3801 i innych układów z tunerów?", page 2, post #40 (machine translation: https://www.elektroda.com/rtvforum/topic4156384-30.html#21933067)
* **Simulator:** boots yes, application yes, display yes, panel ' ON '. Keeps its channel list, so the application tunes a channel at start, shows a channel banner that times out and then its no-signal message (run_dump_globo_capture_screen.py).

Tuner: a Rafael Micro R820T on the chip's first hardware I2C master (0xB8018200, i2c_scb.py) at 7-bit address 0x1A (0x34 as the write address byte): when the application tunes its first channel (about 93 M instructions in) it writes the R820T initialisation array -- registers 0x05..0x1F = 83 32 75 C0 40 D6 6C F5 53 75 68 6C 83 80 00 0F 00 C0 30 48 CC 60 00 54 A6 4A C0, the public R820T driver's bytes but for two values -- then runs the filter and image calibrations (5- and 2-byte reads: the Rafael read protocol starts at register 0 and sends every byte bit-reversed) and its PLL, whose lock it checks in register 2 with a 3-byte read; on no lock it raises the VCO current (0x12: 0x88 -> 0x68) exactly like the Linux r820t driver.  The demodulator is the chip's own ("NIM_S3811_0").

UART log of the real box from the same post (the forum collapses repeated spaces and shows "@" before a domain-like word as "(_at_)"):

APP init! / bl_panel_init! / bl_flash_init! / bl_verify_sw / success! / MC: APP init ok / << SDK4.0ba.4.0_20101217 >> / Libcore version 8.13.0(_at_)SDK4.0bd.8.13_20130731(gcc version 3.4.4 mipssde-6.06.01-20070420)(Vic.Wang@ Thu Aug 1 15:38:18 2013) / Application version 1.0.0(_at_)SDK4.0ba.7.4_20120227


## `ali_sdk.bin`

* **Type:** test program (not a flash dump)
* **SoC:** ALi M3801 (it reads the chip id, "chip id raw: 3811") (M3801)
* **IR coding:** nec
* **Image:** test program, -, 2026-01-18, 39856 bytes, SHA-1 924f7c13ca37a8408ee757ed5d4ccd8369b86e84
* **Layout:** bare MIPS32 code that starts by setting up CP0 Status
* **Source:** not recorded (2026-01-18). The "ALi SDK hello world" of the tests, added on 2026-01-18 for the tests that need a tiny firmware of known behaviour; its sources and the toolchain that built it are not in this repository
* **Simulator:** boots yes, application -, display -. Used by tests/test_ali_sdk_hello_world.py, test_ali_sdk_hello_world_breakpoint.py and test_cp0_timer_interrupt.py.

It prints "Booting...", "Main function", its stack and heap limits, a floating-point result, "chip id raw: 3811" and "Menu!" on the UART.


## `CABLETECH URZ0083Q/Cabletech URZ0083Q/EN25Q32B.bin`

* **Box:** Cabletech URZ0083Q
* **Type:** DVB-T receiver
* **Board:** 6390-M3801-VER1.0
* **SoC:** ALi M3801 (M3801)
* **Demodulator:** internal (NIM_S3811)
* **Tuner:** MaxLinear MxL603 family at I2C 0x60 on the first hardware I2C master: the application writes the MxL603 register table at start (3.7 M instructions in), the Cabletech URZ0194S's sequence
* **Flash:** eFeon Q32B-104HIP (read by the programmer as EN25Q32B; 4 MB SPI)
* **Front panel:** TM1628-class 3-wire (CLK 31, DIO 9, STB 11)
* **IR coding:** plain
* **Image:** dump, maincode "URZ0083Q" 2013-4-2, 2013-04-02, 4194304 bytes, SHA-1 b417d177a667d3540c335031401e68eeb2b63a27
* **Layout:** bootloader 0x000000, HDCPKey 0x01FE00 ("Demo M3801"), maincode 0x020000, Radioback 0x320000, defaultdb 0x330000, userdb 0x34FF80 -- the dump.bin layout
* **Source:** [elektroda.pl](https://www.elektroda.pl/rtvforum/topic2842886.html#13677891), Fairgrounds (2014-05-14) -- login needed. Thread "CABLETECH URZ0083Q Wsad pamięci EFEON Q32B-104HIP", post #1 ("zgrane ze sprawnego dekodera" = read from a working decoder): attachment "CABLETECH URZ0083Q.RAR" (4.74 MB) with this image, INFO.txt and two board photos (the photos are not kept in git)
* **Simulator:** boots yes, application yes, display yes, panel ' ON ' -> 'noCH'. Scans its flash channel database for 12-17 minutes, then draws its first-install wizard (run_dump_cabletech_capture_screen.py); the 3-wire panel reads " ON " at boot and "noCH" without channels, and its wizard reacts to the panel's keys.

Cabletech URZ0083Q DVB-T receiver on the ALi M3801 (PCB 6390-M3801-VER1.0), read from a working decoder.

INFO.txt in the same folder gives the flash part and the PCB marking.


## `CABLETECH_urz0194s_v1_0_8.bin`

* **Box:** Cabletech URZ0194S
* **Type:** DVB-T receiver
* **SoC:** ALi M3801 (M3801)
* **Demodulator:** internal (NIM_S3811)
* **Tuner:** MaxLinear MxL603 family at I2C 0x60 on the first hardware I2C master: the application writes the MxL603 register table at start (3.8 M instructions in: 0xFF=0, 0x14=0x13, 0x6D=0x8A then 0x0A, 0xDF=0x19, 0x45=0x1B, 0xA9=0x59, 0xAA=0x6A, 0xBE=0x4C ... the Strong SRT 8115's sequence), puts the chip in standby (0x12=0) and wakes it again (0x0B and 0x12 set to 1)
* **Flash:** 25Q32FV (4 MB SPI)
* **Front panel:** TM1628-class 3-wire (CLK 31, DIO 9, STB 11)
* **IR coding:** plain
* **Image:** dump, 1.0.8 (maincode "URZ0194" 2013-9-16), 2013-09-16, 4194304 bytes, SHA-1 82438d88edcaaf37da8086184c793cb126abe48d
* **Layout:** bootloader 0x000000 (Libcore 1.1.6, vic.wang, Mon Oct 15 2012 -- the URZ0083Q's build), HDCPKey 0x01FE00 ("Demo M3801"), maincode 0x020000, Radioback 0x320000, defaultdb 0x330000, userdb 0x34FF80 -- the URZ0083Q / dump.bin layout
* **Source:** [elektroda.pl](https://www.elektroda.pl/rtvforum/topic2981605.html#14403424), Krzyś122333 (2015-02-04) -- login needed. Thread "CABLETECH URZ0194S wsad pamięci 25Q32FV", post #1 ("zgrane ze sprawnego dekodera" = read from a working decoder): attachment "CABLETECH_urz0194s_v1_0_8.bin"
* **Simulator:** boots yes, application yes, display yes, panel ' ON ' -> '----' -> 'noCH'. The application (Libcore 8.1j.0@SDK4.0bd.8.1j_20130424) prints its banner 8 s after start, scans its flash channel database for about 11 minutes and then draws the same first-install wizard as the URZ0083Q (run_dump_urz0194s_capture_screen.py).

The firmware's chip-ID table is the M3801 family's and its demodulator driver is the S3811's.  Its bootloader's standby wake code 00FDBA45 is the URZ0083Q's too, so the same remote: a newer application on the URZ0083Q's hardware family.

In the simulator (2026-10-06): the wizard "Witaj" (Region, Język, Tryb Wyświetlania, Proporcje Obrazu, Ok).  Its TM1628-class front panel sits on the URZ0083Q's pins (CLK 31, DIO 9, STB 11) but its digits use the standard 7-segment layout: " ON " at boot, "----" while the application starts, "noCH" (no channels) once the wizard is up.


## `cableteh_urz0195__w25q32bv.BIN`

* **Box:** Cabletech URZ0195
* **Type:** DVB-T receiver
* **SoC:** ALi M3801 (M3801)
* **Demodulator:** internal (NIM_S3811)
* **Tuner:** MaxLinear MxL603 family at I2C 0x60 on the first hardware I2C master: woken at 49 M instructions (0x0B and 0x12 set to 1), the MxL603 register table at 120 M -- while the same model's 2012 firmware (urz0195_full_dump(ESMTF25L3204).bin) drives an MxL5007T: two tuner generations in one box model
* **Flash:** W25Q32BV (4 MB SPI)
* **Front panel:** uPD16312-class 3-wire (CLK 31, DIO 9, STB 14)
* **IR coding:** nec
* **Image:** dump, maincode "M3801 DVBT" 2013-10-23, 2013-10-23, 4194304 bytes, SHA-1 a02cf9db469c60234e26b911d78ed45d370d6a06
* **Layout:** bootloader 0x000000 (Libcore 1.1.6, vic.wang, Mon Nov 26 2012), HDCPKey 0x04FE00 ("Demo M3801"), maincode 0x050000, Radioback 0x290000, defaultdb 0x2A0000, userdb 0x2BFF80 (2012-12-12) -- the dump_maciej.bin layout with a 0x50000-byte bootloader area
* **Source:** [elektroda.pl](https://www.elektroda.pl/rtvforum/topic2973485.html#14357941), Bell72 (2015-01-22) -- login needed. Thread "Dekoder CABLETECH URZ0195 - wsad pamięci", post #1: attachment "cableteh_urz0195__w25q32bv.BIN" (the file name's typo is the poster's)
* **Simulator:** boots yes, application yes, display no. Boots into its application, which had issued no graphics-engine command 14 minutes after its banner; no screen regression.

The newer of the two URZ0195 dumps in this repository (the other is urz0195_full_dump(ESMTF25L3204).bin, with an older firmware).  The forum names the chip in later threads about this model; the firmware's chip-ID table is the M3801 family's.

UART log in the simulator (2026-10-05): the bootloader prints its panel configuration ("stb: 14 clock: 31 data: 9", "nec 16312 attach ok", "digit: 4 seg: 16 data_count: 8" -- a uPD16312-class 3-wire LED driver on GPIO 14 / 31 / 9), then bl_flash_init!, bl_verify_sw, check_program!, success!, and the application prints its banner: Libcore version 8.1c.0@SDK4.0bd.8.7_20121127 (the same Libcore build as dump.bin's application), Application version 1.0.0@SDK4.0bd.8.7_20121127byAdministrator.

Simulator run with the 16312 decoder (tm1628_decoder.py on CLK 31 / DIO 9 / STB 14): the bootloader sends 87, 40, C0 + 8 zero bytes, 41 FD (LED port), 08, 40, 8F, then C0 00 00 EE 00 CE 00 00 00 (two digits lit; this chip's segment wiring is not mapped yet, so the decoded text is wrong), and the application repeats the sequence.  14 minutes after the banner (178k timer ticks) it had issued no graphics-engine command yet; an earlier run jumped to address 0 after 13 minutes (the simulator's known asynchronous-stop race).


## `dump.bin`

* **Box:** Comsat TE 1050 HD
* **Type:** DVB-T HD receiver
* **Board:** MC6379-VER1.0
* **SoC:** ALi M3801 (M3801)
* **Demodulator:** internal (NIM_S3811)
* **Tuner:** MaxLinear MxL603 family, by its wake-up: at start the application sets registers 0x0B and 0x12 of a chip at I2C 0x60 to 1 (the MxL603's tuner-enable and start-tune registers), exactly what the Strong SRT 8115's and Cabletech URZ0195's firmwares do before their first tune writes the MxL603 table; this firmware never tunes without channels, so the table itself was not seen
* **Flash:** 25Q32BSIG (4 MB SPI)
* **IR coding:** nec
* **Image:** dump, DVB-T HD V1.1.5 (maincode "M3801 DVBT" 2013-2-1), 2013-02-01, 4194304 bytes
* **Layout:** bootloader 0x000000 (Libcore 1.1.6, vic.wang, Mon Nov 26 2012), HDCPKey 0x01FE00 ("Demo M3801"), maincode 0x020000, Radioback 0x320000, defaultdb 0x330000, userdb 0x34FF80
* **Source:** [elektroda.pl](https://www.elektroda.pl/rtvforum/topic4155976.html), p.kaczmarek2 (2025-12). The article "Wnętrze tunera Comsat TE 1050 HD, zgrywanie firmware, format partycji z pamięci Flash" (machine translation: https://www.elektroda.com/news/news4155976.html); the same file is published as https://github.com/openshwprojects/FlashDumps (Sat/Comsat TE 1050 HD/Flash_For_M3801_ALI.bin) and https://github.com/openshwprojects/AliUnpacker (dump.bin), identical git blob 5dc3133c8ce82df79ef28dcd69a727703272334a
* **Simulator:** boots yes, application yes, display yes. The simulator's first target; its application draws its first screen after a long start (run_dump_capture_screen.py, boot limit 45 min).

p.kaczmarek2's Comsat TE 1050 HD, read with a CH341 programmer for the elektroda article of December 2025 on the box's inside, the firmware read-out and the flash partition format.

The application's system-information page names it "M3801", "MC6379-VER1.0", "TE 1050 HD", "DVB-T HD V1.1.5", "Jan 29 2013".  Application: Libcore 8.1c.0@SDK4.0bd.8.7_20121127.

Tuner: the application initialises the chip's two hardware I2C masters (0xB8018200, 0xB8018700; i2c_scb.py) at start and, on the first, wakes a tuner at I2C address 0x60 (registers 0x0B and 0x12 set to 0x01) -- and nothing more until a channel is tuned, which it never does with its empty channel list; the demodulator is the chip's own (the firmware's "NIM_S3811_0").  The driver names no tuner in its strings (none of the M3801 firmwares does); the register table it writes at the first tune would identify the chip.


## `dump_maciej.bin`

* **Box:** Opticum STB HD N2
* **Type:** DVB-T set-top box
* **SoC:** ALi M3801 (M3801)
* **Demodulator:** internal (NIM_S3811)
* **Tuner:** unknown: the application touches no hardware I2C master in 300 M instructions (nothing to tune without channels); the Globo STB HD N3 runs the same maincode (name 406000000003002) and has a Rafael R820T
* **Flash:** EN25Q32SB (4 MB SPI)
* **Front panel:** TM1650 (SCL 31, SDA 9)
* **IR coding:** nec
* **Image:** dump, maincode "M3801 DVBT" 2013-6-17 (name 406000000003002), 2013-06-17, 4194308 bytes
* **Layout:** bootloader 0x000000 (Libcore 1.1.6, jessie.wei, Fri Jun 15 2012), HDCPKey 0x04FE00, maincode 0x050000 (LZMA), Radioback 0x290000, defaultdb 0x2A0000, userdb 0x2BFF80; the last 4 bytes (5F E3 28 52) are the UART console's CRC, not flash contents
* **Source:** [elektroda.pl](https://www.elektroda.pl/rtvforum/topic4156384.html#21794256), maciej_333 (2015-12-30) -- login needed. Thread "Jak skompilować i uruchomić własny firmware dla ALI M3801 i innych układów z tunerów?", page 1, post #15: attachment "dump.bin" (machine translation: https://www.elektroda.com/rtvforum/topic4156384.html#21794256)
* **Simulator:** boots yes, application yes, display yes, panel ' ON '. Its LZMA bootloader takes about a minute of emulation; the application draws its first-install wizard (run_dump_maciej_capture_screen.py) and its TM1650 shows " ON " (run_dump_maciej_to_I2C_display_ON.py).

The flash of maciej_333's Opticum STB HD N2, read through the bootloader's UART console ("dump" command), which sends the 4 MB flash followed by a 4-byte CRC -- hence the file's 4194308 bytes.

Application: Libcore 8.9.0@SDK4.0bd.8.9_20130409.

The attachment "opticum_hd_n2_upgraded.bin" of post #12 in the same thread (the box after the firmware update maciej_333 found on chomikuj.pl, read with a programmer) is byte-identical to the first 4 MB of this file, so it is not kept separately: the update installed the same firmware the box already had.


## `FERGUSON ARIVA T650i/T650i_V1.13B4_20160721.abs`

* **Box:** Ferguson Ariva T650i
* **Type:** DVB-T HD receiver with Ethernet and web services (YouTube etc.)
* **SoC:** ALi M3801 (M3801)
* **Demodulator:** internal (NIM_S3811)
* **Tuner:** MaxLinear MxL603 family at I2C 0x63 (an address strap option) on the first hardware I2C master: woken at 76 M instructions, the MxL603 register table when the automatic search tunes its first channel (188 M), then the search's re-tunes (10374 transfers in 700 M instructions)
* **Flash:** 8 MB SPI
* **Front panel:** FD650K (TM1650-compatible) (SCL 31, SDA 9)
* **IR coding:** ext00
* **Image:** update, V1.13B4 (maincode and OTA loader V1.13B5), 2016-07-21, 8388608 bytes, SHA-1 ea4978aabdaa1c890f01f8c297edde61deb409b3
* **Layout:** 8 MB part: bootloader 0x000000 ("HTJ4" 63004-01047, Libcore 1.1.6@Auto_20100413, vic.wang Aug 25 2012), HDCPKey 0x01FE00, OTAloader 0x020000 (V1.13B5), OTAparam 0x0FFE00, maincode 0x100000 (V1.13B5, LZMA-alone, 0x29693F -> 0xA7AC14 bytes; Libcore 8.1c.0@SDK4.0bd.8.7_20121127 = dump.bin's library, Application 1.0.0@SDK4.0bd.8.3_20120828), radioback 0x700000, data1 0x71FF80, "T650i" 0x730000 (an MPEG still, the boot picture), data2 0x74FF80, defaultdb 0x770000, userdb 0x78FF80 (empty)
* **Source:** [ferguson-digital.eu](https://ferguson-digital.eu/download/?dir=dvb-t%2Fseries_Ariva%2FAriva_T650i%2Ffirmware), Ferguson (2016-07-21). Ferguson's official download area: T650i_V1.13B4_20160721.zip (2.94 MB) also holds a changelog (1.10B1 .. 1.13B4: new YouTube / Vimeo / Dailymotion APIs, "Wybieram TV", timer and subtitle fixes) and upgrade guides in EN / DE / PL; only the .abs image is kept here
* **Simulator:** boots yes, application yes, display yes, panel ' On ' -> 'Strt' -> 'Find'. A manufacturer update image, not a dump: a complete 8 MB layout with an empty channel database, so the application runs the first-install automatic search and ends on its "no channel found" dialog (run_dump_t650i_capture_screen.py, ~18 min).

The upper 4 MB are reached the SDK way, at 0xAFC00000 - 4 MB + offset (simulator.py _flash_offset).

In the simulator (2026-10-08): the bootloader identifies the flash as an 8 MB part (RES id 0x16, its table's "16@56" entry), unpacks the maincode (~4-6 min) and prints "success!"; the front panel is an FD650K ("PAN_FD650K", TM1650-compatible on GPIO 31 / 9) showing " On ", then "Strt" and "Find".  The application rewrites three sectors in the upper 4 MB at start, resets its Ethernet MAC (ETHERNET_MAC_0, 0xB802C000) and probes the PHY over MDIO (no PHY: reads 0xFFFF), then -- the channel database being empty -- runs the first-install automatic search ("Przeszukiwanie auto", Polish UI, Ferguson's black / orange skin): its progress screen from ~7 min, "nie znaleziono kanału!" (no channel found) with a "tak" button at 100 % after ~18 min (217 GE commands).


## `Opticum Blue R265 Lite/M3822P.bin`

* **Box:** Opticum Blue R265 Lite
* **Type:** DVB-T2 / HEVC receiver
* **SoC:** ALi M3822P (M3821)
* **Demodulator:** internal (NIM_S3821)
* **Tuner:** MaxLinear MxL608 (reported for this board; the firmware probes MxL608 / R850 / R836, see T2GEN265_1.1.5-2022-08-01.abs)
* **Flash:** 4 MB SPI
* **Front panel:** HD2015 (TM1650-compatible; no display soldered, 3 buttons) (SCL 57, SDA 58)
* **IR coding:** nec
* **Image:** dump, maincode name "N(420000000003002" 2020-2-10 (damaged), 2020-02-10, 4194304 bytes, SHA-1 66755f5bd236f4b15ec067b0a7f31be36c6ebc3d
* **Layout:** the M3801's NCRC chunk chain: bootloader 0x000000 (chunk 0x23010010, area 0x5FE00), HDCPKey 0x05FE00 (version "00000001"), maincode 0x060000 (chunk 0x01FE0101, 1.85 MB), Radioback 0x2B0000, defaultdb 0x2C0000, userdb 0x2DFF80
* **Source:** [github.com/openshwprojects/FlashDumps](https://github.com/openshwprojects/FlashDumps/tree/main/Sat/Opticum%20Blue%20R265%20Lite), openshwprojects. The file name is the SoC's marking; added here on 2026-10-09
* **Simulator:** boots yes, application no, display no, panel ' ON '. The maincode chunk is damaged in the dump: stage 2 of the bootloader computes its CRC, takes its recovery path and halts at 0x81009E08 (run_dump_r265lite_boot.py) -- the box this flash came from halts there too.  The intact images of the same box are the two T2GEN265 update files.

The M3821 family: the bootloader chunk's version string is "M3821b-0.1.0", 2016-07-29; stage 1 writes 0x15503821 to 0xB80010B4.

Unlike the M3801 images the bootloader chunk is built for the chip's boot ROM: a descriptor table at 0x470 (a register script: the clock block 0xB8001000.., the DDR controller 0xB803E02C..), a "HEAD" record at 0x250 (stage 1 at flash 0x800, 0x1DFC bytes; stage 2 at flash 0x3800, 0x24A10 bytes, loaded to 0xA1000000), and stage 1 expects to run from a boot SRAM at 0x9FE00000 (entry 0x9FE00800).  See chips/m3821.py.

In the simulator (2026-10-09): stage 1 prints "NOR1" on the UART (the 16550 at 0xB8018300 as on the M3801), programs the clock tree, trains the DDR controller (0xB803E000..; the simulator answers the training status and pattern words), prints "2", copies stage 2 to RAM, prints "X" and enters it.  Stage 2 prints "\x01", drives the SPI flash controller at 0xB802E098 (the M3329E-style register base the simulator models) and walks the chunk chain.  Its first check is a CRC of every chunk that is not marked "NCRC" (CRC-32/MPEG-2: polynomial 0x04C11DB7 MSB first, init 0xFFFFFFFF, no final xor, over [chunk + 0x10, + length)): for the maincode chunk it computes 0x511F164E but the chunk stores 0xFB1E4E28, so it takes its recovery path (a chunk 0x00FF0000, absent) and halts at 0x81009E08.  The bytes it read are exactly the flash's, the CRC routine is pure software, and the same CRC reproduces the stored words of the Radioback and defaultdb chunks, so the maincode chunk is damaged in the dump and the box this flash came from halts there too.  The maincode is LZMA (props 0x6C, the M3801 images' settings); Python's decoder also fails 0x77000 bytes into the stream, after 1.48 MB of output that starts with a jump to 0x800A1000.  The intact images of the same box are T2GEN265_1.1.5-2022-08-01.abs and T2GEN265_1.2.0-2023-03-17.abs (the official update files): the 1.1.5 image has this dump's bootloader byte for byte and boots into the application.


## `Opticum Blue R265 Lite/T2GEN265_1.1.5-2022-08-01.abs`

* **Box:** Opticum Blue R265 Lite (also sold as Skymaster STB 2GEN, STB M265 and STB N2)
* **Type:** DVB-T2 / HEVC receiver
* **SoC:** ALi M3822P (M3821)
* **Demodulator:** internal (NIM_S3821)
* **Tuner:** MaxLinear MxL608 (reported for this board; the firmware carries MxL608 / R850 / R836 drivers and probes I2C 0x60, 0x7C, 0x3A, 0x1A, 0x1C in turn)
* **Flash:** 4 MB SPI
* **Front panel:** HD2015 (TM1650-compatible; no display soldered, 3 buttons) (SCL 57, SDA 58)
* **IR coding:** nec
* **Image:** update, 1.1.5 (maincode 00000115, 2022-8-1; application Libcore 19.9.d, built 2019-04-23), 2022-08-01, 4194304 bytes, SHA-1 3df227cce48fd502bf5906a6ed0987bfcc0302c0
* **Layout:** a complete 4 MB flash image with the M3822P.bin dump's chunk chain: bootloader 0x000000 (byte-identical to the dump's), HDCPKey 0x05FE00, maincode 0x060000 (intact: CRC-32/MPEG-2 ok; LZMA props 0x6C, 7.24 MB decompressed, loaded by stage 2 at 0x80000200, entry 0x800A1000), Radioback 0x2B0000, defaultdb 0x2C0000, userdb 0x2DFF80
* **Source:** [update.skymaster.de](https://update.skymaster.de/api/downloadfile?file=sw/SW_Opticum_Blue_R265_Lite_1.2.0-2023-03-17.zip), Skymaster (the Polish distributor) (2026-10-09). The official USB update package: the zip holds this image and T2GEN265_1.2.0-2023-03-17.abs; the packages offered there for the Skymaster STB 2GEN, STB M265 and STB N2 are byte-identical (the same M3822P board)
* **Simulator:** boots yes, application yes, display yes, panel ' ON '. Boots into its application (run_dump_r265lite_app_banner.py) and draws its home menu (run_dump_r265lite_capture_screen.py); remote keys reach it (run_dump_r265lite_remote_key.py); the panel chip gets " ON " from the bootloader (run_dump_r265lite_panel_on.py).

In the simulator (2026-10-09, chips/m3821.py): the bootloader prints "NOR1", "2", "X" and "\x01" like the dump, stage 2's chain check passes, it decompresses the application and enters it.  The application (ALi SDK 4.0, "Libcore 19.9.d", built 2019-04-23) wants the chip ID word 0xB8000000 to read 0x38210010 (the M3822P variant; a plain 0x3821 makes it reboot through the watchdog), moves the exception vectors with CP0 EBase, re-trains the DDR controller (the same registers stage 1 uses), reads the flash through the SPI controller's byte-stream mode and DMA engine (the window at 0xB802E0C8 and 0xB802E058..; SF_INS stays in normal read mode) and bit-bangs I2C on GPIO bank 0xB80000D4 (the HD2015 panel on bits 25 / 26, through the direction register: that is its key scan).

Tuner: the application carries three tuner drivers (its strings: MaxLinear MxL608, Rafael R836 and R850; the demodulator is the chip's own, "NIM_S3821_0") and picks one by probing the hardware I2C master at 0xB8018B00 (i2c_scb.py) at start: a one-byte write of 0x00 to the 7-bit addresses 0x60, 0x7C, 0x3A, 0x1A and 0x1C in turn, until one acknowledges.  No model answers, so none does; with sim.i2c_ack_all the first, 0x60, is taken.  Which chip the board really has is not in the image; a web search (2026-10-09) found an elektroda.pl teardown of the R265 Lite listing "M3822P + MXL608", with the same pair reported for the Comsat TE 2050 HD and Edision Picco T265 -- the MxL608 answers at 0x60, the first address.

It prints on the UART: MC: APP  init ok / << SDK4.0ba.4.0_20101217 >> / Libcore version 19.9.d@SDK4.0gc.19.9d_20190423(gcc version 3.4.4 mipssde-6.06.01-20070420)(...) / Application version 1.0.0@SDK4.0gc.19.9d_20190423by -- and then runs its tasks (six, a 1 ms CP0 timer tick that the simulator's 100 MHz Count stretches to 3 ms, bit-banged I2C transactions, flash reads of the databases) until the main task waits in its 12-second message loop and the idle task runs; every ~40 s it polls the panel over the bit-banged I2C and reprograms its display engine (0xB8034000..).  The production build prints nothing beyond the banner.

Input works: the IR receiver is the M3801's M6303 controller at 0xB8018100 (press_key() finds the application's key table in RAM; regression run_dump_r265lite_remote_key.py), and the HD2015 front-panel chip (TM1650-compatible, SCL = GPIO 57, SDA = GPIO 58, front_panel.py) gets " ON " from stage 2 of the bootloader (run_dump_r265lite_panel_on.py) -- the box has no display soldered, the chip only scans its three buttons, which the application was not seen polling.

Display: the application draws through the same graphics engine (0xB800A000, ge_m36f.py) and display layer (0xB8006300, gma_capture.py) as the M3801 boxes -- nothing of the display is this generation's own.  What kept it from drawing were two things its start-up waits on: the 8-channel descriptor-ring DMA engine at 0xB800F000 (its large copies; the index it reads back at +0x30 + channel must reach the one it submits at +0x28 + channel) and the sound engine at 0xB8002000 (it fills a PCM ring with silence and waits until the read index at +0x3A catches up with the write index at +0x38); both are in chips/m3821.py.  With them the home menu is complete at 364 GE commands, about 2.5 minutes into a run: six tiles in Polish ("Edycja kanałów" highlighted, "Skan kanałów", "Media player", "Ustawienia systemu", "Dysk USB" with "Zainstaluj szybki dysk USB.") over an INFO hint bar, 99 colours at the OSD's 1280x720 (tests/expected/r265lite_screen.png, regression run_dump_r265lite_capture_screen.py, which then moves the highlight down with DOWN and opens the tile's description with INFO; the menu ignores a move onto a greyed-out tile such as "Dysk USB").


## `Opticum Blue R265 Lite/T2GEN265_1.2.0-2023-03-17.abs`

* **Box:** Opticum Blue R265 Lite (also sold as Skymaster STB 2GEN, STB M265 and STB N2)
* **Type:** DVB-T2 / HEVC receiver
* **SoC:** ALi M3822P (M3821)
* **Demodulator:** internal (NIM_S3821)
* **Tuner:** MaxLinear MxL608 (reported for this board; the firmware probes the same five I2C addresses as 1.1.5)
* **Flash:** 4 MB SPI
* **Front panel:** HD2015 (TM1650-compatible; no display soldered, 3 buttons) (SCL 57, SDA 58)
* **IR coding:** nec
* **Image:** update, 1.2.0 (maincode 00000121, 2023-3-17; application Libcore 19.17.0, built 2021-07-28), 2023-03-17, 4194304 bytes, SHA-1 fa1ebef2b65dd95dbdc44f7aa639fb29ad5023d1
* **Layout:** the same chunk chain as T2GEN265_1.1.5-2022-08-01.abs; the maincode chunk is intact (CRC ok, 6.29 MB decompressed); the bootloader chunk still says "M3821b-0.1.0 2016-07-29" but is a different build (stage 1 0x19A0 bytes, stage 2 0xD620 bytes at flash 0x3800; the differences start at 0x260)
* **Source:** [update.skymaster.de](https://update.skymaster.de/api/downloadfile?file=sw/SW_Opticum_Blue_R265_Lite_1.2.0-2023-03-17.zip), Skymaster (the Polish distributor) (2026-10-09). The newer image of the same official update package as T2GEN265_1.1.5-2022-08-01.abs
* **Simulator:** boots yes, application yes, display yes, panel ' ON '. Boots through its 2023 bootloader into its application (run_dump_r265lite_120_app_banner.py, ~35 s: stage 2 copies the maincode through the flash window word by word) and draws the same home menu as 1.1.5 (run_dump_r265lite_120_capture_screen.py).

In the simulator (2026-10-09): stage 1 enters at 0x9FE00800 like the old one but prints nothing.  Stage 2 (MIPS16 code with a page allocator) reads the flash like the application does, through the SPI controller's byte-stream mode (chips/m3821.py SpiStream) -- but it keeps bit 24 of the mode register 0xB802E0C8 set between transactions and holds the chip select with bits 26..25 only, and it copies the whole 1.7 MB maincode chunk word by word through the flash window (no DMA), which the simulator's per-access hook makes the slow part of the boot (about 30 s).  Before the model knew that, every window read returned the flash's first bytes, a chunk length came out negative and the allocator wrote through the stage 2 code until it jumped to 0 and the exception handler (0x810011CC: fp = 0xDEADBEAD) rebooted through the watchdog (0xB8018500 / 0xB8018504).

Now the application starts and prints "MC: APP  init ok", "Libcore version 19.17.0@SDK4.0gc.19.17..." and "Application version 1.0.0@SDK4.0gc.19.17..." (regression run_dump_r265lite_120_app_banner.py); it then behaves like firmware 1.1.5's application (see that image), with two differences: it probes the same five tuner addresses on the I2C master at 0xB8018B00, but about 6 M instructions apart (a retry loop per address) instead of back to back; and before drawing it runs a sequence on the block at 0xB802A000 that 1.1.5 only sets up -- a 7-byte table written five times to +0x62, 6 bytes at +0x90.., "TSM5" at +0x27.., then it sets bit 4 of +0x6F and waits for the hardware to clear it, forever in RAM (16.9 M reads of +0x6F in 200 M instructions, no GE command in 900 s).  chips/m3821.py clears that bit on the next read (the simulator's _SELF_COMPLETING mechanism), after which the block sees 288 more operations (+0x70 / +0x72) and the application draws the same home menu as 1.1.5 (363 GE commands) about 4 minutes in; regression run_dump_r265lite_120_capture_screen.py (expected/r265lite_120_screen.png and _nav.png, byte-identical to firmware 1.1.5's expected screens).

Its stage 2 trips the simulator's sporadic fast-mode slice race more often than other images (an unmapped read at PC 0 about one observer run in three); a rerun is the practical answer.


## `other/Echosonic_Mini_ESR-250__GD25Q32B--DVBS2-M3510A-A3__OK--OK.BIN`

* **Box:** Echosonic Mini ESR-250
* **Type:** DVB-S2 satellite receiver
* **Board:** revision A3
* **SoC:** ALi M3510A (other)
* **Demodulator:** internal (the firmware's NIM_S3501 driver)
* **Flash:** GigaDevice GD25Q32B (4 MB SPI)
* **IR coding:** nec
* **Image:** dump, bootloader "3510-r1362", 2015-02-02, 2015-02-02, 4194304 bytes, SHA-1 33ce167f0070858b346e02089b7189c988e321bf
* **Layout:** the ALi NCRC chunk chain, bootloader chunk at 0 (next chunk at 0x06EE00)
* **Source:** not recorded (2026-01-20). Not recorded: added to this repository on 2026-01-20 under dumps/other with the file name it came with, which says what it is (read from a working unit, "OK")
* **Simulator:** boots no, application no, display no. Another chip than the M3801 / M3821 families the simulator models; no test runs it.

Its application names a satellite front end (NIM_S3501 / S3503 tuner-demodulator drivers, "Tuner 1 has no satellite select!").


## `other/sat_main_ali3329-s15125_dump_eeprom_by_h2h_ok.bin`

* **Box:** satellite receiver main board "s15125"
* **Type:** satellite receiver
* **Board:** s15125
* **SoC:** ALi M3329 (other)
* **Demodulator:** the firmware's NIM_M3327 driver
* **Flash:** 512 KB (a 4 Mbit part)
* **IR coding:** nec
* **Image:** dump, bootloader 1.1.0, 2005-2-25, 2005-02-25, 524288 bytes, SHA-1 bcd6bb7a5d3c25935b331894f60eef873b71c890
* **Layout:** the ALi chunk chain with a bootloader chunk at 0 (id 0xE3000010, next chunk at 0x4000)
* **Source:** not recorded (2026-02-19). Not recorded: added to this repository on 2026-02-19 under dumps/other with the file name it came with (read from a working unit, "ok")
* **Simulator:** boots no, application no, display no. An older chip than the families the simulator models; no test runs it.

Its application names a "Djtuner driver" and the NIM_M3327 front end.


## `srt8115.BIN`

* **Box:** Strong SRT 8115
* **Type:** DVB-T receiver
* **Board:** MC6422-M3801
* **SoC:** ALi M3801 (M3801)
* **Demodulator:** internal (NIM_S3811)
* **Tuner:** MaxLinear MxL603 family (MxL603 / pin-compatible MxL608) at I2C 0x60 on the first hardware I2C master: woken at start (registers 0x0B and 0x12 set to 1), and at the first tune (288 M instructions in) the application writes the MxL603 register table -- 0xFF=0 (soft reset), 0x14=0x13, 0x6D=0x8A then 0x0A, 0xDF=0x19, 0x45=0x1B, 0xA9=0x59, 0xAA=0x6A, 0xBE=0x4C, 0xCF=0x25, 0xD0=0x34, 0x77=0xE7, 0x78=0xE3, 0x6F=0x51, 0x7B=0x84, 0x7C=0x9F, 0x56=0x41, 0xCD=0x64, 0xC3=0x2C, 0x9D=0x61, 0xF7=0x52, 0x58=0x81 ... -- reads registers through the 0xFB prefix and then polls the lock status (register 0x2B) and the signal level (0x5F, 0x60, 0x96, 0xB6)
* **Flash:** 25Q32BSIG (4 MB SPI)
* **Front panel:** TM1628-class 3-wire (CLK 31, DIO 9, STB 11)
* **IR coding:** ext00
* **Image:** dump, maincode "SRT8115" 2013-10-10, 2013-10-10, 4194304 bytes, SHA-1 38d1722933cc41714343690277f2a8c499be353c
* **Layout:** bootloader 0x000000 (Libcore 1.1.6, vic.wang, Mon Nov 26 2012 -- the same bootloader build as dump.bin's), HDCPKey 0x01FE00 ("Demo M3801"), maincode 0x020000, Radioback 0x350000, defaultdb 0x360000, userdb 0x37FF80 -- the dump.bin / SRT Prima layout
* **Source:** [elektroda.pl](https://www.elektroda.pl/rtvforum/topic3123357.html#15195863) (2015-11-29) -- login needed. Thread "Strong srt8115 wsad do układu 25Q32BSIG", post #1 ("bin skopiowany z działającego tunera dvbt" = copied from a working DVB-T tuner): attachment "srt8115.BIN"
* **Simulator:** boots yes, application yes, display yes, panel ' ON '. Boots into its application and draws (run_dump_srt8115_capture_screen.py); its panel speaks the Cabletech URZ0195's protocol on the URZ0083Q's pins.

The attachment "Strong srt8115 MC6422-M3801.BIN" of the elektroda thread "Aktualizacja BIOS w telewizorze Strong SRT8115 MC6422-M3801" (topic3612217, 5 September 2019) is byte-identical to this file (same SHA-1), so it is not kept separately.


## `SRT_Prima_VIII_V1.0.6_20160114.abs`

* **Box:** Strong Prima VIII
* **Type:** DVB-T HD receiver
* **Board:** MC6501-M3801 VER1.0
* **SoC:** ALi M3801 (M3801)
* **Demodulator:** internal (NIM_S3811)
* **Tuner:** probably a Silicon Labs Si2144 option: the image's only tuner-name string is "Si2144", and at start (4 M instructions in) the application reads a single status byte at I2C 0x60 over and over (447 reads in 300 M instructions, no write) -- a Silicon Labs tuner's clear-to-send poll, which a chip answering zeros never satisfies; the box's own 2015 firmware (dumps/STRONG PRIMA VIII/) drives an MxL603 family chip at the same address
* **Flash:** 4 MB SPI (the box of dumps/STRONG PRIMA VIII/)
* **IR coding:** nec
* **Image:** update, 1.0.6, 2016-01-14, 4194304 bytes, SHA-1 63861e2ebc24bc2e99df66c9511dc4d9eb6223fd
* **Layout:** a complete 4 MB flash image with the M3801 chunk chain: the bootloader chunk at 0 (1.0.0, 2009-06-18, next chunk at 0x01FE00) like the box's flash dump, newer main code, no user database
* **Source:** not recorded. Not recorded: Strong's firmware update for the Prima VIII, the "update v1.0.6" the owner of dumps/STRONG PRIMA VIII/ says he downloaded (see that dump).  Added to this repository on 2026-01-20 ("Create SRT_Prima_VIII_V1.0.6_20160114.abs") without a note of where it was downloaded from.
* **Simulator:** boots yes, application yes, display -. run_dump_Prima_to_check_program.py, run_dump_Prima_to_print_success.py and run_dump_Prima_to_main_app.py boot it through the bootloader ("bl_flash_init!", "bl_verify_sw", "check_program!", "success!") into the main application; no screen regression yet.

Despite the .abs name it is a complete 4 MB flash image.


## `STRONG PRIMA VIII/GD25Q32B_20190128_141501.BIN`

* **Box:** Strong Prima VIII
* **Type:** DVB-T HD receiver (sold in Bulgaria: Bulgarian UI)
* **Board:** MC6501-M3801 VER1.0
* **SoC:** ALi M3801 (M3801)
* **Demodulator:** internal (NIM_S3811)
* **Tuner:** MaxLinear MxL603 family at I2C 0x60 on the first hardware I2C master: woken at start (0x0B and 0x12 set to 1), the MxL603 register table at the first tune (169 M instructions in, the owner's channel list)
* **Flash:** GigaDevice GD25Q32B (4 MB SPI)
* **IR coding:** ext00
* **Image:** dump, maincode "Prima_viii" 2015-4-21 (0x285F8C bytes, not LZMA-alone); defaultdb 1.1.0 2015-4-21, 2019-01-28, 4194304 bytes, SHA-1 46f3d074bf984a00ebb03ee4ea451a2ddc1dd690
* **Layout:** bootloader 0x000000 (1.0.0, 2009-06-18, Libcore 1.1.6@Auto_20100413), HDCPKey 0x01FE00 ("Demo M3801"), maincode 0x020000, Radioback 0x350000 (byte-identical to srt8115.BIN's), defaultdb 0x360000, userdb 0x37FF80 -- the dump.bin / srt8115.BIN layout
* **Source:** [elektroda.pl](https://www.elektroda.pl/rtvforum/topic3549956.html#17756835), bakardjiev (2019-02-05) -- login needed. Thread "[Rozwiązano] Szukam pełnego firmware do DVB-T HD STRONG PRIMA VIII MC6501-M3801 VER1.0", post #1: attachment GD25Q32B_20190128_141501.rar (2.32 MB, the 4 MB flash read of 28 January 2019).  Post #2 points to a working Prima VIII dump on remont-aud.net (registration needed) instead.
* **Simulator:** boots yes, application yes, display yes. Boots and draws (run_dump_prima8_capture_screen.py): the channel banner of the owner's channel list, re-tuned every minute or two with no signal.  No GPIO front-panel traffic in the first 90 s, so no panel decoder applies.

The owner wrote: "I have a DVB-T HD STRONG PRIMA VIII, Motherboard MC6501-M3801 VER1.0 ... i download update v1.0.6 but just update - no full flash. With my dump i have a black screen (GD25Q32B)".  In the simulator it boots and draws, so the box's problem was probably elsewhere.  SRT_Prima_VIII_V1.0.6_20160114.abs in this repository is the manufacturer's update for the same box (newer firmware, no user database).

Application banner: Libcore version 8.32.0@SDK4.0bd.8.32_20141126, Application version 1.0.0@SDK4.0bd.8.32_20141126.

In the simulator (2026-10-07): bootloader "success!" at 7 s, application banner right after, first GE commands at ~2 min, the channel banner "NOVA TV / няма информация / 0002" (the owner's channel list: BNT1, BNT2, BNT HD, BG on AIR, NOVA TV ...) at ~3 min, redrawn continually: with no signal on any channel the firmware steps through its channel list by itself (BTV 0001, NOVA TV 0002, ... BNT HD 0010 after 15 min), a channel every minute or two, and remote keys are acted on only between those re-tunes (none reliably from a fresh boot).

The firmware runs in a PAL SD output mode: its OSD region head is 77..643 x 32..543 of a 720 x 576 frame with a 1008 x 640 bitmap, i.e. the display engine scales the 1280 x 720 OSD layer down (gma_capture.py undoes that since this dump).  IR remote: the extended-NEC coding ("ext00", address bytes 00 00); the key table (40 entries) numbers keys differently from the other firmwares: 42 = EPG (programme grid), 16 = EXIT, 3 = banner off, 37 = EPG info window, 60 / 61 / 67 = "no favourite channel" / "USB removed" / "no such channel" popups, 15 (MENU elsewhere) = nothing.


## `urz0195_full_dump(ESMTF25L3204).bin`

* **Box:** Cabletech URZ0195
* **Type:** DVB-T receiver
* **SoC:** ALi M3801 (M3801)
* **Demodulator:** internal (NIM_S3811)
* **Tuner:** MaxLinear MxL5007T (I2C 0x60 on the first hardware I2C master): at start (46 M instructions in) the application resets it (0xFF), writes the MxL5007T driver's register pairs (0x02=0x03, 0x03=0x48, 0x05=0x04, 0x06=0x11, 0x2E=0x15, 0x30=0x10, 0x45=0x58, 0x48=0x19, 0x52=0x03, 0x53=0x44, 0x6A=0x4B, 0x76=0x00, 0x78=0x18, 0x7A=0x17, 0x85=0x06), then its tune sequence (0x0F=0, the frequency in 0x0C..0x0E, 0x1F..0x22, 0x80, 0x0F=1) and polls the lock status in register 0xD8 through the 0xFB prefix -- the Linux mxl5007t driver's tables and steps
* **Flash:** ESMT F25L32 (4 MB SPI)
* **Front panel:** uPD16312-class 3-wire (CLK 31, DIO 9, STB 14)
* **IR coding:** ext00
* **Image:** dump, maincode "M3801 DVBT" 2012-08-02, 2012-08-02, 4194304 bytes, SHA-1 43999953261d1753681986872811c9f0c20bec26
* **Layout:** bootloader 0x000000 (Libcore 1.1.6, just.li, Fri Jul 13 2012), HDCPKey 0x04FE00 ("Demo M3801"), maincode 0x050000 (LZMA), Radioback 0x290000, defaultdb 0x2A0000, userdb 0x2BFF80 (2012-9-17) -- the dump_maciej.bin layout
* **Source:** [elektroda.pl](https://www.elektroda.pl/rtvforum/topic3573829.html#17909725) (2019-04-16) -- login needed. Thread "Szukam wsadu do dekodera Cabletech URZ0195, pamięć ESMT F25L32", post #1 ("dekoder sprawny" = the decoder works): attachment "urz0195_full_dump(ESMTF25L3204).bin"
* **Simulator:** boots yes, application yes, display yes, panel ' ON ' -> '----' -> '0004'. Boots into its application and draws (run_dump_urz0195_capture_screen.py, expected urz0195_2012_screen.png); its uPD16312-class panel shows " ON ", "----", then the channel number "0004".

The older of the two URZ0195 dumps in this repository: a different bootloader build than cableteh_urz0195__w25q32bv.BIN's (Libcore 1.1.6, just.li, Fri Jul 13 2012, vs vic.wang Nov 26 2012) and maincode of 2012-08-02 (vs 2013-10-23); the same remote (standby wake code 807F00FF) and the same uPD16312-class front panel driver.
