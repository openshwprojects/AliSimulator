# The firmware images

Rendered by `tools/dump_table.py` from the `<image>.json` sidecar next to each image (`src/dump_catalog.py`; `tests/test_dump_catalog.py` checks them).  Edit the sidecars, not this file.

| Image | Box | SoC | Tuner | Front panel | Boots / app / display | Source |
|---|---|---|---|---|---|---|
| `Ali_3801_Globo_DVBT_dump SPI 4mb.bin` | Globo STB HD N3 | ALi M3801 | Rafael Micro R820T (7-bit I2C address 0x1A, 0x34 as the w... | TM1650 (SCL 31, SDA 9) | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic4156384-30.html#21933067), JacekTorun |
| `ali_sdk.bin` | test program (not a flash dump) | ALi M3801 (it reads the chip id, "chip id raw: 3811") | - | - | yes / - / - | not recorded |
| `CABLETECH URZ0083/J1100056_URZ0083_V1.0.12_20110228.abs` | Cabletech URZ0083 | ALi M3601E | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v1012.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH URZ0083/J1100223_URZ0083_v1.0.16.abs` | Cabletech URZ0083 | ALi M3601E | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v1016.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH URZ0083/J1100223_URZ0083_v1.0.18.abs` | Cabletech URZ0083 | ALi M3601E | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v1018.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH URZ0083/URZ0083_v1.1.1.abs` | Cabletech URZ0083 | ALi M3601E | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v111.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH URZ0083/URZ0083_v1.1.2.abs` | Cabletech URZ0083 | ALi M3601E | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v112.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH URZ0083/URZ0083_V1.2.2.abs` | Cabletech URZ0083 | ALi M3601E | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v122.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH URZ0083/URZ0083_V1.2.3.abs` | Cabletech URZ0083 | ALi M3601E | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v123.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH URZ0083/URZ0083_V1.2.5.abs` | Cabletech URZ0083 | ALi M3601E | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v125.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH URZ0083Q/Cabletech URZ0083Q/EN25Q32B.bin` | Cabletech URZ0083Q | ALi M3801 | MaxLinear MxL603 family at I2C 0x60 on the first hardware... | TM1628-class 3-wire (CLK 31, DIO 9, STB 11) | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic2842886.html#13677891), Fairgrounds |
| `CABLETECH URZ0086/URZ0086_V1.0.7.abs` | Cabletech URZ0086 | ALi M3606 | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/urz0086_v107.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH URZ0086/URZ0086_v1.1.0.abs` | Cabletech URZ0086 | ALi M3606 | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/urz0086_v110.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH URZ0086/URZ0086_v1.1.1.abs` | Cabletech URZ0086 | ALi M3606 | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/urz0086_v111.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH URZ0086/URZ0086_V1.1.9.abs` | Cabletech URZ0086 | ALi M3606 | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/urz0086_v119.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH URZ0086/URZ0086_V1.2.1.abs` | Cabletech URZ0086 | ALi M3606 | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/urz0086_v121.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `CABLETECH_urz0194s_v1_0_8.bin` | Cabletech URZ0194S | ALi M3801 | MaxLinear MxL603 family at I2C 0x60 on the first hardware... | TM1628-class 3-wire (CLK 31, DIO 9, STB 11) | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic2981605.html#14403424), Krzyś122333 |
| `cableteh_urz0195__w25q32bv.BIN` | Cabletech URZ0195 | ALi M3801 | MaxLinear MxL603 family at I2C 0x60 on the first hardware... | uPD16312-class 3-wire (CLK 31, DIO 9, STB 14) | yes / yes / no | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic2973485.html#14357941), Bell72 |
| `dump.bin` | Comsat TE 1050 HD | ALi M3801 | MaxLinear MxL603 family, by its wake-up: at start the app... | - | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic4155976.html), p.kaczmarek2 |
| `dump_maciej.bin` | Opticum STB HD N2 | ALi M3801 | unknown: the application touches no hardware I2C master i... | TM1650 (SCL 31, SDA 9) | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic4156384.html#21794256), maciej_333 |
| `FERGUSON ARIVA T50/ArivaT50_20111118_V102B214.abs` | Ferguson Ariva T50 | ALi M3602 (the maincode chunk's version reads "Demo M3602": ALi's SDK project) | - | - | - / - / - | [ferguson-digital.eu](https://ferguson-digital.eu/download/dvb-t/series_Ariva/Ariva_T50/firmware/ArivaT50_20111118_V102B214.zip), Ferguson |
| `FERGUSON ARIVA T650i/T650i_V1.13B4_20160721.abs` | Ferguson Ariva T650i | ALi M3801 | MaxLinear MxL603 family at I2C 0x63 (an address strap opt... | FD650K (TM1650-compatible) (SCL 31, SDA 9) | yes / yes / yes | [ferguson-digital.eu](https://ferguson-digital.eu/download/?dir=dvb-t%2Fseries_Ariva%2FAriva_T650i%2Ffirmware), Ferguson |
| `FERGUSON ARIVA T750i/Ferguson_T750i_V1.20B2_18092019.abs` | Ferguson Ariva T750i | ALi M3821 family (the maincode's demodulator drivers are NIM_S3821_0 / NIM_S3821_T2_*: the M3821's own DVB-T2 COFDM) | MaxLinear MxL603 (the maincode's tuner driver names it) | FD650K (TM1650-compatible) | no / no / no | [ferguson-digital.eu](https://ferguson-digital.eu/download/dvb-t/series_Ariva/Ariva_T750i/firmware/T750i_20190918_V1.20B2.zip), Ferguson |
| `FERGUSON ARIVA T760i/Ferguson_T760i_V1.4B8_28072020.abs` | Ferguson Ariva T760i | ALi C3505 (the maincode's "ALI_C3505:0x%x" chip-id print, "Ali3505", c3505_phy_set) | - | FD650K (TM1650-compatible) | - / - / - | [ferguson-digital.eu](https://ferguson-digital.eu/download/dvb-t/series_Ariva/Ariva_T760i/firmware/Ferguson_T760i_V1.4B8_28072020.zip), Ferguson |
| `FERGUSON ARIVA T760i/Ferguson_T760i_V1.5B0-22122020.abs` | Ferguson Ariva T760i | ALi C3505 (the maincode's "ALI_C3505:0x%x" chip-id print, "Ali3505", c3505_phy_set) | - | FD650K (TM1650-compatible) | - / - / - | [ferguson-digital.eu](https://ferguson-digital.eu/download/dvb-t/series_Ariva/Ariva_T760i/firmware/Ferguson_T760i_V1.5B0-22122020.zip), Ferguson |
| `FERGUSON ARIVA T760i/Ferguson_T760i_V1.5B0-28012021.abs` | Ferguson Ariva T760i | ALi C3505 (the maincode's "ALI_C3505:0x%x" chip-id print, "Ali3505", c3505_phy_set) | - | FD650K (TM1650-compatible) | - / - / - | [ferguson-digital.eu](https://ferguson-digital.eu/download/dvb-t/series_Ariva/Ariva_T760i/firmware/Ferguson_T760i_V1.5B0-28012021.zip), Ferguson |
| `FERGUSON ARIVA T760i/Ferguson_T760i_V1.5B4-14092021.abs` | Ferguson Ariva T760i | ALi C3505 (the maincode's "ALI_C3505:0x%x" chip-id print, "Ali3505", c3505_phy_set) | - | FD650K (TM1650-compatible) | - / - / - | [ferguson-digital.eu](https://ferguson-digital.eu/download/dvb-t/series_Ariva/Ariva_T760i/firmware/Ferguson_T760i_V1.5B4-14092021.zip), Ferguson |
| `KRUGER MATZ KM0183/J1100393-KM00183-MC6258-V1.0.4.abs` | Kruger&Matz KM0183 ("KM00183") | ALi M3601E (the Cabletech URZ0083's twin) | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/km00183_v104.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `KRUGER MATZ KM0183/KM00183_V1.0.6.abs` | Kruger&Matz KM0183 ("KM00183") | ALi M3601E (the Cabletech URZ0083's twin) | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/km00183_v106.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `KRUGER MATZ KM0183/KM00183_V1.0.8.abs` | Kruger&Matz KM0183 ("KM00183") | ALi M3601E (the Cabletech URZ0083's twin) | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/km00183_v108.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `KRUGER MATZ KM0186/KM00186_v1.0.6.abs` | Kruger&Matz KM0186 ("KM00186") | ALi M3606 (the Cabletech URZ0086's twin) | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/km00186_v106.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `KRUGER MATZ KM0186/KM00186_V1.0.9.abs` | Kruger&Matz KM0186 ("KM00186") | ALi M3606 (the Cabletech URZ0086's twin) | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/km00186_v109.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `KRUGER MATZ KM0186/KM00186_V1.1.1.abs` | Kruger&Matz KM0186 ("KM00186") | ALi M3606 (the Cabletech URZ0086's twin) | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/km00186_v111.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek |
| `Opticum Blue R265 Lite/M3822P.bin` | Opticum Blue R265 Lite | ALi M3822P | MaxLinear MxL608 (reported for this board; the firmware p... | HD2015 (TM1650-compatible; no display soldered, 3 buttons) (SCL 57, SDA 58) | yes / no / no | [github.com/openshwprojects/FlashDumps](https://github.com/openshwprojects/FlashDumps/tree/main/Sat/Opticum%20Blue%20R265%20Lite), openshwprojects |
| `Opticum Blue R265 Lite/T2GEN265_1.1.5-2022-08-01.abs` | Opticum Blue R265 Lite (also sold as Skymaster STB 2GEN, STB M265 and STB N2) | ALi M3822P | MaxLinear MxL608 (reported for this board; the firmware c... | HD2015 (TM1650-compatible; no display soldered, 3 buttons) (SCL 57, SDA 58) | yes / yes / yes | [update.skymaster.de](https://update.skymaster.de/api/downloadfile?file=sw/SW_Opticum_Blue_R265_Lite_1.2.0-2023-03-17.zip), Skymaster (the Polish distributor) |
| `Opticum Blue R265 Lite/T2GEN265_1.2.0-2023-03-17.abs` | Opticum Blue R265 Lite (also sold as Skymaster STB 2GEN, STB M265 and STB N2) | ALi M3822P | MaxLinear MxL608 (reported for this board; the firmware p... | HD2015 (TM1650-compatible; no display soldered, 3 buttons) (SCL 57, SDA 58) | yes / yes / yes | [update.skymaster.de](https://update.skymaster.de/api/downloadfile?file=sw/SW_Opticum_Blue_R265_Lite_1.2.0-2023-03-17.zip), Skymaster (the Polish distributor) |
| `other/Echosonic_Mini_ESR-250__GD25Q32B--DVBS2-M3510A-A3__OK--OK.BIN` | Echosonic Mini ESR-250 | ALi M3510A | - | - | no / no / no | not recorded |
| `other/sat_main_ali3329-s15125_dump_eeprom_by_h2h_ok.bin` | satellite receiver main board "s15125" | ALi M3329 | - | - | no / no / no | not recorded |
| `srt8115.BIN` | Strong SRT 8115 | ALi M3801 | MaxLinear MxL603 family (MxL603 / pin-compatible MxL608)... | TM1628-class 3-wire (CLK 31, DIO 9, STB 11) | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic3123357.html#15195863), andrzej 4 |
| `SRT_Prima_VIII_V1.0.6_20160114.abs` | Strong Prima VIII | ALi M3801 | probably a Silicon Labs Si2144 option: the image's only t... | - | yes / yes / - | not recorded |
| `STRONG PRIMA VIII/GD25Q32B_20190128_141501.BIN` | Strong Prima VIII | ALi M3801 | MaxLinear MxL603 family at I2C 0x60 on the first hardware... | - | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic3549956.html#17756835), bakardjiev |
| `THOMSON THT501/THT501-V1.0.9.abs` | Thomson THT501 | ALi M36xx (the Cabletech URZ0083's generation: the same chunk layout, bootloader "DVBT---0.1.0" of 2011-08-03 and HDCPKey "Demo s3602") | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/strong_thomson/thomson_tht501_v109.rar), Thomson (Strong), mirrored by Gutek |
| `THOMSON THT501/THT501-V1.1.1_20120428.abs` | Thomson THT501 | ALi M36xx (the Cabletech URZ0083's generation: the same chunk layout, bootloader "DVBT---0.1.0" of 2011-08-03 and HDCPKey "Demo s3602") | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/strong_thomson/thomson_tht501_v111.rar), Thomson (Strong), mirrored by Gutek |
| `THOMSON THT501/THT501_V1.1.5a_20120925.abs` | Thomson THT501 | ALi M36xx (the Cabletech URZ0083's generation: the same chunk layout, bootloader "DVBT---0.1.0" of 2011-08-03 and HDCPKey "Demo s3602") | - | - | - / - / - | [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/strong_thomson/thomson_tht501_v115a.rar), Thomson (Strong), mirrored by Gutek |
| `urz0195_full_dump(ESMTF25L3204).bin` | Cabletech URZ0195 | ALi M3801 | MaxLinear MxL5007T (I2C 0x60 on the first hardware I2C ma... | uPD16312-class 3-wire (CLK 31, DIO 9, STB 14) | yes / yes / yes | [elektroda.pl](https://www.elektroda.pl/rtvforum/topic3573829.html#17909725), jmalko |

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
* **Simulator:** boots yes, application yes, display yes, panel ' ON '. Keeps its channel list, so the application tunes a channel at start, shows a channel banner that times out and then its no-signal message (run_dump_globo_capture_screen.py).  With sim.set_signal(True) -- the R820T model and the internal demodulator's lock -- the tuner calibrates and locks at the first try and the no-signal box never appears (run_dump_globo_signal.py).

Tuner: a Rafael Micro R820T on the chip's first hardware I2C master (0xB8018200, i2c_scb.py) at 7-bit address 0x1A (0x34 as the write address byte): when the application tunes its first channel (about 93 M instructions in) it writes the R820T initialisation array -- registers 0x05..0x1F = 83 32 75 C0 40 D6 6C F5 53 75 68 6C 83 80 00 0F 00 C0 30 48 CC 60 00 54 A6 4A C0, the public R820T driver's bytes but for two values -- then runs the filter and image calibrations (5- and 2-byte reads: the Rafael read protocol starts at register 0 and sends every byte bit-reversed) and its PLL, whose lock it checks in register 2 with a 3-byte read; on no lock it raises the VCO current (0x12: 0x88 -> 0x68) exactly like the Linux r820t driver.  The demodulator is the chip's own ("NIM_S3811_0").

The driver is Rafael's R828 reference code (its DVB-T 8 MHz standard: IF 4570 kHz, filter calibration at 63 MHz) with a 16 MHz crystal -- the constant of its image-rejection ring loop, (16+n)*8*16000 >= 3100000, at 0x8025E628; the NIM's own tuner configuration holds the generic PLL-tuner defaults (4 MHz, divider 24, step 166 kHz).  With the R820T model the whole sequence decodes: image-rejection calibration at five ring points (LO 528.0, 194.7, 61.4, 394.7 and 794.7 MHz: 3.2 GHz / 6, 16, 48, 8, 4 minus 5.3 MHz) with the antenna input off, the filter calibration at 63 MHz, then the channel "41. WP": LO 203.070 MHz, RF 198.500 MHz -- VHF channel 8 -- about 117 M instructions in.

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


## `CABLETECH URZ0083/J1100056_URZ0083_V1.0.12_20110228.abs`

* **Box:** Cabletech URZ0083
* **Type:** DVB-T HD receiver (2011)
* **Board:** MC6238 (the change list's "J1100223_MC6238_URZ0083_v1.0.18")
* **SoC:** ALi M3601E (M36xx (not modelled))
* **Demodulator:** ALi M3100, external (Gutek's review; the firmware's NIM_COFDM driver tables name the M3101)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.0.12 (maincode "Demo M3606" 2011-2-28), 2011-02-28, 2097152 bytes, SHA-1 627a408898a69a9966ebaab9b0e0b7a60611c4df
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2010-06-01), HDCPKey 0x00FE00 (Demo s3602, 2009-11-10), maincode 0x010000 (Demo M3606, 2011-2-28), Radioback 0x160000 (1.0.0, 2009-05-08), countryband 0x170000 (1.0.0, 2010-4-1), userdb 0x18FF80 (1.0.0, 2011-2-28)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v1012.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive v1012.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0083 firmware V1.0.12, the manufacturer's USB update image as Gutek's site mirrors it (v1012.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2010-06-01), HDCPKey 0x00FE00 (Demo s3602, 2009-11-10), maincode 0x010000 (Demo M3606, 2011-2-28), Radioback 0x160000 (1.0.0, 2009-05-08), countryband 0x170000 (1.0.0, 2010-4-1), userdb 0x18FF80 (1.0.0, 2011-2-28); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 3.6.0@SDK4.0ba.3.6_patch8_20101227.

Gutek's list: "Cabletech URZ0083 (UWAGA SOFTY NIE DO URZ0083E)" -- not for the URZ0083E; the later URZ0083Q (dumps/CABLETECH URZ0083Q/) is an ALi M3801 board.

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `CABLETECH URZ0083/J1100223_URZ0083_v1.0.16.abs`

* **Box:** Cabletech URZ0083
* **Type:** DVB-T HD receiver (2011)
* **Board:** MC6238 (the change list's "J1100223_MC6238_URZ0083_v1.0.18")
* **SoC:** ALi M3601E (M36xx (not modelled))
* **Demodulator:** ALi M3100, external (Gutek's review; the firmware's NIM_COFDM driver tables name the M3101)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.0.16 (maincode "Demo M3606" 2011-7-5), 2011-07-05, 2097152 bytes, SHA-1 3503b2f029b4cb6d2b043626a697c71ade4a43bd
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2010-06-01), HDCPKey 0x00FE00 (Demo s3602, 2009-11-10), maincode 0x010000 (Demo M3606, 2011-7-5), Radioback 0x160000 (1.0.0, 2009-05-08), countryband 0x170000 (1.0.0, 2010-4-1), userdb 0x18FF80 (1.0.0, 2011-7-5)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v1016.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive v1016.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0083 firmware V1.0.16, the manufacturer's USB update image as Gutek's site mirrors it (v1016.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2010-06-01), HDCPKey 0x00FE00 (Demo s3602, 2009-11-10), maincode 0x010000 (Demo M3606, 2011-7-5), Radioback 0x160000 (1.0.0, 2009-05-08), countryband 0x170000 (1.0.0, 2010-4-1), userdb 0x18FF80 (1.0.0, 2011-7-5); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 5.0.0@SDK4.0ba.5.0_20110425.

Gutek's list: "Cabletech URZ0083 (UWAGA SOFTY NIE DO URZ0083E)" -- not for the URZ0083E; the later URZ0083Q (dumps/CABLETECH URZ0083Q/) is an ALi M3801 board.

Change list (lista_zmian.txt, Polish): J1100223_URZ0083_v1.0.16 / - Poprawione skalowanie formatu obrazu (16/9,4/3) / - Dekodowanie dźwięku Dolby E-AC3 / - Dodano obsługę polskich napisów przy odtwarzaniu filmów z nośników zewnętrznych.

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `CABLETECH URZ0083/J1100223_URZ0083_v1.0.18.abs`

* **Box:** Cabletech URZ0083
* **Type:** DVB-T HD receiver (2011)
* **Board:** MC6238 (the change list's "J1100223_MC6238_URZ0083_v1.0.18")
* **SoC:** ALi M3601E (M36xx (not modelled))
* **Demodulator:** ALi M3100, external (Gutek's review; the firmware's NIM_COFDM driver tables name the M3101)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.0.18 (maincode "Demo M3606" 2011-9-2), 2011-09-02, 2097152 bytes, SHA-1 09b79c8db6af067e3c6dca76784efda318441751
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2010-06-01), HDCPKey 0x00FE00 (Demo s3602, 2009-11-10), maincode 0x010000 (Demo M3606, 2011-9-2), Radioback 0x160000 (1.0.0, 2009-05-08), countryband 0x170000 (1.0.0, 2010-4-1), userdb 0x18FF80 (1.0.0, 2011-9-2)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v1018.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive v1018.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0083 firmware V1.0.18, the manufacturer's USB update image as Gutek's site mirrors it (v1018.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2010-06-01), HDCPKey 0x00FE00 (Demo s3602, 2009-11-10), maincode 0x010000 (Demo M3606, 2011-9-2), Radioback 0x160000 (1.0.0, 2009-05-08), countryband 0x170000 (1.0.0, 2010-4-1), userdb 0x18FF80 (1.0.0, 2011-9-2); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 5.0.0@SDK4.0ba.5.0_20110425.

Gutek's list: "Cabletech URZ0083 (UWAGA SOFTY NIE DO URZ0083E)" -- not for the URZ0083E; the later URZ0083Q (dumps/CABLETECH URZ0083Q/) is an ALi M3801 board.

Change list (lista_zmian.txt, Polish): J1100223_MC6238_URZ0083_v1.0.18 / - wydłużony czas projekcji informacji o czasie nagrywania / J1100223_URZ0083_v1.0.16 / - Poprawione skalowanie formatu obrazu (16/9,4/3) / - Dekodowanie dźwięku Dolby E-AC3 / - Dodano obsługę polskich napisów przy odtwarzaniu filmów z nośników zewnętrznych.

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `CABLETECH URZ0083/URZ0083_v1.1.1.abs`

* **Box:** Cabletech URZ0083
* **Type:** DVB-T HD receiver (2011)
* **Board:** MC6238 (the change list's "J1100223_MC6238_URZ0083_v1.0.18")
* **SoC:** ALi M3601E (M36xx (not modelled))
* **Demodulator:** ALi M3100, external (Gutek's review; the firmware's NIM_COFDM driver tables name the M3101)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.1.1 (maincode "Demo M3606" 2011-9-21), 2011-09-21, 2097152 bytes, SHA-1 cdc26fb31366ed8278261437f58e9126a3f8f81e
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2010-06-01), HDCPKey 0x00FE00 (Demo s3602, 2009-11-10), maincode 0x010000 (Demo M3606, 2011-9-21), Radioback 0x160000 (1.0.0, 2009-05-08), countryband 0x170000 (1.0.0, 2010-4-1), userdb 0x18FF80 (1.0.0, 2011-9-21)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v111.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive v111.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0083 firmware V1.1.1, the manufacturer's USB update image as Gutek's site mirrors it (v111.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2010-06-01), HDCPKey 0x00FE00 (Demo s3602, 2009-11-10), maincode 0x010000 (Demo M3606, 2011-9-21), Radioback 0x160000 (1.0.0, 2009-05-08), countryband 0x170000 (1.0.0, 2010-4-1), userdb 0x18FF80 (1.0.0, 2011-9-21); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 5.0.0@SDK4.0ba.5.0_20110425.

Gutek's list: "Cabletech URZ0083 (UWAGA SOFTY NIE DO URZ0083E)" -- not for the URZ0083E; the later URZ0083Q (dumps/CABLETECH URZ0083Q/) is an ALi M3801 board.

Change list (lista_zmian.txt, Polish): URZ0083_v1.1.1.abs / - Poprawiono skalowanie obrazu przy odtwarzaniu materiałów z nośników zewnętrznych / - Zwiększono zakres wyboru rozdzielczości / J1100223_MC6238_URZ0083_v1.0.18 / - wydłużony czas projekcji informacji o czasie nagrywania / J1100223_URZ0083_v1.0.16 / - Poprawione skalowanie formatu obrazu (16/9,4/3) / - Dekodowanie dźwięku Dolby E-AC3 / - Dodano obsługę polskich napisów przy odtwarzaniu filmów z nośników zewnętrznych.

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `CABLETECH URZ0083/URZ0083_v1.1.2.abs`

* **Box:** Cabletech URZ0083
* **Type:** DVB-T HD receiver (2011)
* **Board:** MC6238 (the change list's "J1100223_MC6238_URZ0083_v1.0.18")
* **SoC:** ALi M3601E (M36xx (not modelled))
* **Demodulator:** ALi M3100, external (Gutek's review; the firmware's NIM_COFDM driver tables name the M3101)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.1.2 (maincode "Demo M3606" 2011-10-12), 2011-10-12, 2097152 bytes, SHA-1 d709969c2df20a0a8d1e802fb7af000379c02fcb
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2010-06-01), HDCPKey 0x00FE00 (Demo s3602, 2009-11-10), maincode 0x010000 (Demo M3606, 2011-10-12), Radioback 0x160000 (1.0.0, 2009-05-08), countryband 0x170000 (1.0.0, 2010-4-1), userdb 0x18FF80 (1.0.0, 2011-10-12)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v112.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive v112.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0083 firmware V1.1.2, the manufacturer's USB update image as Gutek's site mirrors it (v112.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2010-06-01), HDCPKey 0x00FE00 (Demo s3602, 2009-11-10), maincode 0x010000 (Demo M3606, 2011-10-12), Radioback 0x160000 (1.0.0, 2009-05-08), countryband 0x170000 (1.0.0, 2010-4-1), userdb 0x18FF80 (1.0.0, 2011-10-12); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 5.0.0@SDK4.0ba.5.0_20110425.

Gutek's list: "Cabletech URZ0083 (UWAGA SOFTY NIE DO URZ0083E)" -- not for the URZ0083E; the later URZ0083Q (dumps/CABLETECH URZ0083Q/) is an ALi M3801 board.

Change list (lista_zmian.txt, Polish): URZ0083_v1.1.2.abs / - Zwiększono czcionkę przy wyświetlaniu napisów z zewnętrznych nośników / URZ0083_v1.1.1.abs / - Poprawiono skalowanie obrazu przy odtwarzaniu materiałów z nośników zewnętrznych / - Zwiększono zakres wyboru rozdzielczości / J1100223_MC6238_URZ0083_v1.0.18 / - wydłużony czas projekcji informacji o czasie nagrywania / J1100223_URZ0083_v1.0.16 / - Poprawione skalowanie formatu obrazu (16/9,4/3) / - Dekodowanie dźwięku Dolby E-AC3 / - Dodano obsługę polskich napisów przy odtwarzaniu filmów z nośników zewnętrznych.

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `CABLETECH URZ0083/URZ0083_V1.2.2.abs`

* **Box:** Cabletech URZ0083
* **Type:** DVB-T HD receiver (2011)
* **Board:** MC6238 (the change list's "J1100223_MC6238_URZ0083_v1.0.18")
* **SoC:** ALi M3601E (M36xx (not modelled))
* **Demodulator:** ALi M3100, external (Gutek's review; the firmware's NIM_COFDM driver tables name the M3101)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.2.2 (maincode "Demo M3606" 2012-1-10), 2012-01-10, 2097152 bytes, SHA-1 b72cafe791f98cd54af69bbfd4d463b85fa0b870
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (Demo M3606, 2012-1-10), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-1-10)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v122.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive v122.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0083 firmware V1.2.2, the manufacturer's USB update image as Gutek's site mirrors it (v122.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (Demo M3606, 2012-1-10), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-1-10); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 6.4.0@SDK4.0ba.6.4_20111019; SDK6.4-Mico-v0.1.6+lechpol-v1.2.2.

Gutek's list: "Cabletech URZ0083 (UWAGA SOFTY NIE DO URZ0083E)" -- not for the URZ0083E; the later URZ0083Q (dumps/CABLETECH URZ0083Q/) is an ALi M3801 board.

Change list (lista_zmian.txt, Polish): URZ0083_v1.2.2.abs / -poprawiono polskie tłumaczenie w menu / -poprawiono kolor i tło czcionki w EPG / -usunięto wskaźnik poziomu sygnału w OSD przy zmianie kanałów / -opcja nagrywanie jako pierwsza przy programowaniu zdarzeń czasowych / -usunięto błąd rezerwacji miejsca na nośniku przy wyłączonej funkcji timeshift / -zmiana sposobu załączenia dekodera po braku zasilania (dekoder załącza się do stand-by) / -inne drobne błędy / URZ0083_v1.1.2.abs / - Zwiększono czcionkę przy wyświetlaniu napisów z zewnętrznych nośników / URZ0083_v1.1.1.abs / - Poprawiono skalowanie obrazu przy odtwarzaniu materiałów z nośników zewnętrznych / - Zwiększono zakres wyboru rozdzielczości / J1100223_MC6238_URZ0083_v1.0.18 / - wydłużony czas projekcji informacji o czasie nagrywania / J1100223_URZ0083_v1.0.16 / - Poprawione skalowanie formatu obrazu (16/9,4/3) / - Dekodowanie dźwięku Dolby E-AC3 / - Dodano obsługę polskich napisów przy odtwarzaniu filmów z nośników zewnętrznych.

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `CABLETECH URZ0083/URZ0083_V1.2.3.abs`

* **Box:** Cabletech URZ0083
* **Type:** DVB-T HD receiver (2011)
* **Board:** MC6238 (the change list's "J1100223_MC6238_URZ0083_v1.0.18")
* **SoC:** ALi M3601E (M36xx (not modelled))
* **Demodulator:** ALi M3100, external (Gutek's review; the firmware's NIM_COFDM driver tables name the M3101)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.2.3 (maincode "Demo M3606" 2012-2-2), 2012-02-02, 2097152 bytes, SHA-1 d0a5e600c8463472f5c90fa0da3a6d8c5b05da5e
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (Demo M3606, 2012-2-2), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-2-2)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v123.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive v123.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0083 firmware V1.2.3, the manufacturer's USB update image as Gutek's site mirrors it (v123.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (Demo M3606, 2012-2-2), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-2-2); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 6.4.0@SDK4.0ba.6.4_20111019; SDK6.4-Mico-v0.1.7+lechpol-v1.2.3.

Gutek's list: "Cabletech URZ0083 (UWAGA SOFTY NIE DO URZ0083E)" -- not for the URZ0083E; the later URZ0083Q (dumps/CABLETECH URZ0083Q/) is an ALi M3801 board.

Change list (lista_zmian.txt, Polish): URZ0083_v1.2.3.abs / przywrócono odtwarzanie plików .flac / wyście z INFO w EPG klawiszem EXIT / inne drobne błędy / URZ0083_v1.2.2.abs / -poprawiono polskie tłumaczenie w menu / -poprawiono kolor i tło czcionki w EPG / -usunięto wskaźnik poziomu sygnału w OSD przy zmianie kanałów / -opcja nagrywanie jako pierwsza przy programowaniu zdarzeń czasowych / -usunięto błąd rezerwacji miejsca na nośniku przy wyłączonej funkcji timeshift / -zmiana sposobu załączenia dekodera po braku zasilania (dekoder załącza się do stand-by) / -inne drobne błędy / URZ0083_v1.1.2.abs / - Zwiększono czcionkę przy wyświetlaniu napisów z zewnętrznych nośników / URZ0083_v1.1.1.abs / - Poprawiono skalowanie obrazu przy odtwarzaniu materiałów z nośników zewnętrznych / - Zwiększono zakres wyboru rozdzielczości / J1100223_MC6238_URZ0083_v1.0.18 / - wydłużony czas projekcji informacji o czasie nagrywania / J1100223_URZ0083_v1.0.16 / - Poprawione skalowanie formatu obrazu (16/9,4/3) / - Dekodowanie dźwięku Dolby E-AC3 / - Dodano obsługę polskich napisów przy odtwarzaniu filmów z nośników zewnętrznych.

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `CABLETECH URZ0083/URZ0083_V1.2.5.abs`

* **Box:** Cabletech URZ0083
* **Type:** DVB-T HD receiver (2011)
* **Board:** MC6238 (the change list's "J1100223_MC6238_URZ0083_v1.0.18")
* **SoC:** ALi M3601E (M36xx (not modelled))
* **Demodulator:** ALi M3100, external (Gutek's review; the firmware's NIM_COFDM driver tables name the M3101)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.2.5 (maincode "Demo M3606" 2012-4-25), 2012-04-25, 2097152 bytes, SHA-1 90a76c50258d661c80dad2c46d150bcb80e75add
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (Demo M3606, 2012-4-25), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-4-25)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/v125.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive v125.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0083 firmware V1.2.5, the manufacturer's USB update image as Gutek's site mirrors it (v125.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (Demo M3606, 2012-4-25), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-4-25); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 6.4.0@SDK4.0ba.6.4_20111019; SDK6.4-Mico-v0.1.9+lechpol-v1.2.5.

Gutek's list: "Cabletech URZ0083 (UWAGA SOFTY NIE DO URZ0083E)" -- not for the URZ0083E; the later URZ0083Q (dumps/CABLETECH URZ0083Q/) is an ALi M3801 board.

Change list (lista_zmian.txt, Polish): URZ0083_v1.2.5.abs / poprawiono wyświetlanie napisów przy odtwarzaniu filmów z nośników zewnętrznych / inne drobne błędy / URZ0083_v1.2.3.abs / przywrócono odtwarzanie plików .flac / wyście z INFO w EPG klawiszem EXIT / inne drobne błędy / URZ0083_v1.2.2.abs / -poprawiono polskie tłumaczenie w menu / -poprawiono kolor i tło czcionki w EPG / -usunięto wskaźnik poziomu sygnału w OSD przy zmianie kanałów / -opcja nagrywanie jako pierwsza przy programowaniu zdarzeń czasowych / -usunięto błąd rezerwacji miejsca na nośniku przy wyłączonej funkcji timeshift / -zmiana sposobu załączenia dekodera po braku zasilania (dekoder załącza się do stand-by) / -inne drobne błędy / URZ0083_v1.1.2.abs / - Zwiększono czcionkę przy wyświetlaniu napisów z zewnętrznych nośników / URZ0083_v1.1.1.abs / - Poprawiono skalowanie obrazu przy odtwarzaniu materiałów z nośników zewnętrznych / - Zwiększono zakres wyboru rozdzielczości / J1100223_MC6238_URZ0083_v1.0.18 / - wydłużony czas projekcji informacji o czasie nagrywania / J1100223_URZ0083_v1.0.16 / - Poprawione skalowanie formatu obrazu (16/9,4/3) / - Dekodowanie dźwięku Dolby E-AC3 / - Dodano obsługę polskich napisów przy odtwarzaniu filmów z nośników zewnętrznych.

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


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


## `CABLETECH URZ0086/URZ0086_V1.0.7.abs`

* **Box:** Cabletech URZ0086
* **Type:** DVB-T HD PVR receiver with two tuners (2011)
* **Board:** MC6245-M3606-VER1.0 (elektroda topic "Cabletech URZ0086. Potrzebny wsad pamięci")
* **SoC:** ALi M3606 (M36xx (not modelled))
* **Demodulator:** unknown (under the tuner's shield, Gutek's review); the firmware has NIM_COFDM_0 / NIM_COFDM_1: two tuners
* **Flash:** 4 MB SPI
* **IR coding:** nec
* **Image:** update, V1.0.7 (maincode "M3606 2Tuner" 2011-7-16), 2011-07-16, 4194304 bytes, SHA-1 e7c05dd5c23a891f0dbd6abdf92547c31157eb06
* **Layout:** bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2011-7-16), seecode 0x140000 (M3606 SEE, 2011-7-16), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2011-7-16)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/urz0086_v107.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive urz0086_v107.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0086 firmware V1.0.7, the manufacturer's USB update image as Gutek's site mirrors it (urz0086_v107.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2011-7-16), seecode 0x140000 (M3606 SEE, 2011-7-16), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2011-7-16); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 5.0.0@SDK4.0ba.5.0_20110425; Libcore version 1.1.5a@SDK_20100524.

The bootloader chunk's version reads "DVBS2---0.1.0" (ALi's project name) although the box is DVB-T; the maincode is "M3606 2Tuner".  Forum users program these .abs files directly into the flash (renamed .bin): they are complete flash images.

Change list (lista_zmian.txt, Polish): URZ0086_V1.0.7.abs / - soft bazowy

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `CABLETECH URZ0086/URZ0086_v1.1.0.abs`

* **Box:** Cabletech URZ0086
* **Type:** DVB-T HD PVR receiver with two tuners (2011)
* **Board:** MC6245-M3606-VER1.0 (elektroda topic "Cabletech URZ0086. Potrzebny wsad pamięci")
* **SoC:** ALi M3606 (M36xx (not modelled))
* **Demodulator:** unknown (under the tuner's shield, Gutek's review); the firmware has NIM_COFDM_0 / NIM_COFDM_1: two tuners
* **Flash:** 4 MB SPI
* **IR coding:** nec
* **Image:** update, V1.1.0 (maincode "M3606 2Tuner" 2011-11-10), 2011-11-10, 4194304 bytes, SHA-1 530a90e26488b004591d0cb24747f8d60de04313
* **Layout:** bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2011-11-10), seecode 0x140000 (M3606 SEE, 2011-11-10), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2011-11-10)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/urz0086_v110.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive urz0086_v110.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0086 firmware V1.1.0, the manufacturer's USB update image as Gutek's site mirrors it (urz0086_v110.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2011-11-10), seecode 0x140000 (M3606 SEE, 2011-11-10), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2011-11-10); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 5.0.0@SDK4.0ba.5.0_20110425; Libcore version 1.1.5a@SDK_20100524.

The bootloader chunk's version reads "DVBS2---0.1.0" (ALi's project name) although the box is DVB-T; the maincode is "M3606 2Tuner".  Forum users program these .abs files directly into the flash (renamed .bin): they are complete flash images.

Change list (lista_zmian.txt, Polish): URZ0086_V1.0.7.abs / - soft bazowy / URZ0086_v1.1.0.abs / - Poprawiono j. polski w menu, / - Dodano znaczniki nagrywania w liście kanałów.

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `CABLETECH URZ0086/URZ0086_v1.1.1.abs`

* **Box:** Cabletech URZ0086
* **Type:** DVB-T HD PVR receiver with two tuners (2011)
* **Board:** MC6245-M3606-VER1.0 (elektroda topic "Cabletech URZ0086. Potrzebny wsad pamięci")
* **SoC:** ALi M3606 (M36xx (not modelled))
* **Demodulator:** unknown (under the tuner's shield, Gutek's review); the firmware has NIM_COFDM_0 / NIM_COFDM_1: two tuners
* **Flash:** 4 MB SPI
* **IR coding:** nec
* **Image:** update, V1.1.1 (maincode "M3606 2Tuner" 2011-11-15), 2011-11-15, 4194304 bytes, SHA-1 ae41cd38d2d1108d85dfc1e52d84c8b7c90c6558
* **Layout:** bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2011-11-15), seecode 0x140000 (M3606 SEE, 2011-11-15), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2011-11-15)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/urz0086_v111.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive urz0086_v111.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0086 firmware V1.1.1, the manufacturer's USB update image as Gutek's site mirrors it (urz0086_v111.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2011-11-15), seecode 0x140000 (M3606 SEE, 2011-11-15), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2011-11-15); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 5.0.0@SDK4.0ba.5.0_20110425; Libcore version 1.1.5a@SDK_20100524.

The bootloader chunk's version reads "DVBS2---0.1.0" (ALi's project name) although the box is DVB-T; the maincode is "M3606 2Tuner".  Forum users program these .abs files directly into the flash (renamed .bin): they are complete flash images.

Change list (lista_zmian.txt, Polish): URZ0086_V1.0.7.abs / - soft bazowy / URZ0086_v1.1.0.abs / - Poprawiono j. polski w menu, / - Dodano znaczniki nagrywania w liście kanałów. / URZ0086_v1.1.1.abs / przywrócono odtwarzanie plików .flac

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `CABLETECH URZ0086/URZ0086_V1.1.9.abs`

* **Box:** Cabletech URZ0086
* **Type:** DVB-T HD PVR receiver with two tuners (2011)
* **Board:** MC6245-M3606-VER1.0 (elektroda topic "Cabletech URZ0086. Potrzebny wsad pamięci")
* **SoC:** ALi M3606 (M36xx (not modelled))
* **Demodulator:** unknown (under the tuner's shield, Gutek's review); the firmware has NIM_COFDM_0 / NIM_COFDM_1: two tuners
* **Flash:** 4 MB SPI
* **IR coding:** nec
* **Image:** update, V1.1.9 (maincode "M3606 2Tuner" 2012-5-23), 2012-05-23, 4194304 bytes, SHA-1 5b9405127cda0c9f06eb912f44d742d8d409ce26
* **Layout:** bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2012-5-23), seecode 0x140000 (M3606 SEE, 2012-5-23), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2012-5-23)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/urz0086_v119.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive urz0086_v119.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0086 firmware V1.1.9, the manufacturer's USB update image as Gutek's site mirrors it (urz0086_v119.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2012-5-23), seecode 0x140000 (M3606 SEE, 2012-5-23), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2012-5-23); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 7.2.0@SDK4.0ba.7.2_20120115; SDK7.2-Mico1.6-LECHPOL1.1.9; Libcore version 1.1.5a@SDK_20111126.

The bootloader chunk's version reads "DVBS2---0.1.0" (ALi's project name) although the box is DVB-T; the maincode is "M3606 2Tuner".  Forum users program these .abs files directly into the flash (renamed .bin): they are complete flash images.

Change list (lista_zmian.txt, Polish): URZ0086_V1.0.7.abs / - soft bazowy / URZ0086_v1.1.0.abs / - Poprawiono j. polski w menu, / - Dodano znaczniki nagrywania w liście kanałów. / URZ0086_v1.1.1.abs / przywrócono odtwarzanie plików .flac / URZ0086_v1.1.9.abs / -zmiana sposobu załączenia dekodera po braku zasilania (dekoder załącza się do stand-by) / -poprawiono wyświetlanie napisów przy odtwarzaniu filmów z nośników zewnętrznych / -opcja nagrywanie jako pierwsza przy programowaniu zdarzeń czasowych / -poprawiono błędne nagrywanie przy programowaniu nagrań zbieżnych w czasie z tego samego MUX / -inne drobne błędy

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `CABLETECH URZ0086/URZ0086_V1.2.1.abs`

* **Box:** Cabletech URZ0086
* **Type:** DVB-T HD PVR receiver with two tuners (2011)
* **Board:** MC6245-M3606-VER1.0 (elektroda topic "Cabletech URZ0086. Potrzebny wsad pamięci")
* **SoC:** ALi M3606 (M36xx (not modelled))
* **Demodulator:** unknown (under the tuner's shield, Gutek's review); the firmware has NIM_COFDM_0 / NIM_COFDM_1: two tuners
* **Flash:** 4 MB SPI
* **IR coding:** nec
* **Image:** update, V1.2.1 (maincode "M3606 2Tuner" 2012-7-2), 2012-07-02, 4194304 bytes, SHA-1 05dc38c4310fdccbe056a2515bded7fe94e5cd08
* **Layout:** bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2012-7-2), seecode 0x140000 (M3606 SEE, 2012-7-2), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2012-7-2)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/urz0086_v121.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive urz0086_v121.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Cabletech URZ0086 firmware V1.2.1, the manufacturer's USB update image as Gutek's site mirrors it (urz0086_v121.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2012-7-2), seecode 0x140000 (M3606 SEE, 2012-7-2), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2012-7-2); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 7.2.0@SDK4.0ba.7.2_20120115; SDK7.2-Mico1.6-LECHPOL1.2.1; Libcore version 1.1.5a@SDK_20111126.

The bootloader chunk's version reads "DVBS2---0.1.0" (ALi's project name) although the box is DVB-T; the maincode is "M3606 2Tuner".  Forum users program these .abs files directly into the flash (renamed .bin): they are complete flash images.

Change list (lista_zmian.txt, Polish): URZ0086_V1.0.7.abs / - soft bazowy / URZ0086_v1.1.0.abs / - Poprawiono j. polski w menu, / - Dodano znaczniki nagrywania w liście kanałów. / URZ0086_v1.1.1.abs / przywrócono odtwarzanie plików .flac / URZ0086_v1.1.9.abs / -zmiana sposobu załączenia dekodera po braku zasilania (dekoder załącza się do stand-by) / -poprawiono wyświetlanie napisów przy odtwarzaniu filmów z nośników zewnętrznych / -opcja nagrywanie jako pierwsza przy programowaniu zdarzeń czasowych / -poprawiono błędne nagrywanie przy programowaniu nagrań zbieżnych w czasie z tego samego MUX / -inne drobne błędy / URZ0086_v1.2.1.abs / -poprawiono skalowanie obrazu przy odtwarzaniu nagranych materiałów / -zwiększono wielkość dzielonych plików do 4GB / -inne drobne błędy

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


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


## `FERGUSON ARIVA T50/ArivaT50_20111118_V102B214.abs`

* **Box:** Ferguson Ariva T50
* **Type:** DVB-T HD receiver with USB recording and a media player
* **SoC:** ALi M3602 (the maincode chunk's version reads "Demo M3602": ALi's SDK project) (M36xx (not modelled))
* **Demodulator:** ALi M3101, external (the firmware's nim_m3101 driver "nim_m3101_ver_112a"; NIM_COFDM_0 / NIM_COFDM_1)
* **Flash:** 4 MB SPI
* **IR coding:** nec
* **Image:** update, V1.02B214 (maincode "Demo M3602" 2011-11-18), 2011-11-18, 4194304 bytes, SHA-1 48b9e41aae5f90b0af54f138a42deac7dae18344
* **Layout:** bootloader 0x000000 (DMB01---0.1.0, 2011-11-18), maincode 0x010000 (Demo M3602, 2011-11-18), radioback 0x340000 (1.0.0, 2010-6-25), bootlogo 0x348000 (1.0.0, 2010-6-21), customerradiolo 0x358000 (1.0.0, 2011-8-16), countryband 0x360000 (1.1.0, 2011-11-18), userdb 0x36FF80 (1.0.0, 2011-11-18)
* **Source:** [ferguson-digital.eu](https://ferguson-digital.eu/download/dvb-t/series_Ariva/Ariva_T50/firmware/ArivaT50_20111118_V102B214.zip), Ferguson (2011-11-18). Ferguson's official download area (https://ferguson-digital.eu/download/?dir=dvb-t%2Fseries_Ariva%2FAriva_T50%2Ffirmware): ArivaT50_20111118_V102B214.zip (1.54 MB) also holds a Polish upgrade guide and revision_history.txt (the formats its media player plays); only the .abs image is kept here; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (a family chips/ does not model; it would be treated as the default M3801).

Ferguson Ariva T50 firmware V1.02B214, the manufacturer's USB update image from Ferguson's download area (ArivaT50_20111118_V102B214.zip).

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DMB01---0.1.0, 2011-11-18), maincode 0x010000 (Demo M3602, 2011-11-18), radioback 0x340000 (1.0.0, 2010-6-25), bootlogo 0x348000 (1.0.0, 2010-6-21), customerradiolo 0x358000 (1.0.0, 2011-8-16), countryband 0x360000 (1.1.0, 2011-11-18), userdb 0x36FF80 (1.0.0, 2011-11-18); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 1.1.6@Auto_20100413.

The front-panel driver is "PAN_PT_0" (a PT6964-style shift-register panel in ALi's SDK), not one front_panel.py decodes yet.

The bootloader chunk's version is "DMB01---0.1.0" (its Libcore 1.0.9@Auto_20090520); the chain also carries a boot logo ("bootlogo", an MPEG still) and a "customerradiolo" (the radio-mode background).

Not run in the simulator yet.


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


## `FERGUSON ARIVA T750i/Ferguson_T750i_V1.20B2_18092019.abs`

* **Box:** Ferguson Ariva T750i
* **Type:** DVB-T2 HD receiver with Ethernet and web services
* **Board:** the bootloader chunk's version reads "66019-01047" (the T650i's is "63004-01047")
* **SoC:** ALi M3821 family (the maincode's demodulator drivers are NIM_S3821_0 / NIM_S3821_T2_*: the M3821's own DVB-T2 COFDM) (M3821 (not detected: chips.detect looks for "M3821" in the bootloader chunk's version))
* **Demodulator:** internal S3821 (NIM_S3821_0, DVB-T / DVB-T2)
* **Tuner:** MaxLinear MxL603 (the maincode's tuner driver names it)
* **Flash:** 8 MB SPI
* **Front panel:** FD650K (TM1650-compatible)
* **IR coding:** nec
* **Image:** update, V1.20B2 (maincode "V1.20B2" 20190918-180158), 2019-09-18, 8388608 bytes, SHA-1 64fcaaf412d3c77ebbaa4fb8d66887713a77831c
* **Layout:** HAT24 0x000000 (66019-01047, 20150930-172959), HDCPKey 0x01FE00 (1.0.0, 20170502-094524), OTAloader 0x020000 (V1.20B2, 20151112-203754), ota_see 0x0DEE00 (V1.20B2, 20151020-173032), OTAparam 0x10EE00 (1.0.0, 20190918-180159), MemCfg 0x10F000 (00000001, 20190918-180158), maincode 0x110000 (V1.20B2, 20190918-180158), seecode 0x560000 (V1.20B2, 20190918-180158), radioback 0x6D0000 (1.0.0, 20150923-151837), seeback 0x6EFF80 (1.0.0, 20150923-151837), T750i 0x700000 (1.0.0, 20150923-151837), data 0x71FF80 (1.0.0, 20150923-151836), defaultdb 0x770000 (1.0.0, 20150923-151837), userdb 0x78FF80 (1.0.0, 20190918-180159)
* **Source:** [ferguson-digital.eu](https://ferguson-digital.eu/download/dvb-t/series_Ariva/Ariva_T750i/firmware/T750i_20190918_V1.20B2.zip), Ferguson (2019-09-18). Ferguson's official download area (https://ferguson-digital.eu/download/?dir=dvb-t%2Fseries_Ariva%2FAriva_T750i%2Ffirmware): T750i_20190918_V1.20B2.zip (4.01 MB) also holds nothing else; only the .abs image is kept here; downloaded on 2026-10-10
* **Simulator:** boots no, application no, display no. Detected as the default M3801, the bootloader returns to PC 0 after 61k instructions: its stack is in locked D-cache lines at the top of the flash window, which the simulator keeps read-only.  With stand-ins in a scratch experiment (2026-10-10) it boots to the application, which then waits for the SEE co-processor (see the last paragraph).

Ferguson Ariva T750i firmware V1.20B2, the manufacturer's USB update image from Ferguson's download area (T750i_20190918_V1.20B2.zip).

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- HAT24 0x000000 (66019-01047, 20150930-172959), HDCPKey 0x01FE00 (1.0.0, 20170502-094524), OTAloader 0x020000 (V1.20B2, 20151112-203754), ota_see 0x0DEE00 (V1.20B2, 20151020-173032), OTAparam 0x10EE00 (1.0.0, 20190918-180159), MemCfg 0x10F000 (00000001, 20190918-180158), maincode 0x110000 (V1.20B2, 20190918-180158), seecode 0x560000 (V1.20B2, 20190918-180158), radioback 0x6D0000 (1.0.0, 20150923-151837), seeback 0x6EFF80 (1.0.0, 20150923-151837), T750i 0x700000 (1.0.0, 20150923-151837), data 0x71FF80 (1.0.0, 20150923-151836), defaultdb 0x770000 (1.0.0, 20150923-151837), userdb 0x78FF80 (1.0.0, 20190918-180159); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 13.6.0@SDK4.0ga.13.6_20141202; Libcore version 1.1.5a@SDK_20111126.

The image carries a second CPU's code: "seecode" (V1.20B2, the SEE -- ALi's secure co-processor -- with its own Libcore 1.1.5a@SDK_20111126), and the image has an OTA loader with its own SEE part ("OTAloader" / "ota_see", Libcore 13.6.0@SDK4.0ga.13.6_20141202), "MemCfg" and a "T750i" chunk (the boot picture).  The R265 Lite's M3822P images have no SEE chunk, so this is the first M3821-family image that needs the SEE CPU's mailbox (or a stand-in for it).

The front panel is an FD650K ("PAN_FD650K", as on the T650i); its GPIO pins are not known yet.

In the simulator (2026-10-10, scratch experiments, nothing of it in chips/ yet): the bootloader is the M3801 kind -- it runs from the flash window, not from the R265 Lite's boot SRAM -- and takes its M3821 set-up path when the chip ID word says 0x3821.  Until the DDR is up it keeps its stack in locked D-cache lines at 0x8FFF8000..0x8FFFFFFF (cache-as-RAM: it reads that range to load the lines and locks its DDR set-up functions into the I-cache with cache 0x14), so as the default M3801 it pops a return address of 0xFFFFFFFF from flash and ends at PC 0.  With RAM over those 32 KB, the chip word 0x38210000 and the M3821 family's devices it prints "HW BootLoader APP  init!", checks the program ("check_program finish."), unpacks the SEE code (0x57A7A1 -> 0x3370B0 bytes, "run see, see_entry = 0x8132f000!"), writes the SEE's start address 0xA1017804 to 0xB8000200 and waits for bit 0 of 0xB800020C (the SEE has started); with that bit answered it unpacks the main code (0x82EFF8 bytes) and prints "success!".  The application (EBase 0x80002000, its start code picks a set-up by the chip ID: 0x3503, 0x3281, 0x3811, ...) registers handlers for interrupts 0x46 / 0x47 and then waits for five words at 0x808FCF40 to become non-zero -- the SEE's messages -- with its other tasks idle: it needs the SEE CPU running its own code (and the mailbox between the two), which the simulator does not have.  (Fast mode: the two counted calibration slices end at 400k instructions inside the bootloader's CP0 set-up, so its mtc0 EBase runs without its hook and the first interrupt goes to an empty 0x80000180; exact mode for the first 2 M instructions avoids that.)


## `FERGUSON ARIVA T760i/Ferguson_T760i_V1.4B8_28072020.abs`

* **Box:** Ferguson Ariva T760i
* **Type:** DVB-T2 HD receiver with Wi-Fi / Ethernet and web services
* **Board:** the bootloader chunk ("HATB1") has the T750i's version "66019-01047"
* **SoC:** ALi C3505 (the maincode's "ALI_C3505:0x%x" chip-id print, "Ali3505", c3505_phy_set) (M3505 (not modelled))
* **Demodulator:** AltoBeam ATBM7812, external (the firmware's nim_atbm7812 driver, NIM_ATBM7812_0; the tuner sits behind its I2C gateway)
* **Flash:** 8 MB SPI
* **Front panel:** FD650K (TM1650-compatible)
* **IR coding:** nec
* **Image:** update, V1.4B8 (maincode "V1.4B8" 2020-7-28), 2020-07-28, 8388608 bytes, SHA-1 28cde8bafc331042969afcb1cc9a49c0a6e9f4a5
* **Layout:** HATB1 0x000000 (66019-01047, 2020-7-28), HDCPKey 0x02FE00 (1.0.0, 2016-7-14), maincode 0x030000 (V1.4B8, 2020-7-28), seecode 0x480000 (V1.4B8, 2020-7-28), radioback 0x5F0000 (1.0.0, 2016-7-14), seeback 0x60FF80 (1.0.0, 2016-7-14), T760i 0x620000 (1.0.0, 2016-7-14), data 0x63FF80 (1.0.0, 2016-7-14), defaultdb 0x690000 (1.0.0, 2016-12-8), userdb 0x6AFF80 (1.0.0, 2020-7-28)
* **Source:** [ferguson-digital.eu](https://ferguson-digital.eu/download/dvb-t/series_Ariva/Ariva_T760i/firmware/Ferguson_T760i_V1.4B8_28072020.zip), Ferguson (2020-07-28). Ferguson's official download area (https://ferguson-digital.eu/download/?dir=dvb-t%2Fseries_Ariva%2FAriva_T760i%2Ffirmware): Ferguson_T760i_V1.4B8_28072020.zip (3.41 MB) also holds upgrade guides in EN / DE / PL; only the .abs image is kept here; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (a family chips/ does not model; it would be treated as the default M3801).

Ferguson Ariva T760i firmware V1.4B8, the manufacturer's USB update image from Ferguson's download area (Ferguson_T760i_V1.4B8_28072020.zip).

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- HATB1 0x000000 (66019-01047, 2020-7-28), HDCPKey 0x02FE00 (1.0.0, 2016-7-14), maincode 0x030000 (V1.4B8, 2020-7-28), seecode 0x480000 (V1.4B8, 2020-7-28), radioback 0x5F0000 (1.0.0, 2016-7-14), seeback 0x60FF80 (1.0.0, 2016-7-14), T760i 0x620000 (1.0.0, 2016-7-14), data 0x63FF80 (1.0.0, 2016-7-14), defaultdb 0x690000 (1.0.0, 2016-12-8), userdb 0x6AFF80 (1.0.0, 2020-7-28); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 17.15.0@SDK4.0ia.17.15_20171115; Libcore version 1.1.5a@SDK_20111126.

Like the T750i it has a "seecode" chunk (the SEE co-processor's code, Libcore 1.1.5a@SDK_20111126); the maincode's Libcore is 17.15.0@SDK4.0ia.17.15_20171115.  The chip is not an M3821: the C3505 is a later ALi generation (a DVB-S2 SoC; here the external AltoBeam ATBM7812 receives DVB-T2), so the simulator has no family for it yet.

Not run in the simulator yet.


## `FERGUSON ARIVA T760i/Ferguson_T760i_V1.5B0-22122020.abs`

* **Box:** Ferguson Ariva T760i
* **Type:** DVB-T2 HD receiver with Wi-Fi / Ethernet and web services
* **Board:** the bootloader chunk ("HATB1") has the T750i's version "66019-01047"
* **SoC:** ALi C3505 (the maincode's "ALI_C3505:0x%x" chip-id print, "Ali3505", c3505_phy_set) (M3505 (not modelled))
* **Demodulator:** AltoBeam ATBM7812, external (the firmware's nim_atbm7812 driver, NIM_ATBM7812_0; the tuner sits behind its I2C gateway)
* **Flash:** 8 MB SPI
* **Front panel:** FD650K (TM1650-compatible)
* **IR coding:** nec
* **Image:** update, V1.5B0 (2020-12-22) (maincode "V1.5B0" 2020-12-22), 2020-12-22, 8388608 bytes, SHA-1 4edbff4ba0212d52b7f91bf3dbdd4d8853c323b7
* **Layout:** HATB1 0x000000 (66019-01047, 2020-12-22), HDCPKey 0x02FE00 (1.0.0, 2016-7-14), maincode 0x030000 (V1.5B0, 2020-12-22), seecode 0x480000 (V1.5B0, 2020-12-22), radioback 0x5F0000 (1.0.0, 2016-7-14), seeback 0x60FF80 (1.0.0, 2016-7-14), T760i 0x620000 (1.0.0, 2016-7-14), data 0x63FF80 (1.0.0, 2016-7-14), defaultdb 0x690000 (1.0.0, 2016-12-8), userdb 0x6AFF80 (1.0.0, 2020-12-22)
* **Source:** [ferguson-digital.eu](https://ferguson-digital.eu/download/dvb-t/series_Ariva/Ariva_T760i/firmware/Ferguson_T760i_V1.5B0-22122020.zip), Ferguson (2020-12-22). Ferguson's official download area (https://ferguson-digital.eu/download/?dir=dvb-t%2Fseries_Ariva%2FAriva_T760i%2Ffirmware): Ferguson_T760i_V1.5B0-22122020.zip (3.14 MB) also holds nothing else; only the .abs image is kept here; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (a family chips/ does not model; it would be treated as the default M3801).

Ferguson Ariva T760i firmware V1.5B0 (2020-12-22), the manufacturer's USB update image from Ferguson's download area (Ferguson_T760i_V1.5B0-22122020.zip).

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- HATB1 0x000000 (66019-01047, 2020-12-22), HDCPKey 0x02FE00 (1.0.0, 2016-7-14), maincode 0x030000 (V1.5B0, 2020-12-22), seecode 0x480000 (V1.5B0, 2020-12-22), radioback 0x5F0000 (1.0.0, 2016-7-14), seeback 0x60FF80 (1.0.0, 2016-7-14), T760i 0x620000 (1.0.0, 2016-7-14), data 0x63FF80 (1.0.0, 2016-7-14), defaultdb 0x690000 (1.0.0, 2016-12-8), userdb 0x6AFF80 (1.0.0, 2020-12-22); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 17.15.0@SDK4.0ia.17.15_20171115; Libcore version 1.1.5a@SDK_20111126.

Like the T750i it has a "seecode" chunk (the SEE co-processor's code, Libcore 1.1.5a@SDK_20111126); the maincode's Libcore is 17.15.0@SDK4.0ia.17.15_20171115.  The chip is not an M3821: the C3505 is a later ALi generation (a DVB-S2 SoC; here the external AltoBeam ATBM7812 receives DVB-T2), so the simulator has no family for it yet.

Not run in the simulator yet.


## `FERGUSON ARIVA T760i/Ferguson_T760i_V1.5B0-28012021.abs`

* **Box:** Ferguson Ariva T760i
* **Type:** DVB-T2 HD receiver with Wi-Fi / Ethernet and web services
* **Board:** the bootloader chunk ("HATB1") has the T750i's version "66019-01047"
* **SoC:** ALi C3505 (the maincode's "ALI_C3505:0x%x" chip-id print, "Ali3505", c3505_phy_set) (M3505 (not modelled))
* **Demodulator:** AltoBeam ATBM7812, external (the firmware's nim_atbm7812 driver, NIM_ATBM7812_0; the tuner sits behind its I2C gateway)
* **Flash:** 8 MB SPI
* **Front panel:** FD650K (TM1650-compatible)
* **IR coding:** nec
* **Image:** update, V1.5B0 (2021-01-28) (maincode "V1.5B0" 2021-1-28), 2021-01-28, 8388608 bytes, SHA-1 f16a6daf0ad4d02d5bdda04eb32f0a9315b8cce6
* **Layout:** HATB1 0x000000 (66019-01047, 2021-1-28), HDCPKey 0x02FE00 (1.0.0, 2016-7-14), maincode 0x030000 (V1.5B0, 2021-1-28), seecode 0x480000 (V1.5B0, 2021-1-28), radioback 0x5F0000 (1.0.0, 2016-7-14), seeback 0x60FF80 (1.0.0, 2016-7-14), T760i 0x620000 (1.0.0, 2016-7-14), data 0x63FF80 (1.0.0, 2016-7-14), defaultdb 0x690000 (1.0.0, 2016-12-8), userdb 0x6AFF80 (1.0.0, 2021-1-28)
* **Source:** [ferguson-digital.eu](https://ferguson-digital.eu/download/dvb-t/series_Ariva/Ariva_T760i/firmware/Ferguson_T760i_V1.5B0-28012021.zip), Ferguson (2021-01-28). Ferguson's official download area (https://ferguson-digital.eu/download/?dir=dvb-t%2Fseries_Ariva%2FAriva_T760i%2Ffirmware): Ferguson_T760i_V1.5B0-28012021.zip (3.14 MB) also holds nothing else; only the .abs image is kept here; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (a family chips/ does not model; it would be treated as the default M3801).

Ferguson Ariva T760i firmware V1.5B0 (2021-01-28), the manufacturer's USB update image from Ferguson's download area (Ferguson_T760i_V1.5B0-28012021.zip).

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- HATB1 0x000000 (66019-01047, 2021-1-28), HDCPKey 0x02FE00 (1.0.0, 2016-7-14), maincode 0x030000 (V1.5B0, 2021-1-28), seecode 0x480000 (V1.5B0, 2021-1-28), radioback 0x5F0000 (1.0.0, 2016-7-14), seeback 0x60FF80 (1.0.0, 2016-7-14), T760i 0x620000 (1.0.0, 2016-7-14), data 0x63FF80 (1.0.0, 2016-7-14), defaultdb 0x690000 (1.0.0, 2016-12-8), userdb 0x6AFF80 (1.0.0, 2021-1-28); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 17.15.0@SDK4.0ia.17.15_20171115; Libcore version 1.1.5a@SDK_20111126.

Like the T750i it has a "seecode" chunk (the SEE co-processor's code, Libcore 1.1.5a@SDK_20111126); the maincode's Libcore is 17.15.0@SDK4.0ia.17.15_20171115.  The chip is not an M3821: the C3505 is a later ALi generation (a DVB-S2 SoC; here the external AltoBeam ATBM7812 receives DVB-T2), so the simulator has no family for it yet.

Not run in the simulator yet.


## `FERGUSON ARIVA T760i/Ferguson_T760i_V1.5B4-14092021.abs`

* **Box:** Ferguson Ariva T760i
* **Type:** DVB-T2 HD receiver with Wi-Fi / Ethernet and web services
* **Board:** the bootloader chunk ("HATB1") has the T750i's version "66019-01047"
* **SoC:** ALi C3505 (the maincode's "ALI_C3505:0x%x" chip-id print, "Ali3505", c3505_phy_set) (M3505 (not modelled))
* **Demodulator:** AltoBeam ATBM7812, external (the firmware's nim_atbm7812 driver, NIM_ATBM7812_0; the tuner sits behind its I2C gateway)
* **Flash:** 8 MB SPI
* **Front panel:** FD650K (TM1650-compatible)
* **IR coding:** nec
* **Image:** update, V1.5B4 (maincode "V1.5B4" 2021-9-14), 2021-09-14, 8388608 bytes, SHA-1 13af095f240d518282bc193ee6d08609ef799925
* **Layout:** HATB1 0x000000 (66019-01047, 2021-9-14), HDCPKey 0x02FE00 (1.0.0, 2016-7-14), maincode 0x030000 (V1.5B4, 2021-9-14), seecode 0x480000 (V1.5B4, 2021-9-14), radioback 0x5F0000 (1.0.0, 2016-7-14), seeback 0x60FF80 (1.0.0, 2016-7-14), T760i 0x620000 (1.0.0, 2016-7-14), data 0x63FF80 (1.0.0, 2016-7-14), defaultdb 0x690000 (1.0.0, 2016-12-8), userdb 0x6AFF80 (1.0.0, 2021-9-14)
* **Source:** [ferguson-digital.eu](https://ferguson-digital.eu/download/dvb-t/series_Ariva/Ariva_T760i/firmware/Ferguson_T760i_V1.5B4-14092021.zip), Ferguson (2021-09-14). Ferguson's official download area (https://ferguson-digital.eu/download/?dir=dvb-t%2Fseries_Ariva%2FAriva_T760i%2Ffirmware): Ferguson_T760i_V1.5B4-14092021.zip (3.42 MB) also holds a changelog and upgrade guides in EN / DE / PL; only the .abs image is kept here; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (a family chips/ does not model; it would be treated as the default M3801).

Ferguson Ariva T760i firmware V1.5B4, the manufacturer's USB update image from Ferguson's download area (Ferguson_T760i_V1.5B4-14092021.zip).

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- HATB1 0x000000 (66019-01047, 2021-9-14), HDCPKey 0x02FE00 (1.0.0, 2016-7-14), maincode 0x030000 (V1.5B4, 2021-9-14), seecode 0x480000 (V1.5B4, 2021-9-14), radioback 0x5F0000 (1.0.0, 2016-7-14), seeback 0x60FF80 (1.0.0, 2016-7-14), T760i 0x620000 (1.0.0, 2016-7-14), data 0x63FF80 (1.0.0, 2016-7-14), defaultdb 0x690000 (1.0.0, 2016-12-8), userdb 0x6AFF80 (1.0.0, 2021-9-14); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 17.15.0@SDK4.0ia.17.15_20171115; Libcore version 1.1.5a@SDK_20111126.

Like the T750i it has a "seecode" chunk (the SEE co-processor's code, Libcore 1.1.5a@SDK_20111126); the maincode's Libcore is 17.15.0@SDK4.0ia.17.15_20171115.  The chip is not an M3821: the C3505 is a later ALi generation (a DVB-S2 SoC; here the external AltoBeam ATBM7812 receives DVB-T2), so the simulator has no family for it yet.

Changelog (changelog.txt, PL / EN): V1.5B4-14092021 -- YouPorn hidden by the "parental lock" function; improved PVR screen keyboard.

Not run in the simulator yet.


## `KRUGER MATZ KM0183/J1100393-KM00183-MC6258-V1.0.4.abs`

* **Box:** Kruger&Matz KM0183 ("KM00183")
* **Type:** DVB-T HD receiver (2011)
* **Board:** MC6258 (the V1.0.4 image's file name "J1100393-KM00183-MC6258")
* **SoC:** ALi M3601E (the Cabletech URZ0083's twin) (M36xx (not modelled))
* **Demodulator:** ALi M3100 family, external (the firmware's NIM_COFDM driver tables name the M3101)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.0.4 (maincode "Demo M3606" 2011-9-1), 2011-09-01, 2097152 bytes, SHA-1 27723bb273c871f7e0868d1c9b3ac017a1fcc9a2
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2010-06-01), HDCPKey 0x00FE00 (Demo s3602, 2009-11-10), maincode 0x010000 (Demo M3606, 2011-9-1), Radioback 0x160000 (1.0.0, 2009-05-08), countryband 0x170000 (1.0.0, 2010-4-1), userdb 0x18FF80 (1.0.0, 2011-9-1)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/km00183_v104.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive km00183_v104.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Kruger&Matz KM0183 firmware V1.0.4, the manufacturer's USB update image as Gutek's site mirrors it (km00183_v104.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2010-06-01), HDCPKey 0x00FE00 (Demo s3602, 2009-11-10), maincode 0x010000 (Demo M3606, 2011-9-1), Radioback 0x160000 (1.0.0, 2009-05-08), countryband 0x170000 (1.0.0, 2010-4-1), userdb 0x18FF80 (1.0.0, 2011-9-1); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 5.0.0@SDK4.0ba.5.0_20110425.

Kruger&Matz is Lechpol's other brand: the same firmware line as the Cabletech URZ0083 (its V1.0.6 / V1.0.8 change lists repeat the URZ0083 V1.2.2 / V1.2.5 ones).

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `KRUGER MATZ KM0183/KM00183_V1.0.6.abs`

* **Box:** Kruger&Matz KM0183 ("KM00183")
* **Type:** DVB-T HD receiver (2011)
* **Board:** MC6258 (the V1.0.4 image's file name "J1100393-KM00183-MC6258")
* **SoC:** ALi M3601E (the Cabletech URZ0083's twin) (M36xx (not modelled))
* **Demodulator:** ALi M3100 family, external (the firmware's NIM_COFDM driver tables name the M3101)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.0.6 (maincode "Demo M3606" 2012-1-16), 2012-01-16, 2097152 bytes, SHA-1 4f5a7128658ef2f5a88e60b00272363d336efafb
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (Demo M3606, 2012-1-16), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-1-16)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/km00183_v106.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive km00183_v106.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Kruger&Matz KM0183 firmware V1.0.6, the manufacturer's USB update image as Gutek's site mirrors it (km00183_v106.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (Demo M3606, 2012-1-16), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-1-16); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 6.4.0@SDK4.0ba.6.4_20111019; SDK6.4-Mico-v0.1.1+KM00183-v_1.0.6.

Kruger&Matz is Lechpol's other brand: the same firmware line as the Cabletech URZ0083 (its V1.0.6 / V1.0.8 change lists repeat the URZ0083 V1.2.2 / V1.2.5 ones).

Change list (lista_zmian.txt, Polish): KM00183_V1.0.6.abs / -poprawiono polskie tłumaczenie w menu / -poprawiono kolor i tło czcionki w EPG / -usunięto wskaźnik poziomu sygnału w OSD przy zmianie kanałów / -opcja nagrywanie jako pierwsza przy programowaniu zdarzeń czasowych / -usunięto błąd rezerwacji miejsca na nośniku przy wyłączonej funkcji timeshift / -zmiana sposobu załączenia dekodera po braku zasilania (dekoder załącza się do stand-by) / -inne drobne błędy / KM00183_V1.0.4.abs / -soft bazowy

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `KRUGER MATZ KM0183/KM00183_V1.0.8.abs`

* **Box:** Kruger&Matz KM0183 ("KM00183")
* **Type:** DVB-T HD receiver (2011)
* **Board:** MC6258 (the V1.0.4 image's file name "J1100393-KM00183-MC6258")
* **SoC:** ALi M3601E (the Cabletech URZ0083's twin) (M36xx (not modelled))
* **Demodulator:** ALi M3100 family, external (the firmware's NIM_COFDM driver tables name the M3101)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.0.8 (maincode "Demo M3606" 2012-4-27), 2012-04-27, 2097152 bytes, SHA-1 e640613b000499bac0799d875eb53ae81786d8e8
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (Demo M3606, 2012-4-27), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-4-27)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0083/km00183_v108.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive km00183_v108.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Kruger&Matz KM0183 firmware V1.0.8, the manufacturer's USB update image as Gutek's site mirrors it (km00183_v108.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (Demo M3606, 2012-4-27), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-4-27); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 6.4.0@SDK4.0ba.6.4_20111019; SDK6.4-Mico-v0.1.3+KM00183-v_1.0.8.

Kruger&Matz is Lechpol's other brand: the same firmware line as the Cabletech URZ0083 (its V1.0.6 / V1.0.8 change lists repeat the URZ0083 V1.2.2 / V1.2.5 ones).

Change list (lista_zmian.txt, Polish): KM00183_V1.0.8.abs / poprawiono wyświetlanie napisów przy odtwarzaniu filmów z nośników zewnętrznych / inne drobne błędy / KM00183_V1.0.6.abs / -poprawiono polskie tłumaczenie w menu / -poprawiono kolor i tło czcionki w EPG / -usunięto wskaźnik poziomu sygnału w OSD przy zmianie kanałów / -opcja nagrywanie jako pierwsza przy programowaniu zdarzeń czasowych / -usunięto błąd rezerwacji miejsca na nośniku przy wyłączonej funkcji timeshift / -zmiana sposobu załączenia dekodera po braku zasilania (dekoder załącza się do stand-by) / -inne drobne błędy

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `KRUGER MATZ KM0186/KM00186_v1.0.6.abs`

* **Box:** Kruger&Matz KM0186 ("KM00186")
* **Type:** DVB-T HD PVR receiver with two tuners (2011)
* **SoC:** ALi M3606 (the Cabletech URZ0086's twin) (M36xx (not modelled))
* **Demodulator:** unknown; the firmware has NIM_COFDM_0 / NIM_COFDM_1: two tuners
* **Flash:** 4 MB SPI
* **IR coding:** nec
* **Image:** update, V1.0.6 (maincode "M3606 2Tuner" 2011-11-15), 2011-11-15, 4194304 bytes, SHA-1 746234e502efae6c66e78a2b37e573cc06543dcf
* **Layout:** bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2011-11-15), seecode 0x140000 (M3606 SEE, 2011-11-15), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2011-11-15)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/km00186_v106.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive km00186_v106.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Kruger&Matz KM0186 firmware V1.0.6, the manufacturer's USB update image as Gutek's site mirrors it (km00186_v106.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2011-11-15), seecode 0x140000 (M3606 SEE, 2011-11-15), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2011-11-15); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 5.0.0@SDK4.0ba.5.0_20110425; Libcore version 1.1.5a@SDK_20100524.

Kruger&Matz is Lechpol's other brand: the same firmware line as the Cabletech URZ0086 ("M3606 2Tuner" maincode, LECHPOL build tags).

Change list (lista_zmian.txt, Polish): KM00186_v1.0.6.abs / - Poprawiono j. polski w menu, / - Dodano znaczniki nagrywania w liście kanałów. / - przywrócono odtwarzanie plików .flac

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `KRUGER MATZ KM0186/KM00186_V1.0.9.abs`

* **Box:** Kruger&Matz KM0186 ("KM00186")
* **Type:** DVB-T HD PVR receiver with two tuners (2011)
* **SoC:** ALi M3606 (the Cabletech URZ0086's twin) (M36xx (not modelled))
* **Demodulator:** unknown; the firmware has NIM_COFDM_0 / NIM_COFDM_1: two tuners
* **Flash:** 4 MB SPI
* **IR coding:** nec
* **Image:** update, V1.0.9 (maincode "M3606 2Tuner" 2012-5-23), 2012-05-23, 4194304 bytes, SHA-1 8a0053813af891556290dd64078808135e1c6111
* **Layout:** bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2012-5-23), seecode 0x140000 (M3606 SEE, 2012-5-23), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2012-5-23)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/km00186_v109.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive km00186_v109.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Kruger&Matz KM0186 firmware V1.0.9, the manufacturer's USB update image as Gutek's site mirrors it (km00186_v109.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2012-5-23), seecode 0x140000 (M3606 SEE, 2012-5-23), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2012-5-23); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 7.2.0@SDK4.0ba.7.2_20120115; SDK7.2-Mico1.8-LECHPOL1.0.9; Libcore version 1.1.5a@SDK_20111126.

Kruger&Matz is Lechpol's other brand: the same firmware line as the Cabletech URZ0086 ("M3606 2Tuner" maincode, LECHPOL build tags).

Change list (lista_zmian.txt, Polish): KM00186_v1.0.6.abs / - Poprawiono j. polski w menu, / - Dodano znaczniki nagrywania w liście kanałów. / - przywrócono odtwarzanie plików .flac / KM00186_v.1.0.9.abs / -zmiana sposobu załączenia dekodera po braku zasilania (dekoder załącza się do stand-by) / -poprawiono wyświetlanie napisów przy odtwarzaniu filmów z nośników zewnętrznych / -opcja nagrywanie jako pierwsza przy programowaniu zdarzeń czasowych / -poprawiono błędne nagrywanie przy programowaniu nagrań zbieżnych w czasie z tego samego MUX / -inne drobne błędy

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


## `KRUGER MATZ KM0186/KM00186_V1.1.1.abs`

* **Box:** Kruger&Matz KM0186 ("KM00186")
* **Type:** DVB-T HD PVR receiver with two tuners (2011)
* **SoC:** ALi M3606 (the Cabletech URZ0086's twin) (M36xx (not modelled))
* **Demodulator:** unknown; the firmware has NIM_COFDM_0 / NIM_COFDM_1: two tuners
* **Flash:** 4 MB SPI
* **IR coding:** nec
* **Image:** update, V1.1.1 (maincode "M3606 2Tuner" 2012-7-2), 2012-07-02, 4194304 bytes, SHA-1 7e92f6027fbe6d3e61228cfe768fc28950e43a3b
* **Layout:** bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2012-7-2), seecode 0x140000 (M3606 SEE, 2012-7-2), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2012-7-2)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/urz0086/km00186_v111.rar), Lechpol (Cabletech / Kruger&Matz), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm), the archive km00186_v111.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (the ALi M36xx generation; chips/ would treat it as the default M3801 family).

Kruger&Matz KM0186 firmware V1.1.1, the manufacturer's USB update image as Gutek's site mirrors it (km00186_v111.rar); the archive also holds the update instructions (the box's menu: Narzędzia / Aktualizacja oprogramowania przez USB, the file chosen under "Allcode") and the change list.

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBS2---0.1.0, 2011-04-14), HDCPKey 0x01FE00 (Demo s3602, 2011-04-14), maincode 0x020000 (M3606 2Tuner, 2012-7-2), seecode 0x140000 (M3606 SEE, 2012-7-2), Radioback 0x240000 (1.0.0, 2011-04-14), countryband 0x250000 (1.0.0, 2011-04-14), userdb 0x26FF80 (1.0.0, 2012-7-2); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 7.2.0@SDK4.0ba.7.2_20120115; SDK7.2-Mico1.8-LECHPOL1.1.1; Libcore version 1.1.5a@SDK_20111126.

Kruger&Matz is Lechpol's other brand: the same firmware line as the Cabletech URZ0086 ("M3606 2Tuner" maincode, LECHPOL build tags).

Change list (lista_zmian.txt, Polish): KM00186_v1.0.6.abs / - Poprawiono j. polski w menu, / - Dodano znaczniki nagrywania w liście kanałów. / - przywrócono odtwarzanie plików .flac / KM00186_v1.0.9.abs / -zmiana sposobu załączenia dekodera po braku zasilania (dekoder załącza się do stand-by) / -poprawiono wyświetlanie napisów przy odtwarzaniu filmów z nośników zewnętrznych / -opcja nagrywanie jako pierwsza przy programowaniu zdarzeń czasowych / -poprawiono błędne nagrywanie przy programowaniu nagrań zbieżnych w czasie z tego samego MUX / -inne drobne błędy / KM00186_v1.1.1.abs / -poprawiono skalowanie obrazu przy odtwarzaniu nagranych materiałów / -zwiększono wielkość dzielonych plików do 4GB / -inne drobne błędy

Gutek's review of the URZ0083 and URZ0086 (https://www.gutek.com.pl/tunery_cabletech_urz0083_urz0086_recenzja.htm): the URZ0083 is built on the ALi M3601E with an ALi M3100 demodulator and 64 MB DDR2, the URZ0086 on the ALi M3606 with 128 MB DDR2.  Not run in the simulator yet: these are the ALi M36xx generation before the M3801 (chips/ has no family for it).


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
* **Source:** [github.com/openshwprojects/FlashDumps](https://github.com/openshwprojects/FlashDumps/tree/main/Sat/Opticum%20Blue%20R265%20Lite), openshwprojects (2024-08-30). The file name is the SoC's marking; committed to FlashDumps on 2024-08-30 ("Create M3822P.bin", 23b0fdc9), added here on 2026-10-09
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
* **Simulator:** boots yes, application yes, display yes, panel ' ON '. Boots into its application (run_dump_r265lite_app_banner.py) and draws its home menu (run_dump_r265lite_capture_screen.py); remote keys reach it (run_dump_r265lite_remote_key.py); the panel chip gets " ON " from the bootloader (run_dump_r265lite_panel_on.py).  With sim.set_signal(True) -- the tuner model at 0x60 and the internal demodulator's lock -- its manual scan page shows 100 % signal strength and 30 % quality instead of 0 % and 0 % (run_dump_r265lite_signal_capture_screen.py).

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

Now the application starts and prints "MC: APP  init ok", "Libcore version 19.17.0@SDK4.0gc.19.17..." and "Application version 1.0.0@SDK4.0gc.19.17..." (regression run_dump_r265lite_120_app_banner.py); it then behaves like firmware 1.1.5's application (see that image), with two differences: it probes the same five tuner addresses on the I2C master at 0xB8018B00, but about 6 M instructions apart (a retry loop per address) instead of back to back; and before drawing it runs a sequence on the block at 0xB802A000 that 1.1.5 only sets up -- a 7-byte table written five times to +0x62, 6 bytes at +0x90.., "TSM5" at +0x27.., then it sets bit 4 of +0x6F and waits for the hardware to clear it, forever in RAM (16.9 M reads of +0x6F in 200 M instructions, no GE command in 900 s).  chips/m3821.py clears that bit on the next read (the simulator's _SELF_COMPLETING mechanism), after which the block sees 288 more operations (+0x70 / +0x72) and the application draws the same home menu as 1.1.5 (363 GE commands) about 4 minutes in; regression run_dump_r265lite_120_capture_screen.py (expected/r265lite_120_screen.png and _nav.png, byte-identical to firmware 1.1.5's expected screens).  The block is most likely the HDMI transmitter: its register library (the Globo N3's has the same) sets +0x07 and +0x6D up, polls +0x08 bit 0 every few milliseconds like a hot-plug line, and the flash carries an HDCPKey chunk; the wait would then be a DDC transfer of the TV's EDID.

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
* **Source:** [elektroda.pl](https://www.elektroda.pl/rtvforum/topic3123357.html#15195863), andrzej 4 (2015-11-29) -- login needed. Thread "Strong srt8115 wsad do układu 25Q32BSIG", post #1 ("bin skopiowany z działającego tunera dvbt" = copied from a working DVB-T tuner): attachment "srt8115.BIN"
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


## `THOMSON THT501/THT501-V1.0.9.abs`

* **Box:** Thomson THT501
* **Type:** DVB-T HD receiver with USB recording (made for Thomson by Strong)
* **SoC:** ALi M36xx (the Cabletech URZ0083's generation: the same chunk layout, bootloader "DVBT---0.1.0" of 2011-08-03 and HDCPKey "Demo s3602") (M36xx (not modelled))
* **Demodulator:** ALi M3101, external (the firmware's nim_m3101 driver; NIM_COFDM_0 / NIM_COFDM_1)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.0.9 (maincode "501" 2012-3-16), 2012-03-16, 2097152 bytes, SHA-1 d71b0a570b1a39bb97962c81d088e1bd1fc65fca
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (501, 2012-3-16), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-3-16)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/strong_thomson/thomson_tht501_v109.rar), Thomson (Strong), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm, "Thomson THT501"), the archive thomson_tht501_v109.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (a family chips/ does not model; it would be treated as the default M3801).

Thomson THT501 firmware V1.0.9, the manufacturer's USB update image as Gutek's site mirrors it (thomson_tht501_v109.rar, with a Polish USB update guide and the release notes from V1.1.1 on).

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (501, 2012-3-16), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-3-16); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 6.4.f@SDK4.0ba.6.4f_20120131; SDK6.4-Mico1.1-Thomson1.0.9.

The front-panel driver is "PAN_HWSCAN_0" (LEDs / digits scanned straight from the SoC's GPIO).

Not run in the simulator yet.


## `THOMSON THT501/THT501-V1.1.1_20120428.abs`

* **Box:** Thomson THT501
* **Type:** DVB-T HD receiver with USB recording (made for Thomson by Strong)
* **SoC:** ALi M36xx (the Cabletech URZ0083's generation: the same chunk layout, bootloader "DVBT---0.1.0" of 2011-08-03 and HDCPKey "Demo s3602") (M36xx (not modelled))
* **Demodulator:** ALi M3101, external (the firmware's nim_m3101 driver; NIM_COFDM_0 / NIM_COFDM_1)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.1.1 (maincode "501" 2012-4-28), 2012-04-28, 2097152 bytes, SHA-1 54b0cd31938362427ba142e13b4a26abc35c66be
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (501, 2012-4-28), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-4-28)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/strong_thomson/thomson_tht501_v111.rar), Thomson (Strong), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm, "Thomson THT501"), the archive thomson_tht501_v111.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (a family chips/ does not model; it would be treated as the default M3801).

Thomson THT501 firmware V1.1.1, the manufacturer's USB update image as Gutek's site mirrors it (thomson_tht501_v111.rar, with a Polish USB update guide and the release notes from V1.1.1 on).

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (501, 2012-4-28), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-4-28); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 6.4.f@SDK4.0ba.6.4f_20120131; SDK6.4-Mico1.2-Thomson1.1.1.

The front-panel driver is "PAN_HWSCAN_0" (LEDs / digits scanned straight from the SoC's GPIO).

Release notes (THT501_Release_notes_PL.txt, Polish), V1.1.1 of 2012-04-28: HDMI resolution change fixed; recordings named after the event, manual renaming fixed, a message when REC is pressed without a USB device; .srt subtitle size; a progress bar in the info banner; HDMI output 720p by default; volume steps; LCN on for Poland; signal bar; Polish / German / Czech OSD fixes; channel sort / edit with a PIN; first / second audio selection; auto scan for Poland; time zones follow the language.

Not run in the simulator yet.


## `THOMSON THT501/THT501_V1.1.5a_20120925.abs`

* **Box:** Thomson THT501
* **Type:** DVB-T HD receiver with USB recording (made for Thomson by Strong)
* **SoC:** ALi M36xx (the Cabletech URZ0083's generation: the same chunk layout, bootloader "DVBT---0.1.0" of 2011-08-03 and HDCPKey "Demo s3602") (M36xx (not modelled))
* **Demodulator:** ALi M3101, external (the firmware's nim_m3101 driver; NIM_COFDM_0 / NIM_COFDM_1)
* **Flash:** 2 MB SPI
* **IR coding:** nec
* **Image:** update, V1.1.5a (maincode "501" 2012-9-25), 2012-09-25, 2097152 bytes, SHA-1 88ee40ff785571a63815a0c59d5c1329202568c2
* **Layout:** bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (501, 2012-9-25), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-9-25)
* **Source:** [gutek.com.pl](https://www.gutek.com.pl/pobierz/softy/strong_thomson/thomson_tht501_v115a.rar), Thomson (Strong), mirrored by Gutek (2026-10-10). Gutek's firmware list (https://www.gutek.com.pl/tunery_oprog_do_tunerow.htm, "Thomson THT501"), the archive thomson_tht501_v115a.rar; downloaded on 2026-10-10
* **Simulator:** boots -, application -, display -. Not run yet (a family chips/ does not model; it would be treated as the default M3801).

Thomson THT501 firmware V1.1.5a, the manufacturer's USB update image as Gutek's site mirrors it (thomson_tht501_v115a.rar, with a Polish USB update guide and the release notes from V1.1.1 on).

Despite the .abs name it is a complete flash image: the ALi chunk chain from offset 0 -- bootloader 0x000000 (DVBT---0.1.0, 2011-08-03), HDCPKey 0x01FE00 (Demo s3602, 2011-08-03), maincode 0x020000 (501, 2012-9-25), Radioback 0x170000 (1.0.0, 2011-08-03), countryband 0x177200 (1.0.0, 2011-07-08), userdb 0x17FF80 (1.0.0, 2012-9-25); the maincode's CRC-32/MPEG-2 is intact.  Banners in its LZMA streams: Libcore version 6.4.f@SDK4.0ba.6.4f_20120131; SDK6.4-Mico1.1-Thomson1.1.4.

The front-panel driver is "PAN_HWSCAN_0" (LEDs / digits scanned straight from the SoC's GPIO).

Release notes (THT501_Release_notes_PL.txt, Polish), V1.1.5a of 2012-09-25: SD / HD simulcast for France; ONID filtering for Poland (only Polish channels get LCN order, the rest go above 900); Greek OSD; Irish / UK services inactive during the scan are kept; a tidier info banner; larger extended EPG text; external subtitle colour selectable with FAV in the media player.

Not run in the simulator yet.


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
* **Source:** [elektroda.pl](https://www.elektroda.pl/rtvforum/topic3573829.html#17909725), jmalko (2019-04-16) -- login needed. Thread "Szukam wsadu do dekodera Cabletech URZ0195, pamięć ESMT F25L32", post #1 ("dekoder sprawny" = the decoder works): attachment "urz0195_full_dump(ESMTF25L3204).bin"
* **Simulator:** boots yes, application yes, display yes, panel ' ON ' -> '----' -> '0004'. Boots into its application and draws (run_dump_urz0195_capture_screen.py, expected urz0195_2012_screen.png); its uPD16312-class panel shows " ON ", "----", then the channel number "0004".

The older of the two URZ0195 dumps in this repository: a different bootloader build than cableteh_urz0195__w25q32bv.BIN's (Libcore 1.1.6, just.li, Fri Jul 13 2012, vs vic.wang Nov 26 2012) and maincode of 2012-08-02 (vs 2013-10-23); the same remote (standby wake code 807F00FF) and the same uPD16312-class front panel driver.
