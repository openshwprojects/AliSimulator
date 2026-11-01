# AliSimulator

An emulator of ALi set-top-box firmware (MIPS32 + MIPS16e, Unicorn or the project's own C++ core): it boots a flash dump or an official update image, runs the box's application, draws its OSD through models of the graphics engine and display layers, and lets you drive it with a virtual remote, the front-panel keys and the firmware's UART console. The general introduction -- what is emulated and how (display, front panel, remote, tests, the C++ engine) -- is the article at https://www.elektroda.pl/rtvforum/topic4186501.html (Polish). The self-test report with a screenshot of every supported box is published at https://openshwprojects.github.io/AliSimulator/ after every push.

Quick start: `pip install unicorn capstone numpy pillow`, then `python src/tv_gui.py dump_maciej.bin` (the TV window: pick any image from the toolbar), `python src/gui_simulator.py` (the debugger) or `python run_all_tests.py [--slow] [--engine cpp]` (the tests; `--slow` adds the screen regressions). The C++ engine builds with `cpp\build.bat` (MSVC) or `sh cpp/build.sh` (g++) and is selected with `ALISIM_ENGINE=cpp`. The images and their sidecar JSON files (chip, tuner, panel pins, IR coding, where the image came from) are in `dumps/`, one row per image in `dumps/README.md`; the detailed developer notes that used to be this README are in `docs/development_notes.md`.

## Supported chips

| Chip | Module | Chip ID | Receivers | Boxes in `dumps/` | Images | Second CPU (SEE) |
|---|---|---|---|---|---|---|
| ALi M3801 / M3612 (the silicon reports itself as S3811) | `src/chips/m3801.py` | 0x3811 | DVB-T HD (Underline 3in1: DVB-S2 + DVB-T2/C combo) | Comsat TE 1050 HD, Opticum STB HD N2, Globo STB HD N3, Opticum HD T90, Cabletech URZ0083Q / URZ0194S / URZ0195, Strong SRT 8115, Strong Prima VIII, Ferguson Ariva T650i, Edision Optimuss Underline 3in1 | 13 (+ the SDK test program `ali_sdk.bin`) | no |
| ALi M3601E / M3601S / M3602 / M3606 (the M36xx family) | `src/chips/m3602.py` | 0x3602 (Ariva T50, Opticum HD X4 220 / HD X7 / X402p-403p, Yumatu Full HD IQ), 0x3603 (the others, from the sidecar) | DVB-T and DVB-S2 HD | Cabletech URZ0083 / URZ0086, Kruger&Matz KM0183 / KM0186, Thomson THT501, Ferguson Ariva T50 / Ariva 52E, Opticum HD S50 / HD S60 / HD X4 220 / HD X7 / HD X402p-403p / HD X110p / X110TS, Yumatu Full HD IQ, Openbox S16 HD PVR / S16 EU 3606C, Amiko Mini HD, Edision Argus Miniplus Highspeed / Argus VIP3 / Optimuss Underline | 57 | M3606 / S3606H: yes (the `seecode` chunk) |
| ALi M3503 / M3510 / M3511 / M3515 / M3516A | `src/chips/m3503.py` | 0x3503 (0x35030001 rev B on M3510B / M3511 / M3515 / M3516A) | DVB-S2 HD (XS65 Combo / HD8260+ / X-Finder 2: + DVB-T2/C; XS65 Combo / XS65 Twin / HD8260+ / X-Finder 2: 256 MB DDR3) | Globo HD-XS2 / Opticum Blue XS65 / XS65 Combo / XS65 Twin, Echosonic Mini ESR-250, Amiko Impulse SAT / HD8150 / HD8260+ / X-Finder 2 | 11 | ESR-250: no; the others: yes |
| ALi C3503C / C3503D (M3510D) | `src/chips/c3503.py` | 0x3503 (0x3503C000 on C3503C, 0x3503D000 on C3503D) | DVB-S2 HD | Ferguson Ariva 53 / Ariva 54, Edision Picco S2 | 3 | no |
| ALi C3505 (M3521A / M3526A / M3529A / M3529F / M3626A / M3712A / M3716A) | `src/chips/c3505.py` | 0x3505 | DVB-S2, DVB-T2/C and DVB-C HD with HEVC (255 Combo / 255 Combo S / Mini Combo Extra / HD8265+ / HD8275+ / X-Finder 3: 256 MB DDR3) | Ferguson Ariva 104 / 154 Combo / 204 / 254 Combo / 255 Combo / 255 Combo S / T760i, Amiko HD8140C SE / HD8142 Twin-C / HD8155 / HD8265+ / HD8275+ / Impulse H.265 T2/C / Mini Combo Extra / X-Finder 3 | 37 | yes |
| ALi M3821 / M3821A / M3822P | `src/chips/m3821.py` | 0x3821 | DVB-T2/C HD with HEVC | Ferguson Ariva T750i, Opticum Blue R265 Lite, Amiko T58, Amiko Eco TC-200 | 6 | T750i, Eco TC-200: yes; R265 Lite, Amiko T58: no |
| ALi M3329 / M3329C / M3329E (M3327 platform) | `src/chips/m3329.py` | 0x3329 (0x3101 on M3329C / M3101C) | DVB-S SD (2005-2010) | satellite receiver board s15125, Opticum X80 Premium / 7300 PVR CI2CX / 4000A (Globo 7010A), BigSat DSR 6500 Lux, Echolink EL-700 FTA | 6 | no |

Every family boots its bootloader and application, draws its first OSD screen and answers the remote in the test suite; the per-box details are in the last table. Two images stop at their bootloader because their main code is encrypted for an external board security chip that is not modelled: the Ferguson Ariva 52E (I2C 0x62, `run_dump_a52e_security_ic.py`) and the Echolink EL-700 FTA (an 8051 security MCU over UART2 at 0xB8001400 supplying XTEA keys, `run_dump_el700_security_mcu.py`). The M3329 boards boot from either parallel NOR or SPI flash and draw their OSD with the CPU (`OSD_M3327C`, or `GeM3602` at 0xB800E000 on the M3329E 7300 PVR); the T750i and newer C3505 / M3821A firmwares drive the display engine through register lists in RAM; the Ariva T50 draws with the M3602's own graphics engine (`src/ge_m3602.py`); everything else draws through the GE at 0xB800A000 (`src/ge_m36f.py`) and the GMA display layers (`src/gma_capture.py`).

## Front-panel display chips

| Chip | Bus | Boxes (GPIO) | Modelled |
|---|---|---|---|
| TM1650 | I2C bit-banged on two GPIOs (`src/tm1650_decoder.py`) | Opticum STB HD N2, Globo STB HD N3, Opticum HD T90 (SCL 31 / SDA 9); Opticum HD X110p / X110TS (9 / 8); Globo HD-XS2, Echosonic ESR-250 (135 / 134); Openbox S16 / S16 EU, Opticum HD S60 (62 / 63); the M3329 board (15 / 16) | 4 digits in the TV window, brightness and on/off, the key matrix KI1-7 x DIG1-4 answered on SDA when a panel button is pressed |
| FD650K (TM1650-compatible) | the same | Ferguson Ariva T650i (31 / 9), Ariva 54 (24 / 23), T750i (128 / 129), Ariva 104 and T760i (107 / 110), Ariva 154 / 204 / 254 / 255 / 255 S (107 / 108), Opticum XS65 Combo / XS65 Twin (135 / 134) | the same decoder with Ferguson's digit layout and 8-key map |
| CH455 (TM1650-compatible) | the same | Opticum X80 Premium (30 / 31), Edision Optimuss Underline 3in1 (31 / 9), Edision Picco S2 (24 / 23), Amiko T58 / Eco TC-200 (128 / 129), Amiko HD8155 / Impulse H.265 / Mini Combo Extra (107 / 110), Amiko HD8140C SE / HD8142 Twin-C / HD8265+ / HD8275+ / X-Finder 3 (107 / 108), Amiko Impulse SAT / HD8150 / HD8260+ (135 / 134) | the same 4-digit display and key matrix protocol |
| HD2015 (TM1650-compatible) | the same | Opticum Blue R265 Lite (57 / 58; no display soldered, three buttons) | keys |
| Lemontree EuP MCU | I2C 0x28 bit-banged on two GPIOs (`src/lemontree_decoder.py`) | Opticum HD X4 220 / HD X7 / X402p-403p, Yumatu Full HD IQ (SCL 62 / SDA 171); Edision Argus VIP3 (103 / 102); Amiko X-Finder 2 (135 / 134) | 8-byte CRC-16/XMODEM command frames, 4-digit / 8-char VFD text and front-panel key polling |
| TM1628-class | 3-wire: CLK, DIO, STB (`src/tm1628_decoder.py`) | Cabletech URZ0083Q, URZ0194S, Strong SRT 8115 (31 / 9 / 11) | 4 digits, the key matrix KS1-10 x K1-2 |
| uPD16312 / PT6312-class | 3-wire | Cabletech URZ0195 (31 / 9 / STB 14), Opticum 7300 PVR (3 / 2 / STB 4, 14-segment 8-char VFD) | the same command set, 7-segment LED and 14-segment VFD digit wirings |
| PT6964 (TM1628-class) | 3-wire | Ferguson Ariva 52E (CLK 65 / DIO 66 / STB 64) | the command set and the display RAM; the digits' segment wiring is not known |
| 74HC164 shift register + 4-digit LED | CLK, DATA + 4 digit strobes (`src/hc164_decoder.py`) | BigSat DSR 6500 Lux, Opticum 4000A / Globo 7010A (CLK 16 / DATA 17 / DIG 18..21) | time-multiplexed 4-digit 7-segment scan decoded to stable display text |
| none | buttons straight on GPIO inputs (`src/gpio_keys.py`) | Comsat TE 1050 HD, Strong Prima VIII (GPIO 31 / 9) | two buttons, modelled released |

Which chip and which pins a box has is in its sidecar (`device.panel`); `src/front_panel.py` builds the decoder for a dump from it.

## Tuners and demodulators

| Chip | What it is | Boxes | Model (`src/tuners.py`, `src/demods.py`) |
|---|---|---|---|
| Rafael Micro R820T | DVB-T silicon tuner, I2C 0x1A | Globo STB HD N3 (and the HD T90 update) | register file, filter and image-rejection calibration, PLL lock; bit-reversed status reads |
| Rafael Micro R836 / R840 / R850 | DVB-T2/C silicon tuner | Ferguson Ariva 154 / 254 / 255 Combo, Ariva 255 Combo S (R840), Amiko T58, Edision Optimuss Underline 3in1, Opticum Blue R265 Lite firmware's driver | 49 registers, both read protocols |
| Rafael Micro R858 | dual-path DVB-C silicon tuner, I2C 0x6A | Amiko HD8142 Twin-C | dual-path register file, bit-reversed status reads, PLL lock |
| MaxLinear MxL603 / MxL608 | DVB-T/T2/C silicon tuner, I2C 0x60 / 0x63 | Cabletech URZ0083Q / URZ0194S / URZ0195, Comsat TE 1050 HD, Strong SRT 8115, Ferguson Ariva T650i / T750i, Amiko HD8140C SE / X-Finder 3 (MxL603); Opticum Blue R265 Lite, Amiko Impulse H.265 / HD8260+ / HD8265+ / HD8275+ (MxL608) | register protocol, lock status, tuned frequency and bandwidth decoded |
| MaxLinear MxL5007T | DVB-T silicon tuner | Ferguson Ariva T50, Cabletech URZ0195 (2012 firmware) | the same |
| MaxLinear MxL101SF | DVB-T tuner + demodulator in one chip | Cabletech URZ0086, Kruger&Matz KM0186, Thomson THT501, Opticum X110TS (terrestrial side) | registers, lock |
| Airoha AV2011 / AV2012 | DVB-S2 silicon tuner, I2C 0x60 / 0x61 / 0x63 | Opticum HD X4 220 / HD X7 / X402p-403p / HD X110p / X110TS, Yumatu Full HD IQ, Edision Argus VIP3, Openbox S16 EU, Globo HD-XS2 / Opticum Blue XS65 / XS65 Combo / XS65 Twin (AV2011); Edision Optimuss Underline 3in1, Amiko HD8260+ / HD8265+ / HD8275+ (AV2012 at 0x61) | PLL lock, the fractional-N divider decoded to a frequency |
| Silicon Labs Si2144 | DVB-T2/C silicon tuner | Strong Prima VIII | command / property protocol with its status bytes |
| ALi M3031 | DVB-S2 silicon tuner, I2C 0x20 | Ferguson Ariva 53 / 54 / 104 / 154 Combo / 204 / 254 Combo / 255 Combo | chip ID, lock |
| RDA Microelectronics RDA5815 / RDA5816 | DVB-S2 silicon tuner, I2C 0x60 / 0x0C | Echosonic Mini ESR-250 (RDA5815), Ferguson Ariva 255 Combo S (RDA5816 at 0x0C) | chip ID, lock, 24-bit / 32-bit fractional-N PLL decoded |
| ALi S3501-class DVB-S2 demodulator | the M36xx chips' DVB-S2 demodulator on I2C 0x33 (sidecar `demodModel`); the same core sits inside the M3503 / C3505 at 0xB8028000 and the C3503 at 0xB804C000 | Openbox S16 / S16 EU, Opticum HD S50 / S60 / X4 220 / X7 / X402p-403p, Yumatu Full HD IQ, Amiko Mini HD, Edision Argus / VIP3 / Optimuss, Opticum XS65 Twin (second tuner on GPIO 6 / 7); on-chip: Globo HD-XS2, Opticum XS65 Combo, Echosonic ESR-250, Edision Picco S2, Amiko Impulse SAT / HD8150 / HD8155 / HD8260+ / HD8265+ / HD8275+ / Mini Combo Extra / X-Finder 3, Ferguson Ariva 53 / 54 / 104 / 154 / 204 / 254 / 255 / 255 S | chip ID, lock and signal-quality registers |
| AltoBeam ATBM7812 | DVB-T2 demodulator with an I2C repeater to its tuner | Ferguson Ariva 154 / 254 Combo, T760i | chip ID, gateway, lock |
| Availink AVL6862 / AVL6762 | DVB-T2/C (and DVB-S2 on AVL6862) demodulator on SCB0, SCB3 (0xB8018D00) or bit-banged GPIO I2C, I2C 0x14 | Edision Optimuss Underline 3in1 (AVL6862 on SCB0), Ferguson Ariva 255 Combo / 255 Combo S (AVL6862 on SCB3), Amiko HD8265+ / HD8275+ / X-Finder 3 (AVL6762 on SCB3), Amiko HD8260+ (AVL6762 on GPIO 7 / 8), Amiko Impulse H.265 (AVL6762 on GPIO 105 / 104) | 24-bit big-endian registers, FamilyID / ChipID, patch decompression, core ready word & command mailbox |
| on-chip demodulators | the M3801's DVB-T (NIM_S3811), the M3503's DVB-S2 (NIM_S3503), the M3821's DVB-T2, the M3712A / M3716A's DVB-C (NIM_S3281) | Globo N3, Opticum N2, Comsat, the HD-XS2, the T750i, Amiko T58 / Eco TC-200 / HD8140C SE / HD8142 Twin-C and the other boxes without an external demodulator | a lock the firmware sees once "Signal + TS" is on (`src/chips/base.py`) |

With "Signal + TS" on, the tuner reports a lock and the demultiplexer model (`src/dmx_m36.py`) is fed a synthetic DVB transport stream from `src/transport_stream.py`, so channel scans find and store services.

## Tested devices

One row per box (68 boxes, 133 images; the SDK test program `ali_sdk.bin` is not listed). "Boots", "App runs" and "OSD drawn" are what the sidecar records for the box's images; "Remote", "UART console" and "Signal + TS" mean a test in `tests/` covers it on that box (a `-` there means not tested, not necessarily not working).

| Box | SoC | Front panel (GPIO) | Tuner | Images | Boots | App runs | OSD drawn | Remote | UART console | Signal + TS |
|---|---|---|---|---|---|---|---|---|---|---|
| Amiko Eco TC-200 | M3821A | CH455 (SCL 128, SDA 129) | internal DVB-T2/C | 1 | yes | yes | yes | - | - | - |
| Amiko HD8140C SE | M3712A / C3505 | CH455 (SCL 107, SDA 108) | MxL603 | 1 | yes | yes | yes | - | - | - |
| Amiko HD8142 Twin-C | M3716A / C3505 | CH455 (SCL 107, SDA 108) | R858 | 1 | yes | yes | yes | - | - | - |
| Amiko HD8150 | M3511D / M3503 | CH455 (SCL 135, SDA 134) | AV2026 | 1 | yes | yes | yes | - | - | - |
| Amiko HD8155 | C3505 | CH455 (SCL 107, SDA 110) | internal DVB-S2 | 1 | yes | yes | yes | - | - | - |
| Amiko HD8260+ | M3516A / M3503 (256 MB, 16 MB flash) | CH455 (SCL 135, SDA 134) | AV2012 + MxL608 (AVL6762) | 1 | yes | yes | yes | - | - | - |
| Amiko HD8265+ | C3505 (256 MB) | CH455 (SCL 107, SDA 108) | AV2012 + MxL608 (AVL6762) | 1 | yes | yes | yes | - | - | - |
| Amiko HD8275+ | M3529A / C3505 (256 MB) | CH455 (SCL 107, SDA 108) | AV2012 + MxL608 (AVL6762) | 1 | yes | yes | yes | - | - | - |
| Amiko Impulse H.265 T2/C | M3626A / C3505 | CH455 (SCL 107, SDA 110) | MxL608 (AVL6762) | 1 | yes | yes | yes | - | - | - |
| Amiko Impulse SAT | M3510B / M3503 | CH455 (SCL 135, SDA 134) | AV2026 | 1 | yes | yes | yes | - | - | - |
| Amiko Mini Combo Extra | M3526A / C3505 (256 MB) | CH455 (SCL 107, SDA 110) | internal DVB-S2 + DVB-T2/C | 1 | yes | yes | yes | - | - | - |
| Amiko Mini HD | M3606 / C3603 | - | - | 1 | yes | yes | yes | - | - | - |
| Amiko T58 | M3821 | CH455 (SCL 128, SDA 129) | R836 | 1 | yes | yes | yes | yes | - | - |
| Amiko X-Finder 2 | M3516A / M3503 (256 MB, 16 MB flash) | Lemontree meter MCU (SCL 135, SDA 134) | AV2011 / AV2012 + AVL6762 | 1 | yes | yes | yes | - | - | - |
| Amiko X-Finder 3 | M3529F / C3505 (256 MB) | CH455 keypad (SCL 107, SDA 108) | AV2011 + MxL603 (AVL6762) | 1 | yes | yes | yes | - | - | - |
| BigSat DSR 6500 Lux | M3329C | 74HC164 + 4-digit LED (CLK 16, DATA 17, DIG 18..21) | internal DVB-S | 1 | yes | yes | yes | - | - | - |
| Cabletech URZ0083 | M3601E | - | - | 8 | yes | yes | yes | yes | - | - |
| Cabletech URZ0083Q | M3801 | TM1628-class 3-wire (CLK 31, DIO 9, STB 11) | MxL603 | 1 | yes | yes | yes | yes | - | - |
| Cabletech URZ0086 | M3606 | - | MxL101SF | 5 | yes | yes | yes | yes | - | - |
| Cabletech URZ0194S | M3801 | TM1628-class 3-wire (CLK 31, DIO 9, STB 11) | MxL603 | 1 | yes | yes | yes | yes | - | - |
| Cabletech URZ0195 | M3801 | uPD16312-class 3-wire (CLK 31, DIO 9, STB 14) | MxL5007T / MxL603 | 2 | yes | yes | yes | yes | - | - |
| Comsat TE 1050 HD | M3801 | no driver, 2 buttons (GPIO 31 / 9) | MxL603 | 1 | yes | yes | yes | yes | - | yes |
| Echolink EL-700 FTA | M3329C | SMTM51 MCU on UART2 (0xB8001400) | - | 1 | yes (bootloader only: main code is XTEA-encrypted for the board's security MCU) | no | no | - | - | - |
| Echosonic Mini ESR-250 | M3510A | TM1650-compatible (SCL 135, SDA 134) | RDA5815 | 1 | yes | yes | yes | yes | - | - |
| Edision Argus Miniplus Highspeed | M3606 / C3603 | - | - | 1 | yes | yes | yes | - | - | - |
| Edision Argus VIP3 | M3606C / C3603 | Lemontree EuP MCU (SCL 103, SDA 102) | AV2011 (S3501) | 1 | yes | yes | yes | - | - | - |
| Edision Optimuss Underline | M3606 / C3603 | - | - | 1 | yes | yes | yes | - | - | - |
| Edision Optimuss Underline 3in1 | M3612 / M3801 | CH455 (SCL 31, SDA 9) | AV2012 + R836 (AVL6862) | 1 | yes | yes | yes | - | - | - |
| Edision Picco S2 | M3510D / C3503D | CH455 (SCL 24, SDA 23) | internal DVB-S2 | 1 | yes | yes | yes | - | - | - |
| Ferguson Ariva 104 | C3505 | FD650K (SCL 107, SDA 110) | M3031 | 3 | yes | yes | yes | yes | - | - |
| Ferguson Ariva 154 Combo | C3505 | FD650K (SCL 107, SDA 108) | M3031 + R836 | 7 | yes | yes | yes | - | - | - |
| Ferguson Ariva 204 | C3505 | FD650K (SCL 107, SDA 108) | M3031 | 4 | yes | yes | yes | - | - | - |
| Ferguson Ariva 254 Combo | C3505 | FD650K (SCL 107, SDA 108) | M3031 + R836 | 9 | yes | yes | yes | - | - | - |
| Ferguson Ariva 255 Combo | C3505 (256 MB) | FD650K (SCL 107, SDA 108) | M3031 + R836 (AVL6862) | 1 | yes | yes | yes | yes | - | - |
| Ferguson Ariva 255 Combo S | C3505 (256 MB) | FD650K (SCL 107, SDA 108) | RDA5816 + R840 (AVL6862) | 1 | yes | yes | yes | yes | - | - |
| Ferguson Ariva 52E | M3606 class | PT6964 3-wire (CLK 65, DIO 66, STB 64) | - | 1 | yes (bootloader only: the main code needs the board's security IC) | no | no | - | - | - |
| Ferguson Ariva 53 | C3503C | - | M3031 | 1 | yes | yes | yes | yes | - | - |
| Ferguson Ariva 54 | C3503D | FD650K (SCL 24, SDA 23) | M3031 | 1 | yes | yes | yes | yes | - | - |
| Ferguson Ariva T50 | M3602 | - | MxL5007T | 1 | yes | yes | yes | yes | - | - |
| Ferguson Ariva T650i | M3801 | FD650K (SCL 31, SDA 9) | MxL603 | 1 | yes | yes | yes | yes | - | yes |
| Ferguson Ariva T750i | M3821 | FD650K (SCL 128, SDA 129) | MxL603 | 1 | yes | yes | yes | yes | - | - |
| Ferguson Ariva T760i | C3505 | FD650K (SCL 107, SDA 110) | - | 4 | yes | yes | yes | yes | - | - |
| Globo HD-XS2 / Opticum Blue XS65 | M3503 | TM1650-compatible (SCL 135, SDA 134) | AV2011 | 4 | yes | yes | yes | yes | yes | - |
| Globo STB HD N3 | M3801 | TM1650 (SCL 31, SDA 9) | R820T | 1 | yes | yes | yes | yes | yes | yes |
| Kruger&Matz KM0183 | M3601E | - | - | 3 | yes | yes | yes | - | - | - |
| Kruger&Matz KM0186 | M3606 | - | MxL101SF | 3 | yes | yes | yes | - | - | - |
| Openbox S16 HD PVR | M3601S | TM1650-compatible (SCL 62, SDA 63) | - | 1 | yes | yes | yes | yes | - | - |
| Openbox S16 HD PVR (EU ALi 3606C) | S3606H / M3606C | TM1650-compatible (SCL 62, SDA 63) | AV2011 (S3501) | 1 | yes | yes | yes | yes | - | - |
| Opticum 4000A / Globo 7010A | M3329C | 74HC164 + 4-digit LED (CLK 16, DATA 17, DIG 18..21) | internal DVB-S | 1 | yes | yes | yes | yes | - | - |
| Opticum 7300 PVR CI2CX | M3329E | PT6312 14-segment VFD (CLK 3, DIO 2, STB 4) | internal DVB-S | 1 | yes | yes | yes | yes | - | - |
| Opticum Blue R265 Lite | M3822P | HD2015 (SCL 57, SDA 58) | MxL608 | 3 | yes | yes | yes | yes | yes | yes |
| Opticum HD S50 | M3601S | - | - | 2 | yes | yes | yes | yes | - | - |
| Opticum HD S60 | M3601S | TM1650-compatible (SCL 62, SDA 63) | - | 2 | yes | yes | yes | yes | - | - |
| Opticum HD T90 (update for the T90 / STB HD N2 / N3 boards) | M3801 | TM1650 (SCL 31, SDA 9) | R820T | 1 | yes | yes | yes | yes | yes | - |
| Opticum HD X4 220 | M3602B | Lemontree EuP MCU (SCL 62, SDA 171) | AV2011 (S3501) | 1 | yes | yes | yes | - | - | - |
| Opticum HD X402p / X403p | M3602B | Lemontree EuP MCU (SCL 62, SDA 171) | AV2011 (S3501) | 1 | yes | yes | yes | - | - | - |
| Opticum HD X7 Combo | M3602A | Lemontree EuP MCU + VFD (SCL 62, SDA 171) | AV2011 (S3501) | 1 | yes | yes | yes | - | - | - |
| Opticum HD X110p | M3606 | TM1650-compatible (SCL 9, SDA 8) | AV2011 | 10 | yes | yes | yes | yes | yes | - |
| Opticum STB HD N2 | M3801 | TM1650 (SCL 31, SDA 9) | unknown | 1 | yes | yes | yes | yes | yes | - |
| Opticum X110TS | M3606 | TM1650-compatible (SCL 9, SDA 8) | AV2011 + MxL101SF | 9 | yes | yes | yes | yes | yes | - |
| Opticum X80 Premium | M3329C | CH455 (SCL 30, SDA 31) | internal DVB-S | 1 | yes | yes | yes | yes | - | - |
| Opticum XS65 Combo | M3515 / M3503 (256 MB) | FD650K (SCL 135, SDA 134) | AV2011 | 1 | yes | yes | yes | yes | - | - |
| Opticum XS65 Twin | M3511 / M3503 (256 MB) | FD650K (SCL 135, SDA 134) | AV2011 (2x DVB-S2, S3501) | 1 | yes | yes | yes | yes | - | - |
| Satellite board s15125 (2005) | M3329 | TM1650-compatible (SCL 15, SDA 16) | - | 1 | yes | yes | yes | yes | - | - |
| Strong Prima VIII | M3801 | no driver, 2 buttons (GPIO 31 / 9) | MxL603 / Si2144 | 2 | yes | yes | yes | yes | - | - |
| Strong SRT 8115 | M3801 | TM1628-class 3-wire (CLK 31, DIO 9, STB 11) | MxL603 | 1 | yes | yes | yes | yes | - | - |
| Thomson THT501 | M36xx | - | MxL101SF | 3 | yes | yes | yes | yes | - | - |
| Yumatu Full HD IQ / HD X4 | M3602B | Lemontree EuP MCU (SCL 62, SDA 171) | AV2011 (S3501) | 1 | yes | yes | yes | - | - | - |
