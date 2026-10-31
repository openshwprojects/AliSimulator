# AliSimulator

An emulator of ALi set-top-box firmware (MIPS32 + MIPS16e, Unicorn or the project's own C++ core): it boots a flash dump or an official update image, runs the box's application, draws its OSD through models of the graphics engine and display layers, and lets you drive it with a virtual remote, the front-panel keys and the firmware's UART console. The general introduction -- what is emulated and how (display, front panel, remote, tests, the C++ engine) -- is the article at https://www.elektroda.pl/rtvforum/topic4186501.html (Polish). The self-test report with a screenshot of every supported box is published at https://openshwprojects.github.io/AliSimulator/ after every push.

Quick start: `pip install unicorn capstone numpy pillow`, then `python src/tv_gui.py dump_maciej.bin` (the TV window: pick any image from the toolbar), `python src/gui_simulator.py` (the debugger) or `python run_all_tests.py [--slow] [--engine cpp]` (the tests; `--slow` adds the screen regressions). The C++ engine builds with `cpp\build.bat` (MSVC) or `sh cpp/build.sh` (g++) and is selected with `ALISIM_ENGINE=cpp`. The images and their sidecar JSON files (chip, tuner, panel pins, IR coding, where the image came from) are in `dumps/`, one row per image in `dumps/README.md`; the detailed developer notes that used to be this README are in `docs/development_notes.md`.

## Supported chips

| Chip | Module | Chip ID | Receivers | Boxes in `dumps/` | Images | Second CPU (SEE) |
|---|---|---|---|---|---|---|
| ALi M3801 (the silicon reports itself as S3811) | `src/chips/m3801.py` | 0x3811 | DVB-T HD | Comsat TE 1050 HD, Opticum STB HD N2, Globo STB HD N3, Opticum HD T90, Cabletech URZ0083Q / URZ0194S / URZ0195, Strong SRT 8115, Strong Prima VIII, Ferguson Ariva T650i | 12 (+ the SDK test program `ali_sdk.bin`) | no |
| ALi M3601E / M3601S / M3602 / M3606 (the M36xx family) | `src/chips/m3602.py` | 0x3602 (Ariva T50), 0x3603 (the others, from the sidecar) | DVB-T and DVB-S2 HD | Cabletech URZ0083 / URZ0086, Kruger&Matz KM0183 / KM0186, Thomson THT501, Ferguson Ariva T50, Opticum HD S50 / HD S60 / HD X110p / X110TS, Openbox S16 HD PVR, Amiko Mini HD, Edision Argus Miniplus Highspeed / Optimuss Underline | 50 | M3606: yes (the `seecode` chunk) |
| ALi M3503 / M3510A | `src/chips/m3503.py` | 0x3503 | DVB-S2 HD | Globo HD-XS2 / Opticum Blue XS65, Echosonic Mini ESR-250 | 5 | yes |
| ALi C3505 | `src/chips/c3505.py` | 0x3505 | DVB-S2 HD with HEVC (154 / 254 Combo: + DVB-T2/C) | Ferguson Ariva 104 / 154 Combo / 204 / 254 Combo / T760i | 27 | yes |
| ALi M3821 / M3822P | `src/chips/m3821.py` | 0x3821 | DVB-T2 HD with HEVC | Ferguson Ariva T750i, Opticum Blue R265 Lite | 4 | T750i: yes; R265 Lite: no |
| ALi M3329 (M3327 platform) | `src/chips/m3329.py` | 0x3329 | DVB-S SD (2005) | satellite receiver board s15125 | 1 | no |

Every family boots its bootloader and application, draws its first OSD screen and answers the remote in the test suite; the per-box details are in the last table. The M3329 runs its application in place from a parallel NOR flash and draws its OSD with the CPU; the T750i's firmware drives the newer display engine (register lists in RAM); the Ariva T50 draws with the M3602's own graphics engine (`src/ge_m3602.py`); everything else draws through the GE at 0xB800A000 (`src/ge_m36f.py`) and the GMA display layers (`src/gma_capture.py`).

## Front-panel display chips

| Chip | Bus | Boxes (GPIO) | Modelled |
|---|---|---|---|
| TM1650 | I2C bit-banged on two GPIOs (`src/tm1650_decoder.py`) | Opticum STB HD N2, Globo STB HD N3, Opticum HD T90 (SCL 31 / SDA 9); Opticum HD X110p / X110TS (9 / 8); Globo HD-XS2, Echosonic ESR-250 (135 / 134); Openbox S16, Opticum HD S60 (62 / 63); the M3329 board (15 / 16) | 4 digits in the TV window, brightness and on/off, the key matrix KI1-7 x DIG1-4 answered on SDA when a panel button is pressed |
| FD650K (TM1650-compatible) | the same | Ferguson Ariva T650i (31 / 9), T750i (128 / 129), Ariva 104 and T760i (107 / 110), Ariva 154 / 204 / 254 (107 / 108) | the same decoder with Ferguson's digit layout and 8-key map |
| HD2015 (TM1650-compatible) | the same | Opticum Blue R265 Lite (57 / 58; no display soldered, three buttons) | keys |
| TM1628-class | 3-wire: CLK, DIO, STB (`src/tm1628_decoder.py`) | Cabletech URZ0083Q, URZ0194S, Strong SRT 8115 (31 / 9 / 11) | 4 digits, the key matrix KS1-10 x K1-2 |
| uPD16312 / PT6312-class | 3-wire | Cabletech URZ0195 (31 / 9 / STB 14) | the same command set, its own digit wiring |
| none | buttons straight on GPIO inputs (`src/gpio_keys.py`) | Comsat TE 1050 HD, Strong Prima VIII (GPIO 31 / 9) | two buttons, modelled released |

Which chip and which pins a box has is in its sidecar (`device.panel`); `src/front_panel.py` builds the decoder for a dump from it.

## Tuners and demodulators

| Chip | What it is | Boxes | Model (`src/tuners.py`, `src/demods.py`) |
|---|---|---|---|
| Rafael Micro R820T | DVB-T silicon tuner, I2C 0x1A | Globo STB HD N3 (and the HD T90 update) | register file, filter and image-rejection calibration, PLL lock; bit-reversed status reads |
| Rafael Micro R836 / R840 / R850 | DVB-T2/C silicon tuner | Ferguson Ariva 154 / 254 Combo (the terrestrial side), Opticum Blue R265 Lite firmware's driver | 49 registers, both read protocols |
| MaxLinear MxL603 / MxL608 | DVB-T/T2/C silicon tuner, I2C 0x60 / 0x63 | Cabletech URZ0083Q / URZ0194S / URZ0195, Comsat TE 1050 HD, Strong SRT 8115, Ferguson Ariva T650i / T750i, Opticum Blue R265 Lite (MxL608) | register protocol, lock status, tuned frequency and bandwidth decoded |
| MaxLinear MxL5007T | DVB-T silicon tuner | Ferguson Ariva T50, Cabletech URZ0195 (2012 firmware) | the same |
| MaxLinear MxL101SF | DVB-T tuner + demodulator in one chip | Cabletech URZ0086, Kruger&Matz KM0186, Thomson THT501, Opticum X110TS (terrestrial side) | registers, lock |
| Airoha AV2011 | DVB-S2 silicon tuner, I2C 0x60 / 0x63 | Opticum HD X110p / X110TS, Globo HD-XS2 / Opticum Blue XS65 | PLL lock, the fractional-N divider decoded to a frequency |
| Silicon Labs Si2144 | DVB-T2/C silicon tuner | Strong Prima VIII | command / property protocol with its status bytes |
| ALi M3031 | DVB-S2 silicon tuner, I2C 0x20 | Ferguson Ariva 104 / 154 Combo / 204 / 254 Combo | chip ID, lock |
| RDA Microelectronics RDA5815 | DVB-S2 silicon tuner, I2C 0x60 | Echosonic Mini ESR-250 | chip ID, lock |
| ALi S3501-class DVB-S2 demodulator | the M36xx chips' DVB-S2 demodulator on I2C 0x33 (sidecar `demodModel`); the same core sits inside the M3503 / M3510A at 0xB8028000 | Openbox S16, Opticum HD S50 / S60, Amiko Mini HD, Edision Argus / Optimuss (the X110p / X110TS read its chip ID); on-chip: Globo HD-XS2, Echosonic ESR-250 | chip ID, lock and signal-quality registers |
| AltoBeam ATBM7812 | DVB-T2 demodulator with an I2C repeater to its tuner | Ferguson Ariva 154 / 254 Combo | chip ID, gateway, lock |
| on-chip demodulators | the M3801's DVB-T (NIM_S3811), the M3503's DVB-S2 (NIM_S3503), the M3821's DVB-T2 | Globo N3, Opticum N2, Comsat, the HD-XS2, the T750i and the other boxes without an external demodulator | a lock the firmware sees once "Signal + TS" is on (`src/chips/base.py`) |

With "Signal + TS" on, the tuner reports a lock and the demultiplexer model (`src/dmx_m36.py`) is fed a synthetic DVB transport stream from `src/transport_stream.py`, so channel scans find and store services.

## Tested devices

One row per box (34 boxes, 99 images; the SDK test program `ali_sdk.bin` is not listed). "Boots", "App runs" and "OSD drawn" are what the sidecar records for the box's images; "Remote", "UART console" and "Signal + TS" mean a test in `tests/` covers it on that box (a `-` there means not tested, not necessarily not working).

| Box | SoC | Front panel (GPIO) | Tuner | Images | Boots | App runs | OSD drawn | Remote | UART console | Signal + TS |
|---|---|---|---|---|---|---|---|---|---|---|
| Amiko Mini HD | M3606 / C3603 | - | - | 1 | yes | yes | yes | - | - | - |
| Cabletech URZ0083 | M3601E | - | - | 8 | yes | yes | yes | yes | - | - |
| Cabletech URZ0083Q | M3801 | TM1628-class 3-wire (CLK 31, DIO 9, STB 11) | MxL603 | 1 | yes | yes | yes | yes | - | - |
| Cabletech URZ0086 | M3606 | - | MxL101SF | 5 | yes | yes | yes | yes | - | - |
| Cabletech URZ0194S | M3801 | TM1628-class 3-wire (CLK 31, DIO 9, STB 11) | MxL603 | 1 | yes | yes | yes | yes | - | - |
| Cabletech URZ0195 | M3801 | uPD16312-class 3-wire (CLK 31, DIO 9, STB 14) | MxL5007T / MxL603 | 2 | yes | yes | yes | yes | - | - |
| Comsat TE 1050 HD | M3801 | no driver, 2 buttons (GPIO 31 / 9) | MxL603 | 1 | yes | yes | yes | yes | - | yes |
| Echosonic Mini ESR-250 | M3510A | TM1650-compatible (SCL 135, SDA 134) | RDA5815 | 1 | yes | yes | yes | yes | - | - |
| Edision Argus Miniplus Highspeed | M3606 / C3603 | - | - | 1 | yes | yes | yes | - | - | - |
| Edision Optimuss Underline | M3606 / C3603 | - | - | 1 | yes | yes | yes | - | - | - |
| Ferguson Ariva 104 | C3505 | FD650K (SCL 107, SDA 110) | M3031 | 3 | yes | yes | yes | yes | - | - |
| Ferguson Ariva 154 Combo | C3505 | FD650K (SCL 107, SDA 108) | M3031 + R836 | 7 | yes | yes | yes | - | - | - |
| Ferguson Ariva 204 | C3505 | FD650K (SCL 107, SDA 108) | M3031 | 4 | yes | yes | yes | - | - | - |
| Ferguson Ariva 254 Combo | C3505 | FD650K (SCL 107, SDA 108) | M3031 + R836 | 9 | yes | yes | yes | - | - | - |
| Ferguson Ariva T50 | M3602 | - | MxL5007T | 1 | yes | yes | yes | yes | - | - |
| Ferguson Ariva T650i | M3801 | FD650K (SCL 31, SDA 9) | MxL603 | 1 | yes | yes | yes | yes | - | yes |
| Ferguson Ariva T750i | M3821 | FD650K (SCL 128, SDA 129) | MxL603 | 1 | yes | yes | yes | yes | - | - |
| Ferguson Ariva T760i | C3505 | FD650K (SCL 107, SDA 110) | - | 4 | yes | yes | yes | yes | - | - |
| Globo HD-XS2 / Opticum Blue XS65 | M3503 | TM1650-compatible (SCL 135, SDA 134) | AV2011 | 4 | yes | yes | yes | yes | yes | - |
| Globo STB HD N3 | M3801 | TM1650 (SCL 31, SDA 9) | R820T | 1 | yes | yes | yes | yes | yes | yes |
| Kruger&Matz KM0183 | M3601E | - | - | 3 | yes | yes | yes | - | - | - |
| Kruger&Matz KM0186 | M3606 | - | MxL101SF | 3 | yes | yes | yes | - | - | - |
| Openbox S16 HD PVR | M3601S | TM1650-compatible (SCL 62, SDA 63) | - | 1 | yes | yes | yes | yes | - | - |
| Opticum Blue R265 Lite | M3822P | HD2015 (SCL 57, SDA 58) | MxL608 | 3 | yes | yes | yes | yes | yes | yes |
| Opticum HD S50 | M3601S | - | - | 2 | yes | yes | yes | yes | - | - |
| Opticum HD S60 | M3601S | TM1650-compatible (SCL 62, SDA 63) | - | 2 | yes | yes | yes | yes | - | - |
| Opticum HD T90 (update for the T90 / STB HD N2 / N3 boards) | M3801 | TM1650 (SCL 31, SDA 9) | R820T | 1 | yes | yes | yes | yes | yes | - |
| Opticum HD X110p | M3606 | TM1650-compatible (SCL 9, SDA 8) | AV2011 | 10 | yes | yes | yes | yes | yes | - |
| Opticum STB HD N2 | M3801 | TM1650 (SCL 31, SDA 9) | unknown | 1 | yes | yes | yes | yes | yes | - |
| Opticum X110TS | M3606 | TM1650-compatible (SCL 9, SDA 8) | AV2011 + MxL101SF | 9 | yes | yes | yes | yes | yes | - |
| Satellite board s15125 (2005) | M3329 | TM1650-compatible (SCL 15, SDA 16) | - | 1 | yes | yes | yes | yes | - | - |
| Strong Prima VIII | M3801 | no driver, 2 buttons (GPIO 31 / 9) | MxL603 / Si2144 | 2 | yes | yes | yes | yes | - | - |
| Strong SRT 8115 | M3801 | TM1628-class 3-wire (CLK 31, DIO 9, STB 11) | MxL603 | 1 | yes | yes | yes | yes | - | - |
| Thomson THT501 | M36xx | - | MxL101SF | 3 | yes | yes | yes | yes | - | - |
