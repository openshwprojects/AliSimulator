#!/usr/bin/env python3
"""Package a built Maciej application as release files in firmware/maciej_app/bin:
the 4 MiB flash image (dump_maciej.bin with the new main code), the UART
payload (.maincode.bin, what tools/maciej_uart.py flashes), a manifest
(.json: sizes, addresses, SHA-256, commands) and the portable ZIP
(maciej_uart.py, the payload and README_UART.txt), with fixed timestamps so
the same inputs give the same bytes.

  python firmware/maciej_app/build.py --version v4 --demo
  python tools/maciej_release.py --version v4 --app build/maciej_app/v4/app.bin \\
      --readme firmware/maciej_app/bin/README_UART_v4.txt
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import maciej_image                                  # noqa: E402

BIN = ROOT / "firmware" / "maciej_app" / "bin"
BANNER = "ELEKTRODA ALI M3801 TEST FOR MACIEJ"
ZIP_TIME = (2026, 11, 12, 12, 0, 0)

# what each release answers on the UART (v4: whole command lines)
COMMANDS = {
    "v4": {
        "help": "list of commands", "version": "banner and version",
        "ping": "answers pong; ping [-c n] <host>: ICMP echo like Linux's ping (names via DNS)",
        "ifconfig": "the network link: a USB Ethernet adapter (CDC ECM, an RTL8153's), or an LTE module's RNDIS "
                    "function (SIMCom A7670E) when there is no adapter or it gets no address; MAC, address from "
                    "DHCP, router",
        "dhcp": "ask the DHCP server for an address again", "arp": "the ARP table",
        "wget": "[-O n:path] [--no-check-certificate] <http(s)://url>: a page over the network link (TCP, "
                "HTTP/1.0; https:// over TLS 1.2 with BearSSL, the certificate checked against Mozilla's roots and "
                "the NTP clock; redirections followed): on the console, or saved to a disk",
        "ntp": "[server]: the clock set over the network (pool.ntp.org; also by itself after DHCP)",
        "date": "the date and time: UTC and Polish (CET / CEST)",
        "netstat": "TCP: the ports listened on (21 FTP server, 23 telnet console, 80 web page, 445 SMB file server "
                   "-- Windows' \\\\box\\4 --, 6464 netload), connections, counters, the FTP and SMB servers' "
                   "clients, the web page's address, SSDP",
        "loop": "the main loop since the last look: passes, the slowest, which part took the time",
        "info": "chip, clock, memory layout, uptime", "uptime": "time since start",
        "echo": "prints its arguments", "md": "dump memory", "mr": "read a 32-bit word",
        "mw": "write a 32-bit word (RAM, registers)",
        "screen": "draw on the test screen's picture (and show it): demo|bars|clear|text|rect|on|off",
        "testscreen": "the demo's test screen on the TV (its boxes, the colour bars); a key on the USB keyboard or "
                      "'console' brings the console back",
        "console": "the console on the TV: everything the UART shows, scrolling, PgUp/PgDn for earlier lines "
                   "(the view after start)",
        "explorer": "[n:][path]: a file explorer on the TV in the current directory, synced with cd both ways "
                    "(the disks' volumes when there is none): USB keyboard arrows/PgUp/PgDn/Home/End select, Enter "
                    "opens (a picture: the viewer; a .nes or .gb file: the game; another file: its beginning in a "
                    "preview), Backspace goes up, '/' or Tab types a path into the path bar; the mouse clicks, "
                    "double-clicks, scrolls; F2 renames, F7 makes a directory, "
                    "Delete / F8 deletes (asks y/n), F5 / F6 mark a file to copy / move, Insert pastes it (another "
                    "disk too); Esc or 'console' brings the console back",
        "panel": "front panel digits, brightness (boards with the TM1650)",
        "keys": "front panel key state; without a TM1650 (Comsat TE 1050 HD) its two buttons on GPIO 31 / 9",
        "ir": "remote control receiver (raw timing on|off)",
        "usb": "USB port state, the descriptors of its device and, through a hub, of every device behind it; "
               "reset, init, kbd [report|interrupt|raw on|off] (a USB keyboard types into the command line, "
               "read from its interrupt endpoint), mouse (a USB mouse moves a pointer on the TV and paints with "
               "its left button), reg <offset> [byte], ctl <type> <request> <value> <index> <length> [device] "
               "(a control request: data IN, or OUT -- the bytes the last one read)",
        "lsusb": "the USB devices, one line each (with the hub and port of those behind a hub)",
        "disks": "USB disks (sticks, card readers): their size, partitions and file systems",
        "ls": "[n:][path]: a directory on a USB disk's FAT12 / FAT16 / FAT32 or NTFS volume "
              "(n: the disk's device number as lsusb lists it; a path without '/' starts in the current directory)",
        "sum": "[n:]path: a file read to its end: its size, CRC-32, first bytes, speed",
        "head": "[-n N] path: a text file's first N lines (10)", "tail": "[-n N] path: its last N lines (10)",
        "df": "[n:]: the disks' volumes: size, free and used space (FAT: its FAT counted; NTFS: its $Bitmap)",
        "dir": "the same as ls",
        "cd": "[n:][path]: the current directory, shown in the prompt ('..' one up; alone: none)",
        "pwd": "the current directory",
        "cat": "[n:]path: a text file on a USB disk (Ctrl-C stops it)",
        "mkdir": "<path>: make a directory (writes the disk; long names too)",
        "rmdir": "<path>: remove an empty directory (writes the disk)",
        "rm": "[-r] <path>: remove a file; -r: a directory and everything in it (writes the disk)",
        "touch": "<path>: make an empty file (writes the disk)",
        "cp": "[-r] <from> <to>: copy a file (to a directory: into it; onto another disk too); -r: a directory "
              "with everything in it",
        "mv": "<from> <to>: rename a file or directory, or move it into another directory of the same volume",
        "ntfs": "[n:] [reset-journal]: an NTFS volume's geometry, its journal's state and whether the demo writes "
                "it (only a volume Windows closed cleanly: 'Safely remove'); reset-journal empties the journal "
                "as ntfs-3g does",
        "view": "[-1] [-s | -c] <file>: a picture on the TV (JPEG baseline / progressive, PNG, GIF, BMP), fitted "
                "to it, turned as a photo's EXIF says; Right / Space the next one in its directory, Left the one "
                "before, Esc or q ends; a baseline JPEG is decoded by the video engine's JPEG mode (-s: by the CPU; "
                "-c: both, compared)",
        "play": "[-n frames] [-x] [-k] [-v] [-1] <file>: a video file (.ts, .mpg, .m2v, .vob: MPEG-2 / MPEG-1 "
                "video, MPEG audio) on the TV, decoded by the S3811's own MPEG-2 decoder, its sound through 'snd'; "
                "Esc, Ctrl-C, q or the remote's EXIT ends (-n that many frames, -x as fast as it decodes, -k the "
                "last picture stays, -v every picture said, -1 the picture's own size); no H.264",
        "av": "<status|shot <file.bmp|.yuv>|show|off|reset>: the video player's decoder and picture layer: their "
              "registers, the picture shown last saved (RGB .bmp or I420 .yuv), shown again, taken away, reset",
        "gb": "[-f frames] [-k script] <file.gb>: a Game Boy or Game Boy Color game on the TV (a Color game in "
              "its colours, an older one in four shades), 59.7 frames a second (plain ROM, MBC1, MBC2, MBC3, MBC5; "
              "no sound): the keys and the options of nes; battery RAM kept in a .sav file beside it",
        "nes": "[-f frames] [-k script] <file.nes>: a NES game on the TV, 60 frames a second (mappers 0, 1, 2, 3, "
               "4, 7, 11, 34, 66, 71; no sound): arrows / W A S D, X = A, Z = B, Enter = Start, Tab = Select "
               "(USB keyboard, UART, remote); Ctrl-C or Esc ends; battery RAM kept in a .sav file beside it. "
               "Every player also takes its game in a .zip (the largest file in it that is no text or picture) "
               "or a .gz (the Amiga's .adz too)",
        "sms": "[-f frames] [-k script] <file.sms>: a Sega Master System game on the TV (256 x 192 three times "
               "as large; Sega and Codemasters mappers, cartridge RAM kept in a .sav file; no sound): X = button "
               "2, Z = button 1, Enter = Pause; the other keys and the options of nes",
        "gg": "[-f frames] [-k script] <file.gg>: a Sega Game Gear game on the TV (160 x 144 five times as large): "
              "X = button 2, Z = button 1, Enter = Start; the other keys and the options of nes",
        "sg": "[-f frames] [-k script] <file.sg|file.sc>: a Sega SG-1000 / SC-3000 game on the TV (256 x 192 "
              "three times as large; plain ROMs up to 48 KB, Sega mapper above; pads only, no sound): X = button 2, "
              "Z = button 1, Enter = Pause; the other keys and the options of nes",
        "zx": "[-f frames] [-k script] [file]: a ZX Spectrum 48K / 128K + Pentagon BetaDisk 128 on the TV (320 x 240 "
              "with its border, three times as large, 50 frames a second): a snapshot (.sna, .z80), a tape (.tap, .tzx) "
              "or a TR-DOS floppy (.trd, .scl) with 48 kHz beeper + AY-3-8912 sound; no file: BASIC. Optional 48.rom, "
              "128.rom and trdos.rom in zx/ or beside the program (else built-in clean-room loader). The USB keyboard is "
              "the Spectrum's, its arrows a Kempston joystick too; characters typed on the UART are typed on it; Esc ends",
        "c64": "[-f frames] [-k script] [file]: a Commodore 64 (PAL) on the TV (352 x 240 with its border, "
               "three times as large, 50 frames a second): a program (.prg, .t64) or a disk (.d64), loaded and "
               "RUN by itself, or a cartridge (.crt: normal, Ocean, Magic Desk, EasyFlash, System 3, Dinamic, Fun "
               "Play, Super Games, RGCD, Simons' BASIC, Final Cartridge III) started in it; no file: BASIC. Its ROMs are kernal.rom, basic.rom and chargen.rom (not in the "
               "demo) beside the program, in c64/ or at the top of its disk. The USB keyboard is the C64's (Tab = "
               "RUN/STOP, PageUp = RESTORE), its arrows joystick 2 (fire: right Ctrl); Esc ends",
        "amiga": "[-f frames] [-k script] [file.adf]: an Amiga 500 (PAL, OCS) on the TV (352 x 272 with its "
                 "border, twice as large) with a floppy image (.adf) in its drive. Its Kickstart is kick.rom (256 "
                 "or 512 KB; not in the demo) or AROS's free aros-rom.bin + aros-ext.bin, beside the disk, in "
                 "amiga/ or at the top of its disk. The USB keyboard is the Amiga's, its arrows the joystick (fire: "
                 "right Ctrl), Page Up / Down the mouse button; no sound; Esc ends",
        "snd": "<init|beep|status|stop|vol>: the sound (a prototype): the S3811's sound engine set up as dump.bin "
               "does, 48 kHz on HDMI and the SCART's analog out; beep [Hz] [ms] plays a test tone; NES games play "
               "their sound through it",
        "dos": "[-f frames] [-k script] <file.exe>: a DOS PC (a 286 AT with a VGA: text, CGA, EGA and 256-colour "
               "modes) on the TV (320 x 200, three times as large) running a DOS program (.exe, .com); the BIOS and "
               "DOS are built in; no sound. The USB keyboard is the PC's (Esc ends the player)",
        "megadrive": "[-r j|u|e] [-f frames] [-k script] <file>: a Sega Mega Drive / Genesis game on the TV "
                     "(320 x 224 or 256 x 224, three times as large; .md, .gen, .bin, .smd; NTSC or PAL from the "
                     "header's region or -r) with its sound (YM2612 and PSG): X = B, Z = A, Tab / Space = C, Enter = "
                     "Start (USB keyboard, UART, remote); a 3-button pad; cartridge RAM kept in a .sav file beside it",
        "a26": "[-f frames] [-k script] <file.a26>: an Atari 2600 game on the TV (160 x 228, five times as wide "
               "and three times as high; 2K, 4K, F8, F6, F4 and their Superchip RAM, FE, E0, 3F, E7, FA; NTSC; no "
               "sound): arrows, X or Z = fire, Enter = the console's Reset, Tab = Select",
        "pce": "[-f frames] [-k script] <file.pce>: a PC Engine / TurboGrafx-16 HuCard on the TV (256 / 320 / 512 x "
               "240) with its 6-channel PSG sound and 2 KB backup RAM (.sav)",
        "coleco": "[-f frames] [-k script] <file.col>: a ColecoVision cartridge on the TV (256 x 192, three times as "
                  "large; MegaCart and Super Game Module too; coleco.rom in col/ or built-in BIOS) with SN76489 sound",
        "msx": "[-f frames] [-k script] <file.rom|file.mx1>: an MSX1 cartridge on the TV (plain, Konami, Konami SCC, "
               "ASCII8, ASCII16; msx.rom in msx/ or built-in BIOS) with AY-3-8910 + SCC sound",
        "msx2": "[-f frames] [-k script] <file.mx2|file.dsk|file.rom>: an MSX2 home computer on the TV (Yamaha V9938 "
                "256/512 x 192/212, 128 KB VRAM, SCREEN 0..8, hardware blitter, 256 KB Memory Mapper, RP5C01 RTC; "
                "cbios_main_msx2.rom/msx2.rom in msx2/ or built-in BIOS) with AY-3-8910 + SCC + YM2413 FM sound",
        "ws": "[-f frames] [-k script] <file.ws|file.wsc>: a Bandai WonderSwan or WonderSwan Color game on the TV "
              "(224 x 144 five times as large, or 144 x 224 rotated) with 4-channel sound and SRAM / EEPROM (.sav)",
        "snes": "[-f frames] [-k script] <file.sfc|file.smc>: a Super Nintendo / Super Famicom game on the TV "
                "(LoROM, HiROM, ExHiROM, Modes 0-7) with SPC700 / S-DSP BRR sound and SRAM (.sav)",
        "neogeo": "[-f frames] [-k script] <file.neo>: an SNK Neo Geo AES / MVS cartridge on the TV (320 x 224, "
                  "three times as large; uni-bios.rom in neogeo/ or built-in BIOS) with Z80 + YM2610 sound and .sav",
        "gba": "[-f frames] [-k script] <file.gba>: a Game Boy Advance game on the TV (240 x 160, four times as "
               "large; gba_bios.bin in gba/ or built-in BIOS) with DirectSound + PSG sound and SRAM / Flash / EEPROM (.sav)",
        "a78": "[-f frames] [-k script] <file.a78>: an Atari 7800 ProSystem cartridge on the TV (320 x 224 / 240; "
               "MARIA display lists, Linear / SuperGame / Activision / Absolute) with TIA + POKEY sound and .sav",
        "lynx": "[-f frames] [-k script] <file.lnx|file.lyx>: an Atari Lynx game on the TV (160 x 102 six times as "
                "large, or 102 x 160 rotated; Suzy sprite scaling, lynxboot.img in lynx/ or built-in loader) with Mikey sound",
        "vectrex": "[-f frames] [-k script] [file.vec]: a GCE Vectrex vector console on the TV (270 x 360 twice as "
                   "large; no file: Mine Storm with vectrex.rom in vec/, or built-in Vector Storm) with AY-3-8912 sound",
        "fds": "[-f frames] [-k script] <file.fds>: a Famicom Disk System disk image (1-8 sides; disksys.rom in fds/ "
               "or built-in BIOS, Q flips disk sides) on the TV with RP2C33 wavetable + FM sound and .sav disk writes",
        "ngp": "[-f frames] [-k script] <file.ngp|file.ngc>: a Neo Geo Pocket or Neo Geo Pocket Color game on the TV "
               "(160 x 152 four times as large; ngp_bios.rom in ngp/ or built-in BIOS) with T6W28 + DAC sound and Flash .sav",
        "odyssey2": "[-f frames] [-k script] <file.o2>: a Magnavox Odyssey2 / Philips Videopac G7000 cartridge on the "
                    "TV (160 x 240, 640 x 720; o2rom.bin in o2/ or built-in BIOS) with Intel 8244 sound",
        "intv": "[-f frames] [-k script] <file.int|file.rom>: a Mattel Intellivision cartridge on the TV (176 x 208, "
                "704 x 624; exec.bin + grom.bin in intv/ or built-in EXEC/GROM) with AY-3-8914 sound",
        "psx": "[-f frames] [-k script] <file.exe|file.cue|file.iso>: a Sony PlayStation 1 program or CD-ROM on the TV "
               "(R3000A + GTE 3D, GPU 15/24bpp, MDEC, streaming .cue/.bin & .iso, scph1001.bin in psx/ or built-in BIOS) "
               "with 24-voice SPU XA-ADPCM sound and 128 KB Memory Card (.sav)",
        "cps": "[-f frames] [-k script] <file.cps|file.zip>: a Capcom CPS-1 / CPS-1.5 / CPS-2 arcade game on the TV "
               "(384 x 224 three times as large; 10/12/16 MHz 68000 + Z80, Feistel .key & Kabuki decryption, 3 scroll "
               "layers + rowscroll + Z-priority sprites) with YM2151 + OKIM6295 / 16-voice QSound DSP sound and 93C46 "
               "EEPROM (.sav)",
        "atarist": "[-f frames] [-k script] [file.st|file.msa|file.prg]: an Atari 520ST / 1040STFM on the TV (320 x 200 "
                   "x3, 640 x 200, 640 x 400; 8 MHz 68000, Shifter + STE Blitter, MC68901 MFP, IKBD, WD1772 FDC; "
                   "etos256uk.img / tos.img in atarist/ or built-in TOS) with YM2149F sound",
        "sys16": "[-f frames] [-k script] <file.s16|file.zip>: a Sega System 16A / 16B / OutRun-Road arcade game on the "
                 "TV (320 x 224 three times as large; 10/12.5 MHz 68000 + Z80, 315-5195 mapper, 315-5197 tilemaps + "
                 "zoomed sprites + road generator) with YM2151 + uPD7759 + Sega 16-ch PCM sound and 16 KB NVRAM (.sav)",
        "atari8": "[-f frames] [-k script] [file.atr|file.xex|file.car|file.rom]: an Atari 800XL / 130XE (128 KB) on the "
                  "TV (336 x 240 three times as large; SALLY 6502C, ANTIC modes 2..F + DLI + WSYNC, GTIA Players/Missiles "
                  "+ modes 9/10/11, 130XE PORTB banking, POKEY 48 kHz sound, .sav disk writeback; built-in AltirraOS XL + "
                  "BASIC or atarixl.rom / ataribas.rom in atari8/)",
        "a5200": "[-f frames] [-k script] <file.a52|file.car>: an Atari 5200 SuperSystem cartridge on the TV (336 x 240 "
                 "three times as large; 4K..40K mappers, ANTIC + GTIA + POKEY 48 kHz sound, analog stick + 12-key pad; "
                 "built-in Altirra 5200 OS or 5200.rom in a5200/)",
        "megaduck": "[-f frames] [-k script] <file.duck|file.md1|file.md2|file.bin>: a Mega Duck / Cougar Boy cartridge "
                    "on the TV (160 x 144 five times as large, 59.7 frames a second; flat and $0001 / $B000 banked "
                    "cartridges) with 48 kHz 4-channel sound and SRAM (.sav)",
        "sv": "[-f frames] [-k script] <file.sv>: a Watara Supervision cartridge on the TV (160 x 160 four times as "
              "large, 61 frames a second; 16 KB..512 KB Magnum banking) with 4-channel 48 kHz sound",
        "chip8": "[-f frames] [-k script] <file.ch8|file.sc8|file.xo8>: a CHIP-8, SUPER-CHIP 1.1 or XO-CHIP program on "
                 "the TV (128 x 64 ten times as large: 1280 x 640, 4-plane 16 colours) with 48 kHz buzzer & XO-CHIP "
                 "pattern sound and RPL .sav",
        "channelf": "[-f frames] [-k script] <file.chf|file.bin|file.rom>: a Fairchild Channel F / VES cartridge on the "
                    "TV (102 x 58 ten times as large: 1020 x 580; Fairchild F8 CPU, F2102 + Schach SRAM, built-in HLE "
                    "PSU or sl31253.bin + sl31254.bin in channelf/) with 3-tone 48 kHz sound",
        "pokemini": "[-f frames] [-k script] <file.min>: a Nintendo Pokemon Mini cartridge on the TV (96 x 64 ten times "
                    "as large: 960 x 640, 72 frames a second; 4 MHz Seiko S1C88, PRC tile/sprite engine, built-in FreeBIOS "
                    "or bios.min in pokemini/) with 48 kHz piezo PWM sound and 8 KB EEPROM (.sav)",
        "cpc": "[-f frames] [-k script] [file.sna|file.dsk|file.cpr|file.bin]: an Amstrad CPC 464 / 6128 + GX4000 on the "
               "TV (384 x 240 three times as large in Mode 0/1, 640 x 200 in Mode 2, 50 frames a second; 4 MHz Z80, UM6845R "
               "CRTC, 40010 Gate Array, 128 KB RAM, uPD765 FDC with .sav writeback, built-in OS + Locomotive BASIC 1.1 + "
               "AMSDOS) with AY-3-8912 48 kHz sound; no file: BASIC",
        "vic20": "[-f frames] [-k script] [file.prg|file.crt|file.a0|file.d64]: a Commodore VIC-20 (PAL) on the TV (224 x "
                 "240 three times as large, 50 frames a second; MOS 6502, MOS 6561 VIC-I video + 4-channel 48 kHz sound, "
                 "dual 6522 VIAs, automatic unexpanded / +3K / +24K RAM expansion, built-in KERNAL + BASIC V2 + chargen) "
                 "; no file: BASIC",
        "apple2": "[-f frames] [-k script] [file.dsk|file.do|file.po|file.nib|file.bin]: an Apple IIe Enhanced (128 KB) on "
                  "the TV (280 x 192 three times as large or 560 x 192 80-col / Double Hi-Res, 59.92 frames a second; WDC "
                  "65C02, NTSC artifact Hi-Res, Disk II GCR .sav writeback, 48 kHz $C030 speaker + Mockingboard AY-3-8910, "
                  "embedded Apple IIe + Disk II ROMs); no file: Applesoft BASIC",
        "coco": "[-f frames] [-k script] [file.ccc|file.rom|file.bin|file.cas]: a TRS-80 Color Computer 64K (NTSC 60 Hz) "
                "on the TV (320 x 240 three times as large with border; Motorola MC6809, SAM MC6883, dual MC6821 PIAs, "
                "MC6847 VDG + NTSC RG6 artifact colours, 48 kHz 6-bit DAC + 1-bit sound, built-in Color BASIC exec or "
                "bas13.rom/extbas11.rom in coco/); no file: BASIC",
        "dragon": "[-f frames] [-k script] [file.ccc|file.rom|file.bin|file.cas]: a Dragon 32 / 64 (PAL 50 Hz) on the TV "
                  "(320 x 240 three times as large with border; Motorola MC6809, SAM, dual PIAs with Dragon keyboard "
                  "matrix, MC6847 VDG, 48 kHz 6-bit DAC + 1-bit sound, built-in BASIC exec or d32.rom in dragon/); no "
                  "file: BASIC",
        "cv": "[-f frames] [-k script] <file.cv|file.rom|file.bin>: a VTech CreatiVision / Dick Smith Wizzard cartridge "
              "(4K..32K) on the TV (256 x 192 three times as large, 50 Hz PAL; 2 MHz 6502, MC6821 PIA, TMS9929A VDP, "
              "SN76489A 48 kHz sound, built-in BIOS or bioscv.rom in cv/)",
        "m5": "[-f frames] [-k script] <file.m5|file.rom|file.bin>: a Sord M5 / CGL M5 cartridge (4K..20K) on the TV "
              "(256 x 192 three times as large, 60 Hz NTSC; 3.58 MHz Z80 + Z80 CTC IM2, 36 KB RAM, TMS9918A VDP, "
              "SN76489AN 48 kHz sound, built-in Monitor BIOS or m5.rom in m5/)",
        "pv1000": "[-f frames] [-k script] <file.pv|file.bin|file.rom>: a Casio PV-1000 cartridge (8K..32K) on the TV "
                  "(256 x 192 three times as large, 59.92 Hz; 3.58 MHz Z80, NEC D65010G031 VDP, 3-ch square/XOR 48 kHz PSG)",
        "astro": "[-f frames] [-k script] [file.ast|file.bin|file.rom]: a Bally Astrocade cartridge (or no file for "
                 "built-in Star Blaster) on the TV (320 x 204 three times as large, 59.92 Hz; 1.79 MHz Z80, Data Chip "
                 "Magic-RAM blitter + split palette, 3-voice + vibrato + LFSR 48 kHz synth, built-in BIOS or astro.bin)",
        "arcadia": "[-f frames] [-k script] <file.a2k|file.bin>: an Emerson Arcadia 2001 cartridge on the TV (160 x 208, "
                   "640 x 624, 59.92 Hz; Signetics 2650 CPU + 2637 UVI video & 48 kHz tone/noise sound, 12-key pad)",
        "vc4000": "[-f frames] [-k script] <file.vc4|file.bin>: an Interton VC 4000 cartridge on the TV (192 x 224, "
                  "768 x 672, 50 Hz PAL; Signetics 2650 CPU + 2636 PVI programmable grid/objects/score LEDs & 48 kHz sound)",
        "studio2": "[-f frames] [-k script] [file.st2|file.bin]: an RCA Studio II cartridge (or no file for built-in "
                   "COSMAC Interceptor) on the TV (256 x 128, 1024 x 640, 60 Hz; COSMAC CDP1802 + CDP1861 Pixie DMA + "
                   "CA555 48 kHz tone, built-in BIOS or studio2.bin in studio2/)",
        "scv": "[-f frames] [-k script] <file.scv|file.bin|file.cart>: an Epoch Super Cassette Vision cartridge (8K..128K) "
               "on the TV (192 x 222, 768 x 666, 59.92 Hz; 4 MHz NEC uPD7801G, Epoch TV-1 VDP, uPD1771C 48 kHz sound, "
               ".sav SRAM, built-in BIOS + font or upd7801g.s01 in scv/)",
        "vb": "[-m 0|1|2|3] [-f frames] [-k script] <file.vb|file.vboy>: a Nintendo Virtual Boy cartridge on the TV "
              "(384 x 224 three times as large: 1152 x 672, 50.27 Hz; 20 MHz NEC V810 RISC, VIP 32 Worlds/OBJ dual-eye "
              "display with live Red/Black, Red/Cyan 3D Anaglyph, White & Amber modes, 6-ch VSU 48 kHz sound, 64 KB .sav)",
        "sgx": "[-f frames] [-k script] <file.sgx>: an NEC SuperGrafx HuCard on the TV (256/320/512 x 240; HuC6280, "
               "dual HuC6270 VDCs with 128 KB VRAM + HuC6202 VPC priority/window mixer, 32 KB WRAM, 6-ch 48 kHz PSG, .sav)",
        "pcecd": "[-f frames] [-k script] <file.cue|file.iso>: a PC Engine CD-ROM2 / Super CD-ROM2 / Arcade Card disc on "
                 "the TV (streamed CD-ROM + Redbook CD-DA + OKI MSM5205 ADPCM + 6-ch PSG @ 48 kHz, 256 KB System Card 3.0 "
                 "+ 2 MB Arcade Card RAM, 2 KB .sav BRAM, built-in System Card 3.0 BIOS or syscard3.pce in pcecd/)",
        "segacd": "[-r j|u|e] [-f frames] [-k script] <file.cue|file.iso>: a Sega CD / Mega-CD disc on the TV (7.67 MHz "
                  "Main-68000 + 12.5 MHz Sub-68000 + Z80, 512 KB PRG-RAM, 256 KB Word-RAM, Stamp ASIC scaling/rotation, "
                  "LC89510 CDC + CDD, YM2612 + PSG + Ricoh RF5C164 8-ch PCM + Redbook CD-DA @ 48 kHz, 8 KB .sav BRAM, "
                  "built-in CDBIOS or bios_CD_{U,E,J}.bin in segacd/)",
        "bbc": "[-f frames] [-k script] [file.ssd|file.dsd|file.uef]: a BBC Micro Model B / Acorn Electron on the TV "
               "(2 MHz 6502, MC6845 CRTC + Video ULA Modes 0-6 + SAA5050 Teletext Mode 7 + Electron ULA, dual 6522 VIAs, "
               "SN76489 48 kHz sound; built-in OS/BASIC or os12.rom + basic2.rom in bbc/; no file: Mode 7 BASIC)",
        "ti99": "[-f frames] [-k script] [file.rpk|file.bin|file.zip]: a Texas Instruments TI-99/4A on the TV (3 MHz "
                "16-bit TMS9900 CPU, GROM + CRU, 32 KB Expansion RAM, 378/379i banking, TMS9918A VDP, TMS9919 48 kHz "
                "sound; no file: TI BASIC)",
        "oric": "[-f frames] [-k script] [file.tap|file.dsk]: a Tangerine Oric-1 / Oric Atmos 48K on the TV (1 MHz 6502, "
                "HCS10017 240 x 224 serial-attribute ULA Text & Hires, 6522 VIA, AY-3-8912 48 kHz sound; no file: BASIC)",
        "plus4": "[-f frames] [-k script] [file.prg|file.tap|file.t64]: a Commodore Plus/4 or C16 on the TV (1.77 MHz "
                 "MOS 7501/8501, 64 KB RAM, MOS 7360/8360 TED 121-colour video & 2-voice 48 kHz sound; no file: BASIC)",
        "zx81": "[-f frames] [-k script] [file.p|file.81]: a Sinclair ZX81 16K on the TV (3.25 MHz Z80, ULA live D_FILE "
                "256 x 192 display, 50 Hz FRAMES VSync, 48 kHz pulse sound; no file: Sinclair 16K BASIC)",
        "pc88": "[-f frames] [-k script] [file.d88|file.n88]: an NEC PC-8801mkIISR on the TV (4 MHz Z80, 64 KB RAM + "
                "48 KB 640 x 200 3-plane GVRAM + Text VRAM, Sub-CPU disk HLE, YM2203 OPN FM/SSG + beeper @ 48 kHz)",
        "mz700": "[-f frames] [-k script] [file.mzt|file.mzf]: a Sharp MZ-700 on the TV (3.58 MHz Z80, 64 KB banked RAM, "
                 "320 x 200 GRB CGROM display, Intel 8253 PIT 48 kHz sound; no file: 1Z-009A Monitor)",
        "x1": "[-f frames] [-k script] [file.d88|file.2d|file.tap]: a Sharp X1 on the TV (4 MHz Z80, 16-bit I/O 48 KB "
              "GVRAM + 256-char colour PCG, 2 MHz AY-3-8910 @ 48 kHz; no file: X1 IPL/BASIC)",
        "s32x": "[-r j|u|e] [-f frames] [-k script] <file.32x|file.bin>: a Sega 32X cartridge on the TV (7.67 MHz 68000 "
                "+ dual 23 MHz 32-bit Hitachi SH-2 RISC CPUs + Z80, 256 KB SDRAM, SuperVDP 256-colour/RLE/15-bit Direct "
                "framebuffers, stereo 12-bit PWM + YM2612 + PSG @ 48 kHz, .sav SRAM)",
        "cd32": "[-f frames] [-k script] <file.cue|file.iso>: a Commodore Amiga CD32 disc on the TV (14.18 MHz 68EC020 "
                "+ 2 MB Chip RAM, AGA 8-bitplane 256-colour / HAM8 + 2 MB Blitter + Copper, Akiko $C0CACAFE hardware "
                "Chunky-to-Planar + CD DMA + 7-button pad, 4-ch Paula + Redbook CD-DA @ 48 kHz, 1 KB .sav NVRAM)",
        "cps2": "[-f frames] [-k script] <file.zip|file.cps2>: a Capcom CPS-2 QSound arcade game on the TV (16 MHz "
                "68000 + Z80, .key Feistel & .03x XOR decryption, Z-priority tilemaps/sprites, 16-ch QSound DSP @ 48 kHz, "
                "93C46 .sav EEPROM)",
        "arcade": "[-f frames] [-k script] [file.zip]: a Golden-Age Z80 arcade game on the TV (Namco Pac-Man / Ms. "
                  "Pac-Man WSG, Namco Galaxian starfield, Konami Frogger / Scramble dual-Z80 + AY-3-8910, Nintendo Donkey "
                  "Kong DMA + DAC; no file: built-in Maze Chomp)",
        "rf": "the aerial input: the MxL603 tuner (I2C 0x60) and the S3811's DVB-T demodulator as dump.bin drives "
              "them -- init, tune <MHz|channel> [6|7|8], status (lock, level, quality, errors, the stream's "
              "parameters), scan, services (the multiplex's channel names), ts <s> [file] (the PIDs, or a .ts "
              "recording), spectrum (the aerial's level across 174..862 MHz as a chart on the TV), live [from to] (that chart "
              "swept again and again, with keys: marker, zoom, move, faster / slower, pause, peak hold, Enter a "
              "lock tried, Esc ends); DVB-T only, "
              "not DVB-T2",
        "> / >>": "after any command: what it prints goes into a file ('ls > 4:/list.txt'; >> adds to its end); "
                  "\"...\" or '...' keep spaces in a word",
        "sector": "[n:]<number>: one sector of a USB disk in hex",
        "tty": "the USB serial ports: a GSM / LTE module's AT and diagnostic ports (SIMCom, Quectel, Huawei, "
               "ZTE ...), CDC ACM devices, USB-serial chips (CH340 / CH341, CP210x, FTDI, PL2303)",
        "stty": "[n] [baud]: a serial port's baud rate, shown or set (8N1; a chip's ports start at 115200)",
        "cu": "[n]: the terminal joined to serial port ttyUSB<n> (without n: the module's AT port): what you "
              "type goes to it, what it sends is shown; \"~.\" at a line's start or Ctrl-] ends",
        "at": "[command]: one AT command to the module's AT port and its answer up to OK / ERROR, and what "
              "follows at once (AT+HTTPREAD's page); lines the module sent before (+HTTPACTION, RING) first "
              "('at +csq', 'at i'; a line typed as AT... goes there too; > file works)",
        "watchdog": "the chip's watchdog, running from the start: a demo stopped for 8 s restarts the box; "
                    "test (stop feeding it), off, on",
        "clear": "clear the terminal",
        "history": "[n | -c]: the commands typed before, numbered (Up/Down recall the ones starting with what is typed, Ctrl-R searches, !! / !n / !text run one again; Tab completes commands, their choices and file names)",
        "video": "the original firmware's display and HDMI set-up, per board and chip revision "
                 "(init [opticum|comsat] [rev0|rev1]); the demo runs this board's at start, before USB",
        "reboot": "restart through the original bootloader", "restart": "the same as reboot",
        "bootloader": "restart into the original bootloader; hold 'c' (or run the updater) to stay in it",
        "ccc": "three 'c' on an empty line: restart for the UART updater's boot capture",
        "/": "every command may also be written with '/' in front (/restart)",
    },
}


def stem(version: str) -> str:
    return f"elektroda_ali_m3801_maciej_{version}"


def release(version: str, app_path: Path, readme: Path, out_dir: Path = BIN) -> dict:
    original = (ROOT / "dumps" / "dump_maciej.bin").read_bytes()
    application = app_path.read_bytes()
    package = maciej_image.package_image(original, application)
    name = stem(version)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{name}.bin").write_bytes(package.flash)
    (out_dir / f"{name}.maincode.bin").write_bytes(package.payload)
    manifest = dict(package.manifest)
    manifest.update({"application_version": version, "banner": BANNER, "uart": "115200 8E1",
                     "commands": COMMANDS.get(version, {})})
    (out_dir / f"{name}.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
                                         newline="\r\n")   # (CRLF, as the v1-v3 manifests)
    readme_bytes = readme.read_bytes()
    readme_bytes.decode("ascii")                     # the ZIP's instructions are plain ASCII
    members = [("maciej_uart.py", (ROOT / "tools" / "maciej_uart.py").read_bytes()),
               (f"{name}.maincode.bin", package.payload),
               ("README_UART.txt", readme_bytes)]
    with zipfile.ZipFile(out_dir / f"maciej_uart_{version}.zip", "w", zipfile.ZIP_DEFLATED) as bundle:
        for member, data in members:
            info = zipfile.ZipInfo(member, date_time=ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            bundle.writestr(info, data)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True)
    parser.add_argument("--app", type=Path, required=True, help="the built application (app.bin)")
    parser.add_argument("--readme", type=Path, required=True, help="the ZIP's README_UART.txt (ASCII)")
    parser.add_argument("--out-dir", type=Path, default=BIN)
    args = parser.parse_args()
    manifest = release(args.version, args.app, args.readme, args.out_dir)
    print(f"{stem(args.version)}: application {manifest['application_size']} bytes, "
          f"payload {manifest['payload_size']} bytes at 0x{manifest['flash_offset']:x}, "
          f"flash SHA-256 {manifest['flash_sha256']}")


if __name__ == "__main__":
    main()
