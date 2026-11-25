ELEKTRODA ALI M3801 TEST FOR MACIEJ - v4 (demo)

UART update for the bootloader of dump_maciej.bin.
Requirements: Python 3.10+, pyserial, a 3.3 V UART (115200, 8E1).
Unpack the whole ZIP into one directory. Connect TX-RX, RX-TX and GND.
Close other programs using the tuner's port. Replace COM3 with your port.

python -m pip install pyserial
python maciej_uart.py --port COM3 --capture-boot 60 flash elektroda_ali_m3801_maciej_v4.maincode.bin --backup before-maciej-v4.bin

- Original firmware or v1/v2: switch the tuner on after the ready message.
- When v3 or v4 runs: leave the tuner on. The "c" the script sends restarts
  it and captures the original bootloader (v4 does this after three "c"
  characters on an empty command line).
- The script saves a full backup, writes the maincode and verifies all 4 MiB.
  The two reads take about 14 minutes in total. Do not switch the tuner off
  while it writes.
- For the next update use a new backup name. The old one is not overwritten.

v4 is a demo with a real command line: whole commands ended with Enter.
Terminal 115200 8E1 (e.g. PuTTY), prompt "m3801> ".
Line editing as in bash: left/right arrows, Home/End (Ctrl-A/Ctrl-E),
Ctrl-arrows (Alt-B/Alt-F) by a word, Backspace, Delete (Ctrl-D), Ctrl-W
deletes a word, Ctrl-U everything before the cursor, Ctrl-K everything after
it, Ctrl-Y pastes what was deleted, Ctrl-L clears the screen, Ctrl-C drops
the line.
Up/down arrows bring back earlier commands starting with what is already
typed (the last 64, no repeats); Ctrl-R searches for a command containing the
typed text; !! repeats the last one, !n the command numbered n in 'history',
!-n the n-th from the end, !text the last one starting with text.
Tab completes a command's name, its subcommand (e.g. "rf sp" -> "rf spectrum")
and a file or directory name on a disk ("ls 4:/c6" -> "ls 4:/c64/");
when several match, it lists them (long lists after a second Tab).
A command may also start with '/' (e.g. /restart, /lsusb).

  help                 the list of commands (help <command> - one described)
  version / ping       banner and version / answers "pong v4"
  info / uptime        chip, CPU clock, memory addresses, time running
  echo <words>         prints its arguments
  md <addr> [len]      memory dump (RAM, flash window, registers)
  mr <addr>            reads a 32-bit word
  mw <addr> <value>    writes a 32-bit word (RAM and registers, not flash)
  screen ...           draws on the test screen (and shows it): demo | bars |
                       clear [rrggbb] | text <x> <y> <words> |
                       rect <x> <y> <w> <h> <rrggbb> | on | off
  testscreen           the test screen on the TV (boxes, colour bars); any
                       key of the USB keyboard (it is typed too) or
                       "console" goes back to the console
  console              the console on the TV (the view after start)
  explorer [n:][path]
                       a file manager on the TV in the current directory,
                       kept in step with "cd" both ways: arrows/PgUp/PgDn
                       select, Enter opens (a picture: the viewer; a game
                       file - .nes, .gb, .sms, .sg, .md, .crt, .adf etc.,
                       also in .zip or .gz: the game; another file: its
                       beginning), Backspace goes up,
                       "/" or Tab - typing a path in the bar; mouse:
                       click, double click, wheel; Esc goes back to the
                       console; F2 renames, F7 new directory, Delete/F8
                       deletes (y), F5/F6 copy/move a file, Insert pastes
  panel <text>         4 characters on the panel display; panel bright 0..7
                       (boards with a TM1650)
  keys                 the panel keys' state (the keys are also reported by
                       themselves); without a TM1650: two buttons on GPIO 31
                       and 9
  ir                   the last remote control code; ir raw on|off - pulse
                       timings
  usb                  the USB port: state, speed and the descriptors of the
                       connected device (VID:PID, names, interfaces);
                       usb reset - bus reset, usb init - the controller anew,
                       usb kbd [report|interrupt|raw on|off] - the keyboard,
                       usb mouse - the mouse (cursor, buttons, counters),
                       usb reg <offset> [byte] - a controller register,
                       usb ctl <type> <request> <value> <index> <length>
                       [device] - any control request to the device at the
                       given address (e.g. usb ctl 0x80 6 0x100 0 18 2);
                       an OUT request sends the bytes of the last read
  lsusb                USB devices, one line each
  disks                USB disks (sticks, card readers): size, partitions,
                       file systems
  ls [n:][path]        a directory on a USB disk (FAT12, FAT16, FAT32, NTFS,
                       long names); n - the device number from lsusb (e.g.
                       ls 3:/docs), without it the current directory (cd),
                       and before the first cd the first FAT volume; "dir"
                       is the same
  cd [n:][path]        the current directory, shown in the prompt
                       (m3801 3:/Docs>); cd .. - up, cd / - the root,
                       cd alone - no directory; pwd - shows it
  cat [n:]path         a text file from a USB disk (Ctrl-C stops; a binary
                       file: its first 256 bytes in hex)
  mkdir <path>         a new directory (WRITES to the disk; long names too)
  rmdir <path>         removes an empty directory (writes)
  rm [-r] <path>       removes a file; -r: a directory with all it holds
                       (writes)
  touch <path>         a new empty file (writes)
  cp [-r] <from> <to>
                       copies a file (to a directory: into it, under the same
                       name; also to another disk); -r: a directory with all
                       it holds (writes)
  mv <from> <to>       renames a file or directory or moves it to another
                       directory of the same volume (writes)
  command > file       what the command prints goes into the file (e.g.
                       ls > 4:/list.txt, echo text > 4:/a.txt); >> appends
                       to the end of the file; names with spaces in "..." or
                       '...'
  sector [n:]<number>  one sector of a USB disk in hex
  sum [n:]path         a file read to its end: size, CRC-32 (as 7-Zip's),
                       first bytes, speed (Ctrl-C stops)
  head [-n N] <file>   the first N lines of a file (10); tail - the last N
  df [n:]              the disks' volumes: size, free and used space
  ntfs [n:] [reset-journal]
                       an NTFS volume: geometry, the journal's state and
                       whether the demo writes it (only a volume Windows
                       closed cleanly: "Safely Remove Hardware");
                       reset-journal clears the journal as ntfs-3g does
  view [-1] [-s | -c] <file>
                       a picture on the TV (JPEG baseline and progressive,
                       PNG, GIF, BMP), fitted to the screen, turned as the
                       photo's EXIF says; right arrow / space - the next
                       picture of the directory, left - the previous one,
                       i - details, Esc or q ends. The chip's video unit
                       decodes baseline JPEG in hardware (-s: the CPU only;
                       -c: both, compared, nothing shown)
  play [-n frames] [-x] [-k] [-v] [-1] <file>
                       a film from a file (.ts, .mpg, .m2v, .vob, .264, .mp4,
                       .mov: MPEG-2, MPEG-1 or H.264 video, MPEG sound; the
                       sound of .mp4, AAC, does not play) on the TV, decoded
                       by the chip's hardware MPEG-2 / H.264 decoders;
                       sound through "snd". Esc,
                       Ctrl-C, q or EXIT on the remote ends; -n that many
                       frames, -x as fast as it decodes (no sound), -k the
                       last frame stays on the TV (Esc on the USB keyboard,
                       EXIT on the remote or "av off" removes it), -v each
                       frame described, -1 the picture at its own size
                       (instead of the screen's height)
  av <command>         the video decoder and the picture layer: av status
                       (registers), av shot <file.bmp|file.yuv> (the last
                       frame to a file), av show, av off (the menu back),
                       av reset
  gb [-f frames] <file.gb>
                       a Game Boy or Game Boy Color game on the TV (a Color
                       game in colour, an older one in four shades), 59.7
                       frames a second (cartridges without an MBC, MBC1,
                       MBC2, MBC3, MBC5; no sound): keys as in nes;
                       battery memory in a .sav file next to the game
  nes [-f frames] <file.nes>
                       a NES game on the TV, 60 frames a second (mappers 0,
                       1, 2, 3, 4, 7, 11, 34, 66, 71; no sound): arrows or
                       W A S D, X = A, Z = B, Enter = Start, Tab = Select
                       (USB keyboard, UART, remote: arrows, OK = A, 0 = B,
                       MENU = Start, INFO = Select); Ctrl-C or Esc ends;
                       the game's battery memory in a .sav file next to it.
                       Every emulator also takes a game packed in a .zip
                       (the largest file in it that is not text or a
                       picture) or a .gz (an Amiga .adz too)
  sms [-f frames] <file.sms>
                       a Sega Master System game on the TV (256 x 192, 3
                       times as large; Sega and Codemasters mappers,
                       cartridge memory in a .sav file; no sound): X =
                       button 2, Z = button 1, Enter = Pause; the rest as
                       in nes
  gg [-f frames] <file.gg>
                       a Sega Game Gear game on the TV (160 x 144, 5 times
                       as large): X = button 2, Z = button 1, Enter = Start
  sg [-f frames] <file.sg|file.sc>
                       a Sega SG-1000 / SC-3000 game on the TV (256 x 192, 3
                       times as large; cartridges up to 48 KB, above that
                       the Sega mapper; pads only, no sound): X = button 2,
                       Z = button 1, Enter = Pause; the rest as in nes
  megadrive [-r j|u|e] [-f frames] <file>
                       a Sega Mega Drive / Genesis game on the TV (320 x 224
                       or 256 x 224, 3 times as large; .md, .gen, .bin,
                       .smd; NTSC or PAL by the header's region or -r) with
                       sound (YM2612 and PSG): X = B, Z = A, Tab / space =
                       C, Enter = Start (USB keyboard, UART, remote);
                       3-button pad; cartridge memory in a .sav file
  zx [-f frames] [file]
                       ZX Spectrum 48K / 128K + Pentagon BetaDisk 128 on the
                       TV (320 x 240 with the border, 3 times as large, 50
                       frames/s): a snapshot (.sna, .z80), a tape (.tap,
                       .tzx) or a TR-DOS disk (.trd, .scl) with beeper +
                       AY-3-8912 sound at 48 kHz; without a file: BASIC.
                       Optional 48.rom, 128.rom and trdos.rom in the zx/
                       directory, or a built-in loader. The USB keyboard is
                       the Spectrum's keyboard (Shift = CAPS SHIFT, Ctrl /
                       Alt = SYMBOL SHIFT, Backspace = DELETE), the arrows
                       are also a Kempston joystick (fire: OK on the
                       remote); Esc ends
  a26 [-f frames] <file.a26>
                       an Atari 2600 game on the TV (160 x 228, 5 times as
                       wide and 3 times as high; cartridges 2K, 4K, F8, F6,
                       F4 and their Superchip RAM, FE, E0, 3F, E7, FA; NTSC;
                       no sound): arrows, X or Z = fire, Enter = console
                       Reset, Tab = Select
  c64 [-f frames] [file]
                       Commodore 64 (PAL) on the TV (352 x 240 with the
                       border, 3 times as large, 50 frames/s): a program
                       (.prg, .t64) or a disk (.d64) - it loads and starts
                       (RUN) by itself, LOAD from the disk works later too;
                       or a cartridge (.crt: normal 8K/16K/Ultimax, Ocean,
                       Magic Desk, EasyFlash, System 3, Dinamic, Fun Play,
                       Super Games, RGCD, Simons' BASIC, Final Cartridge
                       III) - it starts from the cartridge; without a file:
                       BASIC.
                       The C64 ROMs are the files kernal.rom, basic.rom and
                       chargen.rom (not in the demo) next to the program, in
                       the c64/ directory or at the top of the disk. The USB
                       keyboard is the C64's keyboard (Tab = RUN/STOP,
                       PageUp = RESTORE, Alt = C=), the arrows are a
                       joystick in port 2 (fire: right Ctrl, OK on the
                       remote; F9 swaps the ports); MENU on the remote =
                       SPACE, INFO = F7; characters typed on the UART /
                       telnet are typed on it; Esc ends
  amiga [-f frames] [file.adf]
                       Amiga 500 (PAL, OCS) on the TV (352 x 272 with the
                       border, 2 times as large) with a disk image (.adf) in
                       the drive (without a file: an empty drive). Kickstart
                       is the file kick.rom (256 or 512 KB, not in the demo)
                       or the free AROS: aros-rom.bin + aros-ext.bin - next
                       to the disk, in the amiga/ directory or at the top of
                       the disk. The USB keyboard is the Amiga's keyboard,
                       the arrows are a joystick (fire: right Ctrl, OK on
                       the remote), left mouse button: Page Up / Page Down
                       or 0 on the remote; MENU = Return, INFO = space; no
                       sound; Esc ends
  dos [-f frames] <file.exe>
                       a PC with DOS (286 AT with a VGA card: text modes,
                       CGA, EGA, 256 colours) on the TV (320 x 200, 3 times
                       as large) running a DOS program (.exe, .com); BIOS
                       and DOS are built in, no sound. The USB keyboard is
                       the PC's keyboard (Esc ends); remote: arrows, OK =
                       up, 0 = space, MENU = Enter, INFO = Esc
  pce [-f frames] <file.pce>
                       PC Engine / TurboGrafx-16 on the TV with 6-channel
                       PSG sound and 2 KB of save memory (.sav)
  coleco [-f frames] <file.col>
                       ColecoVision on the TV (256 x 192 x3, MegaCart and
                       Super Game Module, SN76489; coleco.rom in col/ or a
                       built-in BIOS)
  msx [-f frames] <file.rom|file.mx1>
                       MSX1 on the TV (plain, Konami, Konami SCC, ASCII8/16,
                       AY-3-8910 + SCC; msx.rom in msx/ or a built-in BIOS)
  msx2 [-f frames] <file.mx2|file.dsk|file.rom>
                       MSX2 on the TV (Yamaha V9938 128 KB VRAM, SCREEN
                       0..8, hardware blitter, 256 KB Mapper, RP5C01 RTC,
                       .dsk disks, AY-3-8910 + SCC + YM2413 sound;
                       cbios_main_msx2.rom in msx2/ or a built-in MSX2 BIOS)
  ws [-f frames] <file.ws|file.wsc>
                       Bandai WonderSwan / WonderSwan Color on the TV (224 x
                       144 x5 or upright 144 x 224 x3, 4-channel sound, .sav)
  snes [-f frames] <file.sfc|file.smc>
                       Super Nintendo / Super Famicom on the TV (LoROM,
                       HiROM, ExHiROM, modes 0-7, the DSP-1 maths chip of
                       Super Mario Kart, SPC700 BRR sound, .sav saves)
  neogeo [-f frames] <file.neo>
                       SNK Neo Geo AES / MVS on the TV (320 x 224 x3, Z80 +
                       YM2610, 64 KB .sav; uni-bios.rom in neogeo/ or a
                       built-in BIOS)
  gba [-f frames] <file.gba>
                       Game Boy Advance on the TV (240 x 160 x4, DirectSound
                       + PSG, SRAM / Flash / EEPROM .sav; gba_bios.bin or a
                       built-in one)
  a78 [-f frames] <file.a78>
                       Atari 7800 ProSystem on the TV (MARIA, TIA + POKEY,
                       .sav)
  lynx [-f frames] <file.lnx|file.lyx>
                       Atari Lynx on the TV (160 x 102 x6 or upright, Suzy
                       scaling, Mikey sound; lynxboot.img or a built-in
                       loader)
  vectrex [-f frames] [file.vec]
                       GCE Vectrex on the TV (540 x 720 vector screen,
                       AY-3-8912; without a file: Mine Storm from
                       vectrex.rom or Vector Storm)
  fds [-f frames] <file.fds>
                       Famicom Disk System on the TV (1-8 sides, Q turns the
                       disk, RP2C33 sound, disk saves in .sav, built-in BIOS)
  ngp [-f frames] <file.ngp|file.ngc>
                       Neo Geo Pocket / Color on the TV (160 x 152 x4, Z80 +
                       T6W28 + DAC, 64 KB Flash save in .sav, built-in BIOS)
  odyssey2 [-f frames] <file.o2>
                       Magnavox Odyssey2 / Videopac G7000 on the TV (Intel
                       8048 + 8244, 640 x 720, keypad 0..9, built-in BIOS)
  intv [-f frames] <file.int|file.rom>
                       Mattel Intellivision on the TV (CP1610 + STIC +
                       AY-3-8914, 704 x 624, built-in EXEC and GROM or
                       exec.bin/grom.bin)
  psx [-f frames] <file.exe|file.cue|file.iso>
                       Sony PlayStation 1 on the TV (R3000A + GTE 3D, GPU
                       15/24bpp, MDEC, .cue/.bin and .iso CDs read as a
                       stream, 24-voice SPU ADPCM, XA-ADPCM and CD-DA sound,
                       128 KB memory card .sav; scph1001.bin in psx/ or a
                       built-in BIOS)
  cps [-f frames] <file.cps|file.zip>
                       Capcom CPS-1 / CPS-1.5 / CPS-2 arcade games on the TV
                       (384 x 224 x3, 68000 + Z80, CPS-2 .key and Kabuki
                       decryption, 3 background layers + rowscroll, YM2151 +
                       OKIM6295 sound and the 16-voice QSound DSP, EEPROM
                       93C46 save in .sav)
  atarist [-f frames] [file.st|file.msa|file.prg]
                       Atari 520ST / 1040STFM on the TV (320 x 200 x3, 640 x
                       200, 640 x 400; 68000 8 MHz, Shifter + STE Blitter,
                       MFP, IKBD, WD1772 FDC, YM2149F sound; the free EmuTOS
                       etos256uk.img or tos.img in atarist/, or a built-in
                       TOS)
  sys16 [-f frames] <file.s16|file.zip>
                       Sega System 16A / 16B / OutRun-Road arcade games on
                       the TV (320 x 224 x3, 68000 + Z80, 315-5195 mapper,
                       315-5197 tile layers + scaled sprites + road
                       generator, YM2151 + uPD7759 + Sega 16-ch PCM sound,
                       NVRAM save in .sav)
  atari8 [-f frames] [file.atr|file.xex|file.car|file.rom]
                       Atari 800XL / 130XE (128 KB) on the TV (336 x 240 x3,
                       SALLY 6502C, ANTIC modes 2..F + DLI + WSYNC, GTIA P/M
                       sprites and modes 9/10/11, 130XE PORTB banking, POKEY
                       sound 48 kHz, .atr disk saves in .sav; built-in
                       AltirraOS XL + BASIC or atarixl.rom / ataribas.rom in
                       atari8/; without a file: BASIC)
  a5200 [-f frames] <file.a52|file.car>
                       Atari 5200 SuperSystem on the TV (336 x 240 x3,
                       cartridges 4K..40K, ANTIC + GTIA + POKEY 48 kHz,
                       analogue stick and keypad 0..9; built-in Altirra 5200
                       OS or 5200.rom)
  megaduck [-f frames] <file.duck|file.md1|file.bin>
                       Mega Duck / Cougar Boy on the TV (160 x 144 x5, 59.7
                       frames/s, plain and $0001 / $B000 banked cartridges,
                       48 kHz sound, SRAM save in .sav)
  sv [-f frames] <file.sv>
                       Watara Supervision on the TV (160 x 160 x4, 61
                       frames/s, 65SC02 4 MHz, 16..512 KB Magnum cartridges,
                       48 kHz sound)
  chip8 [-f frames] <file.ch8|file.sc8|file.xo8>
                       CHIP-8 / SUPER-CHIP 1.1 / XO-CHIP on the TV (128 x 64
                       x10 = 1280 x 640, 4 planes of 16 colours, 48 kHz
                       sound + XO-CHIP patterns, RPL flags saved in .sav)
  channelf [-f frames] <file.chf|file.bin|file.rom>
                       Fairchild Channel F / VES on the TV (102 x 58 x10 =
                       1020 x 580, 60 frames/s, Fairchild F8 CPU, F2102 +
                       Schach memory, built-in HLE PSU or sl31253.bin +
                       sl31254.bin in channelf/, 3-tone sound 48 kHz)
  pokemini [-f frames] <file.min>
                       Nintendo Pokemon Mini on the TV (96 x 64 x10 = 960 x
                       640, 72 frames/s, Seiko S1C88 4 MHz, PRC background +
                       sprites, built-in FreeBIOS or bios.min in pokemini/,
                       piezo PWM sound 48 kHz, 8 KB EEPROM save in .sav)
  cpc [-f frames] [file.sna|file.dsk|file.cpr|file.bin]
                       Amstrad CPC 464 / 6128 + GX4000 on the TV (384 x 240
                       x3 in Mode 0/1, 640 x 200 in Mode 2, 50 frames/s, Z80
                       4 MHz, UM6845R CRTC, 40010 Gate Array, 128 KB RAM,
                       uPD765 FDC with saves in .sav, AY-3-8912 sound
                       48 kHz, built-in OS + Locomotive BASIC 1.1 + AMSDOS;
                       without a file: BASIC)
  vic20 [-f frames] [file.prg|file.crt|file.a0|file.d64]
                       Commodore VIC-20 PAL on the TV (224 x 240 x3, 50
                       frames/s, MOS 6502, MOS 6561 VIC-I video + 4-channel
                       sound 48 kHz, 2x 6522 VIA, automatic RAM expansion
                       5K / +3K / +24K, built-in KERNAL + BASIC V2 + chargen
                       ROMs; without a file: BASIC)
  apple2 [-f frames] [file.dsk|file.do|file.po|file.nib|file.bin]
                       Apple IIe Enhanced (128 KB) on the TV (280 x 192 x3
                       or 560 x 192 80-column / Double Hi-Res, 59.92
                       frames/s, WDC 65C02, NTSC Hi-Res artifact colour,
                       Disk II GCR drive with .sav saves, $C030 speaker +
                       Mockingboard AY 48 kHz, built-in Apple IIe + Disk II
                       ROMs; without a file: BASIC)
  coco [-f frames] [file.ccc|file.rom|file.bin|file.cas]
                       TRS-80 Color Computer 64K (NTSC 60 Hz) on the TV (320
                       x 240 x3 with the border, Motorola MC6809, SAM
                       MC6883, 2x MC6821 PIA, MC6847 VDG + RG6 artifact
                       colours, 6-bit DAC + 1-bit sound 48 kHz, built-in
                       Color BASIC or bas13.rom in coco/)
  dragon [-f frames] [file.ccc|file.rom|file.bin|file.cas]
                       Dragon 32 / 64 (PAL 50 Hz) on the TV (320 x 240 x3
                       with the border, MC6809, SAM, 2x PIA with the Dragon
                       keyboard matrix, MC6847 VDG, DAC sound 48 kHz,
                       built-in BASIC or d32.rom)
  cv [-f frames] <file.cv|file.rom|file.bin>
                       VTech CreatiVision / Dick Smith Wizzard on the TV
                       (256 x 192 x3, 50 Hz PAL, 6502 2 MHz, PIA, TMS9929A
                       VDP, SN76489A sound 48 kHz, built-in BIOS or
                       bioscv.rom in cv/)
  m5 [-f frames] <file.m5|file.rom|file.bin>
                       Sord M5 / CGL M5 on the TV (256 x 192 x3, 60 Hz NTSC,
                       Z80 3.58 MHz + Z80 CTC IM2, 36 KB RAM, TMS9918A VDP,
                       SN76489AN sound 48 kHz, built-in Monitor BIOS or
                       m5.rom)
  pv1000 [-f frames] <file.pv|file.bin|file.rom>
                       Casio PV-1000 on the TV (256 x 192 x3, 59.92 Hz, Z80
                       3.58 MHz, NEC D65010G031 VDP, 3-channel PSG sound
                       48 kHz)
  astro [-f frames] [file.ast|file.bin|file.rom]
                       Bally Astrocade on the TV (320 x 204 x3, 59.92 Hz,
                       Z80 1.79 MHz, Data Chip Magic-RAM blitter + split
                       256-colour palette, 3-voice synthesizer 48 kHz,
                       keypad 0..9; built-in BIOS and the Star Blaster game
                       or astro.bin in astro/)
  arcadia [-f frames] <file.a2k|file.bin>
                       Emerson Arcadia 2001 on the TV (640 x 624, 59.92 Hz,
                       Signetics 2650 + 2637 UVI video and sound 48 kHz,
                       keypad 0..9)
  vc4000 [-f frames] <file.vc4|file.bin>
                       Interton VC 4000 on the TV (768 x 672, 50 Hz PAL,
                       Signetics 2650 + 2636 PVI grid/objects/LED and sound
                       48 kHz, 0..9)
  studio2 [-f frames] [file.st2|file.bin]
                       RCA Studio II on the TV (1024 x 640, 60 Hz, COSMAC
                       CDP1802 + CDP1861 Pixie DMA + CA555 tone 48 kHz,
                       keypad 0..9; built-in BIOS and game or studio2.bin in
                       studio2/)
  scv [-f frames] <file.scv|file.bin|file.cart>
                       Epoch Super Cassette Vision on the TV (768 x 666,
                       59.92 Hz, NEC uPD7801G 4 MHz, Epoch TV-1 VDP,
                       uPD1771C sound 48 kHz, SRAM .sav save, built-in BIOS
                       or upd7801g.s01 in scv/)
  vb [-m 0|1|2|3] [-f frames] <file.vb|file.vboy>
                       Nintendo Virtual Boy on the TV (384 x 224 x3 = 1152 x
                       672, 50.27 Hz, 32-bit NEC V810 RISC 20 MHz, VIP 32
                       Worlds/OBJ, modes 0 Red/Black, 1 Red/Cyan 3D
                       Anaglyph, 2 White, 3 Amber on V/F2/M, 6-channel VSU
                       sound 48 kHz, 64 KB SRAM .sav)
  sgx [-f frames] <file.sgx>
                       NEC SuperGrafx on the TV (256/320/512 x 240, HuC6280,
                       dual HuC6270 VDC 128 KB VRAM + HuC6202 VPC, 32 KB
                       WRAM, PSG 48 kHz, 2 KB BRAM save in .sav)
  pcecd [-f frames] <file.cue|file.iso>
                       PC Engine CD-ROM2 / Super CD-ROM2 / Arcade Card on
                       the TV (.cue/.bin and .iso CDs read as a stream,
                       Redbook CD-DA + OKI MSM5205 ADPCM + 6-ch PSG 48 kHz,
                       256 KB System Card 3.0 + 2 MB Arcade Card RAM, 2 KB
                       BRAM .sav; built-in System Card 3.0 BIOS or
                       syscard3.pce in pcecd/)
  segacd [-r j|u|e] [-f frames] <file.cue|file.iso>
                       Sega CD / Mega-CD on the TV (Main-68000 7.67 MHz +
                       Sub-68000 12.5 MHz + Z80, 512 KB PRG-RAM, 256 KB
                       Word-RAM, Stamp ASIC 3D scaling/rotation, LC89510 CDC
                       + CDD, YM2612 + PSG + Ricoh RF5C164 8-ch PCM + Redbook
                       CD-DA 48 kHz, 8 KB BRAM .sav; built-in CDBIOS or
                       bios_CD_U/E/J.bin in segacd/)
  bbc [-f frames] [file.ssd|file.dsd|file.uef]
                       BBC Micro Model B / Acorn Electron on the TV (2 MHz
                       6502, MC6845 CRTC + Video ULA modes 0..6 + SAA5050
                       Teletext Mode 7 + Electron ULA, 2x 6522 VIA, SN76489
                       sound 48 kHz; built-in OS/BASIC or os12.rom +
                       basic2.rom; without a file: BASIC)
  ti99 [-f frames] [file.rpk|file.bin|file.zip]
                       Texas Instruments TI-99/4A on the TV (16-bit TMS9900
                       3 MHz, GROM + CRU, 32 KB Expansion RAM, 378/379i
                       banking, TMS9918A VDP, TMS9919 sound 48 kHz; without
                       a file: TI BASIC)
  oric [-f frames] [file.tap|file.dsk]
                       Tangerine Oric-1 / Oric Atmos 48K on the TV (6502
                       1 MHz, HCS10017 ULA 240 x 224 Text + Hires, 6522 VIA,
                       AY-3-8912 sound 48 kHz; without a file: Atmos BASIC)
  plus4 [-f frames] [file.prg|file.tap|file.t64]
                       Commodore Plus/4 and C16 on the TV (MOS 7501/8501
                       1.77 MHz, 64 KB RAM, MOS 7360/8360 TED 121 colours +
                       2-voice sound 48 kHz; without a file: BASIC V3.5)
  zx81 [-f frames] [file.p|file.81]
                       Sinclair ZX81 16K on the TV (Z80 3.25 MHz, ULA D_FILE
                       256 x 192, VSync FRAMES 50 Hz, sound 48 kHz; without
                       a file: BASIC)
  pc88 [-f frames] [file.d88|file.n88]
                       NEC PC-8801mkIISR on the TV (Z80 4 MHz, 64 KB RAM +
                       48 KB 640 x 200 GVRAM + Text VRAM, Sub-CPU disk HLE,
                       Yamaha YM2203 OPN FM/SSG + beeper sound 48 kHz;
                       without a file: N88-BASIC)
  mz700 [-f frames] [file.mzt|file.mzf]
                       Sharp MZ-700 on the TV (Z80 3.58 MHz, 64 KB RAM, GRB
                       video 320 x 200 CGROM, Intel 8253 PIT sound 48 kHz;
                       without a file: Monitor)
  x1 [-f frames] [file.d88|file.2d|file.tap]
                       Sharp X1 on the TV (Z80 4 MHz, 16-bit I/O 48 KB GVRAM
                       + colour PCG of 256 characters, AY-3-8910 sound
                       48 kHz)
  s32x [-r j|u|e] [-f frames] <file.32x|file.bin>
                       Sega 32X on the TV (68000 7.67 MHz + dual 32-bit
                       Hitachi SH-2 RISC 23 MHz + Z80, 256 KB SDRAM,
                       SuperVDP 256 colours / RLE / 15-bit Direct, stereo
                       12-bit PWM + YM2612 + PSG 48 kHz, SRAM .sav save;
                       built-in MARS BIOS)
  cd32 [-f frames] <file.cue|file.iso>
                       Commodore Amiga CD32 on the TV (68EC020 14.18 MHz,
                       2 MB Chip RAM, AGA 8 bitplanes 256 colours / HAM8 +
                       2 MB Blitter + Copper, Akiko $C0CACAFE hardware
                       Chunky-to-Planar + CD DMA + 7-button pad, Paula 4-ch
                       + Redbook CD-DA 48 kHz, 1 KB NVRAM save in .sav)
  cps2 [-f frames] <file.zip|file.cps2>
                       Capcom CPS-2 QSound on the TV (384 x 224 x3, 68000
                       16 MHz + Z80, Feistel .key and .03x XOR table
                       decryption, Z-priority layers, 16-channel QSound DSP
                       48 kHz, EEPROM 93C46 .sav)
  arcade [-f frames] [file.zip]
                       Golden Age Z80 arcade games on the TV (Namco Pac-Man
                       / Ms. Pac-Man WSG, Namco Galaxian, Konami Frogger /
                       Scramble 2xZ80 + AY-3-8910, Nintendo Donkey Kong DMA
                       + DAC; without a file: a game)
  snd <command>        sound (prototype): snd init, snd beep [Hz] [ms] (a
                       test tone), snd vol 0..100, snd status, snd stop -
                       48 kHz on HDMI (after "video init") and on SCART (L/R)
  rf <command>         the antenna input (DVB-T): the MxL603 tuner (I2C
                       0x60) and the S3811 demodulator set up as the original
                       dump.bin software does it: rf init, rf tune <MHz or
                       channel> [6|7|8], rf status (lock, level, quality,
                       errors), rf scan, rf services (the channel names of a
                       multiplex), rf ts <s> [file] (the PIDs or a .ts
                       recording), rf spectrum (the antenna's signal level
                       from 174 to 862 MHz as a chart on the TV), rf live
                       [from to] (that chart refreshed continuously,
                       controlled with keys); DVB-T only, not DVB-T2
  tty                  USB serial ports: the ports of a GSM / LTE module
                       (SIMCom, Quectel, Huawei, ZTE ...), CDC ACM devices
                       and USB-UART adapters (CH340 / CH341, CP210x, FTDI,
                       PL2303)
  stty [n] [baud]      a serial port's speed (8N1): shows or sets it, e.g.
                       stty 0 9600 (adapters start at 115200)
  at [command]         one AT command to the module's AT port and its answer
                       up to OK / ERROR plus what comes right after them
                       (AT+HTTPREAD data); first the lines the module sent
                       before (+HTTPACTION, RING); e.g. at +csq, at i,
                       at +cpin?; a line starting with AT goes there too;
                       > file works
  cu [n]               a terminal connected to serial port n (without n: the
                       module's AT port): what you type goes to the port, the
                       answers are shown; "~." at the start of a line or
                       Ctrl-] ends
  ifconfig             the network link: a USB Ethernet adapter (CDC ECM,
                       e.g. RTL8153) or an LTE module (RNDIS, e.g. SIMCom
                       A7670E) when there is no adapter or it got no address:
                       MAC, IP address from DHCP, router
  dhcp                 asks the DHCP server for an address again
  arp                  the ARP table
  ping [-c n] <host>   ping as in Linux over the network: an address or a name
                       (DNS from DHCP), the TTL and time of each answer,
                       Ctrl-C ends and shows the statistics ("ping" alone:
                       pong)
  wget [-O n:file] [--no-check-certificate] <url>
                       an http:// or https:// page over the network: on the
                       console or saved on a USB disk; redirects (301, 302...)
                       are followed. https: TLS 1.2 (BearSSL), the
                       certificate checked against Mozilla's 118 root
                       authorities and the clock from NTP ("date" must show
                       the time); --no-check-certificate checks nothing.
                       No TLS 1.3.
  ntp [server] / date  the clock from the network (set by itself after DHCP)
                       / date and time: UTC and Polish (CET / CEST)
  netstat              TCP: ports, connections, counters
  loop                 the main loop: passes, the slowest one, what took long
  Over the network: telnet <tuner's address> (port 23) - the same command line
  as on the UART; python tools/maciej_netload.py <address> [app.bin] - a new
  demo version started from RAM in ~1 s (the flash unchanged, a restart goes
  back to it);
  ftp://<tuner's address> (port 21, no password, 2 clients) - an FTP server:
  all disks in the root directory ("4 PHONE CARD", "9 ..."), download,
  upload, delete, rename and directories on FAT and NTFS (NTFS when the demo
  writes it: "ntfs"); passive mode (data ports 50021/50022) and active.
  http://<tuner's address> (port 80, no password) - the tuner's page in a
  browser (also on a phone): files on the disks (browsing, downloading,
  uploading with a button or by dragging, renaming, deleting, new
  directories; pictures and texts open in the browser), the TV picture live
  (about every 1 s; "Full size" - the full 1280 x 720), an on-screen remote
  (arrows, OK, Esc, Tab, A/B for games, Ctrl-C) and the command line as over
  telnet. While a command runs (e.g. a game), the picture, the remote and the
  command line keep working, and files wait for its end; one file at a time
  (the page or FTP - the second one gets "try again in a moment").
  \\<tuner's address>\4 (port 445, SMB2, no password) - the disks as Windows
  shares: in Explorer, "net view \\<address>", "net use", robocopy; copying
  both ways, renaming, deleting, directories. Logging in as a guest: Windows
  10 Home / Pro accept it, Windows 11 24H2 Pro and the Enterprise / Education
  editions block it. One file written at a time.
  SSDP (UPnP, UDP 1900): the tuner shows in Windows under "Network" (Other
  devices) as "M3801 v4 demo (address)"; a double click opens its page.
  The date and time from NTP: in the top right corner of the TV console, after
  the time running
  watchdog [test|off|on]
                       the chip's watchdog: runs from the demo's start; when
                       the demo stops for 8 s, the tuner restarts by itself;
                       test - stops feeding it (the tuner restarts after 8 s)
  clear                clears the terminal's screen (and the TV console)
  history [n | -c]     the earlier commands with numbers (the last n; -c
                       clears the history)
  video init [opticum|comsat] [rev0|rev1]
                       replays the register writes with which the board's
                       original firmware turns on the 720p picture and the
                       HDMI transmitter (the demo does the same at start);
                       without a name - this board's table, without
                       rev0/rev1 - the table of the chip's revision (byte
                       0xB8000000)
  reboot / restart     restart through the original bootloader
  bootloader           restart into the original bootloader: hold the c key
                       (or run maciej_uart.py) to stay in it
  prof [-f frame] [-c addr len | -s event] [-e event0 event1] <command ...>
                       runs the command with the sampling profiler (the CPU
                       timer, about 10,000 samples a second) and lists the
                       64-byte pieces of code it was found in, most first
                       (-f: in a game only from that frame on; -c: samples
                       in that code counted for the function that called
                       it; -s: a sample every 10,000 of that event of
                       performance counter 0 instead of the timer, e.g. 37
                       I-cache miss stall cycles: where they go; -e: the
                       CPU's two performance counters count those events
                       for 100 frames from the -f frame: 0 cycles,
                       1 instructions, 9 I-cache accesses / misses,
                       11 D-cache misses, 37 I-cache / D-cache miss stall
                       cycles)

The console on the TV (the view after start): the same as on the UART - the
start-up messages, the prompt, the commands typed (on the UART or the USB
keyboard), their results and events ([usb] ..., [panel] ...) - like a Linux
console: 105 x 42 characters, a title bar, the prompt in green, a blinking
cursor. Lines scroll up; the last 512 lines stay - PgUp / PgDn (USB keyboard
or ESC [ 5 ~ / ESC [ 6 ~ from a terminal) scroll by half a screen.
"testscreen" shows the demo's old screen (the test screen); a key on the USB
keyboard or "console" goes back to the console.
Writing to disks: mkdir, rmdir, rm, touch, cp, mv and "command > file" write
a FAT volume (all FAT copies, long names, FSInfo in FAT32; text files have
Linux line ends) and NTFS - the latter only when Windows closed it cleanly (an
empty journal: "Safely Remove Hardware" before unplugging; "ntfs n:" says
whether the demo writes it). After the demo has written a stick, it is worth
checking it in Windows (chkdsk). New files and directories get their date from
the clock once NTP has set it (Polish time); before that 2026-11-13 12:00. The
directory part of a path may have 95 characters, a name 127 - longer ones are
refused. A write-protected disk (MODE SENSE) is not written. Note: writing
changes the data on the stick - try it first on a stick without important
files.
GSM / LTE module (tested with a SIMCom A7670E, 1e0e:9011): its ports are
ttyUSB0..3 ("tty"), "at +csq" asks for the signal, "cu" opens the AT port as a
terminal. When the module restarts (e.g. after AT+CRESET), the demo sets it up
again by itself; a single USB transmission error (e.g. while the module
transmits on GSM) does not interrupt "at" or "cu". A SIM card with a PIN:
at +cpin=<PIN> (or turn the PIN off in a phone).
The Internet through the module (its RNDIS function, like usb0 in Linux): when
there is no Ethernet adapter, when it is unplugged or gets no address from
DHCP, the demo's network (ping, wget, ntp, telnet, FTP, netload) goes through
the module; its DHCP gives the address, and its router the way out to the
mobile network. "ifconfig" shows which link is in use. (Tested in the
emulator; the module must have an active data connection.)
A web page through the module (its own HTTP client):
  at +cgact=1,1                              (the data connection)
  at +httpinit
  at +httppara="URL","http://example.com/"
  at +httpaction=0                           (after a few seconds the module
                                              sends +HTTPACTION: 0,200,<length>)
  at +httpread=0,<length>                    (the page; > file works too)
  at +httpterm
Tested over GSM: example.com, 577 bytes.

The remote: every NEC frame received is printed with its code and the key's
name, shown on the screen and on the panel. Panel keys: printed when pressed.
USB: when a device is plugged in, the demo reads its descriptors by itself and
shows its name on the screen. Sticks and card readers (mass storage, SCSI,
bulk-only) are checked at once: name, size, partitions (MBR or GPT) and file
system. Files can be read and written on FAT12/16/32 and NTFS; exFAT is
recognised but not read. Tested on a Comsat TE 1050 HD: a FAT16 card in a
05e3:0751 reader and a 64 GB NTFS stick.
USB-UART adapters (CH340 / CH341 in serial mode, CP210x, FTDI, PL2303): each
one is a port ttyUSB<n> (115200 8N1), "stty n <baud>" changes the speed,
"cu n" opens a terminal. Tested: CH340 1a86:7523 (setting the speed). A
CH341A in I2C/SPI mode (1a86:5512, a 24xx/25xx programmer) is only recognised.
Pictures: "view file" or Enter in the explorer; a 2000 x 1333 JPEG photo
decodes in about 1.5 s. The video unit (the MPEG-2 decoder's JPEG mode)
decodes a baseline (not progressive) JPEG: 1920 x 1080 in 56 ms instead of
1 s, a 6000 x 4000 photo shown in about 1 s instead of 14 s. A progressive,
low-quality or unusual JPEG is decoded by the CPU as before. NES games:
"nes file.nes" or Enter in the explorer; the full 60 frames/s (a frame takes
about 8 ms + 1.5 ms of drawing).
The demo includes no commercial games (e.g. Mario) - you can use your own
copies or free homebrew games (e.g. Nova the Squirrel, Thwaite).
Game Boy and Game Boy Color games: "gb file.gb" (or .gbc) or Enter in the
explorer; a frame takes about 6-7 ms + 0.7 ms of drawing (a Color game at
double speed about 12 ms + 1.5 ms), the picture 5 times as large (800 x 720).
Sega Master System and Game Gear games: "sms file.sms", "gg file.gg" or Enter
in the explorer; a frame takes about 4-5 ms + 1-2 ms of drawing. ZX Spectrum
48K: "zx file.tap" (or .tzx, .sna, .z80) or "zx" without a file (BASIC); the
file 48.rom is needed (the Spectrum ROM, 16 KB - Amstrad allows its use in
emulators) next to the program, in zx/ or at the top of the disk; a frame
takes about 4 ms + 2.5 ms. Tapes are loaded at once through the ROM's
LD-BYTES routine, so games with their own turbo loader do not load. Atari
2600: "a26 file.a26" or Enter in the explorer; a frame takes about 3.5-5.5 ms
+ 1 ms. Tested on a Comsat TE 1050 HD with free homebrew games (e.g. Snake
Pit, Sushi Nights, Ramiro el Vampiro, Halo 2600, Thrust).
Commodore 64: "c64 file.t64" (or .prg, .d64) or "c64" without a file (BASIC)
or Enter in the explorer; the ROMs kernal.rom (8 KB), basic.rom (8 KB) and
chargen.rom (4 KB) are needed next to the program, in c64/ or at the top of
the disk (VICE's files under these names). LOAD is done at once (without a
1541 drive), so games with their own fast loader running in the drive do not
load. A frame takes about 3-4 ms + 3-5 ms of drawing. Tested on the Comsat:
Magicland Dizzy (the .t64 version with a trainer), Hessian (.d64).
Sound (prototype, not listened to yet): the S3811's sound unit set up as the
original software (dump.bin) does it, 48 kHz on HDMI and on the SCART output.
NES games play with sound (both square channels, triangle, noise, DMC). On
the box it was checked only by counters (the hardware takes samples at
48000/s, nothing is lost). Test: "video init", "snd init", "snd beep 1000
3000".
Films: "play file.ts" or Enter in the explorer (.ts, .mpg, .m2v, .vob, .264,
.h264, .mp4, .m4v, .mov). The S3811's hardware MPEG-2 decoder (the same the
original software uses for recordings) decodes the MPEG-1/2 picture, the
H.264 picture is decoded by the same block's second engine (Baseline, Main
and High profiles, up to 1920 x 1080); MPEG sound (Layer II) is decoded in
software, mixed to mono. MPEG-2 on the box: a 720 x 576, 25 frames/s, 6 Mbit/s
file plays in real time (500 frames in 20.3 s, 0 errors), the frames read
from memory match ffmpeg's; 1920 x 1080 decodes too (up to 24 ms a frame),
but single HD frames come late (3 in 250).
The picture scaler takes its filters from a table in RAM (register +0x1E4
points at the parameter block) - the player writes them itself, worked out as
in the original software; without them the picture on the TV was scattered,
although the frames in memory were right. The picture layer reads a frame
line by line (mode 1 in +0x190, bits 17-18); in field mode (0) the picture had
half the height, with garbage under it. The picture on the TV was checked by
eye (a phone camera): whole, colours right.
H.264 on the box: the Sintel trailer 1920 x 1080, 24 frames/s, plays in real
time with sound (1253 frames in 52.6 s, none late), the frames read from
memory identical to ffmpeg's byte for byte, the picture on the TV checked by
eye. .mp4 / .mov files: the H.264 picture plays (720p from an .mp4 file in
real time, frames identical to ffmpeg's), the sound (usually AAC) does not -
the film plays without sound; with sound: convert it to .ts, e.g.
"ffmpeg -i film.mp4 -c:v copy -c:a mp2 film.ts". Not supported: interlaced
H.264 (1080i, common in HD TV recordings), 10 bits, 4:2:2, HEVC (DVB-T2 in
Poland and newer phones: the chip has no decoder for it), fragmented .mp4
files (moof). Upload the files over FTP. Earlier v4 releases could corrupt a
file uploaded over FTP to a USB disk (a few dozen bytes in a few places; a bug
in the handling of the USB controller's DMA, fixed) - files uploaded before
are worth comparing with the original.
A PC with DOS: "dos file.exe" or Enter in the explorer (.exe, .com); one
program without data files next to it (Magicland Dizzy from 1993 needs none:
space on the settings screen, Z / X or the arrows - walk, K or up - jump,
space or Enter - pick up / use). A frame takes about 2.5-4 ms + 2-2.5 ms of
drawing (of 14.3 ms). Tested on the Comsat: Magicland Dizzy (DOS).
Amiga 500: "amiga file.adf" or Enter in the explorer; a Kickstart (kick.rom)
or the free AROS replacement (aros-rom.bin and aros-ext.bin from
aros.sourceforge.io) in amiga/ is needed. The disk is read as a real drive
reads it (MFM tracks), so games with their own loader work too. A frame takes
about 5.5-9 ms + 3-4 ms of drawing. Tested on the Comsat: Magicland Dizzy (the
TRSi version) with AROS - the start takes about 30 s, the intro needs a mouse
click (0 on the remote or Page Down).
Sega Mega Drive / Genesis: "megadrive file.md" (or .gen, .bin, .smd) or Enter
in the explorer (.bin only when the header says it is a Mega Drive game). The
68000 is the same as in the Amiga (the shared file m68k.inc), the Z80 the same
as in the Master System; the picture is drawn line by line (planes A and B,
the window, sprites, shadow / highlight, scrolling of the whole screen, of
strips and of lines), sound YM2612 (FM, 6 channels, DAC) and PSG. On the box
with sound: Super Mario World (Taiwan) 12.3 ms + 2.7 ms of drawing, Super
Mario Bros. (a PD hack) 9.3 + 1.9 ms, Snake 9.7 + 2.3 ms - the full 60
frames/s. The register writes to the sound chips are collected through the
whole frame and played at its end in one go (the same as sample by sample,
but the tables stay in the cache: sound cost 5.1 ms of a frame, now 2.3 ms),
and the FM operators are computed every second sample (26.6 kHz). Demos with
effects on every line (wobble, scaling) do not fit in 16.7 ms. Missing:
changes in the middle of a line, interlace mode 2 (the first field only),
SSG-EG and CSM in the YM2612, a 6-button pad from the keyboard. The game Super
Mario World (Taiwan) has a protection (a read of 0xA13000) - recognised by
the "SEGASEGA" header.
Sega SG-1000 / SC-3000: "sg file.sg" (or .sc) or Enter in the explorer; the
TMS9918 picture modes (Graphics I and II with the masks, Multicolour, 40-column
text, 8x8 / 16x16 sprites with the limit of 4 per line). A frame takes about
5 ms + 1.6 ms. Cartridges with their own RAM: up to 32 KB - 8 KB of RAM from
0x8000 (The Castle), 33-48 KB with an empty 0x2000-0x3FFF - RAM there. No
SC-3000 keyboard.
C64 cartridges (.crt): "c64 game.crt" or Enter in the explorer; the type is
recognised by the "C64 CARTRIDGE" header, not by the name; the C64 ROMs are
still needed. A frame takes about 3.3 ms + 2.7 ms. Writes to the EasyFlash's
flash are ignored (games do not save their state), freezers (Action Replay
etc.) and the Final Cartridge III NMI button are not supported.
More consoles (all with 48 kHz sound through "snd", .zip/.gz support, built-in
clean BIOS replacements and opening from "explorer", tested on the S3811 box
with free homebrew games): PC Engine ("pce", 4-10 ms/frame), ColecoVision
("coleco", 2.5-3.5 ms) and MSX1 ("msx", 3-4.8 ms), WonderSwan / Color ("ws",
2-10 ms at 75.5 Hz), Super Nintendo ("snes", 6-16 ms, SPC700 BRR), Neo Geo
AES/MVS ("neogeo", 2.5-14 ms, YM2610), Game Boy Advance ("gba", 5-17 ms,
ARM7TDMI + DirectSound), Atari 7800 ("a78", 4.3-6 ms) and Atari Lynx ("lynx",
5-8.2 ms), Vectrex ("vectrex", 6-15.7 ms, 540 x 720), Famicom Disk System
("fds", 4.6-11.3 ms), Neo Geo Pocket Color ("ngp", 8.8-11 ms), Odyssey2 /
Videopac ("odyssey2", 2.5 ms), Intellivision ("intv", 4.4 ms) and Sony
PlayStation 1 ("psx", R3000A + GTE 3D + SPU ADPCM, XA-ADPCM and CD-DA,
streamed .cue/.bin and PS-X .exe: 2-15 ms/frame on homebrew 3D games and
demos; the explorer tells PlayStation .exe files from DOS programs by itself).
The PlayStation's memory card (slot 1; slot 2 is empty) is the game's .sav
file, a 128 KB card image: with the built-in BIOS too, games check it, format
it, save to it and load from it (checked with a career of Tony Hawk's Pro
Skater and the records of Tekken 3). Like every .sav it is written to the disk
when the player is left (Esc), not at the moment the game saves: leave the
player before the box is switched off.
Three commercial games were checked on the S3811 box on 2026-11-25 (their
files are not part of this package). Super Mario Kart ("snes"): the
cartridge's DSP-1 maths chip is emulated - its commands in the chip's own
fixed point (multiply, inverse, the rotations, the projection and the raster
parameters the game draws its Mode 7 track with); a frame of a race takes
14.4 ms + 1.8 ms of drawing, where 16.6 ms would be every frame drawn.
Another World for the Game Boy Advance ("gba"): 7.7 ms + 0.8 ms, full speed.
Duke Nukem: Total Meltdown ("psx", the European disc, PAL): the logo videos,
the menus and the first level, with XA-ADPCM video and level music; in the
level a frame takes about 12.1 ms + 1.9 ms of the machine's 20 ms. Discs with
Redbook CD-DA audio tracks in a .cue play their CD audio through the SPU too.
A Super Nintendo or Game Boy Advance frame that starts more than a frame late
is run without its picture (never two in a row): the game and its sound keep
their speed, the picture loses that frame, and leaving the player says how
many were not drawn. Played that way Super Mario Kart's Grand Prix kept its
60 frames a second with nine of every ten frames drawn.
A second round on the three players the same day, each change checked by the
same picture sums on the box and by random pictures drawn with the old and
the new code: PlayStation rectangles - the sprites of 2D games and menus - by
loops of their own (Tetrade 22.0 -> 6.3 ms a frame, Tekken 3's intro and
menus 26.4 -> 20.8 ms); Super Nintendo colour maths on whole colours and each
line's sprites listed once a frame (games with colour maths on every line 18
to 24 % faster, the others up to 8 %); Game Boy Advance lines composed by
painting the layers from the back and written to the TV four pixels at a time
(games with colour effects 15.8 -> 6.3 ms and 22.6 -> 15.3 ms a frame, tile
games 11 to 38 % faster).
A third round the same day, again with the same picture sums on the box:
Game Boy Advance Thumb instructions fetched directly from a pointer in ROM or
RAM with register-resident flags (Blocktrap 17.0 -> 10.3 ms a frame, Another
World 8.3 -> 7.7 ms); Super Nintendo 16-pixel-tile backgrounds and hi-res
Modes 5 and 6 drawn by tile slivers instead of pixel by pixel (Monster Farm
Jump 18.0 -> 12.9 ms); PlayStation one-pixel textured wall columns batched
into cache-line strips before writing VRAM (Duke Nukem in a level 13.3 ->
12.1 ms).
Archives: every emulator takes a game in a .zip (the stored and deflate
methods; the largest file that is not text, a picture or a directory is taken)
or in a .gz (an Amiga .adz too); the CRC-32 sum is checked. The save file is
named after the whole game file with .sav added (game.nes.sav; for an archive
game.zip.sav), so games of different consoles with the same name have
separate saves; an older game.sav file of the right size is still read, and a
save of another size (another console's) is left untouched. A game in an
archive plays the same as unpacked (the same picture sums on the box).
The antenna input ("rf"): the MaxLinear MxL603 tuner on I2C 0x60 (SCB0) and
the COFDM demodulator built into the S3811 - set up register by register as
the tuner's original software (dump.bin) does it. "rf scan" searches channels
21-69, "rf services" reads the channel names (PAT, SDT), "rf ts 10 4:/x.ts"
records the whole multiplex to a file (to play e.g. in VLC). Note: the S3811
receives only DVB-T, and in Poland the multiplexes already broadcast in
DVB-T2, so in Poland the Comsat has nothing to catch: the tuner works, but the
demodulator cannot lock on DVB-T2. "rf spectrum" draws the antenna's signal
level from 174 to 862 MHz on the TV (about 35 s). Three equal 8 MHz rectangles
at 668.25, 742.5 and 816.75 MHz are NOT multiplexes or LTE but interference
from the box itself: harmonics of its 74.25 MHz clock (the 720p picture clock;
9, 10 and 11 x 74.25). Apart from them the level stays at the minimum (16 %):
the antenna was not connected for these measurements. "rf live" is the same
chart measured over and over: each bar drawn right after its measurement (one
pass over the whole band still takes tens of seconds - the tuner must settle
on every frequency; a narrow window refreshes every few seconds). Keys (USB
keyboard, UART, remote): left / right - the marker (frequency, channel,
level), up / down - zoom in / out around the marker, PgUp / PgDn - move the
window, F - the whole band, + / - a shorter / longer measuring time (faster,
but less accurate), space - pause, P - peak hold, Enter - try to lock DVB-T on
the marker's channel, Esc - end.
USB hub: the demo turns on the hub ports' power, resets each port with a
device and reads the devices behind the hub (also a hub behind a hub), up to
15 devices in all (the hub must have one of the first 7 addresses);
"lsusb" shows each one with its hub and port number. Plugging a device into a
hub and unplugging it is noticed within about a second. Low and full speed
devices behind a USB 2.0 hub are handled through the hub's transaction
translator (split). Tested on a Comsat TE 1050 HD with a 7-port hub
(2 x 1a40:0101): the hub, a second hub, three USB memories and a keyboard are
found, the keyboard behind the hub types.
A USB keyboard (HID, boot protocol) types on the same command line as the
UART: US layout, Enter, Backspace, up/down arrows, Caps Lock, Esc = Ctrl-C, a
key held down repeats. The line being typed is also shown on the TV (the
COMMAND LINE box). Keys are read from the keyboard's interrupt endpoint, as a
PC does it: the controller polls it every 1 ms and gets a report when the keys
change. "usb kbd report" switches to reading by GET_REPORT every 16 ms,
"usb kbd interrupt" back (the demo also switches by itself when the chosen way
is refused). Not every keyboard gives its keys through GET_REPORT: the tested
low-speed keyboard 1a2c:2d23 always answers it with zeros. Typing on this
keyboard was tested on a Comsat TE 1050 HD.
A USB mouse (HID, boot protocol) moves a cursor (an arrow) over the picture on
the TV, starting from the middle. With the left button held it draws lines,
the right button picks the next colour (yellow, red, green, blue, white,
orange); the buttons and the wheel are printed on the UART with the cursor's
position. The controller polls the mouse by itself (its endpoint D, every
8 ms), so it does not disturb the keyboard or USB disks. "usb mouse" shows the
cursor's position and the counters. Tested on a Comsat TE 1050 HD: an A4Tech
09da:c10a mouse (low speed) behind a hub.

Boards: Opticum HD N2 (dump_maciej.bin, a TM1650 panel on GPIO 31 and 9) and
Comsat TE 1050 HD (dump.bin: no display, two buttons on the same pins,
shorting to ground). When the TM1650 does not answer, the demo stops driving
these pins and reads them as the UP (GPIO 31) and DOWN (GPIO 9) buttons.

Picture: the application draws 1280x720 (ARGB1555) on the OSD layer. On the
S3811 revision 1 the layer's header (0x280 bytes) carries the RGB->YCbCr
matrix, as in the original applications; without it every colour would be
black. The bootloader does not turn the video output on, so at start the demo
replays its board's picture settings by itself (the same as "video init"), and
only then USB - as the original does, because these writes disconnect the USB
device (after "video init" the demo sets it up again). The original's HDMI
driver starts the transmitter only when it detects a TV, so the tables were
recorded in the emulator with a "connected" TV: they include the HDMI
transmitter's start (out of reset, mute off) and end 1.5 s later. Tested on a
Comsat TE 1050 HD (S3811 revision 1): picture over HDMI, colours right.
Should the demo hang, the watchdog restarts the tuner by itself after 8 s
through the original bootloader (the update script catches it without a power
cycle). Should even that not help: switch the power off and on again.

The UART update uses .maincode.bin. The bootloader, keys and settings are
kept. No encryption is needed - LZMA and CRC are used.
