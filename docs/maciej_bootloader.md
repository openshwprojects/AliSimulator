# Applications for the original Opticum N2 bootloader

This workflow targets `dumps/dump_maciej.bin`, the Opticum STB HD N2 / ALi
M3801 dump supplied by maciej_333. It builds a small independent C application
and updates the application through the existing UART bootloader. The original
dump is never overwritten. The demonstration uses the DRAM and clock setup
already performed by the original loader; it is not a replacement reset ROM.

## Ready-to-use binaries

The latest application is the v4 demo (below): a command line, a TV picture,
the front panel, the remote control and the USB port. v3 is the small
application of the first software-restart tests; v2 files remain available
for reproducing the first hardware validation.

- [v4 UART payload](../firmware/maciej_app/bin/elektroda_ali_m3801_maciej_v4.maincode.bin):
  64 KiB application chunk for upload at `0x50000`.
- [v4 full flash image](../firmware/maciej_app/bin/elektroda_ali_m3801_maciej_v4.bin):
  complete 4 MiB image for the simulator or an external programmer.
- [v4 manifest](../firmware/maciej_app/bin/elektroda_ali_m3801_maciej_v4.json):
  sizes, addresses, commands, and SHA-256 checksums.
- [Portable v4 UART ZIP](../firmware/maciej_app/bin/maciej_uart_v4.zip):
  standalone `maciej_uart.py`, payload, and ASCII Polish instructions
  ([README_UART_v4.txt](../firmware/maciej_app/bin/README_UART_v4.txt)).
- The same four files exist for v3 (`..._v3.*`, `maciej_uart_v3.zip`).

```powershell
python tools/maciej_uart.py --port COM3 --capture-boot 60 flash firmware/maciej_app/bin/elektroda_ali_m3801_maciej_v4.maincode.bin --backup before-maciej-v4.bin
```

Replace `COM3` with the tuner adapter. For stock firmware or v1/v2, power the
tuner on after capture starts. When v3 is already running, leave it powered:
the first capture `c` requests a restart and subsequent `c` bytes interrupt
the original loader. A single `c` without continuing capture need not leave
the receiver in the loader. The unchanged Python and C# capture protocols
support this path. A new backup filename is required for every update.

From the extracted ZIP, install `pyserial` and use the same command with
`maciej_uart.py` and the payload filename in the current directory.
The image uses LZMA and CRC checks; no encryption or signing step is needed.
The updater preserves the loader and all bytes outside the maincode payload.

## UART restart in v3

The application accepts individual characters without Enter at 115200 8E1:

- `v`: print the banner and version.
- `p`: reply `pong v3`.
- `r`: restart through the original loader and boot the application again.
- `c`: restart for the updater's repeated-`c` bootloader capture.

The shipped v3's `platform_restart` follows the M3801/S3811 branch of this
dump's own `sys_watchdog_reboot` / `sys_ic_reboot`: set the warm-boot
marker, restore SPI controller mode, mask CPU interrupts, pulse the same
peripheral reset registers, and jump to `0xBFC00000`. The original loader
then reinitializes DRAM and caches and loads the application. The app waits
for UART transmit completion before restarting. It neither writes flash nor
replaces the bootloader. These register values apply to the exact supported
loader and board profile, not arbitrary ALi devices. Since the v4 demo
`start.S` resets the chip through the watchdog first and keeps this path
as the fallback (see the v4 demo below): the jump hung on a real box once
the display engine and VCAP were running.

`tests/run_dump_maciej_app_restart.py` builds the source. On C++ it exercises
two updates with different application bytes in one continuously running
simulator using the production Python CLI. It checks full backups/readbacks,
`r`, repeated-`c` capture, the original loader's verification, application
replies, and flash preservation. On Unicorn it checks native restarts,
software capture, and reboot without the long full-flash transfers. It is
included in the GitHub `--slow` suite; artifacts are under
`build/maciej_app/selftest/ENGINE/restart/`.

`tests/run_dump_maciej_ready_v3.py` also tests the exact shipped v3 binary and
ZIP on both engines: archive contents and hashes, native cold boot, three
`r` restarts, software capture, loader handshake/reboot, and unchanged flash.
This shorter regression runs in the default suite, with artifacts under
`build/maciej_app/selftest/ENGINE/ready_v3/`.

## The v4 demo

`firmware/maciej_app/demo/` is a larger freestanding application (about 180 KB,
most of it the four recorded display set-ups; no SDK, no RTOS, interrupts
masked, everything polled) for the same bootloader. It prints the same banner and `Version: v4`, then:

- **Command line** on the UART (115200 8E1): whole lines ended by Enter,
  echo, Backspace, Ctrl-C / Ctrl-U, Up/Down history (8 lines), prompt
  `m3801> `. `help` lists the commands: `version`, `ping` (`pong v4`),
  `info` (chip ID 0x3811 = S3811 and its revision byte, CPU clock from the
  strap, memory layout, which of the two boards it found, the display
  layer's enable register as the demo found it at start and now),
  `uptime`, `echo`, `md <addr> [len]`, `mr <addr>`, `mw <addr> <value>`
  (RAM, the flash window and the device registers only; `mw` refuses the
  flash), `screen`, `panel`, `keys`, `ir`, `usb`, `lsusb`, `clear`,
  `video init [opticum|comsat] [rev0|rev1]`, `reboot` / `restart` and `bootloader`. Every command may
  also be written with `/` in front (`/restart`, `/lsusb`).
- **TV picture**: a 1280 x 720 ARGB1555 bitmap on GMA layer 0 through one
  region head, the way the original application shows its OSD (head word
  0x`AA200B51`, pitch 2560). On a revision-1 S3811 -- a real box reads the
  chip word 0x38110001 -- the head is a 0x280-byte block whose +0x240 holds
  the matrix the layer's RGB colours are converted to YCbCr with; the demo
  puts the originals' BT.709 matrix there (on revision 0 too, where they
  leave it zero; no revision-0 chip was tried), enables the layer as they do (0x00040001
  on revision 1: bit 18 set, bit 19 clear; 1 on revision 0) and marks the
  region true-colour (0xB80063B8 = 1). The demo screen has live boxes for the system,
  the remote, the front panel, the command line and USB, and colour bars;
  `screen demo | bars | clear [rrggbb] | text <x> <y> <words> |
  rect <x> <y> <w> <h> <rrggbb> | on | off` draw on it (a drawing command
  pauses the live boxes until `screen demo`). The font is the demo's own
  5 x 7 bitmap font (`gen_font.py`).
- **Front panel** (TM1650 on GPIO 31 / 9, bit-banged as the bootloader does):
  `panel <text>` shows four characters, `panel bright 0..7`; key presses
  are reported as they happen (`[panel] key 47 pressed: KI1/DIG4 UP`) and
  shown as `P xx`; `keys` reads the key register. A board without the
  chip -- the Comsat TE 1050 HD (dump.bin's board) has no display, and two
  buttons on the same two pins, each pulled up and shorted to ground when
  pressed -- gives no acknowledge at start. The demo then lets go of both
  pins for good (a pin driven high would be shorted by a pressed button),
  says so on the UART and reads them as two buttons, UP (GPIO 31) and DOWN
  (GPIO 9): `[panel] button UP (GPIO 31) pressed` / `released` (two reads
  100 ms apart must agree), the front panel box shows them, `keys` gives
  their state and `panel` text is refused.
- **Remote control**: the M6303 IR receiver set up as the SDK's driver does
  and read by polling; every NEC frame is printed with its 32-bit code (as
  the SDK's decoder shifts it in), the four bytes and the button name from
  the original firmware's own key table (`gen_ir_keys.py`), and shown on
  the screen and the panel. The remote's POWER is `023750af` -- exactly the
  wake code the bootloader's standby loop waits for. `ir raw on` prints the
  pulse timings of every frame.
- **USB**: `usb` reads the host controller's port (connected, speed,
  over-current, the PHY's settings) and enumerates a connected device over
  endpoint 0 (its VID:PID, strings, interfaces, endpoints; then sets its
  configuration); plugging a device in does the same by itself and shows it
  on the TV, and so does a device already plugged in when the demo starts.
  `lsusb` lists the controller and the device in one line each
  (`Bus 001 Device 001: ID 1209:0001 AliSimulator Virtual USB stick, high
  speed (480 Mbit/s)` in the emulator). `usb reset` drives a bus reset,
  `usb init` sets the controller up again, `usb reg <offset> [byte]` reads
  or writes one of its registers (byte-wide; not the PHY's), `usb ctl <type>
  <request> <value> <index> <length> [device]` sends a control request to
  the device with that address (1, the one on the box's port, when none is
  given) and prints what it answers.
- **USB hubs**: a hub on the port is set up with everything behind it --
  its ports powered, each port with a device reset in turn, the device given
  the next address and enumerated like the first; a hub behind a hub the
  same way -- up to seven devices in all. `usb` lists each with its hub and
  port, `lsusb` one line each (`Bus 001 Device 004: ID 1209:0002 ..., low
  speed (1.5 Mbit/s), hub 1 port 4`). A device that is not high speed behind
  a high-speed hub is reached through that hub's transaction translator
  (split transfers: the controller's split registers). One port of one hub
  is looked at every 100 ms, each in its turn, so a device plugged into a
  hub or pulled out is noticed within a second or so and said on the
  console (`[usb] hub 1 port 2: device connected`). The first keyboard
  found types; when it is unplugged the next one takes over. Limits: seven
  devices, a hub's first seven ports (the split registers hold three bits
  of a hub's address and port); a low-speed device behind a full-speed
  (USB 1.1) hub does not answer and is left alone.
- **USB disks**: a stick, a card reader or a USB disk (mass storage with
  SCSI commands over the bulk-only transport) is found as it is set up --
  its name, size, partitions (MBR or GPT) and file systems -- and `disks`
  lists them. On FAT12, FAT16 and FAT32 (long file names too; read only)
  `ls [n:][/path]` lists a directory -- dates, sizes, names -- and `cat
  [n:]/path` shows a text file (a binary one: its first 256 bytes in hex;
  Ctrl-C on the UART stops it); `sector [n:]<number>` shows any sector in
  hex. A disk is named by its USB device number as `lsusb` lists it (`ls
  3:/docs`, `n.p:` for its partition p); without one the first FAT volume
  is used, and paths take any case. NTFS and exFAT are listed but not
  read; only a device's first logical unit is used, and up to four disks.
- **USB keyboard**: a keyboard (an interface of class HID, protocol
  keyboard) types into the same command line as the UART -- US layout,
  Enter, Backspace, Up / Down (history), Caps Lock, Escape (as Ctrl-C), Ctrl
  with a letter; a held key repeats after 500 ms -- and the line being typed
  shows on the TV too, in the command line box. Its reports are read from
  its interrupt endpoint, as a PC reads a keyboard: an IN transfer that
  stays pending on the controller's endpoint B and is asked again every
  millisecond until a key goes down or up. `usb kbd report` reads them with
  GET_REPORT over endpoint 0 every 16 ms instead and `usb kbd interrupt`
  switches back (the demo changes the way by itself, once, when the one in
  use is stalled three times) -- but not every keyboard answers GET_REPORT
  with its keys; `usb kbd` tells which way is in use. A keyboard that stops
  answering (three reads with no answer at all, not a stall -- a reset
  device, as after a display set-up) is set up again by itself, three
  times at most before a report comes. `ccc` typed on it is just
  text: the restart for the UART updater listens to the UART. `usb kbd raw
  on` prints every report that differs from the last. Known limits: the
  reports are taken only between commands, so a key pressed and released
  while a long command runs (`md` of 4 KB, `video init`) can arrive late or
  be lost; an unplug and replug within 100 ms is not noticed (`usb`
  enumerates again); and the keyboard's LEDs are not driven. See the USB
  section below.
- **USB mouse**: a mouse (HID, boot protocol mouse) moves a pointer -- a
  black and white arrow -- over the TV picture, starting in the middle;
  with the left button held it paints a line (a 5-pixel brush), the right
  button picks the next colour (yellow, red, green, blue, white, orange),
  and the buttons and the wheel are told on the UART with the pointer's
  place (`[usb] mouse: left down at 700,390`). Its interrupt endpoint is
  polled by the controller's endpoint D on its own, every 8 ms for the
  usual 10 ms mouse, so the keyboard keeps endpoint B and a disk's
  transfers disturb neither. `usb mouse` gives the pointer's place, the
  buttons, the wheel and the counts. Limits: one mouse (a second is listed
  and left alone); reports that come while a command runs wait in endpoint
  D's FIFO and their movement arrives in one step afterwards.
- **`video init [opticum|comsat] [rev0|rev1]`**: the bootloader never
  touches the display, so on the box the TV stays dark until something
  programs it -- the demo runs its board's set-up by itself as it starts,
  before USB (the set-up's reset and clock stores knock a USB device out:
  on the box a keyboard answered nothing afterwards until a bus reset; the
  originals too start their USB only after their display), and `video
  init` sets a connected USB device up again afterwards. This replays the register stores with which a board's own
  original application brings up its 720p picture -- display engine, TV
  encoder (0xB8008000), VCAP, the HDMI transmitter (0xB802A000) and its
  PHY setting 0xB8000400, clock and reset bits, with the pauses of 2 ms or
  more between them (about 1.8 s in all) -- then drives GPIO 17 low (both
  originals do) and puts the demo's layer back. There are four tables,
  recorded in the emulator by `gen_video_init.py`: per board, `opticum`
  from dump_maciej.bin and `comsat` from dump.bin (without a name the
  board's own: the TM1650's answer tells them apart), and per chip
  revision, which both firmwares branch on -- the TV encoder's set-up and
  the moment the output is switched on differ (without `rev0` / `rev1` the
  chip's own). The boards' tables differ in the TV encoder's output set-up
  (0xB800808C; on revision 1 also 0xB800809B) and in the addresses of the
  display buffers (0xB80061E4, 0xB8006234, VCAP's 0xB800F010 / 0xB800F01C),
  which the demo keeps its own picture clear of (it is at 0x02000000). Each recording
  starts from the register values a real S3811 has after a reset
  (`s3811_rev1_reset_values.json`, read on the box below): the emulator's
  device registers start at 0 and the drivers change single bits of them.
  The HDMI driver (the SDK's libHDMI: `hdmi_ctrl_task`) keeps the
  transmitter in soft reset, bit 0 of 0xB802A007, until it sees a TV --
  hot plug and receiver sense, bits 0 and 1 of 0xB802A008 -- so the
  recording shows the firmware one. Then both set the PHY up, send their
  AVI / audio / MPEG / SPD infoframes, change a clock (bit 16 of
  0xB8000078), release the reset (0xB802A007 = 0x7C) and unmute three times
  (bit 3 of 0xB802A009); the tables end 1.5 s later, past the output's
  switch-on on both revisions. The TV's EDID makes no difference to what
  the drivers write (they keep their 720p 50 Hz). On the real box below it
  gives the TV its picture.
- **Watchdog**: the demo runs the chip's watchdog from its start, as both
  original applications run theirs (the SDK's `dog_m3327e` at 0xB8018500: a
  32-bit counter at +0 counting up at the memory clock / 2^(5+n), the
  control byte at +4 -- n in bits 0..1, bit 2 counting, 0x60 a chip reset at
  the overflow; in the emulator dump.bin and dump_maciej.bin write 0xFDC3CB9F,
  then 0x64, and the counter again about three times a second -- 8 s if it
  counted at 150 MHz / 32). The demo
  measures the counter's rate against CP0 Count over 20 ms (control 0x04:
  counting, no reset), starts it 8 s before the overflow with 0x64 and feeds
  it every 0.1 s from its time reads -- the main loop's, every delay's and
  every wait's. A demo that stops -- a bus access that never ends, as one with
  the USB PHY held in reset did on the box, or a loop that reads no time --
  restarts the box within 8 s through the original bootloader, where the
  updater can catch it without a power cycle. `watchdog` reports it, `watchdog
  test` stops feeding it on purpose, `watchdog off` / `on`. On the real box
  (revision 1) the counter measured 844,100 ticks/s with n = 0 -- 27 MHz /
  32, the crystal's clock, not the memory clock the SDK's driver computes
  with -- and `watchdog test` restarted the box 8.5 s after the demo stopped
  feeding it, straight back into the demo.
- **Updates keep working**: three `c` on an empty line (what
  `maciej_uart.py --capture-boot` sends) restart the box through the
  original bootloader, which the updater then captures, as with v3;
  `reboot` (or `restart`) restarts it into the demo. `bootloader` restarts
  it too and says how to stay in the original bootloader's shell: hold the
  c key (or start the updater). The bootloader keeps its shell only when
  'c' arrives while it starts (it has no other way in: the SDK's
  0xdead2bee "boot code" path is not reachable in this build); a held key
  works either way, because the demo restarts again on `ccc`. Every restart
  (`start.S`'s `platform_restart`, also in the small apps) first resets the
  chip through the watchdog, as the M3801 loaders' own `reboot` does
  (0xB8018500 = 0xFFFFF000, then 0x67 at +4: the SDK's `dog_m3327e`), so the
  bootloader starts as at power-on; only when no reset comes within about
  0.3 s -- in the emulator, which has no chip reset (`src/watchdog.py`, opt-in,
  counts and records the overflows only) -- does it stop the watchdog, switch
  the OSD layer off and jump into the loader's warm restart (`$s8` =
  0xdeadbead) as before.

Build and release (the release script makes the four files above and its
ZIP byte-for-byte reproducible):

```powershell
python firmware/maciej_app/build.py --version v4 --demo
python tools/maciej_release.py --version v4 --app build/maciej_app/v4/app.bin --readme firmware/maciej_app/bin/README_UART_v4.txt
```

`tests/run_dump_maciej_demo_v4.py` (default suite, about a minute) checks the
shipped files and, with a MIPS GCC, that the source rebuilds to the shipped
bytes; then it boots the shipped image through the original bootloader and
drives it only through its inputs: 172 checks over the commands (every one
listed by `help`; all but `uptime`, `clear`, `ir raw` and `panel bright`
run), the line
editing, the screen pixel by pixel (banner, header colour, the eight colour
bars, clear / rect / text / off / demo, the ARGB1555 words in RAM), the
layer's head block (the head, the filter table zero, the BT.709 matrix at
+0x240) and enable registers, the panel's digits and both keys,
four buttons of the box's remote and an unknown remote, the emulator's
virtual remote by key name, USB plug-in / enumeration (descriptors,
strings, configuration, the exact SETUP packets) / speed / bus reset /
plug-out and the controller's set-up (the PHY as the box's firmware writes
it), `lsusb`, a USB keyboard (as the real one tried on a box: low speed,
two interfaces, GET_REPORT always empty; enumerated in 8-byte packets, the
boot protocol, the IN on endpoint B set up as the SDK's bulk IN with its
packet into RAM by DMA, one IN token per millisecond while no key changes,
typing with Shift, punctuation, Backspace, Up, Caps Lock, Escape, a held key
repeating, `ccc` only text, the line on the TV; a control request while the
IN is pending; nothing typed with `usb kbd report` on that keyboard, typing
again after `usb kbd interrupt`; enumerated again with no report lost to the
data toggle; unplugged without an error line; a full-speed keyboard, also
with GET_REPORT; keyboards that stall GET_REPORT, the interrupt endpoint, or
both), a USB hub (the tree tried on a real box: a high-speed hub with a
second hub, a stick and the low-speed keyboard behind it -- all enumerated,
the ports powered and reset one after the other, the keyboard addressed
and read through the translator with the split registers, `lsusb`, the TV's
USB box, `usb ctl` to a device behind the hub; a second keyboard plugged
in, the first unplugged and the second taking over; the keyboard moved
behind the second hub; that hub unplugged with what is behind it; a
full-speed hub with a full-speed and a low-speed keyboard), USB disks (a
hub with a FAT32 stick -- one file in clusters that are not one after the
other -- a card reader's FAT16 card that first answers "the medium may
have changed", a full-speed FAT12 stick without a partition table, and the
keyboard: each found as it is set up, `disks`, `ls` in any case, `cat` of
text, of the scattered file and of a binary one, `sector`, the errors, the
keyboard typing between the disks' commands with no packet dropped and no
command broken; a card reader without a card; a stick that leaves the
first command after idling unanswered, sent again after 2 s; a stick pulled
out), a USB
mouse (as on the real box: low speed behind the second hub, the keyboard on
the first, a stick -- its endpoint polled by endpoint D as the SDK sets it
up, both toggles DATA0 first; the pointer drawn and moved, a click, a
painted line in the framebuffer and on the captured screen, the right
button's colour, the wheel, `usb mouse`; the keyboard typing and `ls` /
`cat` on the stick while the mouse moves, nothing dropped; unplugged and
plugged in again), the
watchdog (running in reset mode from the start, fed every
0.1 s, never overflowing through all of it; the model in `src/watchdog.py`),
`video init` (the Opticum's table: 720p timing, the HDMI
transmitter out of reset and unmuted, the board's own TV encoder values),
`reboot` / `/restart` (arming the watchdog first), `bootloader` with a held c key, the updater's
capture and handshake from the running demo, and that the flash never
changes. `tests/run_dump_maciej_demo_v4_comsat.py` (default suite, about
40 s) runs the same image on the Comsat's board -- two buttons on GPIO 31
/ 9 (`gpio_keys.GpioKeys`), no TM1650 -- and, as the real box, on a
revision-1 chip, in 62 checks: button mode, both pins inputs after the
probe and never driven again, the buttons' events (a single low read is
not a press), `keys`, the front panel box, `info`, `panel` refused, the
layer enabled as the originals do on revision 1 with their matrix in its
head; what the real box showed -- the matrix zeroed by `mw`, every colour
black; bit 19 set, the dark background green -- and the colours back with
the matrix written again; `video init` picking the Comsat's revision-1
table and starting the HDMI transmitter, `video init opticum`, `video init
comsat rev0`; a low-speed USB keyboard typing (read from its interrupt
endpoint), with the controller's PHY set up with the revision-1 values, set
up again by itself when it stops answering (reset behind the demo's back)
and after `video init`; a restart that comes back the same way, the
keyboard, still plugged in, found before the first prompt; and `watchdog
test` stopping the feeding (the counter running on to its overflow).

### On a real box

The first v4 build was flashed on a Comsat TE 1050 HD on 2026-11-12 --
dump.bin's board, which has carried the Opticum's flash image since v3 --
by the transfer and burn of the main code chunk alone (41 s, no backup).
The original bootloader starts it and the command line works. USB works:
a CH341 adapter (1a86:5512 "USB UART-LPT", USB 1.10, full speed, vendor
class, three endpoints) plugged in was noticed, enumerated and configured,
and `lsusb` listed it. `keys` found no TM1650 (the board has none) and
`video init` ran to the end (720p timing set, the demo kept running) but
the TV stayed dark: that build's table left the HDMI transmitter in reset.
Then `ccc` (the updater's capture) printed its restart message and the box
went silent: the jump into the loader's warm restart, which v3 always
survived, hung with the display engine and VCAP running after `video init`
(and the USB controller set up) -- most likely the loader reinitializing
the DRAM under their transfers; the emulator models no bus, so it never
showed. The second build changed all three (button mode; the HDMI start in
the table; the restart through the watchdog). It went onto the box the same
way, except that the old build had to be caught at power-on (paced 'c'
while the box was switched on: its own restart hangs). It found no TM1650
there, both front buttons reported their presses and releases, each once
(UP on GPIO 31, DOWN on GPIO 9), and `restart` after `video init` came
back through the watchdog reset. But the TV still stayed dark after `video
init`, although the transmitter saw it (0xB802A008 read hot plug and
receiver sense) and the TV worked with a PC on the same cable. Writing
0x300 to 0xB8000400 by hand -- both applications do at their HDMI init,
outside that build's recorded ranges (the tables include it now), and it
read 0 -- before `video init`, and GPIO 17 low (both pull it low next to
their HDMI start; `video init` now does too) did not change that either.

It was not the box, the cable or the TV: the Opticum's original main code,
flashed back for a comparison, showed its language wizard over HDMI. (This
TV, with no signal, goes dark and says it enters power saving -- "black"
meant no signal at all, not black pixels.) Its console's REBOOT resets the
display engine, the TV encoder and the transmitter too, so its working
set-up could not simply be handed over to the demo. Two differences
between the emulator and the chip were behind the missing signal:

- **The chip's revision.** The box reads 0x38110001 at 0xB8000000 --
  revision 1 -- where the emulator answered 0x38110000, and both firmwares
  branch on it (`sys_ic_get_rev_id`): the TV encoder's set-up, the GMA
  layer's enable bits and, on the Comsat, when the output is switched on.
  `gen_video_init.py` now records each board at both revisions, and the
  demo replays the table of its chip's.
- **The reset values.** The emulator's device registers start at 0, the
  chip's do not -- the transmitter's PHY bytes +0x0A..+0x0F come up as 02
  92 24 49 82 21, the display engine with a PAL timing, the TV encoder with
  dozens of values, 0xB800006C / 0xB80000B0 as 0x80000000 / 0x00030100 --
  and the drivers change single bits of them, so a recording made from
  zeros wrote values the chip never gets from its own firmware. They were
  read on the box after a watchdog reset with the demo's `md`
  (`s3811_rev1_reset_values.json`), and the recordings start from them.

With both, `video init` gave the TV a signal, and a black picture. The
display engine's background colour (0xB8006188, YCbCr) set to red changed
nothing at first: the demo's opaque, black layer covered it. With the layer
switched to CLUT8 (the picture's own data as its palette) and its head
pointer 0xB8006304 written again, the whole screen turned red, and with the
layer off a green background (0x00913622) showed: the output reached the
TV. The layer itself showed its alpha -- a transparent palette entry let
the background through, an opaque one covered it in black -- but never a
colour, ARGB1555 and CLUT8 alike.

To watch the TV from the PC, a phone on USB pointed its camera at it: `adb
shell am start -a android.media.action.STILL_IMAGE_CAMERA`, then `adb
exec-out screencap -p` and the average colour of the middle of the view;
small scripts sent console commands (`mw`, `screen clear ...`) one by one
and looked after each. Setting the bits of the layer's enable register
0xB8006300 one at a time found bit 19: with it the colours came, but dark
ones green. The layer then takes a pixel's red, green and blue fields as
Cr, Y and Cb -- all zero, the demo's black, is green in YCbCr -- and
colours written that way (black as Cr 16 / Y 2 / Cb 16) were right.

The original applications' GMA driver (the same code in both, newer than
the SDK's) had the rest. On revision 1 a region head is a 0x280-byte block
whose +0x240 holds the matrix the layer's RGB is converted to YCbCr with,
copied into every head by `gma_m36f_sync_block_header`: BT.709's for an HD
output (x512, the rows Y, Cb, Cr of R, G, B and an offset: 93 314 32 0 /
-52 -173 225 0 / 225 -204 -21 0, then 45), BT.601's for SD. Their
`gma_m36f_open` also sets bit 18 of the enable register and clears bit 19
(set, the bit skips the matrix), and `gma_m36f_create_region` writes
0xB80063B8 = 1 for a true-colour region. The demo's 40-byte head left the
matrix zero: every colour black. Written into its head with `mw` (bit 19
clear), the originals' matrix ended the black: the picture came through it
-- the build then running still stored its colours as YCbCr words, so its
black showed purple, that word read as RGB. Bit 18 and 0xB80063B8 made no
visible difference. The final build does what the
originals do -- the 0x280-byte head with the matrix, 0x00040001,
0xB80063B8 = 1 -- and the demo's picture is on the TV in its colours: the
demo screen, the colour bars, black, greys, white and red, checked through
the camera.
`info` reads 0xB8006300 as 0 when the demo starts after a reset, so the
chip does not set bit 19 itself. The emulator now shows what the box
showed (`gma_capture.py`, `chips/m3801.py`): a revision-1 head's colours go
through its matrix -- all zero, black -- and bit 19 makes them YCbCr;
`run_dump_maciej_demo_v4_comsat.py` zeroes the matrix and sets the bit.

## USB

The S3811 has an ALi USB 2.0 host controller (the SDK's `hc_s3602` /
`hcd_s3602` driver, `refs/MainCode/ddk/libcore_hd.a` and, newer,
`libcore_v40b.a`). The original application attaches it at **0xB8032000**
(found by breaking on the driver's register accessors) on
interrupt-controller line **29** (the SDK's OS IRQ 0x25), after a reset
pulse on bit 28 of 0xB8000080. The accessors, the interrupt handlers and the
box's own firmware's driver (dump.bin and dump_maciej.bin, traced in the
emulator at both chip revisions) give the register map:

| Register | Meaning |
| --- | --- |
| +0x10 | port: bit 0 over-current, bit 1 device connected, bit 2 (revision 0: cleared and set after the PHY set-up and before a bus reset), bit 5 drive a bus reset (written as 0x20; the controller ends it), bit 6 suspend, bit 7 resume |
| +0x11 | endpoint 0: bits 0..1 token PID (0 SETUP, 1 OUT, 2 IN), bit 4 FIFO reset, bit 5 send the token; read: bit 7 FIFO empty |
| +0x12 | endpoint 0's FIFO port |
| +0x13 / +0x16 / +0x19 / +0x22 | endpoints A / B / C / D: bits 6..7 the transfer type (0x80 bulk, 0xC0 interrupt), bits 2..5 the device's endpoint |
| +0x14 / +0x17 / +0x1A / +0x23 | their FIFOs: bit 4 reset (endpoint B's also ends a pending IN), bit 0 pulsed: the data toggle back to DATA0 (`set_ep_data_toggle`; measured for B and D); read: bit 7 empty, bit 6 full. +0x1B / +0x24: endpoint C's / D's FIFO port |
| +0x1C | device address (before the new mode) |
| +0x1D | why the last token failed: 0x80 stall, 0x40 PID error, 0x20 no response, 0x10 unexpected, 0x08 data toggle, 0x04 UTMI, 0x02 CRC (`hcd_s3602_upt_parse_error`) |
| +0x1E / +0x1F | interrupt enables |
| +0x20 | interrupt flags 1 (read to clear): bit 0 connection changed, bit 1 bus reset done, bit 5 a token got no answer (seen with endpoint B's) |
| +0x21 | interrupt flags 2 (read to clear): bits 7 / 3 endpoint 0's token done / failed, 6 / 2 endpoint A, 5 / 1 B, 4 / 0 C |
| +0x2B | bit 5: endpoint C polls its endpoint every +0xA2 ms; bit 3: endpoint D every 2^(+0xA3 - 1) microframes (`en_int_interval_ctrl`) |
| +0x2C | 16 bits: the size of endpoint B's last packet |
| +0x2E / +0x2F | interrupt enable 3 (0x77: `en_host_int_flag3_all`) / interrupt flags 3 (read to clear): bit 4 endpoint D's packet came, bit 0 its token failed (`hcd_s3602_h2c_int`: `epD_finish_ok`, `ep_err_finish`) |
| +0x30 | packet sizes, 8 << n: endpoint A's in bits 0..2 (set with bit 3), endpoint B's in bits 4..6 (with bit 7) |
| +0x31 | packet sizes, 8 << n: endpoint C's in bits 0..2, endpoint D's in bits 4..6 |
| +0x32 | bits 5..6 the device's speed: 0x00 high, 0x20 full, 0x40 low (`hcd_ioctrl_get_speed_ex`; its high / full / low values are the hub code's, from the port status); bit 2 the controller sends the IN tokens of a DMA receive (`dma_host_in_token`), bit 3 the DMA transfer runs (`en_dma_transfer`) -- the controller clears both when the transfer ends |
| +0x34 / +0x3E | host mode (\|= 0x90), `en_epa_auto_force` (\|= 0x08) |
| +0x38 | 24 bits: the bytes a DMA receive takes (`set_dma_rx_cnt`) |
| +0x3D | revision 0: \|= 0x60 before every bus reset |
| +0x40 / +0x44 / +0x48 | DMA receive: the buffer's physical address (32-byte aligned), its index, the bytes received (24 bits; final only once +0x63 bit 2 is set -- read at endpoint B's done flag it can still be one short) |
| +0x50 / +0x54 / +0x58 / +0x5C | DMA transmit: the buffer's physical address (32-byte aligned), its index (0x20 after a 31-byte block), the bytes to send (24 bits), the bytes left |
| +0x60 | DMA strobes (they read back 0): bit 5 / 4 the receiver's state set up / its transfer started, bit 1 / 0 the transmitter's, bits 7 / 6 the bulk-only command list's |
| +0x62 / +0x63 | interface interrupt mask / status (read to clear): bits 0 and 3 -- flags 1 / 2 are pending; 0 and 2 -- a DMA receive is done; 0 and 1 -- a DMA transmit is done (both measured); 0 and 4 a bulk-only command (the SDK's handler) |
| +0x68 | DMA options: 0x80 \| size code << 4 receive (`enable_dma_auto_rx`), 0x08 \| size code transmit |
| +0x80 / +0x82 / +0x84 / +0x86 / +0x88 | endpoint 0's / A's / B's / C's / D's device address << 1, once +0x8F = 0x80 (the per-endpoint addresses both firmwares switch on); bit 0: the device is reached through a high-speed hub's transaction translator (split transfers) |
| +0x81 / +0x83 / +0x85 / +0x87 / +0x89 | that translator, per endpoint (`set_ssplit_ctrl_info`): bits 0..2 the hub's address, bits 3..5 its port, bit 6 the device is low speed (the SDK never sets it; measured: a low-speed keyboard or mouse behind a hub answers with it). +0x89 bit 7 reads 1 while endpoint D's split transaction is under way (about 1 ms) |
| +0x90 | `set_plug_status`: the SDK writes 3 before a bulk transfer to a high-speed device and 1 to a full-speed one (2 and 1 before the first requests to a device behind a hub), dump.bin's driver 0 for a full-speed stick. Measured: with 2 or 3 the controller does not split, so a low-speed device behind a hub gets no answer; the demo leaves it at 0 |
| +0xA2 / +0xA3 | endpoint C's polling interval (the endpoint's bInterval) / endpoint D's: a token every 2^(n - 1) microframes (7: 8 ms, measured), 0 stops it |
| +0xA8 | NAK retry: 1 (the SDK's value) -- an IN the device answered with NAK goes out again in the next frame, 1 ms later; 2..15 that many times a frame; 0 at once; 0x10 and above never again (measured with endpoint B) |
| +0xF2, +0xF0 / +0xF4 | the PHY: its reset (7, 2 ms, 0; byte writes), then its 32-bit settings -- revision 0 read-modify-writes to 0x60007500 / 0x10000000, revision 1 0x6800355C / 0x09000FF0 (the box reads 0x0800F514 / 0x10000FF0 before) |

A register access while the PHY is held in reset hangs the box: a hand-made
pulse (`mw` putting 7 into +0xF2 with a 32-bit store) left it silent until it
was switched off, so `usb reg` refuses the PHY's registers and only `usb
init` touches them, the way the firmware does.

`src/usb_host.py` models the port, endpoint 0's control transfers,
endpoint B's IN with DMA -- one packet into RAM, the token again every
millisecond while the device answers NAK, the data toggle, "no response",
the FIFO reset that ends it: all as measured on the box, below --
endpoint C's interrupt polling (which, as on the box, sends a low-speed
device nothing) and endpoint D's (which does: a token every 2^(+0xA3 - 1)
microframes, the packet into its FIFO, flags 3 bit 4, its own data toggle),
with two built-in devices: a USB 2.0
mass-storage stick (pid.codes test IDs 1209:0001, "AliSimulator" / "Virtual
USB stick", one interface: class 08 / SCSI / bulk-only, bulk endpoints 0x81
and 0x02) and a keyboard (`VirtualKeyboard`, 1209:0002, endpoint
0 of 8 bytes, a HID boot keyboard with its interrupt endpoint 0x81:
SET_PROTOCOL / SET_IDLE / GET_REPORT, `.type(text)` presses the keys in
emulated time; `get_report="empty"` makes GET_REPORT always answer eight
zero bytes and `composite=True` adds a second HID interface, as the real
keyboard below has; `get_report=False` / `interrupt=False` make it stall
GET_REPORT / its interrupt endpoint). A third is a mouse (`VirtualMouse`,
1209:0004, low speed, a boot mouse with the A4Tech's report descriptor:
`.move(dx, dy, over)`, `.press` / `.release` / `.click`, `.wheel(n)` in
emulated time; a report only when something changed). A fourth is a hub
(`VirtualHub`, 1209:0003: the hub descriptor, a port's power / reset /
enable and change bits, GET_STATUS, its status-change endpoint;
`.plug(port, device, speed)` / `.unplug(port)`, hubs behind hubs too): a
device behind it answers only while its port is powered and enabled, a
device that is not high speed behind a high-speed hub only to a token with
the split flag and that hub's address, port and speed bit in the split
register -- and a silent port behind a translator comes back as a stall,
not as "no response", as on the box. Given a disk image the stick
(`VirtualStick(image)`; `src/fat_image.py` builds FAT12 / FAT16 / FAT32
images with long names, a label, an MBR or none, and files in scattered
clusters) answers the bulk-only transport -- endpoint A's OUT by DMA from
RAM, its command block, the data and the status on endpoint B -- with the
SCSI commands a host reads a disk with; `full_speed=True` gives it 64-byte
packets, `unit_attention=True` a first "the medium may have changed",
`no_medium=True` makes it a card reader without a card,
`lose_after_idle=s` leaves the first command after s idle seconds
unanswered (as the 64 GB stick below); like the real
stick below it ends a command whose bulk IN's halt is cleared after the
command block (the status stalls). Both endpoints keep their data toggles
per device endpoint, the controller's per endpoint A and B, and a packet
sent with the other toggle is dropped as on the bus. A token
reaches the device only at the address it carries (+0x80 in the new mode,
+0x1C before), and SET_ADDRESS takes effect after its status stage, as on a
real bus. It is opt-in: `sim.attach_usb_host()`, then `.attach(speed[,
device])` / `.detach()`.

Checked against the original firmware (`tests/run_dump_maciej_usb_attach.py`):
when the stick is plugged in, the original driver enables its interrupts,
debounces, drives a bus reset and enumerates the stick -- SET_ADDRESS(1),
GET_DESCRIPTOR(device) 8 and 18 bytes, GET_DESCRIPTOR(configuration) 9 and
32 bytes, SET_CONFIGURATION(1) -- then sends the mass-storage class's GET
MAX LUN and sets up its first bulk-only command (a 31-byte CBW through the
DMA engine). So the model's registers mean what the original driver
expects, up to the bulk transfers, which are not modelled.

The v4 demo does the same with its own polled code. It sets the controller
up as the box's firmware does for the chip's revision -- the block's reset
pulse, the PHY's reset and settings, host mode, the endpoints, NAK retry 1
-- and `usb` (and plugging a device in) resets the bus, switches the
per-endpoint addresses on and enumerates the device over endpoint 0 --
VID:PID, USB version, manufacturer / product / serial strings, interfaces
and endpoints -- sets its configuration and shows it on the TV
(`Device 1209:0001 Virtual USB stick` in the emulator). A SETUP goes out as
`hcd_s3602_issue_setup` sends it (the PID set to IN and back to SETUP, the
FIFO reset, the 8 bytes); a failed transfer is tried three times (not after
a stall), the enumeration's first request after three bus resets, and a
failure names the stage and the token error (`GET_DESCRIPTOR (device, 8
bytes), attempt 1 of 3: SETUP stage: no response (token error 0x20)`).
A keyboard among the interfaces is started (`kbd.c`): SET_PROTOCOL(boot),
SET_IDLE(0), endpoint B's data toggle reset (bit 0 of +0x17 pulsed), then
an IN on endpoint B aimed at its interrupt endpoint, set up as the SDK's
bulk IN (`hcd_s3602_bulkin_start`): the device's address at +0x84, the
endpoint at +0x16, the packet size at +0x30, one packet by DMA into RAM
(0x00F00400: +0x40, +0x38 = 8, +0x68 = 0x80, the +0x60 strobes), started
with +0x32 bits 2 and 3. When flags 2 bit 5 comes the report is read from
that RAM and the IN started again; bit 1 (a token nobody answered) counts
towards setting the keyboard up again. `usb kbd report` reads the reports
by GET_REPORT every 16 ms instead.

A disk (`disk.c`: an interface of class 8, subclass 6 -- SCSI -- protocol
0x50, bulk-only, with a bulk IN and a bulk OUT endpoint) is set up after its
configuration: GET MAX LUN, INQUIRY, TEST UNIT READY until it is ready
(REQUEST SENSE after each failure: 2/3A is "no medium", a unit attention
6/28 comes first from a card reader), READ CAPACITY(10), then sector 0: a
FAT, NTFS or exFAT boot sector without a partition table, else the MBR's
four primary entries (a protective 0xEE: the GPT's entries), and each
partition's first sector for its file system. A command is a 31-byte
command block wrapper sent from RAM by endpoint A's DMA (the SDK's
`hcd_s3602_bulkout_start`: +0x82 / +0x83 the device, +0x30 bits 0..2 the
packet size, +0x13 the endpoint, +0x50 / +0x58 the buffer and length, the
+0x60 bit 0 strobe, +0x32 bit 3; done at flags 2 bit 6 and +0x63 bits 0 and
1), the data and the 13-byte status wrapper received by endpoint B's
(several packets in one transfer: a 512-byte sector in eight from a
full-speed stick). A stalled data stage has its halt cleared and the status
read; a status that makes no sense, a command block the device does not
take, or no data or status within 2 s leads to the bulk-only reset recovery
(the class's reset, both halts cleared, 100 ms) and one more try, which may
take 10 s. FAT: the boot sector's geometry, the type
from the cluster count, a cached FAT sector, the root's label entry, long
names put together from their parts (checked against the 8.3 entry's
checksum), Windows' lower-case flags on 8.3 names.

Endpoint B now serves the keyboard's interrupt endpoint and every disk's
bulk IN, endpoint A every disk's bulk OUT, and there is one DMA engine (the
SDK takes a semaphore around it): the keyboard's pending IN is stopped
before a disk transfer and started again afterwards. The controller has one
data toggle per endpoint, a device one per endpoint of its own, so the demo
keeps every device's, counts the packets of each transfer, and before an
endpoint serves another device endpoint puts the controller's back to
DATA0 -- and the device's too, with CLEAR_FEATURE(ENDPOINT_HALT), when it is
DATA1. For a disk both happen before the command block: one in its middle
ends the command on a real stick.

A hub (device or interface class 9) is set up after its configuration: its
hub descriptor (GET_DESCRIPTOR 0x29) for the number of ports, SET_FEATURE
PORT_POWER on each, a wait of its power-on time plus 100 ms, then every
port whose GET_STATUS shows a device: SET_FEATURE PORT_RESET, GET_STATUS
until the reset's change bit comes (the hub ends the reset itself), the
change bits cleared, the speed read from the status (bit 9 low, bit 10
high), and the device enumerated at address 0 exactly like the one on the
box's port, with the next free address. Each device keeps how it is
reached -- its address, and for one that is not high speed behind a
high-speed hub the split flag and the hub's address and port -- and
endpoint 0's registers (+0x80, +0x81) are written from that before every
request; endpoint B's (+0x84, +0x85) before the keyboard's IN. A device
that does not answer has its port switched off again (it would answer at
address 0 together with the next one) and is left alone until it is
plugged in again. Afterwards one port is asked for its status every
100 ms.

On the real box the first v4 build's USB code (the controller set up from
a recording of the revision-0 path, no PHY settings, the old addressing)
enumerated a CH341 USB-serial adapter at full speed, but a keyboard
(1a2c:2d23 "USB Keyboard") never answered its first SETUP: token error
0x20, no response. That build read +0x32 = 0x20 for it -- full speed. With
the PHY reset and the revision-1 settings the box's own firmware writes,
the same keyboard reads 0x40 -- low speed, which it is -- and enumerates:
USB 1.10, endpoint 0 of 8 bytes, a boot keyboard on interface 0 (interrupt
endpoint 0x81) and a second HID interface (0x82). Without the PHY set-up
the controller took the low-speed device for a full-speed one and talked
to it at full speed, which a low-speed device cannot hear; the full-speed
CH341 never showed it. GET_REPORT then answers every 16 ms without errors.

But typing on it showed nothing. Its GET_REPORT answers every request with
an empty report -- 93 answers of eight zeros while a key was held, although
the HID specification makes the request mandatory: this keyboard puts its
keys only on its interrupt endpoint (its report descriptor, read with `usb
ctl 0x81 6 0x2200 0 255`, is a plain boot keyboard without report IDs), where
a PC reads them.

What the controller can do with that endpoint was measured on the box
itself, with small test programs run from its RAM over the demo's own
console: `mw` wrote a loader into free RAM and pointed the `ping` command's
handler at it; the loader took a compiled test as raw bytes and called it,
and a test, linked against the demo's symbols, used its control transfers
and its console and sampled the controller's registers every few
microseconds. What they showed:

- Endpoint C, the SDK's interrupt endpoint, set up as
  `hcd_s3602_IntInC_start` does it (the same code is in dump.bin), sends this
  low-speed keyboard nothing at all: no report in 10 s, and no error either
  when it is aimed at an address or an endpoint nobody has. (The SDK uses it
  for a hub's status endpoint, at full or high speed.)
- An IN on endpoint B -- the SDK's bulk IN with DMA -- does go out: aimed at
  an address or an endpoint nobody has, it reports "no response" (+0x1D =
  0x20) 0.09 ms after its start and fails (flags 2 bit 1) after a second
  token; aimed at one of the keyboard's interrupt endpoints it stays
  pending -- the keyboard answers NAK.
- Receiving works: the data stage of a GET_DESCRIPTOR sent on endpoint 0,
  read through endpoint B (its endpoint number set to 0), arrived packet by
  packet, eight bytes each and a last one of three, each about 0.1 ms after
  its start (flags 2 bit 5, +0x63 = 0x05, the byte count at +0x48, +0x17 =
  0x86, +0x32's two bits cleared).
- The data toggle lasts from one transfer to the next: the packets came in
  order. The first of that data stage (DATA1, against the DATA0 the endpoint
  expected) was acknowledged and dropped (+0x1D bit 3) and the next one
  taken, as the USB rules say. Bit 0 of +0x17 pulsed (`set_ep_data_toggle`)
  puts it back to DATA0: with the pulse before every IN, every second packet
  was dropped.
- A NAKed IN goes out again once per frame: with the address register
  changed to one nobody has, the "no response" came at the next millisecond
  boundary. That is +0xA8 = 1, the SDK's value; 2..15 gave that many tokens
  a frame, 0 one after the other, 0x10 and above none.
- Only the FIFO reset (+0x17 bit 4) ends a pending IN: clearing +0x32's two
  bits, +0x68 or the +0x60 strobe leaves the controller sending tokens.
- Control transfers on endpoint 0 run alongside a pending IN: 150 of 150
  GET_DESCRIPTORs, none slower.
- This keyboard resets itself when nothing asks it anything: with the bus
  left without transfers it dropped off the port about every 62 s and was
  back 35 ms later, at address 0 and unconfigured. With the IN pending on
  its interrupt endpoint it stayed for the four minutes watched. This --
  not data arriving -- is what an earlier build's endpoint C mode ran into:
  nothing was asking the keyboard, it reset itself, and the demo enumerated
  it again.

The demo reads a keyboard that way now, and on 2026-11-13 typing on that
keyboard reached the command line on the box: 43 reports, 23 keys, no
error, no drop-out. When an enumeration gets no answer after three bus
resets, the demo also sets the controller up again, its PHY included, and
tries once more: the box's port was found stuck once after a long time
without transfers (connected, but a SETUP neither done nor failed), and
only `usb init` brought it back. `usb ctl <type> <request> <value> <index>
<length>` sends any control request for such probing.

A hub went onto the same box the same day: a seven-port USB 2.0 hub made
of two Terminus chips (1a40:0101, high speed, one transaction translator
each; the second chip on the first one's port 1), with storage devices on
both chips and the low-speed keyboard on the first one's port 4. Driven
first by hand with `usb ctl` (PORT_POWER, GET_STATUS, PORT_RESET) and then
from RAM-loaded tests, it showed:

- High-speed transfers work on this box (the first high-speed device it
  saw): the hub's descriptors in 64-byte packets, and the high-speed
  devices behind it need nothing but their address.
- The low-speed keyboard behind it answers control transfers once endpoint
  0's split registers are set: +0x80 = address << 1 | 1, +0x81 = 0x61 (low
  speed, port 4, hub 1). With +0x90 = 2 or 3 it gets no answer.
- Endpoint B's IN goes through the translator the same way (+0x84, +0x85):
  aimed at the keyboard's interrupt endpoint it stays pending, aimed at an
  endpoint the keyboard does not have it fails with a stall after 0.24 ms
  -- the translator's answer for three tries nobody answered -- where the
  same without a hub is "no response".
- Endpoint B reads the hub's own status-change endpoint at high speed: the
  byte 0x10 (port 4 changed) 3 microseconds after the start.
- Endpoint C stays silent here too (the hub's status endpoint, an endpoint
  it does not have, the keyboard through the translator).

The demo's hub support then listed the whole tree on the box -- both hub
chips, three storage devices (two behind the second chip), the keyboard at
address 6 -- and the keyboard, read through the translator, stayed
connected for the 13 minutes watched (it resets itself within a minute
when nothing asks it, so the IN tokens reach it) and typed: 14 reports, 8
keys, no error.

The storage devices behind that hub were read next, first by RAM-loaded
tests. The bulk OUT works as the SDK sets it up: a 31-byte command block
goes out 5 microseconds after the start (flags 2 bit 6, +0x63 = 0x03), and
all three devices answered INQUIRY, TEST UNIT READY, READ CAPACITY and
READ(10) at high speed with +0x90 left at 0: a 64 GB stick (090c:2000,
"USB Disk 3.0", one NTFS partition made by Rufus), a 961 MB stick
(ffff:5678, FAT32 'SLITAZ CORE' and a small second partition of type 0xEA)
and a card reader (05e3:0751, "Generic STORAGE DEVICE") with a 942 MB
FAT16 card, whose first TEST UNIT READY failed with a unit attention
(6/28). One status wrapper arrived one byte short: the count at +0x48 was
read at endpoint B's done flag, before the DMA's (+0x63 bit 2).

A CLEAR_FEATURE(ENDPOINT_HALT) on the bulk IN endpoint between a command
block and its data broke the command: the 961 MB stick still sent the data,
then stalled the status; the card reader refused the request and timed out
(its next command block was not taken until the bulk-only reset). The
first disk build did exactly that when a stick's IN toggle had to be put
back to DATA0, and `ls` on that stick timed out; the toggles are now set
before the command block. After those experiments the 961 MB stick stopped
answering at all, even after its port's reset (its controller had hung;
the hub's PORT_POWER requests did not cut the power, the hub has no
switch) -- a stick to plug in again by hand.

With the disk build on the box `disks` listed the card (FAT16 'PHONE
CARD') and the 64 GB stick (NTFS, not read), and `ls` the card's root --
long names, dates, hidden entries, 20 of them -- `ls 3:/rtltest` a
directory, `cat` two of its text files and a 26 KB G-code file in full (903
lines: the FAT16 chain followed across its clusters).

A mouse came last: an A4Tech (09da:c10a, low speed, a boot mouse with its
interrupt endpoint 0x81 of 8 bytes every 10 ms; GET_REPORT answers the tail
of its report descriptor, and SET_IDLE is taken but gives no idle reports)
on the second hub chip's port 4, the keyboard staying on the first one's.
Read alone through endpoint B it was fine. The first mouse build shared
endpoint B between the two -- each device's IN pending in turns, the data
toggles kept as for the disks -- and on the box the pointer only moved a
little: the mouse's reads failed now and then, packets were dropped for
their toggle, and the keyboard got spurious empty reports. Ending a pending
IN (the FIFO reset) can throw away a packet that the hub's translator
already acknowledged to the device, and the toggles fall out of step; with
two devices behind translators taking turns, that happens all the time.
Endpoint C sends nothing to a low-speed device, also with interrupt enable
3 written as the SDK does (+0x2E = 0x77). Endpoint D, the SDK's second
interrupt engine (`hcd_s3602_IntInD_start`), does poll, and RAM-loaded tests
showed how:

- With +0xA3 = 7 a token goes out every 8 ms; behind the hub +0x89 bit 7
  reads 1 for about 1 ms each time (the split transaction), the first
  within a few ms of the start. Aimed at an endpoint the mouse does not
  have, each fails with token error 0x10 and flags 1 bit 4 (at the hub's own
  missing endpoint, without a translator: 0x20 and bit 5), flags 3 stays 0
  and the polling goes on.
- A packet goes into endpoint D's FIFO -- +0x24, read until +0x23 bit 7
  says it is empty -- with flags 3 bit 4 and +0x63 = 0x09. The SDK's
  `epD_finish_ok` stops the polling (+0xA3 = 0, +0x2B bit 3 cleared),
  empties the FIFO and the next request starts it again; read before the
  flag, the FIFO gave half a keyboard report.
- The hub's own status endpoint, read through endpoint D while one of its
  ports was suspended and resumed three times, answered each change (the
  byte 0x04: port 2) and nothing before; the data toggle lasted through the
  stops and starts. After a CLEAR_FEATURE(ENDPOINT_HALT) on the hub's
  endpoint (its toggle back to DATA0) the next packet was dropped for its
  toggle (+0x1D = 0x08; the hub sent its change again) unless bit 0 of
  +0x23 had been pulsed: that puts endpoint D's toggle back to DATA0.
- The low-speed keyboard behind the translator delivered its report
  through endpoint D as well.

So the demo reads the mouse with endpoint D, and the keyboard keeps
endpoint B to itself as before the mouse. On the box (2026-11-13) the
pointer then followed the A4Tech behind the second hub chip and the
keyboard typed alongside it: 641 mouse reports, none dropped for its
toggle, no error, the buttons told on the UART; 163 keyboard reports, 90
keys, no error. The keyboard's count of reports dropped for their toggle
read 6 -- a toggle error seen in +0x1D while its IN was pending, which with
endpoint D busy may not have been the keyboard's own (with the mouse
still, 20 s of endpoint D's polling never set +0x1D).

Then a CH341 (1a86:5512, "USB UART-LPT", full speed, a vendor interface with
two 32-byte bulk endpoints and an interrupt one) went into the second hub
chip's port 1: enumerated and configured through that chip's translator --
the first full-speed device behind the hub on this box (+0x81 bit 6 clear).
The demo has no driver for it; `lsusb` lists it. The disks showed two
quirks. The 64 GB stick (090c:2000) left the first command after a minute or
more without commands unanswered -- no data, no status, 5 times in 5 -- and
answered the next one at once; a RAM-loaded test showed that a plain
CLEAR_FEATURE(ENDPOINT_HALT) does put its toggles back to DATA0, so it is not
the toggles. A command now gets 2 s, then the reset recovery and a second
try: on the box, after 100 s idle, `sector 6:0` read in 2.4 s and `disks`
counted one command sent again. The failure was told with the stage name
of the recovery's own requests ("status (IN) stage: time-out"): the error
text now keeps the
failed transfer's stage. And the 961 MB stick (ffff:5678) stopped answering
after two restarts of the box and a `usb` (its port reset), as it had once
before: it needs to be plugged in again.

## The flash procedure on every image

`tools/bootloader_flash_survey.py` runs the procedure of this page (capture,
handshake, backup dump, transfer + burn of a test application packed for
each image's own main code format, readback dump, reboot, cold boot) on
every firmware image in `dumps/` in the emulator and writes
[bootloader_flash_survey.md](bootloader_flash_survey.md).

Loaders built with the SDK's `TRANSFER_FORMAT3_ONLY` answer the classic
handshake bytes with 0xFF - byte: they speak only ALi's packet ("format 3")
protocol. `tools/ali_packet.py`, written from the SDK's own loader sources
(`refs/BootLoader/SRC/lib/libapplet/libbootupg3`), speaks it -- every
command, data block and status in a CRC-checked `HEAD` packet -- and the
survey runs the same procedure through it on those loaders
(`tests/test_ali_packet.py`, `tests/run_packet_protocol_amiko.py`).
`tools/maciej_uart.py` itself stays the classic client for dump_maciej.bin.

## Build the application

Use a little-endian MIPS GCC cross-compiler with its matching `objcopy` and
`objdump`. No vendor SDK, libc, or operating system is required. The sources
are in `firmware/maciej_app/`.

From the repository root, with the compiler installed on this workstation:

```powershell
$env:MIPS_CROSS_COMPILE = 'W:\TOOLS\g++-mipsel-none-elf-15.2.0\bin\mipsel-none-elf-'
python firmware/maciej_app/build.py --version v1
python firmware/maciej_app/build.py --version v2
python firmware/maciej_app/build.py --version v3
python firmware/maciej_app/build.py --version v4 --demo
```

On other machines, set `MIPS_CROSS_COMPILE` to the local prefix, pass
`--cross-prefix`, or put `mipsel-none-elf-gcc` / `mipsel-linux-gnu-gcc` and the
matching binutils on PATH. The build script uses argument arrays, so compiler
and output paths may contain spaces.

The result for each version is `build/maciej_app/VERSION/app.bin` plus an ELF,
link map, disassembly, and build manifest. The v3 application compiles
to 892 bytes with GCC 15.2.0; the archived v2 binary is 624 bytes. Each build
prints the exact UART banner `ELEKTRODA ALI M3801 TEST FOR MACIEJ`, followed by
its configured version on a separate line. Sending `p` returns `pong VERSION`,
and `v` prints the banner and version again. The application uses 115200 baud, 8 data bits,
even parity, 1 stop bit.

The essential build settings are MIPS32 (not MIPS32r2), little endian, o32 ABI,
soft float, no PIC/abicalls, and `-G0`. Linking explicitly uses `-static -no-pie`
so a Linux cross-compiler cannot introduce a dynamic loader. `link.ld` places `_start` at
`0x80000200`. `start.S` masks CPU interrupts, supplies its own stack, initializes
`$gp`, clears BSS, and calls C. It does not repeat the board's DRAM startup.

## Package for the loader

```powershell
python tools/maciej_image.py inspect dumps/dump_maciej.bin
python tools/maciej_image.py pack --app build/maciej_app/v1/app.bin --output build/maciej_app/v1/flash.bin
python tools/maciej_image.py pack --app build/maciej_app/v2/app.bin --output build/maciej_app/v2/flash.bin
```

Each packaging command writes:

- `flash.bin`: a complete 4 MiB flash image for a simulator or programmer.
- `flash.maincode.bin`: the application chunk to send through the bootloader.
- `flash.json`: addresses, lengths, checksums, and preservation hashes.

The UART payload begins at flash offset `0x50000`. It includes the ALi chunk
header and compressed application, rounded to a 64 KiB boundary using the
original bytes as padding. It is 64 KiB for this demo. The chunk's existing
`0x240000` allocation remains unchanged, so subsequent chunks stay at their
original addresses. Bytes beyond the new compressed stream are retained.

| Item | Value in this dump |
| --- | --- |
| Flash contents | `0x400000` bytes |
| UART dump trailer | 4-byte big-endian CRC, excluded from flash |
| Bootloader | Starts at `0x000000`; next chunk at `0x04FE00` |
| HDCP key chunk | `0x04FE00` |
| Maincode header | `0x050000`, chunk ID `0x01FE0101` |
| Maincode allocation | `0x240000` bytes; next chunk at `0x290000` |
| Header size | 128 bytes |
| Load and entry | `0x80000200` (original header uses default values) |
| Compression | LZMA-alone, `lc=0`, `lp=2`, `pb=2`, 8 MiB dictionary |
| LZMA decoded size | Explicit little-endian 64-bit size at stream bytes 5..12 |
| Chunk CRC | CRC-32/MPEG-2 over bytes `[header+16, header+16+length)` |

Chunk words are big endian, despite the CPU running little endian. The chunk
`length` is **128-byte header plus compressed stream minus 16**; it excludes
sector padding and the unused part of the allocation. The 128-byte header's
other fields, including its next-chunk span, are preserved. The old decoder
stops at the declared uncompressed size, so the packager writes that size
instead of Python's default unknown-size LZMA header.

Python's compressor also emits an end-of-stream marker, which the original
loader does not need after decoding the declared size. Python's generic
`lzma.decompress(..., format=lzma.FORMAT_ALONE)` rejects this generated
known-size/marker combination. To extract a packaged application, use
`tools.maciej_image.extract_application(flash_bytes)` with the complete flash
image: it validates the image and decodes the raw LZMA stream to the declared
size, matching the bootloader.

## Test repeated flashing in the simulator

The self-test builds both versions from source before running the update
checks. With the compiler selected as above:

```powershell
python tests/run_dump_maciej_custom_app.py --require-toolchain --engine cpp
```

This test is included in the repository's `--slow` suite and GitHub Actions.
GitHub installs `gcc-mipsel-linux-gnu` and its binutils, treats a missing
compiler as a failure, includes the test in its HTML report, and uploads the
builds, flash snapshots, and UART transcripts as `maciej-app-selftest-cpp`
(or the corresponding Unicorn artifact). Locally, a missing compiler is
reported as not applicable unless `--require-toolchain` is given. An explicitly
configured but incomplete toolchain always fails.

To run only this regression through the suite and generate its HTML report:

```powershell
python run_all_tests.py --slow -k maciej_custom_app --engine cpp
```

The distributed ZIP has a separate regression:

```powershell
python run_all_tests.py --slow -k maciej_uart_bundle --engine cpp
```

It checks the archive against the canonical files, extracts it, and runs the
updater's CLI against the original bootloader through an emulated pyserial
device. It installs the same v2 payload twice, checks both full backups and
UART readbacks, refuses reused backup filenames, and checks native reboot,
cold boot, and `p`/`v` responses after each installation. No physical serial
port is used. This complete CLI regression runs on C++ and keeps the updater's
hardware timeouts unchanged; the slower Unicorn engine reports it as not
applicable. Results are saved under `build/maciej_app/selftest/cpp/bundle/`
and included in the existing GitHub self-test artifact upload.

Validated locally on 2026-11-11: the packaged CLI completed both installations
in 941.536 seconds (943 seconds including the suite wrapper), with four full
UART dumps, preserved backups, native reboot/cold boot, and `p`/`v` checks.
The second backup exactly matched the flash produced by the first cycle.
The separate fresh-build original-to-v1-to-v2 test passed in 181.539 seconds,
and the distributed v2 image also passed a native Unicorn cold boot. These
are simulator results; the updated GitHub workflow still requires its own run.
Physical-board results are recorded below.

To test already-built applications directly:

```powershell
python tests/run_maciej_bootloader_update.py --engine cpp
```

The integration test starts from the original dump and sends UART bytes to
the running firmware. It interrupts boot, enters the bootloader protocol,
transfers and burns v1, compares the resulting flash, requests a bootloader
reboot, checks the application banner and ping, and checks a fresh cold boot.
It then starts from the persisted v1 image and repeats the sequence for v2.
The loader's own LZMA decoder runs with `lzma_hle=False` for both new
applications, including their cold boots. Entering recovery on the original
image uses the simulator's existing decompression shortcut for its large
stock application; the shortcut is disabled before testing the new apps.
The harness does not patch guest PC, RAM, or flash to perform an update.

The self-test writes results, UART transcripts, and flash contents actually
written by the guest under `build/maciej_app/selftest/cpp/integration/`.
The direct harness uses `build/maciej_app/integration/`. The test asserts the
bootloader and every byte outside the transferred region remain unchanged.
`--engine unicorn` selects the alternative emulator; it is slower.

Validated on 2026-11-11 after the banner update: the complete C++ self-test
built both versions from source and passed in 200.849 seconds of simulation checks,
including both updates, reboot and cold boot of each version, UART pings,
and the final 4 MiB UART dump with CRC verification. Separate Unicorn cold
boots of both versions also passed with native LZMA decoding. The five image
tests and thirteen protocol tests passed. An independent simulated bad-CRC
packet was rejected and successfully retried before programming and reboot.
No simulator core changes were needed. The complete UART update test was run
locally on C++; GitHub execution will occur when the workflow is triggered.

The test transport delivers 16-byte bursts paced for 115200 8E1. Injecting a
whole 1028-byte packet instantaneously overflowed the firmware's receive
buffer; baud pacing made the same protocol complete successfully.

For a graphical run of a packaged image:

```powershell
python src/gui_simulator.py build/maciej_app/v1/flash.bin
```

The v1..v3 applications use the UART only and draw no TV picture. The v4
demo is best tried in the interactive TV, which shows its screen live, has
a virtual remote (it finds the codes in the key table the demo carries)
and a UART console on F5 for the command line:

```powershell
python src/tv_gui.py firmware/maciej_app/bin/elektroda_ali_m3801_maciej_v4.bin
```

## Flash a board through its existing loader

`tools/maciej_uart.py` uses the same protocol client as the simulator test.
The serial adapter requires pyserial. Select the actual COM port explicitly;
the examples below use `COM3` only as a placeholder. Connect UART TX/RX and
ground with appropriate signal levels, and configure **115200 8E1**. Maciej's
post reports 3.3 V UART levels on this board.

```powershell
python tools/maciej_uart.py --port COM3 --capture-boot 60 probe
```

Power-cycle the box when the command prints its capture message. It sends
`c` during startup to hold the bootloader. It does not manipulate RTS/DTR to
reset the board. A successful `comtest` handshake confirms communication.

To install v1, run this and power-cycle when prompted:

```powershell
python tools/maciej_uart.py --port COM3 --capture-boot 60 flash build/maciej_app/v1/flash.maincode.bin --backup build/maciej_app/before-v1.bin
```

The command reads a full CRC-checked backup, checks the bootloader identity,
updates only the maincode, reads back the complete flash, compares it against
the expected result, and reboots. Full backups/readback take several minutes
at 115200 baud. An existing backup filename is refused so earlier recovery
copies remain available. `--stay` keeps the box in the loader after verifying.

Repeat with the second version and a fresh backup filename:

```powershell
python tools/maciej_uart.py --port COM3 --capture-boot 60 flash build/maciej_app/v2/flash.maincode.bin --backup build/maciej_app/before-v2.bin
```

Power-cycling re-enters the unchanged factory bootloader on every version.
The v3 application also supports software capture without cycling power. Use `flash.maincode.bin` as the UART
payload; `app.bin` lacks its chunk header and `flash.bin` is a full flash image.

## Wire protocol and the original investigation

The relevant public observations are Maciej's
[UART setup, post 7](https://www.elektroda.pl/rtvforum/topic4156384.html#21788762),
[update commands and dump, post 15](https://www.elektroda.pl/rtvforum/topic4156384.html#21794256),
[corrected packet length, post 21](https://www.elektroda.pl/rtvforum/topic4156384.html#21794965),
and [bootloader-preserving application question, post 32](https://www.elektroda.pl/rtvforum/topic4156384-30.html#21803726).
Local reference SDK code supplies the protocol structure; simulator execution
against this exact dump checks which variant it actually implements.

1. Send `c` during startup.
2. Send `comtest 2\r`, then two test bytes. The client uses `XX`; Maciej used
   two additional carriage returns. The command and test bytes are echoed.
3. Send `address 327680\r`. The reply after its echo is `O`.
4. Send `transfer LENGTH\r` using the decimal payload length. Wait for `O`.
5. Send blocks of 1024 data bytes plus a 4-byte big-endian CRC. Wait for `O`
   after each block; `E` requests a retry. CRC polynomial is `0x04C11DB7`,
   initial value `0xFFFFFFFF`, no reflection and no final XOR.
6. After a complete transfer, send `burn\r`. Read `O`, progress records,
   and final `F`. An acknowledged transfer alone has not programmed flash.
7. Read back with `dump\r`: BE32 flash size, host `O`, flash bytes, BE32 CRC.
8. Send `reboot\r`, receive `O`, and let the loader verify/decompress the app.

The numeric parser takes **decimal**. In particular, `address 0x50000` is
parsed as zero, which points at the bootloader. The supplied client fixes the
only writable start at `327680` and checks the chunk span before transmission.
This loader does not need a `go` command: a valid maincode chunk plus reboot
uses its normal application-loading path.

Physical validation on 2026-11-11 used a 3.3 V CH340 UART on COM46 at 115200
8E1. A complete CRC-checked backup matched the original dump byte for byte
(raw flash SHA-256 `fac12fb68bdd76a86c5f7ba0b8c1325ed9ee1e401daafb14529a35df6729dc44`).
The bootloader accepted the distributed 64 KiB v2 payload, reported `B0320K`
and completion, and returned a complete CRC-checked readback matching the
distributed v2 image (SHA-256
`0088537d657984b6e50d603d51cc08e64304b5c278a5d46191a7d3dbce827b15`).
Every byte outside the payload remained unchanged. A bootloader-requested
reboot printed the exact banner and v2 version; `p`, `v`, and three further
pings over 30 seconds passed. The original backup and UART logs are kept locally under ignored
`hardware_backups/`.

A second physical update on the same tuner used BK7231GUIFlashTool's shared
C# backend through its CLI to install v3. Its full backup matched the
previously verified v2 image. Complete readback matched the distributed v3
image (SHA-256
`3564d45b5354989f90f704c7bbf4ce1869182675a91bc3f158c6303da40c46c6`),
with every byte outside the payload unchanged. The v3 banner, version,
ping, and three further pings over 30 seconds passed.

The application's `r` command restarted through the original loader and
returned to v3. The Python client's existing repeated-`c` capture then
entered the bootloader without a power cycle; handshake, loader reboot,
and final v3 version/ping checks passed.

These results establish two physical updates and working software restart
and bootloader entry. A complete further update initiated from running v3,
and a power-off cold boot of v3, remain simulator validations.
