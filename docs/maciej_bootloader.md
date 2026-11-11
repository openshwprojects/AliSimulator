# Applications for the original Opticum N2 bootloader

This workflow targets `dumps/dump_maciej.bin`, the Opticum STB HD N2 / ALi
M3801 dump supplied by maciej_333. It builds a small independent C application
and updates the application through the existing UART bootloader. The original
dump is never overwritten. The demonstration uses the DRAM and clock setup
already performed by the original loader; it is not a replacement reset ROM.

## Ready-to-use binaries

The tested v2 binaries are stored in the repository, outside the ignored build
directory:

- [elektroda_ali_m3801_maciej_v2.maincode.bin](../firmware/maciej_app/bin/elektroda_ali_m3801_maciej_v2.maincode.bin):
  64 KiB application chunk for UART upload at `0x50000`.
- [elektroda_ali_m3801_maciej_v2.bin](../firmware/maciej_app/bin/elektroda_ali_m3801_maciej_v2.bin):
  complete 4 MiB flash image for the simulator or an external programmer.
- [Manifest](../firmware/maciej_app/bin/elektroda_ali_m3801_maciej_v2.json):
  sizes, addresses, application version, and SHA-256 checksums.
- [Portable UART ZIP](../firmware/maciej_app/bin/maciej_uart_v2.zip):
  the standalone `maciej_uart.py`, 64 KiB payload, and an ASCII Polish README.
  Extract all three files together; only Python 3.10+ and `pyserial` are needed.

These bytes match the image written by the successful UART self-test exactly.
No compilation is needed to upload this version:

```powershell
python tools/maciej_uart.py --port COM3 --capture-boot 60 flash firmware/maciej_app/bin/elektroda_ali_m3801_maciej_v2.maincode.bin --backup before-maciej-v2.bin
```

Replace `COM3` with the actual adapter port and power-cycle immediately when
prompted. The 60-second capture window gives the stock loader time to finish
its startup checks; the earlier 15-second example expired before command
processing began in the simulator.
This dump's maincode update requires LZMA compression and CRC checks, with no
encryption or signing step. The updater writes the application region and
preserves the existing bootloader and other flash regions.

From the extracted portable ZIP's directory, use:

```powershell
python -m pip install pyserial
python maciej_uart.py --port COM3 --capture-boot 60 flash elektroda_ali_m3801_maciej_v2.maincode.bin --backup before-maciej-v2.bin
```

## Build the application

Use a little-endian MIPS GCC cross-compiler with its matching `objcopy` and
`objdump`. No vendor SDK, libc, or operating system is required. The sources
are in `firmware/maciej_app/`.

From the repository root, with the compiler installed on this workstation:

```powershell
$env:MIPS_CROSS_COMPILE = 'W:\TOOLS\g++-mipsel-none-elf-15.2.0\bin\mipsel-none-elf-'
python firmware/maciej_app/build.py --version v1
python firmware/maciej_app/build.py --version v2
```

On other machines, set `MIPS_CROSS_COMPILE` to the local prefix, pass
`--cross-prefix`, or put `mipsel-none-elf-gcc` / `mipsel-linux-gnu-gcc` and the
matching binutils on PATH. The build script uses argument arrays, so compiler
and output paths may contain spaces.

The result for each version is `build/maciej_app/VERSION/app.bin` plus an ELF,
link map, disassembly, and build manifest. Both demonstration versions compile
to 624 bytes with GCC 15.2.0. Both print the exact UART banner
`ELEKTRODA ALI M3801 TEST FOR MACIEJ`, followed by `Version: v1` or `Version: v2`
on a separate line. Sending `p` returns `pong v1` or `pong v2`, and `v` prints
the banner and version again. The application uses 115200 baud, 8 data bits,
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
are simulator results; the updated GitHub workflow and physical board still
require their own runs.

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

The demo uses UART only and does not initialize a TV picture.

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

Power-cycling re-enters the unchanged factory bootloader even though the custom
application has no update command. Use `flash.maincode.bin` as the UART
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

The simulator results verify the software workflow. Serial timing, electrical
connections, and real flash behavior still require validation on the board;
no physical device was flashed during this work.
