ELEKTRODA ALI M3801 TEST FOR MACIEJ - v3

UART update for the bootloader of dump_maciej.bin.
Requirements: Python 3.10+, pyserial, a 3.3 V UART (115200, 8E1).
Unpack the whole ZIP into one directory. Connect TX-RX, RX-TX and GND.
Close other programs using the tuner's port. Replace COM3 with your port.

python -m pip install pyserial
python maciej_uart.py --port COM3 --capture-boot 60 flash elektroda_ali_m3801_maciej_v3.maincode.bin --backup before-maciej-v3.bin

- Original firmware or v1/v2: switch the tuner on after the ready message.
- When v3 already runs: leave the tuner on. The "c" the script sends
  restarts it and captures the original bootloader.
- The script saves a full backup, writes the maincode and verifies all 4 MiB.
  The two reads take about 14 minutes in total. Do not switch the tuner off
  while it writes.
- For the next update use a new backup name. The old one is not overwritten.

Application commands - a single character, without Enter:
- "v" - the banner and "Version: v3"
- "p" - "pong v3"
- "r" - restart through the original bootloader, which starts the application
- "c" - restart for capture by the updater; the updater must keep sending "c"

A single "c" alone does not guarantee staying in the bootloader.
For updates use the script with --capture-boot 60 or the ALIM3801 profile
in BK7231GUIFlashTool. A plain "r" without a capture starts the application.

The UART update uses .maincode.bin. The bootloader, keys and settings are kept.
No encryption is needed - LZMA and CRC are used.
