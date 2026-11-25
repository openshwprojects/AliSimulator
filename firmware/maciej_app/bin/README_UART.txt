ELEKTRODA ALI M3801 TEST FOR MACIEJ - v2

UART update package for the bootloader of dump_maciej.bin.
Requirements: Python 3.10 or newer, pyserial, a 3.3 V UART adapter.
There is no need to download the repository or to build the application.

1. Unpack the whole ZIP into one directory and open a terminal in it.
2. Connect the adapter's TX to the tuner's RX, the adapter's RX to the
   tuner's TX, and a common ground.
   Close other programs using this COM port.
3. Install pyserial:

python -m pip install pyserial

4. Run the command below, replacing COM3 with your port:

python maciej_uart.py --port COM3 --capture-boot 60 flash elektroda_ali_m3801_maciej_v2.maincode.bin --backup before-maciej-v2.bin

5. When "Power-cycle the device now" appears, switch the tuner's power off
   and on at once. The script captures the bootloader for 60 seconds
   and sets the UART to 115200, 8E1 by itself.
6. Wait for the end. The script reads a backup, checks the bootloader, writes
   the maincode, reads the whole memory back to verify it and restarts the
   tuner. The two flash reads alone take about 14 minutes in total.
   Keep the backup file. Do not cut the power while the flash is written.
7. When it has finished, open a serial terminal at 115200, 8E1.
   Send "v" without Enter - expected:

ELEKTRODA ALI M3801 TEST FOR MACIEJ
Version: v2

   Send "p" without Enter - expected: "pong v2".

Later updates are done the same way. Use a new backup name,
e.g. before-maciej-v2-repeat.bin. The script refuses to overwrite an old backup.

The UART update uses the .maincode.bin file (64 KiB). The full 4 MiB image is
meant for the simulator or a programmer and is not included in this ZIP.
The maincode from 0x50000 is replaced; the original bootloader stays.
No encryption is needed - the image uses LZMA compression and CRC sums.

Tested in the simulator: two updates in a row (original -> v1 -> v2),
a restart and a cold start of each version, the "v" and "p" answers and the
flash verification. A packet retry after a bad CRC was tested as well.
A test on a physical tuner is still to be done.
