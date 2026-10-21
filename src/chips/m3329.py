"""
ALi M3329 (dumps/other/sat_main_ali3329-s15125_dump_eeprom_by_h2h_ok.bin: a
2005 satellite receiver board "s15125"), a chip of the M3327 platform: its
drivers are the SDK's NIM_M3327, DMX_M3327, DECV_M3327, VPO_M3327, SND_M3327
and OSD_M3327C, and its main code is stored unpacked in the flash: the
application runs in place, cached (0x8FC0B080..), its flash driver and other
code copied to RAM.

Its bootloader reads the chip's revision from the chip ID word: with a chip
ID in the upper half, the low byte -- 0x60 / 0x63, 0x70 / 0x30, 0xF0, 0xF1,
0xF2, 0xF3, others -- is revision 0x20001 .. 0x20007 (0xAFC00B68), and from
revision 0x20004 on it first calls a routine of the chip's boot ROM
(0xBFC0003D), which the simulator does not have: with the M3801's chip word
it jumped there and ended at PC 0.  The family's chip word reads revision
0xF0 (0x20003), the newest that boots from the flash alone.

The bootloader then sets up the SDRAM controller (0xB8000080): timings in
+0x82..+0x87, and commands in bits 0..1 of +0x80 -- 2 precharge, 3 refresh
(eight times), 1 the mode register --, each polled until those bits read 0
(0xAFC007F4).  The model completes a command at once.

Its UART is a 16550 at 0xB8001300.  Its flash is parallel NOR on an 8-bit
bus (parallel_flash.py): the application's flash driver probes it with the
AMD autoselect command and matches the IDs against its table of 41 parts
(0x8FC4ADAC, their sector maps at 0x8FC4AD58..); unidentified it set up no
database region and later read a null pointer's -4.  The model is an MXIC
MX29LV400B -- the bottom-boot 4 Mbit part the image's layout fits: a 16 KB
bootloader, the "userdb(64+64)" chunk in the last two 64 KB sectors.

Its interrupt controller has its status word at 0xB8000038 and its enables
at 0xB800003C (lines 0..16, on IP3: simulator.set_ic_layout).  The video
decoder (0xB8004200) and the video output's interrupt (0xB8004004: enables
bits 0..4, status bits 8..12) are the M36xx's (video_m36.py), both on line 9;
the IR receiver is the later chips' controller at 0xB8001100 on line 7.  Its
remote (the table at 0x8003E0CC: command byte and complement per key, the
customer code 0x205D from 0x8003B644) is NEC address 0x04 / 0xBA, received
most significant bit first.

The kernel ticks every 108000 Count cycles (0x8002F710): at the simulator's
100 MHz that is about a millisecond of emulation time, of which the tick
took most, so the application got a few thousand instructions per tick.
The family's Count runs at 10 MHz.

Recognised by the first chunk's ID, 0xE3000010 (every later image here has
0x23010010): the M3327 platform's chunk header, which is also the
bootloader's first instruction (a branch over the header).
"""
import struct

from .base import ChipFamily, chunk_chain

BOOTLOADER_CHUNK_ID = 0xE3000010
SDRAM_CONTROL = 0x80                    # in the device window
UART = 0x1300
IC_STATUS, IC_ENABLE = 0x38, 0x3C       # the interrupt controller: lines 0..16, on IP3
VIDEO_LINE = 9                          # the video decoder's and the video output's line
VPO_INT = 0xB8004004
IRC, IRC_LINE = 0x1100, 7               # the IR receiver
COUNT_HZ = 10_000_000
OSD_PALETTE_PORTS = (0x41AC, 0x41C8)    # OSD layer 0's / 1's palette port
# The remote: the application's key codes for the key names (its key table
# holds them with their IR codes), and where the table is: the panel /
# remote configuration at 0x8003B640 -- the table's address, the customer
# code in the upper half of +4, the number of entries at +0xE (the panel's
# first, then the remote's)
REMOTE_KEYS = {'LEFT': 0x0A, 'RIGHT': 0x0B, 'UP': 0x0C, 'DOWN': 0x0D, 'MENU': 0x0E,
               'OK': 0x0F, 'ENTER': 0x0F, 'EXIT': 0x10, 'BACK': 0x10, 'MUTE': 0x11,
               'POWER': 0x12, 'PAUSE': 0x13, 'TVRADIO': 0x14, 'AUDIO': 0x15,
               'INFO': 0x17, 'TEXT': 0x19, 'PAGE+': 0x1A, 'PAGE-': 0x1B,
               'VOL-': 0x1F, 'VOL+': 0x20, 'CH-': 0x21, 'CH+': 0x22,
               'RECALL': 0x23, 'FAV': 0x29,
               **{str(d): 0x30 + d for d in range(10)}}
KEY_CONFIG = 0x8003B640


def _rev8(b):
    return int(f"{b:08b}"[::-1], 2)


class Osd:
    """OSD_M3327C's display layers, as far as a capture needs more than the
    registers and the RAM (gma_capture.m3327_regions): their palettes, which
    the driver writes through one port per layer (0xB80041AC, 0xB80041C8),
    an entry per store -- the index in bits 24..31, then Y, Cb and Cr, the
    entry's 4-bit alpha in the low two bits of Cb and Cr."""

    def __init__(self, sim):
        self.palettes = ({}, {})
        for layer, port in enumerate(OSD_PALETTE_PORTS):
            sim._mmio_on('w', lambda uc, access, address, size, value, user_data, layer=layer:
                         self._write(layer, size, value), port, port)

    def _write(self, layer, size, value):
        if size == 4:
            self.palettes[layer][value >> 24] = value & 0xFFFFFF


class M3329(ChipFamily):
    name = "M3329"
    chip_id = 0x3329
    chip_variant = 0x00F0               # the revision byte: 0x20003 to the bootloader (no boot-ROM call)

    @classmethod
    def matches(cls, image):
        chain = chunk_chain(image, limit=2)
        return bool(chain) and chain[0][1] == "bootloader" and \
            struct.unpack_from(">I", image, chain[0][0])[0] == BOOTLOADER_CHUNK_ID

    def install(self):
        super().install()
        sim = self.sim
        sim._mmio_on('w', self._sdram_command, SDRAM_CONTROL, SDRAM_CONTROL)
        # the UART, a 16550 like the later chips' at 0xB8018300, sits at 0xB8001300
        sim._mmio_on('w', sim._hook_uart_write, UART, UART + 5)
        sim._mmio_on('r', sim._hook_uart_read, UART, UART + 9)
        from parallel_flash import MX29LV400B, ParallelNorFlash
        self.flash = ParallelNorFlash(sim, **MX29LV400B)
        self.flash.connect()
        sim.set_ic_layout(IC_STATUS, IC_ENABLE)
        from video_m36 import VideoEngine, VideoOutput
        self.video_engine = VideoEngine(sim, line=VIDEO_LINE)
        self.video_output = VideoOutput(sim, register=VPO_INT, line=VIDEO_LINE, field_bit=0)
        self._count_hz = sim.count_hz
        sim.count_hz = COUNT_HZ
        sim._mmio_on('r', sim._hook_irc_read, IRC + 1, IRC + 1)
        sim._mmio_on('r', sim._hook_irc_read, IRC + 7, IRC + 8)
        sim._mmio_on('w', sim._hook_irc_write, IRC + 7, IRC + 7)
        sim.irc_base, sim.irc_line = IRC, IRC_LINE
        self.osd = Osd(sim)

    def remote_frame(self, key):
        """(address, command, address_hi) of the NEC frame of a remote key
        (a name of REMOTE_KEYS or the application's key code), from the
        application's key table (simulator.press_key); None if it has none.
        The table holds a command byte and its complement per key and the
        configuration the customer code, all as the receiver assembles a
        frame -- most significant bit first: customer code 0x205D is NEC
        address 0x04 / 0xBA."""
        code = REMOTE_KEYS.get(key.upper()) if isinstance(key, str) else int(key)
        sim = self.sim
        word = lambda a: int.from_bytes(sim.peek(a, 4), 'little')   # noqa: E731
        table, customer = word(KEY_CONFIG), word(KEY_CONFIG + 4) >> 16
        count = int.from_bytes(sim.peek(KEY_CONFIG + 0xE, 2), 'little')
        if code is None or not 0x80000000 <= table < 0x80000000 + sim.ram_size or count > 0x100:
            return None
        for a in range(table, table + 4 * count, 4):
            b0, b1, k, _ = sim.peek(a, 4)
            if b0 ^ b1 == 0xFF and k == code:
                return _rev8(customer >> 8), _rev8(b1), _rev8(customer & 0xFF)
        return None

    def uninstall(self):
        sim = self.sim
        self.flash.disconnect()
        sim.set_ic_layout(sim.ic_base, sim.ic_base + 8)
        sim.count_hz = self._count_hz
        sim.irc_base, sim.irc_line = 0x18100, sim._IC_IRC

    def start(self):
        self.flash.reset()
        super().start()

    @staticmethod
    def _sdram_command(uc, access, address, size, value, user_data):
        """A command to the SDRAM controller is done at once: its bits 0..1 land clear."""
        return value & ~3
