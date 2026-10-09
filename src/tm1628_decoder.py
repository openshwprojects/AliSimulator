"""
TM1628 / TM1618 / PT6964-class LED driver decoder (3-wire serial bus)

The Cabletech URZ0083Q (ALi M3801, PCB 6390-M3801) drives its front panel
through a TM1628-style chip on three bit-banged GPIO lines instead of the
TM1650's I2C: STB (strobe, active low, frames a command), CLK and DIO (data,
LSB first, sampled by the chip on the CLK rising edge).  A frame is one
command byte plus its data bytes:

  0x00-0x03  display mode (grids x segments)
  0x40       data command: write display RAM, auto-increment address
  0x44       data command: write display RAM at a fixed address
  0x42       data command: read the key matrix (the chip then shifts out 5
             bytes; the CPU switches DIO to input and reads it after each
             CLK falling edge, i.e. before the next rising edge)
  0xC0+addr  display RAM address (0..13), followed by the data bytes
  0x80-0x8F  display control: bit 3 on/off, bits 0-2 brightness

The decoder follows the CPU's GPIO DO writes (on_gpio_write), keeps the
14-byte display RAM and the display state, and answers key reads through
di_override(): the simulator calls it for every GPIO DI read and the decoder
drives the DIO bit with the key byte bit the CPU is clocking in.  Which key
matrix positions mean what on a given board is found by trying them
(press_key); the Cabletech's panel in the simulator (CLK = GPIO 31, DIO =
GPIO 9, STB = GPIO 11) is watched in tv_gui.py.

The 7-segment digit layout of the display RAM is board specific: `digit_addrs`
names the RAM bytes shown as the 4 digits and `seg_map` which bit of such a
byte drives which segment (the bit numbers of a, b, c, d, e, f, g, DP).
get_display_text() / .digits present the digits in the TM1650 decoder's order
(bit 0..6 = segments a..g, bit 7 = DP).  The Cabletech's digits are RAM 0, 2,
4, 6 with the segments on bits (4, 2, 0, 6, 7, 3, 1, 5): " ON " at boot, "----"
while its application starts and "noCH" with no channels; RAM 1 and 11 (grid
1 SEG14, grid 6 SEG9) are indicator LEDs.
"""
from tm1650_decoder import PanelDecoder


class TM1628Decoder(PanelDecoder):
    TAG = '[TM1628]'
    RAM_SIZE = 14
    KEY_BYTES = 5

    def __init__(self, clk_gpio=31, dio_gpio=9, stb_gpio=11, digit_addrs=(0, 2, 4, 6),
                 seg_map=PanelDecoder.STANDARD_SEG_MAP, log_handler=None, on_frame=None):
        super().__init__(log_handler)
        self.clk_offset, self.clk_bit = self._gpio_to_offset_bit(clk_gpio)
        self.dio_offset, self.dio_bit = self._gpio_to_offset_bit(dio_gpio)
        self.stb_offset, self.stb_bit = self._gpio_to_offset_bit(stb_gpio)
        self.digit_addrs = tuple(digit_addrs)
        self.seg_map = tuple(seg_map)
        self.on_frame = on_frame            # on_frame(list of bytes) for every completed frame

        # Bus state
        self.prev_clk = 1
        self.prev_stb = 1
        self.frame = None                   # bytes of the frame in progress (None: STB high)
        self.bits = []                      # bits of the byte in progress (LSB first)
        self._key_read = False              # after a 0x42 command: the chip drives DIO
        self._rises = 0                     # CLK rising edges since the key command byte

        # Chip state
        self.ram = [0x00] * self.RAM_SIZE
        self.leds = 0x00                    # uPD16312-class chips: the LED port (command 0x41)
        self.display_on = False
        self.brightness = 0
        self.mode = None
        self.auto_increment = True
        self.address = 0

        # Key scan: the 5 bytes the chip answers a key read with (see
        # press_key / dio_in).  All zero: no key.
        self.key_bytes = [0x00] * self.KEY_BYTES
        self._press_reads_left = 0
        self._answer = [0x00] * self.KEY_BYTES
        self._answered_frame = -1
        self.key_reads_answered = 0

        # Stats
        self.frame_count = 0
        self.key_read_count = 0
        self._frame_serial = 0

    # ---- the CPU side: GPIO DO writes ----------------------------------------
    def on_gpio_write(self, address, size, value):
        """Called for every GPIO DO register write (any bank)."""
        offset = address & 0xFFF
        changed = self._gpio_changed(offset, value)
        if not changed:
            return

        # STB edges frame the command; CLK rising edges clock DIO (LSB first)
        if offset == self.stb_offset and changed & (1 << self.stb_bit):
            stb = (value >> self.stb_bit) & 1
            if stb == 0:
                self.frame, self.bits = [], []
                self._key_read, self._rises = False, 0
                self._frame_serial += 1
            else:
                self._end_frame()
            self.prev_stb = stb
        if offset == self.clk_offset and changed & (1 << self.clk_bit):
            clk = (value >> self.clk_bit) & 1
            if clk and self.frame is not None:
                if self._key_read:
                    self._rises += 1                # the chip shifts the next key bit out
                else:
                    dio = (self._prev_reg_values.get(self.dio_offset, 0) >> self.dio_bit) & 1
                    self.bits.append(dio)
                    if len(self.bits) == 8:
                        byte = sum(b << i for i, b in enumerate(self.bits))
                        self.bits = []
                        self.frame.append(byte)
                        if len(self.frame) == 1 and byte & 0xC3 == 0x42:
                            self._key_read, self._rises = True, 0
            self.prev_clk = clk

    def _end_frame(self):
        frame, self.frame, self.bits = self.frame, None, []
        if frame is None or not frame:
            return                                  # an STB pulse without clocks
        self.frame_count += 1
        if self.on_frame:
            self.on_frame(frame)
        cmd = frame[0]
        kind = cmd & 0xC0
        if kind == 0x00:
            self.mode = cmd & 0x03
            self.log(f"[TM1628] Display mode {self.mode} ({(4, 5, 6, 7)[self.mode]} grids)")
        elif kind == 0x40:
            if cmd & 0x02:
                self.key_read_count += 1            # data bytes were the chip's (see dio_in)
            elif cmd & 0x01:                        # uPD16312 / PT6312: write the LED port
                if len(frame) > 1:
                    self.leds = frame[1]
                self.log(f"[TM1628] LED port = 0x{self.leds:02X}")
            else:
                self.auto_increment = not (cmd & 0x04)
                self.log(f"[TM1628] Data command 0x{cmd:02X}: write display, "
                         f"{'auto-increment' if self.auto_increment else 'fixed'} address")
        elif kind == 0xC0:
            self.address = cmd & 0x0F
            for i, byte in enumerate(frame[1:]):
                addr = self.address + (i if self.auto_increment else 0)
                if addr < self.RAM_SIZE:
                    self.ram[addr] = byte
            if len(frame) > 1:
                self.log(f"[TM1628] RAM[{self.address}..] = {' '.join(f'{b:02X}' for b in frame[1:])}"
                         f"  display [{self.get_display_text()}]")
        elif kind == 0x80:
            self.display_on = bool(cmd & 0x08)
            self.brightness = cmd & 0x07
            self.log(f"[TM1628] Display {'ON' if self.display_on else 'OFF'}, brightness={self.brightness}")

    # ---- the chip side: key reads answered on DIO -----------------------------
    @staticmethod
    def key_code(ks, k):
        """Key at scan line KS<ks> (1..10) and K<k> (1..2) as a code for
        press_key(): byte index * 8 + bit, with the TM1628 key byte layout
        (KS odd: bits 0-1, KS even: bits 3-4, one byte per KS pair)."""
        return ((ks - 1) // 2) * 8 + ((ks - 1) % 2) * 3 + (k - 1)

    def press_key(self, code, hold_reads=1):
        """Press a front-panel key: the next hold_reads key reads answer with
        the key's bit set (code from key_code()), later reads with no key.
        Any thread may call it."""
        self.key_bytes = [0x00] * self.KEY_BYTES
        self.key_bytes[code // 8] |= 1 << (code % 8)
        self._press_reads_left = hold_reads

    def dio_in(self):
        """Level the chip drives on DIO now: during a key read the bit the CPU
        is clocking in (it reads DI while CLK is low, before the rising edge
        that shifts the next bit; LSB first, 5 bytes), else 0."""
        if not self._key_read or self.frame is None:
            return 0
        if self._answered_frame != self._frame_serial:   # first bit of this read: latch the answer
            self._answered_frame = self._frame_serial
            self.key_reads_answered += 1
            self._answer = list(self.key_bytes)
            if self._press_reads_left > 0:
                self._press_reads_left -= 1
                if self._press_reads_left == 0:
                    self.key_bytes = [0x00] * self.KEY_BYTES    # released from the next read on
        n = self._rises
        if n >= 8 * self.KEY_BYTES:
            return 0
        return (self._answer[n // 8] >> (n % 8)) & 1

    def di_override(self, di_offset, di_value):
        """Called by the simulator for every GPIO DI read: sets the DIO bit of
        the read value to the level the chip drives, for the bank that holds
        DIO (DI register = DO register - 4)."""
        if di_offset == self.dio_offset - 4 and self._key_read and self.frame is not None:
            return (di_value & ~(1 << self.dio_bit)) | (self.dio_in() << self.dio_bit)
        return di_value

    # ---- what the display shows ------------------------------------------------
    @property
    def digits(self):
        """Segment bytes of the 4 digits (RAM bytes digit_addrs), standard layout."""
        return [self._segments(self.ram[a]) if a < self.RAM_SIZE else 0 for a in self.digit_addrs]
