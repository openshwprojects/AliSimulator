"""
Globo / Opticum "Lemontree" Front-Panel and EuP Standby MCU Decoder

Models the external front-panel and EuP standby microcontroller (7-bit I2C
address 0x28: 8-bit 0x50 write, 0x51 read) bit-banged over GPIO I2C on
Globo / Opticum M3602B "Lemontree" boards such as the Opticum HD X4 220
(SCL = GPIO 62, SDA = GPIO 171 on the legacy third GPIO bank 0xB80000E8 bit 11).

Protocol (decoded from the bootloader and application MCU driver):
  * Master writes an 8-byte frame `[op, 0x04, p0, p1, p2, p3, crc_lo, crc_hi]`
    (or a 38-byte VFD frame `[0x33, 0x22, mode, c0, a0, ..., c15, a15, crc_lo, crc_hi]`),
    protected by a little-endian 16-bit CRC-16/XMODEM (poly 0x1021, init 0x0000).
  * Master then reads an 8-byte response `[rt, 0x04, d0, d1, d2, d3, crc_lo, crc_hi]`
    with the same CRC-16/XMODEM:
      - `op == 0x31` sets the 4-digit 7-segment LED display (`p0..p3`, left to
        right, segments a..g, DP on bits 7..0: " ON ", "    ", " on ", "tUnE").
      - `op == 0x33` with `len == 38` and `mode != 3` (`[0x33, 0x22, mode, 0x00,
        addr0, val0, ..., addr15, val15, crc_lo, crc_hi]`) updates the 8-grid
        14-segment PT6311 VFD display RAM (`0xC0..0xD6`, 3 bytes per grid:
        "  BOOT  ", "        ", "   ON   " on the Opticum HD X7).
      - `op == 0x11` polls front-panel buttons (`rt = 0x11`, `d0 = key`, 0 = none).
      - `op == 0x33` with `mode == 3` queries VFD status (`rt = 0x13`, `d0 = 0`).
      - Status / wakeup query opcodes (`0x14, 0x52, 0x54..0x58, 0x6A, 0x6D..0x71,
        0x77, 0x79`) echo `rt = op` with `d0 = 1`.
      - Configuration / RTC / IR-wake opcodes (`0x30, 0x31, 0x32, 0x50, 0x53,
        0x59..0x69, 0x6B..0x6C, 0x72..0x76, 0x78`) answer `rt = 0x10`, `d0 = 1`.
"""
import struct

from tm1650_decoder import PanelDecoder


def crc16_xmodem(data):
    """CRC-16/XMODEM (polynomial 0x1021, initial value 0x0000) over `data`."""
    crc = 0
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


class LemontreeDecoder(PanelDecoder):
    """I2C slave + 4-digit 7-segment / 8-char PT6311 VFD front-panel decoder for the Lemontree MCU."""
    TAG = "[LEMONTREE]"
    ADDRESS = 0x28
    TM1650_ADDRS = frozenset({0x24, 0x34, 0x35, 0x36, 0x37})   # bootloader CH455 / TM1650 on shared bus (Amiko X-Finder 2/3)
    LEMONTREE_SEG_MAP = (7, 6, 5, 4, 3, 2, 1, 0)    # bit 7..0 = a, b, c, d, e, f, g, DP
    ECHO_OPS = frozenset({
        0x12, 0x14, 0x50, 0x52, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x5E, 0x60, 0x62, 0x64, 0x66, 0x6A, 0x6B, 0x6D, 0x6E,
        0x6F, 0x70, 0x71, 0x77, 0x79, 0x7A, 0x83, 0x84, 0x85,
        0x90, 0xA0,
    })
    # PT6311 14-segment VFD glyph words (low | high << 8 at PT6311 RAM 0xC0+3*g, 0xC1+3*g),
    # read directly from the PAN_PT6311 font table in Opticum HD X7 firmware (0x80741A48).
    PT6311_VFD_FONT = {
        0x0000: ' ', 0x38F1: 'A', 0x7274: 'B', 0x6801: 'C', 0x7254: 'D',
        0x68E1: 'E', 0x28E1: 'F', 0x6871: 'G', 0x18F1: 'H', 0x6244: 'I',
        0x2245: 'J', 0x0646: 'K', 0x4801: 'L', 0x1D51: 'M', 0x1953: 'N',
        0x7811: 'O', 0x38E1: 'P', 0x7813: 'Q', 0x38E3: 'R', 0x68F0: 'S',
        0x2244: 'T', 0x5811: 'U', 0x0C49: 'V', 0x185B: 'W', 0x054A: 'X',
        0x0544: 'Y', 0x6448: 'Z', 0x0142: '\\', 0x7010: ']', 0x0943: '^',
        0x00E0: '-', 0x07EE: '*', 0x02E4: '+', 0x0050: ',', 0x0005: '.',
        0x0448: '/', 0x0244: '1', 0x70E1: '2', 0x70F0: '3', 0x0AE4: '4',
        0x68F1: '6', 0x3010: '7', 0x78F1: '8', 0x78F0: '9',
    }
    _CHAR_TO_7SEG = PanelDecoder.CHAR_TO_7SEG

    def __init__(self, scl_gpio=62, sda_gpio=171, log_handler=None,
                 digit_order=(0, 1, 2, 3), seg_map=LEMONTREE_SEG_MAP):
        super().__init__(log_handler)
        self.digit_order = tuple(digit_order)
        self.seg_map = tuple(seg_map)
        self.scl_offset, self.scl_bit = self._gpio_to_offset_bit(scl_gpio)
        self.sda_offset, self.sda_bit = self._gpio_to_offset_bit(sda_gpio)

        # Bit-banged I2C slave state (matches gpio_i2c.GpioI2cBus)
        self.scl, self.sda = 1, 1
        self.state = "IDLE"
        self.phase = "bits"
        self.nbits = 0
        self.byte = 0
        self.out = 0
        self.reading = False
        self.master_ack = False
        self.written = bytearray()

        # Display and key state
        self._cur_addr = 0
        self.raw = [0x00, 0x00, 0x00, 0x00]
        self._tm1650_digits = None
        self.vfd_ram = [0x00] * 24
        self.vfd_text = None
        self._last_text = None
        self.frame_count = 0
        self.i2c_transaction_count = 0
        self.key_read_count = 0
        self.key_reads_answered = 0
        self.key_byte = 0x00
        self._press_reads_left = 0

        body = bytes([0x10, 0x04, 1, 0, 0, 0])
        self._resp = body + struct.pack("<H", crc16_xmodem(body))
        self._resp_idx = 0

    @staticmethod
    def key_code(code):
        return int(code) & 0xFF

    def press_key(self, code, hold_reads=1):
        self.key_byte = int(code) & 0xFF
        self._press_reads_left = hold_reads

    @property
    def digits(self):
        """Segment bytes of the 4 display positions, left to right, standard layout."""
        if self.vfd_text is not None:
            return self.vfd_to_7seg_digits(self.vfd_text)
        if self._tm1650_digits is not None:
            return list(self._tm1650_digits)
        return [self._segments(self.raw[i]) for i in self.digit_order]

    def get_display_text(self):
        if self.vfd_text is not None:
            return self.vfd_text
        return super().get_display_text()

    # ---- GPIO pin transitions ------------------------------------------------
    def gpio_watch(self):
        if self.dump_enabled:
            return None
        watch = {self.scl_offset: 1 << self.scl_bit}
        watch[self.sda_offset] = watch.get(self.sda_offset, 0) | (1 << self.sda_bit)
        return watch

    def on_gpio_write(self, address, size, levels):
        offset = address & 0xFFF
        if not self._gpio_changed(offset, levels):
            return
        scl, sda = self.scl, self.sda
        if offset == self.scl_offset:
            scl = (levels >> self.scl_bit) & 1
        if offset == self.sda_offset:
            sda = (levels >> self.sda_bit) & 1
        if scl != self.scl:
            self.scl = scl
            if scl:
                self._scl_rise()
            else:
                self._scl_fall()
        if sda != self.sda:
            self.sda = sda
            if self.scl and self._sda_out() is None:
                if not sda:
                    self._start()
                else:
                    self._stop()

    def _start(self):
        self._finish_write()
        self.state, self.phase = "ADDR", "bits"
        self.nbits, self.byte = 0, 0

    def _stop(self):
        self._finish_write()
        self.state = "IDLE"

    def _finish_write(self):
        if self.state == "WRITE" and self.written:
            if self._cur_addr == self.ADDRESS:
                self._handle_command(bytes(self.written))
            elif 0x34 <= self._cur_addr <= 0x37 and self.vfd_text is None and self.raw == [0, 0, 0, 0]:
                if self._tm1650_digits is None:
                    self._tm1650_digits = [0x00, 0x00, 0x00, 0x00]
                self._tm1650_digits[self._cur_addr - 0x34] = self.written[0]
                self.frame_count += 1
                text = self.get_display_text()
                if text != self._last_text:
                    self._last_text = text
                    self.log(f"{self.TAG} CH455 Display: [{text}]")
            self.written.clear()

    def _scl_rise(self):
        if self.state in ("IDLE", "IGNORE"):
            return
        if self.phase == "bits":
            self.byte = ((self.byte << 1) | self.sda) & 0xFF
            self.nbits += 1
        elif self.phase == "mack":
            self.master_ack = (self.sda == 0)

    def _scl_fall(self):
        if self.state in ("IDLE", "IGNORE"):
            return
        if self.phase == "bits" and self.nbits == 8:
            if self.state == "ADDR":
                addr = self.byte >> 1
                self.reading = bool(self.byte & 1)
                if addr != self.ADDRESS and (self.reading or addr not in self.TM1650_ADDRS):
                    self.state = "IGNORE"
                    return
                self._cur_addr = addr
                self.phase = "ack"
            elif self.state == "WRITE":
                self.written.append(self.byte)
                self.phase = "ack"
            elif self.state == "READ":
                self.phase = "mack"
        elif self.phase == "ack":
            self.nbits, self.byte = 0, 0
            if self.state == "ADDR":
                if self.reading:
                    self.state = "READ"
                    self._next_read_byte()
                else:
                    self.state = "WRITE"
                    self.written.clear()
            self.phase = "bits"
        elif self.phase == "mack":
            self.nbits, self.byte = 0, 0
            if self.master_ack:
                self._next_read_byte()
                self.phase = "bits"
            else:
                self.state = "IGNORE"

    def _next_read_byte(self):
        self.out = self._resp[self._resp_idx % len(self._resp)]
        self._resp_idx += 1

    def _handle_command(self, b):
        self.i2c_transaction_count += 1
        op = b[0]
        if op == 0x31 and len(b) >= 6:
            self.vfd_text = None
            self._tm1650_digits = None
            self.raw = [b[2], b[3], b[4], b[5]]
            self.frame_count += 1
            text = self.get_display_text()
            if text != self._last_text:
                self._last_text = text
                self.log(f"{self.TAG} Display: [{text}] (raw: {' '.join(f'{x:02X}' for x in self.raw)})")
        elif op == 0x33 and len(b) >= 38 and b[1] == 0x22 and b[2] != 3:
            self._tm1650_digits = None
            for idx in range(4, 36, 2):
                addr, val = b[idx], b[idx + 1]
                if 0xC0 <= addr < 0xD8:
                    self.vfd_ram[addr - 0xC0] = val
            chars = []
            for g in range(8):
                word = self.vfd_ram[3 * g] | (self.vfd_ram[3 * g + 1] << 8)
                chars.append(self.PT6311_VFD_FONT.get(word, '?'))
            self.vfd_text = "".join(chars)
            self.frame_count += 1
            if self.vfd_text != self._last_text:
                self._last_text = self.vfd_text
                self.log(f"{self.TAG} VFD: [{self.vfd_text}]")
        if op == 0x33 and len(b) >= 3 and b[2] == 3:
            body = bytes([0x13, 0x04, 0, 0, 0, 0])
        elif op == 0x11:
            self.key_read_count += 1
            if self._press_reads_left > 0:
                key = self.key_byte
                self._press_reads_left -= 1
                self.key_reads_answered += 1
            else:
                key = 0
            body = bytes([0x11, 0x04, key, 0, 0, 0])
        elif op in self.ECHO_OPS:
            body = bytes([op, 0x04, 1, 0, 0, 0])
        else:
            body = bytes([0x10, 0x04, 1, 0, 0, 0])
        self._resp = body + struct.pack("<H", crc16_xmodem(body))
        self._resp_idx = 0

    # ---- Slave SDA drive -----------------------------------------------------
    def _sda_out(self):
        if self.phase == "ack" and self.state in ("ADDR", "WRITE"):
            return 0
        if self.state == "READ" and self.phase == "bits":
            i = self.nbits - 1 if self.scl else self.nbits
            if 0 <= i <= 7:
                return (self.out >> (7 - i)) & 1
        return None

    def di_override(self, di_offset, value):
        if di_offset == self.scl_offset - 4:
            value |= 1 << self.scl_bit
        if di_offset == self.sda_offset - 4:
            out = self._sda_out()
            level = 1 if out is None else out
            value = value & ~(1 << self.sda_bit) | (level << self.sda_bit)
        return value
