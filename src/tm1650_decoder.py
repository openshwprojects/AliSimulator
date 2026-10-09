"""
TM1650/HD2015 I2C LED Display Decoder

Decodes I2C bit-bang GPIO events into TM1650 LED display commands.
Tracks SCL/SDA transitions on GPIO pins to reconstruct I2C protocol,
then interprets TM1650 register writes to show the displayed characters.

Which digit register drives which display position and which bit of a digit
byte drives which segment is board specific: `digit_order` lists the digit
registers (0..3 = 0x68, 0x6A, 0x6C, 0x6E) from left to right and `seg_map`
the bit numbers of segments a, b, c, d, e, f, g, DP (the Ferguson Ariva
T650i's FD650K: digits 0x6C, 0x6E, 0x6A, 0x68, segments on bits
1, 5, 6, 0, 7, 2, 4, 3).  .digits / get_display_text() give the display in
the standard layout (bit 0..6 = a..g, bit 7 = DP), left to right; .raw holds
the bytes as written to registers 0x68..0x6E.
"""


GPIO_DO_OFFSETS = (0x054, 0x0D4, 0x0E8, 0x0F4)    # the DO (data-out) register of GPIO bank 0..3 (32 pins
                                                  # each); the bank's DI register is DO - 4, DIR is DO + 4


class PanelDecoder:
    """What the LED-driver decoders share: the GPIO pins as (DO register
    offset, bit), the bookkeeping of the DO writes the simulator reports to
    on_gpio_write(), the log with the chip's tag, and the 7-segment digits
    (.digits of the subclass, standard layout: bit 0..6 = a..g, bit 7 = DP)
    as text."""
    TAG = ''                            # '[TM1650]': the messages still shown with dump_enabled off

    # 7-segment to character map (standard encoding, bit7=DP ignored)
    SEG_TO_CHAR = {
        0x00: ' ', 0x3F: 'O', 0x06: '1', 0x5B: '2', 0x4F: '3',
        0x66: '4', 0x6D: 'S', 0x7D: '6', 0x07: '7', 0x7F: '8',
        0x6F: '9', 0x77: 'A', 0x5F: 'a', 0x7C: 'b', 0x39: 'C',
        0x58: 'c', 0x5E: 'd', 0x79: 'E', 0x71: 'F', 0x76: 'H',
        0x74: 'h', 0x30: 'I', 0x10: 'i', 0x1E: 'J', 0x38: 'L',
        0x37: 'N', 0x54: 'n', 0x5C: 'o', 0x73: 'P', 0x50: 'r', 0x70: 'r',
        0x78: 't', 0x3E: 'U', 0x1C: 'u', 0x6E: 'Y',
        0x40: '-', 0x08: '_', 0x80: '.',
    }

    STANDARD_SEG_MAP = (0, 1, 2, 3, 4, 5, 6, 7)      # bit of a, b, c, d, e, f, g, DP in a digit byte

    def __init__(self, log_handler=None):
        self.log_handler = log_handler
        # Stats
        self.gpio_event_count = 0
        self._offsets_seen = set()
        self._prev_reg_values = {}
        self._bit_toggle_counts = {}
        self.dump_enabled = True

    @staticmethod
    def _gpio_to_offset_bit(gpio_num):
        """GPIO pin number -> (DO register offset, bit position)."""
        bank = min(gpio_num // 32, len(GPIO_DO_OFFSETS) - 1)
        return GPIO_DO_OFFSETS[bank], gpio_num - 32 * bank

    @staticmethod
    def gpio_number(offset, bit):
        """(DO register offset, bit position) -> GPIO pin number, -1 for another register."""
        return GPIO_DO_OFFSETS.index(offset) * 32 + bit if offset in GPIO_DO_OFFSETS else -1

    def log(self, msg):
        if not self.dump_enabled and not msg.startswith(self.TAG):
            return                      # dump off: only the chip's own messages
        if self.log_handler:
            self.log_handler(msg)
        else:
            print(msg)

    def _gpio_changed(self, offset, value):
        """Note a GPIO register write: the bits that changed (0: none), with
        the toggles counted and the first one of every bit logged."""
        prev = self._prev_reg_values.get(offset, 0)
        changed = value ^ prev
        if not changed:
            return 0
        self._prev_reg_values[offset] = value
        if offset not in self._offsets_seen:
            self._offsets_seen.add(offset)
            self.log(f"[GPIO] New reg offset 0x{offset:03X} val=0x{value:08X}")
        for bit in range(32):
            if changed & (1 << bit):
                key = (offset, bit)
                self._bit_toggle_counts[key] = self._bit_toggle_counts.get(key, 0) + 1
                if self._bit_toggle_counts[key] <= 1:
                    self.log(f"[GPIO] off=0x{offset:03X} bit{bit} (GPIO#{self.gpio_number(offset, bit)}) -> "
                             f"{(value >> bit) & 1} (toggle #{self._bit_toggle_counts[key]})")
        self.gpio_event_count += 1
        return changed

    def _segments(self, byte):
        """A digit byte in the standard layout (bit 0..6 = a..g, bit 7 = DP)."""
        return sum(((byte >> src) & 1) << seg for seg, src in enumerate(self.seg_map))

    def get_display_text(self):
        """The 4 digits as characters (unknown segment patterns show as '?')."""
        return ''.join(self.SEG_TO_CHAR.get(d & 0x7F, '?') for d in self.digits)


class TM1650Decoder(PanelDecoder):
    TAG = '[TM1650]'
    # TM1650 register addresses
    ADDR_DISPLAY_CTRL = 0x48
    ADDR_DIG1 = 0x68
    ADDR_DIG2 = 0x6A
    ADDR_DIG3 = 0x6C
    ADDR_DIG4 = 0x6E
    # Key scan read command: 0x4F on FD650/HD2015-style chips, 0x49 on original TM1650.
    # LSB=1 means I2C read; the data byte is driven by the display chip, not the CPU.
    KEY_READ_ADDRS = (0x4F, 0x49)

    DIGIT_ADDRS = {0x68: 0, 0x6A: 1, 0x6C: 2, 0x6E: 3}

    def __init__(self, scl_gpio=61, sda_gpio=74, log_handler=None, on_transaction=None,
                 digit_order=(0, 1, 2, 3), seg_map=PanelDecoder.STANDARD_SEG_MAP):
        super().__init__(log_handler)
        self.digit_order = tuple(digit_order)
        self.seg_map = tuple(seg_map)
        self.scl_offset, self.scl_bit = self._gpio_to_offset_bit(scl_gpio)
        self.sda_offset, self.sda_bit = self._gpio_to_offset_bit(sda_gpio)
        self.on_transaction = on_transaction

        # I2C state
        self.prev_scl = 1
        self.prev_sda = 1
        self.state = 'IDLE'
        self.bit_count = 0
        self.current_byte = 0
        self.bytes_received = []

        # Display state: the bytes written to digit registers 0x68, 0x6A, 0x6C, 0x6E
        self.raw = [0x00, 0x00, 0x00, 0x00]

        # Key scan: the byte the chip answers a key read (address 0x4F / 0x49)
        # with, driven onto SDA bit by bit while the CPU clocks the data byte
        # (see di_override / press_key).  0x00: no key.
        self.key_byte = 0x00
        self._press_reads_left = 0
        self.key_reads_answered = 0
        self._tx_serial = 0             # counts I2C STARTs (one answer byte per transaction)
        self._answer_tx = -1
        self._answer = 0x00

        # Stats
        self.i2c_transaction_count = 0
        self.key_read_count = 0
        self._last_key_value = None
        self._i2c_trace_count = 0

    def on_gpio_write(self, address, size, value):
        """Called when a GPIO register is written. Auto-detects I2C pins."""
        offset = address & 0xFFF
        if not self._gpio_changed(offset, value):
            return

        # Also try I2C decode with current scl/sda config
        scl = self.prev_scl
        sda = self.prev_sda
        scl_changed = False
        sda_changed = False

        if offset == self.scl_offset:
            new_scl = (value >> self.scl_bit) & 1
            if new_scl != self.prev_scl:
                scl = new_scl
                scl_changed = True

        if offset == self.sda_offset:
            new_sda = (value >> self.sda_bit) & 1
            if new_sda != self.prev_sda:
                sda = new_sda
                sda_changed = True

        if scl_changed or sda_changed:
            # Log first 200 I2C-level transitions
            if self._i2c_trace_count < 200:
                self._i2c_trace_count += 1
                self.log(f"[I2C_TRACE] SCL={scl}{'*' if scl_changed else ' '} SDA={sda}{'*' if sda_changed else ' '} state={self.state}")
            
            if scl_changed and sda_changed:
                # Both changed simultaneously (same register write).
                if self._i2c_trace_count < 200:
                    self.log(f"[I2C_SIMULT] SCL:{self.prev_scl}→{scl} SDA:{self.prev_sda}→{sda} state={self.state}")
                # Check the final state for START/STOP:
                #   If SCL ends HIGH and SDA went 1→0: START
                #   If SCL ends HIGH and SDA went 0→1: STOP
                #   Otherwise: just update
                if scl == 1 and sda == 0 and self.prev_sda == 1:
                    # START condition (or simultaneous setup)
                    self.prev_scl = scl
                    self.prev_sda = sda
                    self._process_i2c(scl, sda, False, True)  # treat as SDA-only change
                elif scl == 1 and sda == 1 and self.prev_sda == 0:
                    # STOP condition
                    self.prev_scl = scl
                    self.prev_sda = sda
                    self._process_i2c(scl, sda, False, True)  # treat as SDA-only change
                else:
                    self.prev_scl = scl
                    self.prev_sda = sda
            else:
                self._process_i2c(scl, sda, scl_changed, sda_changed)
                self.prev_scl = scl
                self.prev_sda = sda

    def _process_i2c(self, scl, sda, scl_changed, sda_changed):
        """Process I2C signal transitions for TM1650 non-standard protocol.
        
        TM1650 bit-bang sequence per byte:
        1. START: SDA falls while SCL high (both were 1)
        2. For each of 8 bits: SCL low, set SDA, SCL high (sample bit)
        3. ACK: SCL low, release SDA, SCL high
        4. STOP: SCL low, SDA low, SCL high, SDA high
        
        The firmware may change SDA while SCL is still high between bit clocks.
        We only sample data on SCL RISING edges.
        """
        if self.state == 'IDLE':
            # START: SDA falls while SCL is high
            if sda_changed and sda == 0 and scl == 1:
                self.state = 'DATA'
                self.bit_count = 0
                self.current_byte = 0
                self.bytes_received = []
                self._tx_serial += 1
                self.log(f"[I2C] START detected")
                return
        
        elif self.state == 'DATA':
            # Sample data on SCL rising edge
            if scl_changed and scl == 1:
                if self.bit_count < 8:
                    self.current_byte = (self.current_byte << 1) | sda
                    self.bit_count += 1
                    if self.bit_count == 8:
                        self.log(f"[I2C] Byte: 0x{self.current_byte:02X}")
                else:
                    # 9th clock = ACK/NACK
                    ack = "ACK" if sda == 0 else "NACK"
                    self.log(f"[I2C] {ack}")
                    self.bytes_received.append(self.current_byte)
                    self.bit_count = 0
                    self.current_byte = 0
                return
            
            # STOP: SDA rises while SCL is high (after receiving at least one byte)
            if sda_changed and sda == 1 and scl == 1:
                if len(self.bytes_received) > 0:
                    self.log(f"[I2C] STOP detected ({len(self.bytes_received)} bytes)")
                    self._decode_transaction()
                    self.state = 'IDLE'
                    return
                # If no bytes received yet, might be a false STOP or bus reset
                # Stay in DATA state and reset bit counter
                self.bit_count = 0
                self.current_byte = 0
                return
            
            # SDA falls while SCL high and no real data yet = repeated START
            if sda_changed and sda == 0 and scl == 1:
                if len(self.bytes_received) > 0:
                    self._decode_transaction()
                self.bit_count = 0
                self.current_byte = 0
                self.bytes_received = []
                self._tx_serial += 1
                self.log(f"[I2C] Repeated START")
                return

    def _decode_transaction(self):
        """Decode a complete I2C transaction as TM1650 command."""
        if len(self.bytes_received) < 2:
            return

        self.i2c_transaction_count += 1
        addr = self.bytes_received[0]
        data = self.bytes_received[1]

        if self.on_transaction:
            self.on_transaction(addr, data)

        if addr == self.ADDR_DISPLAY_CTRL:
            on = bool(data & 0x01)
            brightness = (data >> 4) & 0x07
            self.log(f"[TM1650] Display {'ON' if on else 'OFF'}, brightness={brightness}")

        elif addr in self.DIGIT_ADDRS:
            idx = self.DIGIT_ADDRS[addr]
            self.raw[idx] = data
            char = self.SEG_TO_CHAR.get(self._segments(data) & 0x7F, '?')
            self.log(f"[TM1650] Digit {idx+1}: 0x{data:02X} = '{char}'")

            # After digit 4, show full display string
            if addr == self.ADDR_DIG4:
                display = ''.join(
                    self.SEG_TO_CHAR.get(d & 0x7F, '?') for d in self.digits
                )
                self.log(f"[TM1650] Display: [{display}]")
        elif addr in self.KEY_READ_ADDRS:
            # Key read: 7-bit I2C addr 0x27 -> (0x27<<1)|1 = 0x4F.
            # Firmware polls the keypad continuously; only log the first read
            # and whenever the observed value changes.
            # NOTE: we only see the GPIO output latch, so 'data' is not the real
            # key code unless the simulator emulates the chip driving SDA.
            self.key_read_count += 1
            if data != self._last_key_value:
                self._last_key_value = data
                self.log(f"[TM1650] Key read: {self.parse_key_byte(data)} "
                         f"(read #{self.key_read_count}, identical reads suppressed)")
        else:
            self.log(f"[TM1650] I2C write: addr=0x{addr:02X} data=0x{data:02X}")

    # ---- key scan: the chip drives SDA during the data byte of a key read ----
    @staticmethod
    def key_code(ki, dig, pressed=True):
        """Key-scan byte of the key at row KI<ki> (1..7), column DIG<dig> (1..4)."""
        return ((0x40 if pressed else 0) | ((ki - 1) & 7) << 3 | 0x04 | ((dig - 1) & 3)) & 0xFF

    def press_key(self, code, hold_reads=1):
        """Press a front-panel key: the next hold_reads key reads answer `code`
        with its pressed bit (0x40) set, later reads the same code released
        (bit 6 clear), as the chip reports the last key.  `code` as returned
        by key_code() (the pressed bit is added here).  Any thread may call it.
        dump_maciej's panel driver turns every poll that sees the key pressed
        into a key event, so hold_reads=1 is one press."""
        self._press_reads_left = hold_reads
        self.key_byte = (code | 0x40) & 0xFF

    def sda_in(self):
        """Level the chip drives on SDA now: during the data byte of a key
        read the bit the CPU is clocking in (MSB first; it reads DI after the
        SCL rising edge, when bit_count already counts that edge), else 0 (ACK
        / idle: the CPU drives the line)."""
        if (self.state == 'DATA' and len(self.bytes_received) == 1
                and self.bytes_received[0] in self.KEY_READ_ADDRS and 1 <= self.bit_count <= 8):
            if self._answer_tx != self._tx_serial:        # first bit of this transaction's data byte
                self._answer_tx = self._tx_serial
                self.key_reads_answered += 1
                self._answer = self.key_byte
                if self._press_reads_left > 0:
                    self._press_reads_left -= 1
                    if self._press_reads_left == 0:
                        self.key_byte &= ~0x40 & 0xFF      # released from the next read on
            return (self._answer >> (8 - self.bit_count)) & 1
        return 0

    def di_override(self, di_offset, di_value):
        """Called by the simulator for every GPIO DI read: sets the SDA bit of
        the read value to the level the chip drives (sda_in), for the bank
        that holds SDA."""
        if di_offset == self.sda_offset - 4 and self.sda_in():      # DI register = DO register - 4
            return di_value | (1 << self.sda_bit)
        return di_value

    @staticmethod
    def parse_key_byte(b):
        """Format a TM1650/FD650 key-scan byte.

        bit6    = 1 if key currently pressed (else: last pressed key history)
        bits5:3 = KI row (0..6 -> KI1..KI7)
        bit2    = always 1 in valid codes
        bits1:0 = DIG column (0..3 -> DIG1..DIG4)
        """
        if b == 0xFF:
            return "0xFF (no chip response - SDA idle high)"
        pressed = bool(b & 0x40)
        ki = ((b >> 3) & 0x07) + 1
        dig = (b & 0x03) + 1
        state = "PRESSED" if pressed else "released"
        return f"0x{b:02X} {state} KI{ki}/DIG{dig}"

    @property
    def digits(self):
        """Segment bytes of the 4 display positions, left to right, standard layout."""
        return [self._segments(self.raw[i]) for i in self.digit_order]
