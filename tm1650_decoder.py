"""
TM1650/HD2015 I2C LED Display Decoder

Decodes I2C bit-bang GPIO events into TM1650 LED display commands.
Tracks SCL/SDA transitions on GPIO pins to reconstruct I2C protocol,
then interprets TM1650 register writes to show the displayed characters.
"""


class TM1650Decoder:
    # TM1650 register addresses
    ADDR_DISPLAY_CTRL = 0x48
    ADDR_DIG1 = 0x68
    ADDR_DIG2 = 0x6A
    ADDR_DIG3 = 0x6C
    ADDR_DIG4 = 0x6E

    DIGIT_ADDRS = {0x68: 0, 0x6A: 1, 0x6C: 2, 0x6E: 3}

    # 7-segment to character map (standard encoding, bit7=DP ignored)
    SEG_TO_CHAR = {
        0x00: ' ', 0x3F: 'O', 0x06: '1', 0x5B: '2', 0x4F: '3',
        0x66: '4', 0x6D: 'S', 0x7D: '6', 0x07: '7', 0x7F: '8',
        0x6F: '9', 0x77: 'A', 0x5F: 'a', 0x7C: 'b', 0x39: 'C',
        0x58: 'c', 0x5E: 'd', 0x79: 'E', 0x71: 'F', 0x76: 'H',
        0x74: 'h', 0x30: 'I', 0x10: 'i', 0x1E: 'J', 0x38: 'L',
        0x37: 'N', 0x54: 'n', 0x5C: 'o', 0x73: 'P', 0x50: 'r',
        0x78: 't', 0x3E: 'U', 0x1C: 'u', 0x6E: 'Y',
        0x40: '-', 0x08: '_', 0x80: '.',
    }

    def __init__(self, scl_gpio=61, sda_gpio=74, log_handler=None):
        self.scl_offset, self.scl_bit = self._gpio_to_offset_bit(scl_gpio)
        self.sda_offset, self.sda_bit = self._gpio_to_offset_bit(sda_gpio)
        self.log_handler = log_handler

        # I2C state
        self.prev_scl = 1
        self.prev_sda = 1
        self.state = 'IDLE'
        self.bit_count = 0
        self.current_byte = 0
        self.bytes_received = []

        # Display state
        self.digits = [0x00, 0x00, 0x00, 0x00]

        # Stats
        self.gpio_event_count = 0
        self.i2c_transaction_count = 0
        self._offsets_seen = set()
        self._prev_reg_values = {}
        self._bit_toggle_counts = {}
        self._i2c_trace_count = 0
        self.dump_enabled = True


    @staticmethod
    def _gpio_to_offset_bit(gpio_num):
        """Convert GPIO pin number to (DO register offset, bit position)."""
        if gpio_num < 32:
            return 0x054, gpio_num
        elif gpio_num < 64:
            return 0x0D4, gpio_num - 32
        elif gpio_num < 96:
            return 0x0E8, gpio_num - 64
        else:
            return 0x0F4, gpio_num - 96

    def log(self, msg):
        if not self.dump_enabled:
            # When dump is disabled, only show [TM1650] results
            if not msg.startswith('[TM1650]'):
                return
        if self.log_handler:
            self.log_handler(msg)
        else:
            print(msg)

    def on_gpio_write(self, address, size, value):
        """Called when a GPIO register is written. Auto-detects I2C pins."""
        offset = address & 0xFFF

        # Track previous values per register offset
        prev = self._prev_reg_values.get(offset, 0)
        if value == prev:
            return

        # Find which bits changed
        changed_bits = value ^ prev
        self._prev_reg_values[offset] = value

        # Count toggles per (offset, bit) and log first occurrence of each offset
        if offset not in self._offsets_seen:
            self._offsets_seen.add(offset)
            self.log(f"[GPIO] New reg offset 0x{offset:03X} val=0x{value:08X}")

        for bit in range(32):
            if changed_bits & (1 << bit):
                key = (offset, bit)
                self._bit_toggle_counts[key] = self._bit_toggle_counts.get(key, 0) + 1
                # Calculate the actual GPIO pin number
                if offset == 0x054:
                    gpio_num = bit
                elif offset == 0x0D4:
                    gpio_num = 32 + bit
                elif offset == 0x0E8:
                    gpio_num = 64 + bit
                elif offset == 0x0F4:
                    gpio_num = 96 + bit
                else:
                    gpio_num = -1

                # Log first transition of each bit for debugging
                if self._bit_toggle_counts[key] <= 1:
                    bval = (value >> bit) & 1
                    self.log(f"[GPIO] off=0x{offset:03X} bit{bit} (GPIO#{gpio_num}) -> {bval} (toggle #{self._bit_toggle_counts[key]})")

        self.gpio_event_count += 1

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
                self.log(f"[I2C] Repeated START")
                return

    def _decode_transaction(self):
        """Decode a complete I2C transaction as TM1650 command."""
        if len(self.bytes_received) < 2:
            return

        self.i2c_transaction_count += 1
        addr = self.bytes_received[0]
        data = self.bytes_received[1]

        if addr == self.ADDR_DISPLAY_CTRL:
            on = bool(data & 0x01)
            brightness = (data >> 4) & 0x07
            self.log(f"[TM1650] Display {'ON' if on else 'OFF'}, brightness={brightness}")

        elif addr in self.DIGIT_ADDRS:
            idx = self.DIGIT_ADDRS[addr]
            self.digits[idx] = data
            char = self.SEG_TO_CHAR.get(data & 0x7F, '?')
            self.log(f"[TM1650] Digit {idx+1}: 0x{data:02X} = '{char}'")

            # After digit 4, show full display string
            if addr == self.ADDR_DIG4:
                display = ''.join(
                    self.SEG_TO_CHAR.get(d & 0x7F, '?') for d in self.digits
                )
                self.log(f"[TM1650] Display: [{display}]")
        else:
            self.log(f"[TM1650] I2C write: addr=0x{addr:02X} data=0x{data:02X}")

    def get_display_text(self):
        """Return current display as a 4-char string."""
        return ''.join(
            self.SEG_TO_CHAR.get(d & 0x7F, '?') for d in self.digits
        )
