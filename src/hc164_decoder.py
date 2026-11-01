"""
74HC164 Shift-Register Multiplexed 4-Digit 7-Segment Front-Panel Decoder

Models the ALi SDK's `PAN_COMMON` 2-wire shift-register + 4-digit GPIO-strobed
multiplexed LED front panel (used on M3327 / M3329 receivers such as the BigSat
DSR 6500 Lux: CLK = GPIO 16, DATA = GPIO 17, active-low digit strobes = GPIO
18..21 on GPIO bank 0 `0xB8000054`).

Hardware multiplex cycle (`pan_common` timer ISR):
  1. Deasserts all digit-select strobes (HIGH when `active_low_digits=True`).
  2. Shifts 8 bits into an external 74HC164 serial-in / parallel-out shift
     register on rising edges of `CLK` (often preceded by an 8-bit `0x00`
     clear shift while all digit strobes remain inactive).
  3. Asserts exactly one digit-select strobe (LOW when `active_low_digits=True`)
     for the newly shifted digit until the next multiplex tick (~1..2.5 ms).

Because `pan_common` shifts out its active-low font byte LSB-first into the
74HC164, outputs `Q0..Q7` carry segments `a, b, c, d, e, f, g, DP` directly in
standard bit order `(0, 1, 2, 3, 4, 5, 6, 7)` once inverted (`(~sr) & 0xFF`).
"""
from tm1650_decoder import PanelDecoder


class HC164Decoder(PanelDecoder):
    """74HC164 shift-register + GPIO-multiplexed 4-digit 7-segment decoder."""
    TAG = "[HC164]"

    def __init__(self, clk_gpio=16, data_gpio=17, digit_gpios=(18, 19, 20, 21),
                 seg_map=PanelDecoder.STANDARD_SEG_MAP,
                 active_low_segments=True, active_low_digits=True,
                 log_handler=None):
        super().__init__(log_handler)
        self.seg_map = tuple(seg_map)
        self.active_low_segments = bool(active_low_segments)
        self.active_low_digits = bool(active_low_digits)

        self.clk_offset, self.clk_bit = self._gpio_to_offset_bit(clk_gpio)
        self.data_offset, self.data_bit = self._gpio_to_offset_bit(data_gpio)
        self.digit_pins = [self._gpio_to_offset_bit(g) for g in digit_gpios]
        n = len(self.digit_pins)

        blank = 0xFF if self.active_low_segments else 0x00
        self.raw = [blank] * n
        self.sr = blank
        self.clk = 1
        self.data = 1
        self._digit_levels = [1 if self.active_low_digits else 0] * n
        self._last_text = None
        self.frame_count = 0

        # Fast-path single-bank bitmasks when CLK, DATA, and all digit strobes
        # share one GPIO bank (the common case on M3329 bank 0 0xB8000054).
        banks = {self.clk_offset, self.data_offset} | {off for off, _ in self.digit_pins}
        if len(banks) == 1 and n == 4:
            self._fast_offset = self.clk_offset
            self._clk_mask = 1 << self.clk_bit
            self._data_mask = 1 << self.data_bit
            d0, d1, d2, d3 = (1 << b for _, b in self.digit_pins)
            self._dig_masks = (d0, d1, d2, d3)
            self._all_dig_mask = d0 | d1 | d2 | d3
            self._watch_mask = self._clk_mask | self._data_mask | self._all_dig_mask
            self._single_strobe = {d0: 0, d1: 1, d2: 2, d3: 3}
        else:
            self._fast_offset = None
        self._prev_masked = None

    @property
    def digits(self):
        """Segment bytes of the display positions, left to right, standard layout."""
        inv = 0xFF if self.active_low_segments else 0x00
        if self.seg_map == self.STANDARD_SEG_MAP:
            return [(b ^ inv) & 0xFF for b in self.raw]
        return [self._segments((b ^ inv) & 0xFF) for b in self.raw]

    def di_override(self, di_offset, di_value):
        return di_value

    def on_gpio_write(self, address, size, levels):
        offset = address & 0xFFF
        if self._fast_offset is not None:
            if offset != self._fast_offset:
                return
            masked = levels & self._watch_mask
            if masked == self._prev_masked:
                return
            self._prev_masked = masked
            self.gpio_event_count += 1

            new_clk = 1 if (masked & self._clk_mask) else 0
            if new_clk and not self.clk:
                bit = 1 if (masked & self._data_mask) else 0
                self.sr = ((self.sr << 1) | bit) & 0xFF
            self.clk = new_clk

            dig_bits = masked & self._all_dig_mask
            active = (self._all_dig_mask ^ dig_bits) if self.active_low_digits else dig_bits
            idx = self._single_strobe.get(active)
            if idx is not None and self.raw[idx] != self.sr:
                self.raw[idx] = self.sr
                self.frame_count += 1
                text = self.get_display_text()
                if text != self._last_text:
                    self._last_text = text
                    self.log(f"{self.TAG} Display: [{text}]")
            return

        if not self._gpio_changed(offset, levels):
            return
        if offset == self.data_offset:
            self.data = (levels >> self.data_bit) & 1
        if offset == self.clk_offset:
            new_clk = (levels >> self.clk_bit) & 1
            if new_clk and not self.clk:
                self.sr = ((self.sr << 1) | self.data) & 0xFF
            self.clk = new_clk
        active_idx = None
        active_count = 0
        for i, (doff, dbit) in enumerate(self.digit_pins):
            if offset == doff:
                self._digit_levels[i] = (levels >> dbit) & 1
            lvl = self._digit_levels[i]
            is_on = (lvl == 0) if self.active_low_digits else (lvl == 1)
            if is_on:
                active_idx = i
                active_count += 1
        if active_count == 1 and self.raw[active_idx] != self.sr:
            self.raw[active_idx] = self.sr
            self.frame_count += 1
            text = self.get_display_text()
            if text != self._last_text:
                self._last_text = text
                self.log(f"{self.TAG} Display: [{text}]")
