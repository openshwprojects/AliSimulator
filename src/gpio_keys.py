"""
Front-panel buttons wired straight to GPIO inputs, with no LED-driver chip:
a pull-up holds each pin high and a pressed key pulls it low.

The Strong Prima VIII (MC6501-M3801) has two, on GPIO 31 and 9 -- the pins
the Opticum / Globo boards give their TM1650 -- which its application polls
(a press is two reads 50 ms apart) and sends on as the panel keys 0xFFFF0001
(GPIO 31, channel up) and 0xFFFF0002 (GPIO 9, channel down).  The simulator reads an input pin that
nothing drives as 0 -- its stand-in for an I2C slave's ACK, see
simulator._hook_gpio_di_read -- which holds both keys down for ever: the
firmware then steps through its channels by itself.  This model answers the
firmware's reads of its pins, high unless a test presses a key.
"""
from tm1650_decoder import PanelDecoder


class GpioKeys:
    """The decoder interface of front_panel.make_panel (tm1650_decoder.py):
    on_gpio_write, di_override, press_key, digits; no display."""
    has_display = False

    def __init__(self, pins, log_handler=None):
        self.pins = tuple(pins)
        self.log_handler = log_handler
        self.dump_enabled = False
        self.digits = [0, 0, 0, 0]
        self._held = {}                 # pin -> reads of its bank that still see it pressed
        self._bank_pins = {}            # di_offset -> [(pin, mask), ...]
        for pin in self.pins:
            do_offset, bit = PanelDecoder._gpio_to_offset_bit(pin)
            self._bank_pins.setdefault(do_offset - 4, []).append((pin, 1 << bit))

    @staticmethod
    def key_code(pin):
        """A key's code for press_key(): its GPIO pin."""
        return pin

    def on_gpio_write(self, address, size, value):
        """GPIO DO writes: no chip on the pins to follow."""

    def get_display_text(self):
        return ""

    def press_key(self, code, hold_reads=3):
        """Press the key on GPIO `code`: the next hold_reads reads of its bank's
        DI register see the pin low.  The Prima's key task reads the bank for
        each key it checks and once more 50 ms later to confirm a press, so 3
        reads are one press whichever of the two keys it checks first.  Any
        thread may call it."""
        self._held[code] = hold_reads

    def di_override(self, di_offset, di_value):
        """Called by the simulator for every GPIO DI read: the key pins of that
        bank read high (released) or low (pressed)."""
        bank = self._bank_pins.get(di_offset)
        if not bank:
            return di_value
        held = self._held
        for pin, mask in bank:
            left = held.get(pin, 0)
            if left > 0:
                held[pin] = left - 1
                di_value &= ~mask
            else:
                di_value |= mask
        return di_value
