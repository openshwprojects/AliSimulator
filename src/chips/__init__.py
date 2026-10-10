"""
The ALi chip families the simulator knows.  A family (one module each) holds
what differs between SoC generations: the chip ID the firmware reads, how the
CPU gets from reset to the flash's bootloader (a boot ROM, or none), which
memory the chip has besides RAM and flash, and the devices of that generation.
The simulator picks the family of the image it loads (detect()), so the common
parts -- the MIPS core, the device window, the UART, the flash model, the
timers -- stay in simulator.py and the family modules add only the deltas.
"""
from .m3602 import M3602
from .m3801 import M3801
from .m3821 import M3821

FAMILIES = (M3821, M3602, M3801)    # M3801 last: it is the default


def detect(image):
    """The family of a flash image (its bootloader chunk header says), M3801 by default."""
    for family in FAMILIES:
        if family.matches(image):
            return family
    return M3801
