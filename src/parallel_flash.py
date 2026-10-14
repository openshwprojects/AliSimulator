"""A parallel NOR flash with the AMD command set, in byte mode on an 8-bit
bus: the M3329 board's (chips/m3329.py; the SPI flashes of the later chips
are simulator._hook_spi_flash_write's).

Its commands are stores to the flash window itself: the unlock cycles AA and
55 (at 0xAAA and 0x555 in byte mode), then the command --
  90             autoselect: the manufacturer ID reads at word address 0
                 (byte address >> 1, its bits 0..6), the device ID at word 1,
                 a sector's protection (0) at word 2, anything else 0;
  A0, data       program: the byte's bits can only clear;
  80, AA, 55, 30 erase the sector the 30 is written to (10 instead: the chip);
  20             unlock bypass: A0, data programs without the unlock cycles,
                 90, 00 leaves it --
and F0 (any time) goes back to reading the array.  Program and erase are done
at once, so a status poll -- DQ7 data polling, the DQ6 toggle bit -- reads the
final data.  The unlock addresses are not checked, only the sequence.

The window stays the simulator's read-only mapping of the flash image (the
M3329 runs code from it: its bootloader at 0xAFC00000, its application in
place at 0x8FC0B080..): a store faults into simulator._hook_flash_write_prot,
which hands it to store() here, and lands; the simulator reverts it like an
SPI flash's.  In autoselect mode the whole image buffer holds the ID pattern
instead -- the guest's driver runs from RAM meanwhile --, until the command
that ends it.  The M3329's probe stores that reset command in a branch delay
slot, which the simulator's Unicorn mishandles (_device_access).
"""

UNLOCK = (0xAA, 0x55)
# the command sequences (data bytes from the read state) and what they are
SEQUENCES = {
    UNLOCK + (0x90,): 'autoselect',
    UNLOCK + (0xA0,): 'program',
    UNLOCK + (0x80,) + UNLOCK + (0x30,): 'erase sector',
    UNLOCK + (0x80,) + UNLOCK + (0x10,): 'erase chip',
    UNLOCK + (0x20,): 'bypass',
}
PREFIXES = {seq[:n] for seq in SEQUENCES for n in range(1, len(seq))}

# MXIC MX29LV400B (4 Mbit, bottom boot block), byte mode
MX29LV400B = dict(manufacturer=0xC2, device=0xBA,
                  sectors=(0x4000, 0x2000, 0x2000, 0x8000) + (0x10000,) * 7)


class ParallelNorFlash:
    """The flash's command state machine over the simulator's flash image
    (sim.rom_image, and the buffer the windows map)."""

    def __init__(self, sim, manufacturer, device, sectors):
        self.sim = sim
        self.ids = {0: manufacturer, 1: device, 2: 0}
        self.sectors = []                       # [(offset, size)]
        offset = 0
        for size in sectors:
            self.sectors.append((offset, size))
            offset += size
        self.commands = {}                      # name -> count (for tests and debugging)
        self.reset()

    def reset(self):
        """Power-on (a new image): reading the array."""
        self.cycles = ()                        # the data bytes of the command so far
        self.autoselect = False
        self.bypass = False                     # in unlock bypass mode
        self.program_next = False               # the next write is the data to program
        self.exit_bypass_next = False

    def connect(self):
        """Take the stores to the flash windows (chip-family install)."""
        self.sim.flash_device = self

    def disconnect(self):
        if self.sim.flash_device is self:
            self.sim.flash_device = None

    # -- the guest's view ----------------------------------------------------
    def read(self, offset, size):
        """The bytes the guest reads at flash offset `offset`."""
        if self.autoselect:
            return bytes(self.ids.get(((offset + i) >> 1) & 0x7F, 0) for i in range(size))
        image = self.sim.rom_image
        return bytes(image[(offset + i) % len(image)] for i in range(size))

    def store(self, uc, access, address, size, value, user_data):
        """A store to the read-only windows (simulator._hook_flash_write_prot):
        its bytes are bus cycles, once (a store an asynchronous stop rewound
        comes again); it lands and is reverted."""
        sim = self.sim
        sim._device_access(uc, hooked=True)
        if sim._rom_dirty:
            sim._rom_restore()
        offset = sim._flash_offset(address)
        sim._rom_dirty.append((offset, size))
        if sim._dev_replay_of(uc, 'nor', address, value) is not None:
            return
        for i in range(size):
            self.write(offset + i, (value >> (8 * i)) & 0xFF)
        sim._dev_note(uc, 'nor', address, value, exact=True)

    def write(self, offset, byte):
        """One bus cycle: the guest stored `byte` at flash offset `offset`."""
        if self.program_next:
            self.program_next = False
            self._count('program')
            self.sim._flash_program(offset % len(self.sim.rom_image), byte)
            return
        if self.exit_bypass_next:
            self.exit_bypass_next = False
            if byte == 0x00:
                self.bypass = False
                return
        if byte == 0xF0:
            self.cycles = ()
            self._count('reset')
            self._set_autoselect(False)
            return
        if self.bypass and not self.cycles:
            if byte == 0xA0:
                self.program_next = True
                return
            if byte == 0x90:
                self.exit_bypass_next = True
                return
        cycles = self.cycles + (byte,)
        if cycles not in PREFIXES and cycles not in SEQUENCES:
            cycles = (byte,) if (byte,) in PREFIXES else ()     # a broken sequence starts over
        name = SEQUENCES.get(cycles)
        self.cycles = () if name else cycles
        if name is None:
            return
        if name != 'program':                   # (counted with its data)
            self._count(name)
        if name == 'autoselect':
            self._set_autoselect(True)
            return
        self._set_autoselect(False)
        if name == 'program':
            self.program_next = True
        elif name == 'bypass':
            self.bypass = True
        elif name == 'erase chip':
            self.sim._flash_erase(0, len(self.sim.rom_image))
        else:
            offset %= len(self.sim.rom_image)
            for start, size in self.sectors:
                if start <= offset < start + size:
                    self.sim._flash_erase(start, size)
                    break

    def _count(self, name):
        self.commands[name] = self.commands.get(name, 0) + 1

    # -- the image buffer --------------------------------------------------------
    def _set_autoselect(self, on):
        """Show the ID pattern in the windows (on) or the array again."""
        if on == self.autoselect:
            return
        self.autoselect = on
        size = len(self.sim.rom_image)
        if on:
            pattern = self.read(0, 0x100)
            self.sim._rom_write(0, pattern * (size // 0x100))
        else:
            self.sim._rom_write(0, bytes(self.sim.rom_image))
