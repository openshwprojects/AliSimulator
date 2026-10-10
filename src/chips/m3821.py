"""
ALi M3821 family (M3821 / M3822P, the DVB-T2 generation: the Opticum Blue
R265 Lite dump).  The flash has the same NCRC chunk chain as the M3801's and
is memory-mapped at 0xAFC00000 like there, but the bootloader chunk is built
for an on-chip boot ROM:

  * the chunk's version string is "M3821b-0.1.0" (that is how the family is
    recognised);
  * offset 0x470.. holds a descriptor table the boot ROM interprets (a
    register script: clock registers at 0xB8001000.., the DDR controller at
    0xB803E02C..), not code;
  * the bootloader itself starts at offset 0x800 and expects to run from a
    boot SRAM at physical 0x1FE00000 (KSEG0 0x9FE00000: its stack sits at
    0x9FE04000 and it jumps to 0x9FE02488), so the boot ROM copies the
    bootloader area there and enters at 0x9FE00800.

Once there it prints "NOR1" on the UART (the same 16550 at 0xB8018300),
programs the clock tree, trains the DDR controller (0xB803E000..) and copies
the next stage from the flash window into RAM (its "HEAD" record at flash
offset 0x250: load address 0xA1000000).  The simulator's RAM needs no
training, so the DDR model only answers the status and pattern words the
training loop checks (DdrTraining).

The application (ALi SDK 4.0, "libcore 19.9") wants the chip ID word at
0xB8000000 to carry the M3822P variant bits (chip_variant), moves the
exception vectors with CP0 EBase, and talks to the flash through the SPI
controller's byte-stream mode and DMA engine (SpiStream) instead of the
M3801 driver's SF_INS command register.  Its start-up runs its large
memory copies through an 8-channel descriptor-ring DMA engine (DmaRings)
and fills the sound engine's PCM ring, whose read index must follow the
write index (MirrorRegisters); then it draws its OSD through the same
graphics engine (0xB800A000, ge_m36f.py) and display layer (0xB8006300,
gma_capture.py) as the M3801 boxes, so nothing of the display is this
family's own.  Firmware 1.2.0's application also waits, before it draws,
for a start bit it sets in the block at 0xB802A000 to clear (install(); most
likely the HDMI transmitter's DDC reading the TV's EDID: the block's +0x08
bit 0 is polled like a hot-plug line and the flash carries an HDCPKey
chunk).  Demodulator models the internal DVB-T / T2 demodulator's lock for
sim.set_signal().

The Ferguson T750i's M3821 boots without the boot ROM's step: its
bootloader is the M3801's kind, run from the flash window (a branch over
the chunk header, code at 0x490), with its stack in locked D-cache lines
until the DDR is up (CacheAsRam) and its set-up run through the window's
cached view; it takes its M3821 path for the chip ID 0x3821 (the plain
M3821: no variant bits), starts the SEE co-processor (see.py) and unpacks
the main code and the SEE's program from its dual-CPU image.  Such an image
is recognised by that bootloader, a SEE program chunk and a main code that
drives the M3821's own demodulator ("NIM_S3821").
"""
import ctypes
import struct

from unicorn import UC_HOOK_CODE, UC_PROT_ALL
from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_SP

from .base import ChipFamily, chunk_chain, maincode
from .see import SeeStart

SRAM_PHYS = 0x1FE00000          # the boot SRAM the boot ROM copies the bootloader into
SRAM_SIZE = 0x100000
BOOT_COPY = 0x60000             # the bootloader area of the flash (its chunk: 0..0x5FE00)
ENTRY = 0x80000000 + SRAM_PHYS + 0x800


def xip_bootloader(image):
    """A bootloader that runs from the flash window (the M3801's kind): its
    word at 0x490, where the chunk header's branch lands, calls into the
    flash window (JAL 0x?FCxxxxx)."""
    w = struct.unpack_from("<I", image, 0x490)[0]
    return w >> 26 == 0x03 and ((w & 0x03FFFFFF) << 2) & 0x0FC00000 == 0x0FC00000


class CacheAsRam:
    """The stack of an XIP bootloader before the DDR is up (the T750i's): it
    loads the D-cache lines of 0x8FFF8000..0x8FFFFFFF -- the top of the flash
    window's cached view -- and keeps its stack there (and its DDR set-up
    functions locked in the I-cache), so stores to those addresses stay in
    the cache and loads see them.  The simulator has no cache: 32 KB of RAM
    over that range, holding the flash's bytes, given back the flash's bytes
    once the bootloader runs from RAM with its stack elsewhere (its RAM copy
    reads nothing there through the cache)."""
    PHYS, SIZE = 0x0FFF8000, 0x8000

    def __init__(self, sim):
        self.sim = sim
        self.flash = bytes(sim.mu.mem_read(self.PHYS, self.SIZE))
        self.ram = ctypes.create_string_buffer(self.flash, self.SIZE)
        sim.mu.mem_unmap(self.PHYS, self.SIZE)
        sim.mu.mem_map_ptr(self.PHYS, self.SIZE, UC_PROT_ALL, ctypes.addressof(self.ram))
        self.active = True
        self._hook = sim.mu.hook_add(UC_HOOK_CODE, self._code_in_ram, begin=0x80000000, end=0x80000000 + sim.ram_size - 1)

    def _code_in_ram(self, uc, address, size, user_data):
        sp = uc.reg_read(UC_MIPS_REG_SP) & 0x1FFFFFFF
        if self.PHYS <= sp < self.PHYS + self.SIZE:
            return                      # (still on the cache's stack)
        ctypes.memmove(self.ram, self.flash, self.SIZE)     # host memory: no translation to flush
        uc.hook_del(self._hook)
        self.active = False
        self.sim.log(f"[CAR] the bootloader runs from RAM (0x{address:08X}, sp 0x{sp | 0x80000000:08X}): "
                     f"0x8FFF8000..0x8FFFFFFF show the flash again")


class DdrTraining:
    """The DDR controller's training status at 0xB803E08C.. and the pattern
    capture words at 0xB803E090.. (one 32-byte block per byte lane) the
    bootloader reads while it sweeps the delay taps of each lane
    (0xB803E02E + lane, 0xB803E082 + lane, 0xB803E034 / 38, applied with bit 7
    of 0xB803E03B / 3F): it keeps a setting when the status says locked and the
    captured words are its test patterns (bootloader 0x9FE00B20; lane 0 is
    compared against different words than the other lanes).  The simulator's
    RAM always reads back what was written, so the model is the answers only."""
    STATUS = 0x3E08C            # bits 8..0 = 2 * delay taps, bits 31..30 = locked
    CAPTURE = 0x3E090           # + lane * 0x20 + word * 4
    LANES = 4
    TAPS = 32
    PATTERNS_LANE0 = (0x0FF00FF0, 0xFF00FF00, 0x00FF00FF, 0xF00FF00F,
                      0x0FF00FF0, 0x00FF00FF, 0xFF00FF00, 0x0FF00FF0)
    PATTERNS_OTHER = (0xA55AA55A, 0xFF00FF00, 0x00FF00FF, 0x5AA55AA5,
                      0xA55AA55A, 0x00FF00FF, 0xFF00FF00, 0xA55AA55A)

    def __init__(self, sim):
        self.sim = sim
        sim._mmio_on('r', self._read_status, self.STATUS, self.STATUS + 3)
        sim._mmio_on('r', self._read_capture, self.CAPTURE, self.CAPTURE + self.LANES * 0x20 - 1)

    def _read_status(self, uc, access, address, size, value, user_data):
        word = 0xC0000000 | (2 * self.TAPS)
        uc.mem_write(0xB8000000 + self.STATUS, word.to_bytes(4, 'little'))

    def _read_capture(self, uc, access, address, size, value, user_data):
        off = (address & 0xFFFFFF) - self.CAPTURE
        lane, word = off >> 5, (off & 0x1F) >> 2
        patterns = self.PATTERNS_LANE0 if lane == 0 else self.PATTERNS_OTHER
        uc.mem_write(address & ~3, patterns[word].to_bytes(4, 'little'))


class SpiStream:
    """The byte-stream mode of the M3821's SPI flash controller (base
    0xB802E000), which the application's flash driver uses for everything but
    memory-mapped reads.  With bits 26..25 of the register at +0xC8 set (the
    application sets and clears 26..24, the 2023 bootloader keeps 24) the
    controller holds the chip select and the flash window becomes a byte
    stream: every store clocks its bytes out to the part (the command, then
    address and data bytes), every load clocks reply bytes in, and clearing
    the bits ends the transaction (a program or erase takes effect then).
    Transfers of 256 bytes and more go through the controller's DMA engine:
    the RAM address at +0x58, the length at +0x60, a control word at +0x64
    whose write starts it (bit 7: RAM to part, else part to RAM), and bit 0
    of the status at +0xA0 (write 1 to clear) once it is done.  SF_INS / FMT /
    DUM / CFG stay in normal read mode throughout, so the simulator's flash
    window hooks defer to this stream while it is on (simulator._spi_stream)."""
    MODE, MODE_BITS = 0x2E0C8, 0x06000000      # (the 2023 bootloader leaves bit 24 set between transactions)
    DMA_ADDR, DMA_LEN, DMA_CTRL, DMA_STATUS = 0x2E058, 0x2E060, 0x2E064, 0x2E0A0
    DMA_TO_PART = 0x80
    # commands with 3 address bytes -> dummy bytes between the address and the data
    ADDRESSED = {0x03: 0, 0x0B: 1, 0x3B: 1, 0x6B: 1, 0x02: 0, 0x32: 0, 0x20: 0, 0x52: 0, 0xD8: 0}
    READS = (0x03, 0x0B, 0x3B, 0x6B)

    def __init__(self, sim):
        self.sim = sim
        self.active = False
        self.dma_done = False
        self._reset()
        sim._mmio_on('w', self._write_mode, self.MODE, self.MODE + 3)
        sim._mmio_on('w', self._write_dma_ctrl, self.DMA_CTRL, self.DMA_CTRL + 3)
        sim._mmio_on('w', self._write_dma_status, self.DMA_STATUS, self.DMA_STATUS + 3)
        sim._mmio_on('r', self._read_dma_status, self.DMA_STATUS, self.DMA_STATUS + 3)
        sim._spi_stream = self

    def _reset(self):
        self.tx = bytearray()       # what went out so far
        self.rx = 0                 # how much came in so far

    def _parse(self):
        """(command, flash address, data bytes) of the transaction so far."""
        if not self.tx:
            return None, 0, b""
        cmd = self.tx[0]
        dummy = self.ADDRESSED.get(cmd)
        if dummy is None:
            return cmd, 0, bytes(self.tx[1:])
        return cmd, int.from_bytes(self.tx[1:4], 'big'), bytes(self.tx[4 + dummy:])

    def write(self, data):
        """Bytes the firmware clocks out: a store to the window or a DMA from RAM."""
        self.tx += data

    def read(self, n):
        """The next n bytes the part clocks in: flash contents from the address
        of a read command, the reply to an ID / status command, else idle."""
        cmd, addr, _ = self._parse()
        start, self.rx = self.rx, self.rx + n
        if cmd in self.READS:
            rom, size = self.sim.rom_image, self.sim.rom_size
            first = (addr + start) % size
            if first + n <= size:
                return bytes(rom[first:first + n])
            return bytes(rom[(first + i) % size] for i in range(n))
        reply = self.sim._spi_command_response(cmd) if cmd is not None else []
        return bytes(reply[i] if i < len(reply) else 0x00 for i in range(start, start + n))

    def _end(self):
        cmd, addr, data = self._parse()
        if cmd is not None:
            self.sim._spi_log(f"STREAM 0x{cmd:02X} ({self.sim._SPI_CMD_NAMES.get(cmd, 'Unknown')})"
                              f" @ 0x{addr:06X}: {len(data)} B out, {self.rx} B in")
            if cmd not in self.READS:
                self.sim._spi_execute(cmd, addr, data)
        self._reset()

    def _write_mode(self, uc, access, address, size, value, user_data):
        # The register as the store leaves it: the application writes the word, the
        # 2023 bootloader only its top byte.
        shift = 8 * (address & 3)
        mask = ((1 << (8 * size)) - 1) << shift
        word = int.from_bytes(uc.mem_read(0xB8000000 + self.MODE, 4), 'little') & ~mask | (value << shift) & mask
        on = bool(word & self.MODE_BITS)
        if on == self.active:
            return                  # (also the replay of this store after the hook change below)
        self.active = on
        if on:
            self._reset()
        else:
            self._end()
        self.sim._update_flash_read_hooks()     # the window's hooks follow the mode

    def _write_dma_ctrl(self, uc, access, address, size, value, user_data):
        sim = self.sim
        if not value or sim._dev_replay_of(uc, 'spi_dma', address, value) is not None:
            return                  # cleared after a transfer, or this store replayed after a stop at it
        sim._dev_note(uc, 'spi_dma', address, value)
        ram = 0x80000000 + (int.from_bytes(sim.peek(0xB8000000 + self.DMA_ADDR, 4), 'little') & 0x1FFFFFFF)
        length = int.from_bytes(sim.peek(0xB8000000 + self.DMA_LEN, 4), 'little')
        if value & self.DMA_TO_PART:
            self.write(bytes(sim.mu.mem_read(ram, length)))
        else:
            sim.mu.mem_write(ram, self.read(length))
        self.dma_done = True

    def _write_dma_status(self, uc, access, address, size, value, user_data):
        if value & 1:
            self.dma_done = False

    def _read_dma_status(self, uc, access, address, size, value, user_data):
        uc.mem_write(0xB8000000 + self.DMA_STATUS, int(self.dma_done).to_bytes(4, 'little'))


class DmaRings:
    """The 8-channel descriptor-ring DMA engine at 0xB800F000 the firmware's
    large memory copies go through.  Per channel: the ring's physical base at
    +0x00 + 4 * ch (16-byte descriptors: source, destination, flags | length - 1,
    0), its length minus one at +0x20 + ch, the ring index after the last
    descriptor submitted written to +0x28 + ch, and the index the engine has
    reached read back from +0x30 + ch, which the firmware polls (with 100 us
    delays) until it equals what it submitted; +0x48 / +0x4A hold the channels'
    enable bits.  (The block the M3801 SDK calls VCAP_M36F: bit 0 of its +0x4B
    is the self-clearing reset the simulator answers for every chip,
    _SELF_COMPLETING.)  The simulator copies a descriptor's bytes the moment it
    is submitted."""
    BASE = 0xF000
    RING, RING_LEN, SUBMIT, DONE = 0x00, 0x20, 0x28, 0x30
    CHANNELS = 8

    def __init__(self, sim):
        self.sim = sim
        self.done = [0] * self.CHANNELS
        self.submissions = 0            # logged ones
        b = self.BASE
        sim._mmio_on('w', self._write_submit, b + self.SUBMIT, b + self.SUBMIT + self.CHANNELS - 1)
        sim._mmio_on('r', self._read_done, b + self.DONE, b + self.DONE + self.CHANNELS - 1)

    def _reg(self, offset, size):
        return int.from_bytes(self.sim.peek(0xB8000000 + self.BASE + offset, size), 'little')

    def _write_submit(self, uc, access, address, size, value, user_data):
        sim = self.sim
        for i in range(size):                       # (a word write submits to several channels)
            ch = (address & 0xFFFFFF) - self.BASE - self.SUBMIT + i
            if not 0 <= ch < self.CHANNELS:
                continue
            count = (value >> (8 * i)) & 0xFF
            ring = self._reg(self.RING + 4 * ch, 4) & 0x0FFFFFF0
            length = self._reg(self.RING_LEN + ch, 1) + 1
            while self.done[ch] != count:
                desc = sim.peek(0x80000000 + ring + 16 * (self.done[ch] % length), 16)
                src, dst, word = (int.from_bytes(desc[o:o + 4], 'little') for o in (0, 4, 8))
                src, dst, n = src & 0x0FFFFFFF, dst & 0x0FFFFFFF, (word & 0x1FFFFFFF) + 1
                ok = max(src, dst) + n <= sim.ram_size
                if self.submissions < 16:
                    self.submissions += 1
                    sim.log(f"[DMA] ch{ch} #{self.done[ch]}: 0x{src:08X} -> 0x{dst:08X}, {n} bytes (ring 0x{ring:08X} x{length})"
                            + ("" if ok else " -- outside RAM, skipped"))
                if ok:
                    sim.mu.mem_write(0x80000000 + dst, bytes(sim.mu.mem_read(0x80000000 + src, n)))
                self.done[ch] = (self.done[ch] + 1) & 0xFF

    def _read_done(self, uc, access, address, size, value, user_data):
        ch = (address & 0xFFFFFF) - self.BASE - self.DONE
        uc.mem_write(address, bytes(self.done[ch:ch + size]))


class MirrorRegisters:
    """Status registers that follow another register at once: the hardware
    has consumed everything the firmware queued.  The sound engine at
    0xB8002000 streams PCM from a ring in RAM (base +0x30, size +0x34): the
    firmware fills it (silence at boot, through the DMA rings), writes the
    write index to +0x38 and waits until the read index at +0x3A catches up.
    {register offset: (register it mirrors, size in bytes)}."""
    def __init__(self, sim, mirrors):
        self.mirrors = mirrors
        for offset, (_source, size) in mirrors.items():
            sim._mmio_on('r', self._read, offset, offset + size - 1)

    def _read(self, uc, access, address, size, value, user_data):
        offset = address & 0xFFFFFF
        for target, (source, n) in self.mirrors.items():
            if target <= offset < target + n:
                uc.mem_write(0xB8000000 + target, bytes(uc.mem_read(0xB8000000 + source, n)))


class Demodulator:
    """The chip's own DVB-T / T2 demodulator ("NIM_S3821_0"), registers memory-
    mapped at 0xB804C000 + register (the nim_device's base address).  Its
    get_lock() (R265 Lite 1.1.5, 0x804B3558) reads the standard from the upper
    nibble of register 0x2FF (written by the driver, so RAM keeps it) and then,
    for DVB-T (1, 2), tests bit 6 of register 0x1D (0x804B34CC); for DVB-T2
    (4) it wants the low nibble of register 0x67 at 0xA or above and, from the
    two bytes at 0x11D, the second below the first minus one (0x804B33DC).
    With `signal` on those registers read that way."""
    BASE = 0x4C000
    LOCK = {0x01D: lambda v: v | 0x40,            # DVB-T locked
            0x067: lambda v: (v & 0xF0) | 0x0F,    # DVB-T2 state machine: locked
            0x11D: lambda v: 0x20,
            0x11E: lambda v: 0x00}

    def __init__(self, sim):
        self.signal = False
        self.lock_reads = 0
        for reg in self.LOCK:
            sim._mmio_on('r', self._read, self.BASE + reg, self.BASE + reg)

    def _read(self, uc, access, address, size, value, user_data):
        self.lock_reads += 1
        if not self.signal:
            return
        start = (address & 0xFFFFFF) - self.BASE
        data = bytearray(uc.mem_read(address, size))
        for i in range(size):
            f = self.LOCK.get(start + i)
            if f:
                data[i] = f(data[i]) & 0xFF
        uc.mem_write(address, bytes(data))


class ReadyBits:
    """Status bits the application polls (with 100 us delays) until the hardware
    reports ready, which the simulator's hardware is at once: register offset in
    the device window -> the bits that always read as set."""
    def __init__(self, sim, bits):
        self.bits = bits
        for offset in bits:
            sim._mmio_on('r', self._read, offset, offset)

    def _read(self, uc, access, address, size, value, user_data):
        offset = address & 0xFFFFFF
        byte = uc.mem_read(address, 1)[0] | self.bits[offset]
        uc.mem_write(address, bytes([byte]))


class M3821(ChipFamily):
    name = "M3821"
    chip_id = 0x3821
    chip_variant = 0x0010       # the M3822P: the application's chip-ID function wants
                                # (word & 0xFFFF00F0) == 0x38210010, else it reboots

    @classmethod
    def matches(cls, image):
        if bytes(image[0x20:0x25]) == b"M3821":         # the bootloader chunk's version string
            return True
        return (xip_bootloader(image) and any(name == "seecode" for _o, name, _v in chunk_chain(image))
                and b"NIM_S3821" in maincode(image))

    def install(self):
        sim = self.sim
        self.xip = xip_bootloader(sim.rom_image)       # (the C3505's is the boot ROM's kind too)
        if self.xip:
            self.chip_variant = 0x0000  # the T750i's plain M3821
        super().install()
        # (count_hz stays at the simulator's 100 MHz although the chip's Count runs at
        # 297 MHz: at the real rate the kernel's 1 ms tick is shorter than the host time
        # its hooked CP0 instructions take, and the next tick lands inside its task
        # switch -- between its Count reset and Compare write -- which wedges it.  The
        # application's time therefore runs at a third of real time.)
        # The boot SRAM, in place of the flash mirror the M3801 shows there
        self.sram = ctypes.create_string_buffer(SRAM_SIZE)
        ptr = ctypes.addressof(self.sram)
        for seg in (0x00000000, 0x80000000, 0xA0000000):
            sim.mu.mem_unmap(seg + SRAM_PHYS, SRAM_SIZE)
            sim.mu.mem_map_ptr(seg + SRAM_PHYS, SRAM_SIZE, UC_PROT_ALL, ptr)
        self.ddr = DdrTraining(sim)
        self.spi = SpiStream(sim)
        self.dma = DmaRings(sim)
        self.demod = Demodulator(sim)
        self.ready = ReadyBits(sim, {
            0x000633: 0x80,     # the PLL at 0xB8000600..: locked (polled after it is programmed)
        })
        self.mirrors = MirrorRegisters(sim, {
            0x00203A: (0x002038, 2),    # the sound engine's read index has caught up with the write index
        })
        # Start bits the application sets and then waits to see cleared (the simulator's
        # _SELF_COMPLETING mechanism): bit 4 of +0x6F of the block at 0xB802A000 (most likely
        # the HDMI transmitter: both firmwares set it up at start and poll +0x08 bit 0 like a
        # hot-plug line), whose +0x6F firmware 1.2.0 spins on before it draws anything --
        # probably a DDC transfer of the TV's EDID (288 more operations at +0x70 / +0x72).
        sim._SELF_COMPLETING = {**sim._SELF_COMPLETING, 0x2A06F: (0x10, 0x00, 0x10)}
        sim._mmio_on('r', sim._hook_selfcomplete_read, 0x2A06C, 0x2A06F)
        if self.xip:
            self.car = CacheAsRam(sim)
            self.see = SeeStart(sim)

    def start(self):
        """What the boot ROM does: the bootloader area into the SRAM, enter it
        (an XIP bootloader starts at the flash window, like the M3801's)."""
        sim = self.sim
        if self.xip:
            sim.mu.reg_write(UC_MIPS_REG_PC, sim.base_addr)
            return
        ctypes.memmove(ctypes.addressof(self.sram), bytes(sim.rom_image[:BOOT_COPY]), BOOT_COPY)
        sim._rescan_cp0_sites(self.code_ranges())
        sim.mu.reg_write(UC_MIPS_REG_PC, ENTRY)

    def code_ranges(self):
        return [] if self.xip else [(0x80000000 + SRAM_PHYS, BOOT_COPY)]

    def set_signal(self, on):
        self.demod.signal = bool(on)
        return True
