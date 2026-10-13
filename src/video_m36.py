"""
The M36xx's MPEG video engine and its video output's interrupt, as far as a
firmware's boot logo needs them: the M3601E boxes (Cabletech URZ0083,
Kruger&Matz KM0183, Thomson THT501) decode a logo from the flash before
anything else and wait until their decoder reports its first picture shown.

  * Video engine (vdec_s3601's VE, 0xB8004200).  The driver parses a
    picture's headers itself and programs the engine -- the quantiser
    tables, the stream buffer (+0x224: address bits 0..23 in its bits 0..23,
    bits 24..27 in its bits 27..30 -- 0x1550DE00 is the URZ0083's logo at
    0x0250DE00, 0x3DCD3F00 the URZ0086's at 0x07CD3F00), the VLD's bit
    offset (+0x228, at the first slice) and the bits it may read from there
    (+0x22C), the frame buffers
    through +0x2E0 / +0x2E4 -- then starts it: the low nibble of +0x214.
    The model finishes the picture at once: status +0x218 bit 0 (write 1 to
    clear; interrupt-controller line 1 while a status bit is set), +0x220
    the macroblocks decoded (+0x208: width and height in macroblocks), and
    the VLD's offset on at the next start code that is not a slice's (00 00
    01 01..AF) within the bits it was given -- the driver takes its buffer's
    read pointer from there.  No picture is decoded: the frame buffers keep
    what they had.
  * Video output's interrupt (VPO_S3602F_HD, 0xB8006004): enables in bits
    0..5, status in bits 8..13 (write 1 to clear), the field the output is
    in at bit 18; interrupt-controller line 2 while an enabled status bit is
    set.  Every 20 ms of emulation time (a 50 Hz field) the model sets bits
    2 (vertical blank) and 4 (field start) and flips the field.  The
    driver's blank handler asks the decoder for its display state; its field
    handler, which goes on only when the field changed, requests and
    releases the decoder's frames -- and the decoder's first frame request
    sets "first picture shown".  With the field bit standing still the
    handler never moved on and the URZ0083 waited for its logo for ever.
    Half a field after each field start the model sets status bit 0, which
    no driver here enables: the Ferguson T50's polls it before it
    reprograms the output for its TV system (0x80283B70) and spun on it for
    ever without it -- set at the field start, its interrupt handler, which
    clears every status bit it finds, took it first.
  * The SD output's (the DEO, 0xB8020004) is the same but for the field,
    which its driver reads at bit 19, on interrupt-controller line 15 (OS
    IRQ 23).  The T50 drives an HD and an SD output, and its decoder, in
    that dual-output mode (+0xB44 of its private data = 8), reports the
    first picture shown only once the SD output's field handler has asked
    for the frame too (a request whose src_path is not 0), which it does
    when the field it reads has changed: without the DEO's interrupts and
    its field, its OSD driver waited for its logo for ever and the UI drew
    nothing.
"""
import struct

VE = 0xB8004200
VE_START, VE_STATUS, VE_MBS = 0x14, 0x18, 0x20
VE_SIZE_MB = 0x08                       # width << 8 | height, in macroblocks
VE_BUFFER, VE_VLD_BITS, VE_VLD_AVAIL = 0x24, 0x28, 0x2C
VE_LINE = 1                             # interrupt-controller line (OS IRQ 9)

VPO_INT = 0xB8006004
VPO_LINE = 2                            # interrupt-controller line (OS IRQ 10)
DEO_INT = 0xB8020004                    # the SD output's
DEO_LINE = 15                           # (OS IRQ 23)
VPO_MID_FIELD, VPO_BLANK, VPO_FIELD_START = 0x01, 0x04, 0x10
VPO_FIELD_BIT = 1 << 18
DEO_FIELD_BIT = 1 << 19
FIELD_S = 0.02                          # 50 Hz fields


def _merge(uc, address, size, value):
    """(word address, the register word with this store applied, shift, mask of the stored bytes)."""
    base = address & ~3
    shift = (address & 3) * 8
    mask = ((1 << (size * 8)) - 1) << shift
    word = int.from_bytes(uc.mem_read(base, 4), 'little')
    return base, (word & ~mask) | ((value << shift) & mask), shift, mask


class _Device:
    """What both models share: their register handlers on every core that drives the device (the
    M3606's SEE runs the video drivers: chips/m3602.py core_devices, see.SeeStart._wire) and their
    interrupt raised on the cores whose interrupt controller has the line enabled -- a pending
    line nobody enabled sent the URZ0086's main CPU into its fatal path ("eis: 0x4")."""

    def __init__(self, sim):
        self.sim = sim
        self.wire(sim)

    def _cores(self):
        cores = [self.sim]
        see = getattr(self.sim.chip, "see", None)
        core = getattr(getattr(see, "core", None), "core", None)
        if core is not None:
            cores.append(core)
        return cores

    def _set_line(self, line, on):
        for core in self._cores():
            if on:
                enables = int.from_bytes(core.peek(core._ic + 8 + 4 * (line // 32), 4), 'little')
                on_here = bool(enables >> (line % 32) & 1)
            else:
                on_here = False
            if on_here or core._ic_lines >> line & 1:
                core._ic_set_line(line, on_here)


class VideoEngine(_Device):
    def __init__(self, sim):
        self.status = 0
        self.pictures = 0
        super().__init__(sim)

    def wire(self, core):
        core._mmio_on('w', self._write_start, 0x4214, 0x4217)
        core._mmio_on('w', self._write_status, 0x4218, 0x421B)

    def _rd(self, offset):
        return int.from_bytes(self.sim.peek(VE + offset, 4), 'little')

    def _wr(self, offset, value):
        self.sim.poke(VE + offset, struct.pack("<I", value & 0xFFFFFFFF))

    def _write_start(self, uc, access, address, size, value, user_data):
        base, word, shift, mask = _merge(uc, address, size, value)
        if not word & 0xF:
            return None
        self.pictures += 1
        self._decode()
        return ((word & ~0xF) & mask) >> shift          # the start bits clear themselves

    def _decode(self):
        size = self._rd(VE_SIZE_MB)
        self._wr(VE_MBS, ((size >> 8) & 0xFF) * (size & 0xFF))
        self._advance_vld()
        self.status |= 1
        self._wr(VE_STATUS, self.status)
        self._set_line(VE_LINE, True)

    def _advance_vld(self):
        """The VLD's bit offset on at the end of the picture's slices."""
        start, avail = self._rd(VE_VLD_BITS), self._rd(VE_VLD_AVAIL)
        end_byte = (start + avail) // 8
        reg = self._rd(VE_BUFFER)
        buffer = 0x80000000 | (reg >> 3 & 0x0F000000) | (reg & 0x00FFFFFF)
        try:
            data = bytes(self.sim.mu.mem_read(buffer, end_byte + 4))
        except Exception:
            return
        i = data.find(b"\x00\x00\x01", start // 8)
        while 0 <= i < end_byte and 0x01 <= data[i + 3] <= 0xAF:
            i = data.find(b"\x00\x00\x01", i + 3)
        self._wr(VE_VLD_BITS, i * 8 if 0 <= i < end_byte else start + avail)

    def _write_status(self, uc, access, address, size, value, user_data):
        base, word, shift, mask = _merge(uc, address, size, value)
        written = (value << shift) & mask
        self.status &= ~written
        if not self.status:
            self._set_line(VE_LINE, False)
        return (self.status & mask) >> shift


class VideoOutput(_Device):
    """A video output's interrupt register: the HD output's (VPO_INT, line VPO_LINE, VPO_FIELD_BIT) or the
    SD output's (DEO_INT, DEO_LINE, DEO_FIELD_BIT)."""

    def __init__(self, sim, register=VPO_INT, line=VPO_LINE, field_bit=VPO_FIELD_BIT):
        self.register, self.line, self.field_bit = register, line, field_bit
        self.status = 0                 # bits 0..5 of the status (register bits 8..13)
        self.field = 0
        self.fields = 0
        self._next = None
        self._mid = None                # when status bit 0 comes in this field
        super().__init__(sim)
        sim.slice_services.append(self.service)

    def wire(self, core):
        offset = self.register & 0xFFFFFF
        core._mmio_on('w', self._write, offset, offset + 3)

    def _word(self, enables_from=None):
        word = int.from_bytes(self.sim.peek(self.register, 4), 'little') if enables_from is None else enables_from
        return (word & ~0x3F00 & ~self.field_bit) | (self.status << 8) | (self.field and self.field_bit)

    def _line(self, word):
        self._set_line(self.line, bool(self.status & word & 0x3F))

    def _write(self, uc, access, address, size, value, user_data):
        base, word, shift, mask = _merge(uc, address, size, value)
        self.status &= ~(((value << shift) & mask) >> 8) & 0x3F
        landed = self._word(enables_from=word)
        self._line(landed)
        return (landed & mask) >> shift

    def service(self):
        """Between emulation slices: a field every FIELD_S of emulation time, status bit 0 half-way."""
        now = self.sim._vtime()
        if self._next is None:
            self._next = now + FIELD_S
        if self._mid is not None and now >= self._mid:
            self._mid = None
            self._post(VPO_MID_FIELD)
        if now < self._next:
            return
        self._next = now + FIELD_S
        self._mid = now + FIELD_S / 2
        self.fields += 1
        self.field ^= 1
        self._post(VPO_BLANK | VPO_FIELD_START)

    def _post(self, bits):
        self.status |= bits
        word = self._word()
        self.sim.poke(self.register, struct.pack("<I", word))
        self._line(word)
