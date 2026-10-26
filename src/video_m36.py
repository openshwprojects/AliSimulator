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
    what they had.  The chip's device reset (on the M36xx bit 1 of
    0xB8000080, `reset`) puts the VLD's offset back to 0 and drops the
    status: the S60's driver (0x802BF284) pulses it at a channel change and
    then reads +0x228 as a status word, taking its fatal path -- a reboot
    into the bootloader -- if any of bits 8..25 is set; a bit offset left
    from the last picture had them set, and the box started over a few
    seconds after a key in 7 of 11 runs of its screen regression.
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
                enables = int.from_bytes(core.peek(core._ic_en + 4 * (line // 32), 4), 'little')
                on_here = bool(enables >> (line % 32) & 1)
            else:
                on_here = False
            if on_here or core._ic_lines >> line & 1:
                core._ic_set_line(line, on_here)


# MPEG-2 Table B.12 (luma) and B.13 (chroma) DCT DC size VLCs: (code, bit_length) -> size
_DC_LUMA_VLC = {
    (0b100, 3): 0, (0b00, 2): 1, (0b01, 2): 2, (0b101, 3): 3, (0b110, 3): 4,
    (0b1110, 4): 5, (0b11110, 5): 6, (0b111110, 6): 7, (0b1111110, 7): 8,
    (0b11111110, 8): 9, (0b111111110, 9): 10, (0b111111111, 9): 11,
}
_DC_CHROMA_VLC = {
    (0b00, 2): 0, (0b01, 2): 1, (0b10, 2): 2, (0b110, 3): 3, (0b1110, 4): 4,
    (0b11110, 5): 5, (0b111110, 6): 6, (0b1111110, 7): 7, (0b11111110, 8): 8,
    (0b111111110, 9): 9, (0b1111111110, 10): 10, (0b1111111111, 10): 11,
}


class _BitReader:
    def __init__(self, data):
        self.data = data
        self.bit_pos = 0
        self.total_bits = len(data) * 8

    def read(self, n):
        if self.bit_pos + n > self.total_bits:
            raise EOFError
        val = 0
        for _ in range(n):
            b = self.data[self.bit_pos >> 3]
            val = (val << 1) | ((b >> (7 - (self.bit_pos & 7))) & 1)
            self.bit_pos += 1
        return val

    def read_vlc(self, table, max_len=10):
        code = 0
        for length in range(1, max_len + 1):
            code = (code << 1) | self.read(1)
            if (code, length) in table:
                return table[(code, length)]
        raise ValueError("invalid VLC")

    def read_dc_diff(self, table):
        size = self.read_vlc(table)
        if size == 0:
            return 0
        half = 1 << (size - 1)
        val = self.read(size)
        return val if val >= half else val - ((1 << size) - 1)


def encode_dc_iframe_slices(y_mb, cb_mb=128, cr_mb=128, quant_scale=8):
    """Build a valid MPEG-2 intra slice bitstream (start codes 00 00 01 01..mb_h)
    with pure-DC 8x8 blocks (Table B.12/B.13 + EOB '10') for testing and
    synthetic video frames.  y_mb is a 2D sequence (mb_h, mb_w) of luma values
    0..255 (or 4-tuples of 8x8 sub-block luma values); cb_mb / cr_mb are scalar
    or 2D (mb_h, mb_w) chroma values."""
    luma_inv = {sz: (code, ln) for (code, ln), sz in _DC_LUMA_VLC.items()}
    chroma_inv = {sz: (code, ln) for (code, ln), sz in _DC_CHROMA_VLC.items()}

    def put_bits(buf, acc, n_acc, val, n):
        acc = (acc << n) | (val & ((1 << n) - 1))
        n_acc += n
        while n_acc >= 8:
            n_acc -= 8
            buf.append((acc >> n_acc) & 0xFF)
        return acc, n_acc

    def put_dc(buf, acc, n_acc, diff, inv_table):
        diff = int(round(diff))
        if diff == 0:
            code, ln = inv_table[0]
            return put_bits(buf, acc, n_acc, code, ln)
        mag = abs(diff)
        sz = mag.bit_length()
        code, ln = inv_table[sz]
        acc, n_acc = put_bits(buf, acc, n_acc, code, ln)
        val = diff if diff > 0 else ((1 << sz) - 1 + diff)
        return put_bits(buf, acc, n_acc, val, sz)

    out = bytearray()
    mb_h = len(y_mb)
    mb_w = len(y_mb[0]) if mb_h else 0
    for row in range(mb_h):
        out += bytes((0x00, 0x00, 0x01, (row + 1) & 0xFF))
        acc, n_acc = 0, 0
        acc, n_acc = put_bits(out, acc, n_acc, quant_scale & 0x1F, 5)
        acc, n_acc = put_bits(out, acc, n_acc, 0, 1)    # extra_bit_slice = 0
        pred_y = pred_cb = pred_cr = 128
        for col in range(mb_w):
            # macroblock_address_increment = 1 ('1'), macroblock_type = Intra ('1'), dct_type = 0 ('0' frame)
            acc, n_acc = put_bits(out, acc, n_acc, 0b11, 2)
            cell = y_mb[row][col]
            ys = cell if isinstance(cell, (tuple, list)) else (cell, cell, cell, cell)
            for y_val in ys:
                q_y = max(0, min(255, int(round(y_val)))) // 8 * 8
                acc, n_acc = put_dc(out, acc, n_acc, (q_y - pred_y) // 8, luma_inv)
                acc, n_acc = put_bits(out, acc, n_acc, 0b10, 2)     # EOB
                pred_y = q_y
            cb_val = cb_mb[row][col] if isinstance(cb_mb, (tuple, list)) else cb_mb
            cr_val = cr_mb[row][col] if isinstance(cr_mb, (tuple, list)) else cr_mb
            q_cb = max(0, min(255, int(round(cb_val)))) // 8 * 8
            q_cr = max(0, min(255, int(round(cr_val)))) // 8 * 8
            acc, n_acc = put_dc(out, acc, n_acc, (q_cb - pred_cb) // 8, chroma_inv)
            acc, n_acc = put_bits(out, acc, n_acc, 0b10, 2)         # EOB
            pred_cb = q_cb
            acc, n_acc = put_dc(out, acc, n_acc, (q_cr - pred_cr) // 8, chroma_inv)
            acc, n_acc = put_bits(out, acc, n_acc, 0b10, 2)         # EOB
            pred_cr = q_cr
        if n_acc > 0:
            out.append((acc << (8 - n_acc)) & 0xFF)
    out += b"\x00\x00\x01\x00"
    return bytes(out)


def decode_mpeg2_slices(data, mb_width, mb_height):
    """Decode an MPEG-2 intra slice buffer into an RGB uint8 array
    (mb_height * 16, mb_width * 16, 3).  Parses each slice start code
    00 00 01 01..AF, decodes pure-DC intra macroblock VLCs (Table B.12 / B.13)
    when present, and falls back per slice row to a deterministic bitstream
    reconstruction when full AC VLCs are encountered."""
    import numpy as np
    if mb_width <= 0 or mb_height <= 0:
        return None
    H, W = mb_height * 16, mb_width * 16
    y_plane = np.full((H, W), 16.0, dtype=np.float32)
    cb_plane = np.full((H, W), 128.0, dtype=np.float32)
    cr_plane = np.full((H, W), 128.0, dtype=np.float32)

    pos = data.find(b"\x00\x00\x01")
    while 0 <= pos <= len(data) - 4:
        code = data[pos + 3]
        nxt = data.find(b"\x00\x00\x01", pos + 3)
        end = nxt if nxt >= 0 else len(data)
        if 1 <= code <= mb_height:
            row = code - 1
            payload = data[pos + 4:end]
            y0 = row * 16
            decoded_cols = 0
            if payload:
                try:
                    br = _BitReader(payload)
                    _q_scale = br.read(5)
                    while br.read(1):
                        br.read(8)
                    pred_y = pred_cb = pred_cr = 128
                    for col in range(mb_width):
                        if br.read(1) != 1:             # macroblock_address_increment == 1
                            break
                        mb_type_1 = br.read(1)
                        if mb_type_1 == 0:
                            if br.read(1) != 1:
                                break
                            _q_scale = br.read(5)
                        ys = []
                        ok = True
                        for _ in range(4):
                            diff = br.read_dc_diff(_DC_LUMA_VLC)
                            if br.read(2) != 0b10:      # EOB
                                ok = False
                                break
                            pred_y = max(0, min(255, pred_y + diff * 8))
                            ys.append(pred_y)
                        if not ok:
                            break
                        diff_cb = br.read_dc_diff(_DC_CHROMA_VLC)
                        if br.read(2) != 0b10:
                            break
                        pred_cb = max(0, min(255, pred_cb + diff_cb * 8))
                        diff_cr = br.read_dc_diff(_DC_CHROMA_VLC)
                        if br.read(2) != 0b10:
                            break
                        pred_cr = max(0, min(255, pred_cr + diff_cr * 8))
                        x0 = col * 16
                        y_plane[y0:y0 + 8, x0:x0 + 8] = ys[0]
                        y_plane[y0:y0 + 8, x0 + 8:x0 + 16] = ys[1]
                        y_plane[y0 + 8:y0 + 16, x0:x0 + 8] = ys[2]
                        y_plane[y0 + 8:y0 + 16, x0 + 8:x0 + 16] = ys[3]
                        cb_plane[y0:y0 + 16, x0:x0 + 16] = pred_cb
                        cr_plane[y0:y0 + 16, x0:x0 + 16] = pred_cr
                        decoded_cols += 1
                except (EOFError, ValueError):
                    pass
                if decoded_cols < mb_width:
                    raw = np.frombuffer(payload, dtype=np.uint8)
                    for col in range(decoded_cols, mb_width):
                        chunk = raw[col * len(raw) // mb_width:(col + 1) * len(raw) // mb_width]
                        if len(chunk) == 0:
                            chunk = raw
                        x0 = col * 16
                        y_plane[y0:y0 + 16, x0:x0 + 16] = 32.0 + float(chunk.mean()) * 0.75
                        cb_plane[y0:y0 + 16, x0:x0 + 16] = 96.0 + float(int(chunk[0]) & 0x3F)
                        cr_plane[y0:y0 + 16, x0:x0 + 16] = 96.0 + float(int(chunk[-1]) & 0x3F)
        pos = nxt

    cb = cb_plane - 128.0
    cr = cr_plane - 128.0
    r = np.clip(y_plane + 1.402 * cr + 0.5, 0, 255).astype(np.uint8)
    g = np.clip(y_plane - 0.344136 * cb - 0.714136 * cr + 0.5, 0, 255).astype(np.uint8)
    b = np.clip(y_plane + 1.772 * cb + 0.5, 0, 255).astype(np.uint8)
    return np.stack((r, g, b), axis=-1)


class VideoEngine(_Device):
    def __init__(self, sim, line=VE_LINE, reset=None):
        self.line = line                # (the M3329's DECV_M3327 is the same engine on line 9)
        self.reset = reset              # (device-reset register offset, the engine's bit) or None
        self.status = 0
        self.pictures = 0
        self.resets = 0
        self.last_picture = None
        super().__init__(sim)

    def wire(self, core):
        core._mmio_on('w', self._write_start, 0x4214, 0x4217)
        core._mmio_on('w', self._write_status, 0x4218, 0x421B)
        if self.reset is not None:
            core._mmio_on('w', self._write_reset, self.reset[0], self.reset[0] + 3)

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
        mb_w, mb_h = (size >> 8) & 0xFF, size & 0xFF
        self._wr(VE_MBS, mb_w * mb_h)
        self._advance_vld(mb_w, mb_h)
        self.status |= 1
        self._wr(VE_STATUS, self.status)
        self._set_line(self.line, True)

    def _advance_vld(self, mb_w=0, mb_h=0):
        """The VLD's bit offset on at the end of the picture's slices."""
        start, avail = self._rd(VE_VLD_BITS), self._rd(VE_VLD_AVAIL)
        end_byte = (start + avail) // 8
        reg = self._rd(VE_BUFFER)
        buffer = 0x80000000 | (reg >> 3 & 0x0F000000) | (reg & 0x00FFFFFF)
        try:
            data = bytes(self.sim.mu.mem_read(buffer, end_byte + 4))
        except Exception:
            return
        slice_start = start // 8
        i = data.find(b"\x00\x00\x01", slice_start)
        slices = 0
        while 0 <= i < end_byte and 0x01 <= data[i + 3] <= 0xAF:
            slices += 1
            i = data.find(b"\x00\x00\x01", i + 3)
        end_pos = i if 0 <= i < end_byte else end_byte
        bit_end = end_pos * 8 if 0 <= i < end_byte else start + avail
        self.last_picture = {
            "width": mb_w * 16,
            "height": mb_h * 16,
            "mb_width": mb_w,
            "mb_height": mb_h,
            "buffer": buffer,
            "bit_start": start,
            "bit_end": bit_end,
            "slice_count": slices,
            "data": data[slice_start:end_pos],
        }
        self._wr(VE_VLD_BITS, bit_end)

    def decode_last_frame(self):
        """Decode the last picture's MPEG-2 slices into an (H, W, 3) uint8 RGB
        array, or None if no picture has been decoded yet."""
        pic = self.last_picture
        if not pic or not pic["mb_width"] or not pic["mb_height"]:
            return None
        return decode_mpeg2_slices(pic["data"], pic["mb_width"], pic["mb_height"])

    def _write_status(self, uc, access, address, size, value, user_data):
        base, word, shift, mask = _merge(uc, address, size, value)
        written = (value << shift) & mask
        self.status &= ~written
        if not self.status:
            self._set_line(self.line, False)
        return (self.status & mask) >> shift

    def _write_reset(self, uc, access, address, size, value, user_data):
        """The chip's device-reset register: the engine's bit set puts it in
        reset -- its VLD bit offset back to 0, no status pending."""
        if (value << (address & 3) * 8) & self.reset[1]:
            self.resets += 1
            self._wr(VE_VLD_BITS, 0)
            if self.status:
                self.status = 0
                self._wr(VE_STATUS, 0)
                self._set_line(self.line, False)
        return None


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

    def due(self):
        """The emulation time the service is next needed at (its next field start
        or half-field): an engine whose slices can outlast a field ends one there
        (the C++ engine's; the Unicorn engine's end at every timer tick anyway)."""
        if self._next is None:
            return None
        return self._next if self._mid is None else min(self._next, self._mid)

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
