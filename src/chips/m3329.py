"""
ALi M3329 (dumps/other/sat_main_ali3329-s15125_dump_eeprom_by_h2h_ok.bin: a
2005 satellite receiver board "s15125"), a chip of the M3327 platform: its
drivers are the SDK's NIM_M3327, DMX_M3327, DECV_M3327, VPO_M3327, SND_M3327
and OSD_M3327C, and its main code is stored unpacked in the flash: the
application runs in place, cached (0x8FC0B080..), its flash driver and other
code copied to RAM.

Its bootloader reads the chip's revision from the chip ID word: with a chip
ID in the upper half, the low byte -- 0x60 / 0x63, 0x70 / 0x30, 0xF0, 0xF1,
0xF2, 0xF3, others -- is revision 0x20001 .. 0x20007 (0xAFC00B68), and from
revision 0x20004 on it first calls a routine of the chip's boot ROM
(0xBFC0003D), which the simulator does not have: with the M3801's chip word
it jumped there and ended at PC 0.  The family's chip word reads revision
0xF0 (0x20003), the newest that boots from the flash alone.

The bootloader then sets up the SDRAM controller (0xB8000080): timings in
+0x82..+0x87, and commands in bits 0..1 of +0x80 -- 2 precharge, 3 refresh
(eight times), 1 the mode register --, each polled until those bits read 0
(0xAFC007F4).  The model completes a command at once.

Its UART is a 16550 at 0xB8001300.  Its flash is parallel NOR on an 8-bit
bus (parallel_flash.py): the application's flash driver probes it with the
AMD autoselect command and matches the IDs against its table of 41 parts
(0x8FC4ADAC, their sector maps at 0x8FC4AD58..); unidentified it set up no
database region and later read a null pointer's -4.  The model is an MXIC
MX29LV400B -- the bottom-boot 4 Mbit part the image's layout fits: a 16 KB
bootloader, the "userdb(64+64)" chunk in the last two 64 KB sectors.

Its interrupt controller has its status word at 0xB8000038 and its enables
at 0xB800003C (lines 0..16, on IP3: simulator.set_ic_layout).  The video
decoder (0xB8004200) and the video output's interrupt (0xB8004004: enables
bits 0..4, status bits 8..12) are the M36xx's (video_m36.py), both on line 9;
the IR receiver is the later chips' controller at 0xB8001100 on line 7.  Its
remote (the table at 0x8003E0CC: command byte and complement per key, the
customer code 0x205D from 0x8003B644) is NEC address 0x04 / 0xBA, received
most significant bit first.

The kernel ticks every 108000 Count cycles (0x8002F710): at the simulator's
100 MHz that is about a millisecond of emulation time, of which the tick
took most, so the application got a few thousand instructions per tick.
The family's Count runs at 10 MHz.

Recognised by the first chunk's ID, 0xE3000010 (every later image here has
0x23010010): the M3327 platform's chunk header, which is also the
bootloader's first instruction (a branch over the header).
"""
from collections import deque
import os
import struct

from .base import ChipFamily, ReadyBits, chunk_chain

BOOTLOADER_CHUNK_ID = 0xE3000010
SDRAM_CONTROL = 0x80                    # in the device window
UART = 0x1300
UART2, UART2_LINE = 0x1400, 6           # SCI_16550_1 (external front-panel / security MCU link)
IC_STATUS, IC_ENABLE = 0x38, 0x3C       # the interrupt controller: lines 0..16, on IP3
VIDEO_LINE = 9                          # the video decoder's and the video output's line
VPO_INT = 0xB8004004
IRC, IRC_LINE = 0x1100, 7               # the IR receiver
COUNT_HZ = 10_000_000
OSD_PALETTE_PORTS = (0x41AC, 0x41C8)    # OSD layer 0's / 1's palette port
# The remote: the application's key codes for the key names (its key table
# holds them with their IR codes), and where the table is: the panel /
# remote configuration at 0x8003B640 -- the table's address, the customer
# code in the upper half of +4, the number of entries at +0xE (the panel's
# first, then the remote's)
REMOTE_KEYS = {'LEFT': 0x0A, 'RIGHT': 0x0B, 'UP': 0x0C, 'DOWN': 0x0D, 'MENU': 0x0E,
               'OK': 0x0F, 'ENTER': 0x0F, 'EXIT': 0x10, 'BACK': 0x10, 'MUTE': 0x11,
               'POWER': 0x12, 'PAUSE': 0x13, 'TVRADIO': 0x14, 'AUDIO': 0x15,
               'INFO': 0x17, 'TEXT': 0x19, 'PAGE+': 0x1A, 'PAGE-': 0x1B,
               'VOL-': 0x1F, 'VOL+': 0x20, 'CH-': 0x21, 'CH+': 0x22,
               'RECALL': 0x23, 'FAV': 0x29,
               **{str(d): 0x30 + d for d in range(10)}}
# 2006-2008 Globo / Opticum / BigSat M3329 SDK builds store flat 8-byte
# {uint32 nec32, uint32 vkey} tables in RAM where digits '0'..'9' are 0..9 and
# POWER / MUTE are 0x18 / 0x15.
GLOBO_M3329_KEYS = {
    **{str(d): (d,) for d in range(10)},
    'LEFT': (0x0A,), 'RIGHT': (0x0B,), 'UP': (0x0C,), 'DOWN': (0x0D,),
    'MENU': (0x0E,), 'OK': (0x0F,), 'ENTER': (0x0F,), 'EXIT': (0x10,), 'BACK': (0x10,),
    'MUTE': (0x15, 0x11), 'INFO': (0x17,), 'POWER': (0x18, 0x12),
    'PAUSE': (0x29, 0x13), 'TVRADIO': (0x35, 0x14), 'AUDIO': (0x26, 0x15),
    'FAV': (0x2A, 0x29), 'PAGE+': (0x2C, 0x1A), 'PAGE-': (0x2B, 0x1B),
    'RECALL': (0x34, 0x23), 'VOL-': (0x0A, 0x1F), 'VOL+': (0x0B, 0x20),
    'CH-': (0x0D, 0x21), 'CH+': (0x0C, 0x22),
}
KEY_CONFIG = 0x8003B640


from ir_remote import bitrev8 as _rev8


class Uart16550:
    """M3329's second 16550 UART (`SCI_16550_1` at 0xB8001400, IC line 6),
    used on boards such as Moresat / Echolink `SMT01` to talk to an external
    front-panel / security microcontroller (`PAN_SMTM51_0`) without mixing
    binary frames into the primary console UART (`SCI_16550_0` at 0xB8001300)."""

    def __init__(self, sim, base=UART2, line=UART2_LINE):
        self.sim = sim
        self.base = base
        self.line = line
        self.tx_handler = None
        self.rx_queue = deque()
        self.tx_bytes = bytearray()
        self.reset()
        sim._mmio_on('w', self._write, base, base + 7)
        sim._mmio_on('r', self._read, base, base + 9)

    def reset(self):
        self.rx_queue.clear()
        self.tx_bytes.clear()
        self.lcr = 0
        self.ier = 0
        self.dll = 0
        self.dlm = 0
        self.sim._ic_set_line(self.line, False)

    def _sync_irq(self):
        self.sim._mmio_view[(self.base & 0xFFFFFF) + 5] = 0x60 | (0x01 if self.rx_queue else 0x00)
        self.sim._ic_set_line(self.line, bool((self.ier & 0x01) and self.rx_queue))

    def receive(self, data):
        if isinstance(data, int):
            self.rx_queue.append(data & 0xFF)
        else:
            self.rx_queue.extend(b & 0xFF for b in data)
        self._sync_irq()

    def _write(self, uc, access, address, size, value, user_data):
        sim = self.sim
        sim._device_access(uc)
        reg = (address - self.base) & 0xF
        val = value & 0xFF
        if reg == 0:
            if self.lcr & 0x80:
                self.dll = val
            else:
                if sim._dev_replay_of(uc, 'u2thr', address, val) is None:
                    self.tx_bytes.append(val)
                    sim._dev_note(uc, 'u2thr', address, val)
                    if self.tx_handler is not None:
                        self.tx_handler(val)
                sim._mmio_view[(self.base & 0xFFFFFF) + 5] = 0x60 | (0x01 if self.rx_queue else 0x00)
        elif reg == 1:
            if self.lcr & 0x80:
                self.dlm = val
            else:
                self.ier = val
                self._sync_irq()
        elif reg == 2:
            if val & 0x02:
                self.rx_queue.clear()
                self._sync_irq()
        elif reg == 3:
            self.lcr = val
        elif reg == 5:
            return 0x60 | (0x01 if self.rx_queue else 0x00)

    def _read(self, uc, access, address, size, value, user_data):
        sim = self.sim
        sim._device_access(uc)
        off = address & 0xFFFFFF
        reg = (address - self.base) & 0xF
        if reg <= 5 < reg + size:
            sim._mmio_view[(self.base & 0xFFFFFF) + 5] = 0x60 | (0x01 if self.rx_queue else 0x00)
        if reg == 0:
            if self.lcr & 0x80:
                sim._mmio_view[off] = self.dll
            else:
                rp = sim._dev_replay_of(uc, 'u2rbr', address)
                if rp is not None:
                    sim._mmio_view[off] = rp[2]
                elif self.rx_queue:
                    b = self.rx_queue.popleft()
                    sim._mmio_view[off] = b
                    sim._dev_note(uc, 'u2rbr', address, b)
                    self._sync_irq()
        elif reg == 1:
            sim._mmio_view[off] = self.dlm if (self.lcr & 0x80) else self.ier
        elif reg == 2:
            n = len(self.rx_queue)
            if not (self.ier & 0x01) or n == 0:
                sim._mmio_view[off] = 0x01
            elif n >= 4:
                sim._mmio_view[off] = 0x04
            else:
                sim._mmio_view[off] = 0x0C
        elif reg == 3:
            sim._mmio_view[off] = self.lcr


class Osd:
    """OSD_M3327C's display layers, as far as a capture needs more than the
    registers and the RAM (gma_capture.m3327_regions): their palettes, which
    the driver writes through one port per layer (0xB80041AC, 0xB80041C8),
    an entry per store -- the index in bits 24..31, then Y, Cb and Cr, the
    entry's 4-bit alpha in the low two bits of Cb and Cr."""

    def __init__(self, sim):
        self.palettes = ({}, {})
        for layer, port in enumerate(OSD_PALETTE_PORTS):
            sim._mmio_on('w', lambda uc, access, address, size, value, user_data, layer=layer:
                         self._write(layer, size, value), port, port)

    def _write(self, layer, size, value):
        if size == 4:
            self.palettes[layer][value >> 24] = value & 0xFFFFFF


class M3329(ChipFamily):
    name = "M3329"
    chip_id = 0x3329
    chip_variant = 0x00F0               # the revision byte: 0x20003 to the bootloader (no boot-ROM call)
    flash = None

    @classmethod
    def matches(cls, image):
        chain = chunk_chain(image, limit=2)
        return bool(chain) and struct.unpack_from(">I", image, chain[0][0])[0] == BOOTLOADER_CHUNK_ID

    @staticmethod
    def _uses_spi_flash(image):
        """Later M3329C / M3101C / M3329E boards wire an SPI flash to SF_INS /
        SF_FMT (0xB8000098 / 0x99, driver `STO_SFLASH_0` without `STO_FLASH_0`);
        older M3327 / M3329 / M3329C boards wire an 8-bit parallel NOR flash
        directly to 0xAFC00000 (`STO_FLASH_0`)."""
        chain = chunk_chain(image, limit=2)
        bl_end = chain[1][0] if len(chain) > 1 and 0 < chain[1][0] <= len(image) else min(len(image), 0x10000)
        bl = bytes(image[:bl_end])
        if b"STO_FLASH_0" in bl:
            return False
        if b"STO_SFLASH_0" in bl:
            return True
        for off in range(0, len(bl) - 16, 4):
            w = struct.unpack_from("<I", bl, off)[0]
            if (w & 0xFFE0FFFF) == 0x3C00B800:      # lui $r, 0xb800
                reg = (w >> 16) & 0x1F
                for k in range(4, 20, 4):
                    w2 = struct.unpack_from("<I", bl, off + k)[0]
                    if (w2 >> 26) in (0x28, 0x29) and ((w2 >> 21) & 0x1F) == reg and (w2 & 0xFFFF) in (0x0098, 0x0099):
                        return True
        return False

    def default_chip_id(self):
        """M3329E / multi-chip bootloaders check 0x3329 in their early startup
        (`addiu $at, $zero, 0x3329` in the first 8 KB); M3329C / M3101C
        bootloaders only accept 0x0000, 0x3327 or 0x3101 there (hitting sdbbp
        or returning chip ID 0 on 0x3329)."""
        if b"\x29\x33\x01\x24" in bytes(self.sim.rom_image[:0x2000]):
            return 0x3329
        return 0x3101

    def variant(self):
        """M3329C (0x3327) checks the package bond-option bits in bits 8..15
        against flash[0x9F] & 0x18 (0x0100 DDR vs 0x0400 SDRAM) above the 0xF0
        revision byte; 0x3101 / 0x3329 / 0x0000 take 0x00F0."""
        if self.chip_id == 0x3327 and len(self.sim.rom_image) > 0x9F:
            bond = 0x0100 if (self.sim.rom_image[0x9F] & 0x18) else 0x0400
            return bond | self.chip_variant
        return self.chip_variant

    def _configure_flash(self):
        sim = self.sim
        if self.flash is not None:
            self.flash.disconnect()
        if self._uses_spi_flash(sim.rom_image):
            self.flash = None
            return
        from parallel_flash import ParallelNorFlash, part_for_size
        path = getattr(sim, "dump_path", None)
        size = os.path.getsize(path) if path and os.path.isfile(path) else len(sim.rom_image)
        self.flash = ParallelNorFlash(sim, **part_for_size(size))
        self.flash.connect()

    def install(self):
        super().install()
        sim = self.sim
        sim._mmio_on('w', self._sdram_command, SDRAM_CONTROL, SDRAM_CONTROL)
        # the UART, a 16550 like the later chips' at 0xB8018300, sits at 0xB8001300;
        # SCI_16550_1 sits at 0xB8001400 on IC line 6
        sim._mmio_on('w', sim._hook_uart_write, UART, UART + 5)
        sim._mmio_on('r', sim._hook_uart_read, UART, UART + 9)
        self.uart2 = Uart16550(sim)
        self._configure_flash()
        sim.set_ic_layout(IC_STATUS, IC_ENABLE)
        from video_m36 import VideoEngine, VideoOutput
        self._ve = VideoEngine(sim, line=VIDEO_LINE, reset=(0x60, 0x04))
        self._ve_e = VideoEngine(sim, line=12, reset=(0x60, 0x04), base=0xB8013200)
        self.video_output = VideoOutput(sim, register=VPO_INT, line=VIDEO_LINE, field_bit=0, reset=(0x60, 0x08))
        self._count_hz = sim.count_hz
        sim.count_hz = COUNT_HZ
        sim._mmio_on('r', sim._hook_irc_read, IRC + 1, IRC + 1)
        sim._mmio_on('r', sim._hook_irc_read, IRC + 7, IRC + 8)
        sim._mmio_on('w', sim._hook_irc_write, IRC + 7, IRC + 7)
        sim.irc_base, sim.irc_line = IRC, IRC_LINE
        self.osd = Osd(sim)
        # M3329E (Opticum 7300 PVR) integrates GE_M36 at 0xB800E000 and polls
        # SND_M3327 reset-completion bits at 0xB80020E3 / 0xB80020E4 bit 0.
        from ge_m3602 import GeM3602
        self.ge = GeM3602(sim, base=0xE000)
        self.snd_ready = ReadyBits(sim, {0x20E3: 0x01, 0x20E4: 0x01})
        self._ir_usr_code = None
        self._nec32_key_table = None

    @property
    def video_engine(self):
        return self._ve_e if self._ve_e.pictures else self._ve

    def _find_ir_usr_code(self):
        """Scan loaded MIPS32 code (RAM, then flash) for `key_get_key()`'s
        customer-code check off `$gp`:
            lw  $r1, o1($gp)    # IR_USR_MASK == 0xFFFF0000
            and ...
            lw  $r2, o2($gp)    # IR_USR_CODE == 0xHHLL0000
        Returns the 32-bit `IR_USR_CODE` word (e.g. `0x02370000`), or 0."""
        if self._ir_usr_code is not None:
            return self._ir_usr_code
        import numpy as np
        from uc_const import UC_MIPS_REG_GP
        sim = self.sim
        gp = sim.mu.reg_read(UC_MIPS_REG_GP) & 0xFFFFFFFF
        ram_words = np.frombuffer(sim.ram_buffer, dtype='<u4', count=sim.ram_size // 4)
        ram_limit = sim.ram_size

        def sdata_word(imm16):
            off = imm16 - 0x10000 if imm16 & 0x8000 else imm16
            addr = (gp + off) & 0xFFFFFFFF
            if not (0x80000000 <= (addr & 0xDFFFFFFF) < 0x80000000 + ram_limit) or (addr & 3):
                return None
            return int(ram_words[(addr & 0x1FFFFFFF) >> 2])

        regions = [ram_words[:min(len(ram_words), 0x800000 // 4)]]
        if len(sim.rom_image) >= 32:
            regions.append(np.frombuffer(sim.rom_image, dtype='<u4', count=len(sim.rom_image) // 4))
        for words in regions:
            hits = np.nonzero((words & 0xFFE00000) == 0x8F800000)[0]
            for idx in hits:
                i = int(idx)
                if sdata_word(int(words[i]) & 0xFFFF) != 0xFFFF0000:
                    continue
                window = words[i + 1:min(i + 8, len(words))]
                if not np.any((window & 0xFC0007FF) == 0x00000024):
                    continue
                for w2 in window:
                    ins = int(w2)
                    if (ins & 0xFFE00000) == 0x8F800000:
                        usr = sdata_word(ins & 0xFFFF)
                        if usr is not None and (usr & 0xFFFF) == 0 and 0 < (usr >> 16) < 0xFFFF:
                            self._ir_usr_code = usr
                            return usr
        return 0

    def _find_nec32_key_table(self):
        """Scan loaded RAM (then flash) for 2006-2008 M3329 8-byte
        `{uint32 nec32, uint32 vkey}` remote tables where every `nec32` has a
        valid NEC command / complement pair (`((nec32 >> 8) ^ nec32) & 0xFF == 0xFF`)
        and `vkey < 0x80`.  Returns `{vkey: nec32}`."""
        if self._nec32_key_table:
            return self._nec32_key_table
        import numpy as np
        sim = self.sim
        ram_words = np.frombuffer(sim.ram_buffer, dtype='<u4', count=min(sim.ram_size, 0x800000) // 4)
        regions = [ram_words]
        if len(sim.rom_image) >= 128:
            regions.append(np.frombuffer(sim.rom_image, dtype='<u4', count=len(sim.rom_image) // 4))
        best_len = 0
        best_pairs = None
        for words in regions:
            for phase in (0, 1):
                w = words[phase:]
                n = len(w) // 2
                if n < 16:
                    continue
                nec = w[:2 * n:2]
                vk = w[1:2 * n:2]
                ok = (((nec >> 8) ^ nec) & 0xFF == 0xFF) & ((nec >> 16) != 0) & ((nec >> 16) != 0xFFFF) & (vk < 0x80)
                if not np.any(ok):
                    continue
                padded = np.empty(n + 2, dtype=np.int8)
                padded[0] = 0
                padded[1:-1] = ok
                padded[-1] = 0
                diff = np.diff(padded)
                starts = np.nonzero(diff == 1)[0]
                ends = np.nonzero(diff == -1)[0]
                lengths = ends - starts
                idx = int(np.argmax(lengths))
                run_len = int(lengths[idx])
                if run_len >= 16 and run_len > best_len:
                    s, e = int(starts[idx]), int(ends[idx])
                    best_len = run_len
                    best_pairs = (nec[s:e], vk[s:e])
            if best_pairs is not None:
                break
        if best_pairs is None:
            return {}
        table = {}
        nec_arr, vk_arr = best_pairs
        for nec32, vkey in zip(nec_arr.tolist(), vk_arr.tolist()):
            table.setdefault(int(vkey), int(nec32))
        self._nec32_key_table = table
        return table

    def remote_frame(self, key):
        """(address, command, address_hi) of the NEC frame of a remote key
        (a name of REMOTE_KEYS / ir_remote.VKEYS or the application's key
        code), from the application's key table (simulator.press_key); None if
        it uses the standard ir_remote path.  Older 2005 builds (s15125) keep
        a 4-byte {cmd, ~cmd, key, 0} table at KEY_CONFIG; 2006-2008 Globo /
        Opticum / BigSat builds keep a flat 8-byte {uint32 nec32, uint32 vkey}
        table; later M3329C / M3329E Libcore builds keep an 8-byte 0x0101
        ir_key_map_t table with 8-bit key codes (0x00xx) gated by `IR_USR_CODE`
        off `$gp`."""
        code = REMOTE_KEYS.get(key.upper()) if isinstance(key, str) else int(key)
        sim = self.sim
        word = lambda a: int.from_bytes(sim.peek(a, 4), 'little')   # noqa: E731
        table, customer = word(KEY_CONFIG), word(KEY_CONFIG + 4) >> 16
        count = int.from_bytes(sim.peek(KEY_CONFIG + 0xE, 2), 'little')
        if code is not None and 0x80000000 <= table < 0x80000000 + sim.ram_size and 0 < count <= 0x100:
            for a in range(table, table + 4 * count, 4):
                b0, b1, k, _ = sim.peek(a, 4)
                if b0 ^ b1 == 0xFF and k == code:
                    return _rev8(customer >> 8), _rev8(b1), _rev8(customer & 0xFF)
        import ir_remote
        import numpy as np
        if not sim._ir_key_table:
            ram = np.frombuffer(sim.ram_buffer, dtype=np.uint8, count=min(sim.ram_size, 0x2000000))
            sim._ir_key_table = ir_remote.find_key_table(ram)
        if sim._ir_key_table:
            vkey = ir_remote.VKEYS.get(key.upper()) if isinstance(key, str) else int(key)
            if vkey is not None and vkey not in sim._ir_key_table and isinstance(key, str):
                vkey = next((v for v in ir_remote.VKEY_FALLBACKS.get(key.upper(), ())
                             if v in sim._ir_key_table), vkey)
            ir16 = sim._ir_key_table.get(vkey)
            if ir16 is not None and (ir16 >> 8) == 0:
                usr = self._find_ir_usr_code()
                if usr:
                    return _rev8((usr >> 24) & 0xFF), (~_rev8(ir16 & 0xFF)) & 0xFF, _rev8((usr >> 16) & 0xFF)
        nec_table = self._find_nec32_key_table()
        if nec_table:
            candidates = GLOBO_M3329_KEYS.get(key.upper(), ()) if isinstance(key, str) else (int(key),)
            for cand in candidates:
                nec32 = nec_table.get(cand)
                if nec32 is not None:
                    return (_rev8((nec32 >> 24) & 0xFF),
                            _rev8((nec32 >> 8) & 0xFF),
                            _rev8((nec32 >> 16) & 0xFF))
        return None

    def uninstall(self):
        sim = self.sim
        if self.flash is not None:
            self.flash.disconnect()
            self.flash = None
        self.uart2.reset()
        sim.set_ic_layout(sim.ic_base, sim.ic_base + 8)
        sim.count_hz = self._count_hz
        sim.irc_base, sim.irc_line = 0x18100, sim._IC_IRC
        super().uninstall()

    def start(self):
        self._ir_usr_code = None
        self._nec32_key_table = None
        self.uart2.reset()
        self._configure_flash()
        super().start()

    @staticmethod
    def _sdram_command(uc, access, address, size, value, user_data):
        """A command to the SDRAM controller is done at once: its bits 0..1 land clear."""
        return value & ~3
