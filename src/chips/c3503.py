"""
ALi C3503C / C3503D (the Ferguson Ariva 53 and Ariva 54 update images): a
single-CPU DVB-S2 chip family of the C3505's generation.  Its bootloader is
built for the same on-chip boot ROM as the M3821's and the C3505's (the area
from offset 0x800 copied into the boot SRAM at 0x1FE00000, entered at
0x9FE00800), so it is the C3505 family with four differences the firmwares
show:

  * the chip ID word 0xB8000000 reads 0x3503 in its upper half and the
    product in bits 12..15 of the lower: the SDK's chip-code function
    (0x800032A0 in the Ariva 53's main code, 0x800A32A0 in the Ariva 54's)
    tells the C3503C (0x3503C000, chip code 0x10050) and the C3503D
    (0x3503D000, 0x10051) apart before it looks at the plain ID.  Each board's
    start-up checks for its own variant (0x80150EBC in the Ariva 53 wants
    0x10050, the Ariva 54 wants 0x10051) and reboots through the watchdog
    otherwise.
  * on the C3503C, the SDK's background check task (0x805B9B60 in the Ariva
    53) asks 0x80320BB0 whether the chip's OTP product ID (bits 20..24 of OTP
    word 0x210, read through Otp at 0xB8042000) has the DVB-S2 capability byte
    set in its 13-byte product table (0x8079ED98): only product 5 does, and
    with a blank OTP (product 0) the task clears bit 0 of 0xB8006300 every
    second to keep the OSD layer off.
  * its DVB-S2 demodulator -- the S3501 core of the M3503 / C3505, driven
    as NIM_S3505_0 -- sits at 0xB804C000 (where the M3821 has its DVB-T2
    demodulator), not at 0xB8028000: the driver's open reads the chip ID
    registers 0xA3..0xA6 there, ten times, and gives up ("ERROR: reset nim
    failed!!!"); without the demodulator its application keeps the OSD layer
    off (0xB8006300 bit 0) although it has drawn its System Setup menu.
  * no SEE program: the image has no seecode chunk, and although the
    application starts the "SEE" at 0xA0000A00 nothing is there (the SEE's
    window 0x03F52000.. in its memory map, 0xB8041010.., stays empty), so
    the second core is not run (SeeStart.run_program cleared): the program
    would run the main code's own RAM as code.

Recognised by a boot-ROM bootloader (a NOP at 0x800 and a LUI of the boot
SRAM's 0x9FE0 / 0x9FE1 / 0xBFE0 in the next words), no seecode chunk, and a
main code that has the C3503C/D clock functions (get_clock_3503D).  The Ariva
53's bootloader does not set its stack pointer -- the boot ROM does --, so
start() gives it one at the top of the bootloader's SRAM area (0x9FE07F00,
where the Ariva 54's bootloader puts its own).
"""
import struct

from unicorn.mips_const import UC_MIPS_REG_SP

from .base import ReadyBits, chunk_chain, maincode
from .c3505 import C3505
from .m3503 import InternalDemod

BOOT_SRAM_LUI = (0x9FE0, 0x9FE1, 0xBFE0)
BOOTROM_STACK = 0x9FE07F00          # the Ariva 54's bootloader's own (lui sp, 0x9FE0; ori sp, 0x7F00)
DEMOD_BASE = 0x4C000                # the internal DVB-S2 demodulator's registers (0xB804C000)
# Board-init guard for the C3503C (chip code 0x10050, Ariva 53 0x80150EC4):
#   lui $v1, 1; ori $v1, $v1, 0x50; beq $v0, $v1, +4 (else sys_ic_reboot)
C3503C_GUARD = struct.pack("<III", 0x3C030001, 0x34630050, 0x10430004)
C3503C_OTP_PRODUCT = (5 << 20).to_bytes(4, "little")    # OTP 0x210 bits 20..24 = 5 (DVB-S2 product in 0x8079ED98)


def bootrom_bootloader(image):
    """A bootloader that the boot ROM copies to the boot SRAM: a NOP at
    0x800 and a LUI of the SRAM's upper half within the next three words."""
    if len(image) < 0x810 or struct.unpack_from("<I", image, 0x800)[0] != 0:
        return False
    for w in struct.unpack_from("<3I", image, 0x804):
        if w >> 26 == 0x0F and w & 0xFFFF in BOOT_SRAM_LUI:
            return True
    return False


class C3503(C3505):
    name = "C3503"
    chip_id = 0x3503
    chip_variant = 0xD000           # 0xD000 for C3503D (Ariva 54), 0xC000 for C3503C (Ariva 53)

    @classmethod
    def matches(cls, image):
        if not bootrom_bootloader(image):
            return False
        if any(name == "seecode" for _o, name, _v in chunk_chain(image)):
            return False            # (the dual-CPU C3505 images)
        mc = maincode(image)
        return b"get_clock_3503D" in mc or C3503C_GUARD in mc or b"c3507_phy_set" in mc

    def default_chip_id(self):
        mc = maincode(bytes(self.sim.rom_image)) if self.sim.rom_image else b""
        return 0x3507 if b"c3507_phy_set" in mc else 0x3503

    def write_chip_id(self):
        mc = maincode(bytes(self.sim.rom_image)) if self.sim.rom_image else b""
        is_c3507 = b"c3507_phy_set" in mc
        is_c3503c = C3503C_GUARD in mc
        self.chip_variant = 0x0000 if is_c3507 else (0xC000 if is_c3503c else 0xD000)
        super().write_chip_id()
        if is_c3507:
            self.sim.poke(0xB8080000, struct.pack("<HH", self.chip_variant, self.chip_id))
            self.sim.set_ic_layout(0x81080, 0x81040)
        self.sim._IC_GE = 76 if is_c3507 else 4
        self.sim.irc_line = 12 if is_c3507 else 19
        if hasattr(self, "video_output"):
            self.video_output.line = 68 if is_c3507 else 2
            self.video_engine.line = 72 if is_c3507 else 0
        if hasattr(self, "otp"):
            import dump_catalog
            contents = dump_catalog.otp(self.sim.dump_path) if getattr(self.sim, "dump_path", None) else None
            self.otp.data[:] = bytes(self.otp.SIZE)
            for offset, blob in (contents or {}).items():
                self.otp.data[offset:offset + len(blob)] = blob[:self.otp.SIZE - offset]
            if (is_c3503c or is_c3507) and self.otp.data[0x210:0x214] == bytes(4):
                self.otp.data[0x210:0x214] = C3503C_OTP_PRODUCT

    def install(self):
        super().install()
        if (self.chip_variant == 0xC000 or self.chip_id == 0x3507) and self.otp.data[0x210:0x214] == bytes(4):
            self.otp.data[0x210:0x214] = C3503C_OTP_PRODUCT
        # 0xB8000300: besides the ready bit 8 (C3505.ready300) the upper half holds the count of
        # the DDR PHY's ring oscillator, which the Ariva 53's bootloader divides by ("RingOSDelay(ns)
        # = 1024*37.037/count"): zero there was a divide-by-zero trap (TEQ, code 7).  128 counts:
        # a ~300 ns ring delay.  0xB8080253 bit 7 is the M3507/C3507 bootloader PLL ready bit.
        self.ring_count = ReadyBits(self.sim, {0x302: 0x80, 0x80201: 0x01, 0x80253: 0x80})
        if self.chip_id == 0x3507:
            from video_m36 import DEO_FIELD_BIT, VPO_FIELD_BIT, VideoOutput
            self.sim.set_ic_layout(0x81080, 0x81040)
            self.sim._IC_GE = 76            # OS IRQ 0x54 (84) - 8 = 76 on C3507 (0x10056)
            self.sim.irc_line = 12          # OS IRQ 0x14 (20) - 8 = 12 on C3507 (0x10056)
            if self.video_output.service in self.sim.slice_services:
                self.sim.slice_services.remove(self.video_output.service)
            self.video_output = VideoOutput(self.sim, line=68, field_bit=VPO_FIELD_BIT | DEO_FIELD_BIT)
            self.video_engine.line = 72     # OS IRQ 0x50 (80) - 8 = 72 on C3507 (0x10056)
        # the demodulator where this chip has it (the C3505's at 0xB8028000 removed)
        self.nim.remove()
        self.nim = InternalDemod(self.sim, base=DEMOD_BASE)
        # no SEE program on this chip: the "start" at 0xA0000A00 points at nothing
        self.see.run_program = False

    def start(self):
        if self.default_chip_id() == 0x3507:
            self._configure_memory()
            from .m3821 import M3821
            M3821.start(self)
        else:
            super().start()
        self.sim.mu.reg_write(UC_MIPS_REG_SP, BOOTROM_STACK)

    def code_ranges(self):
        return super().code_ranges() + ([(0x80100000, 0x100000)] if self.default_chip_id() == 0x3507 else [])

    def uninstall(self):
        self.sim._IC_GE = 4
        self.sim.irc_line = 19
        self.sim.set_ic_layout(0x30, 0x38)
        super().uninstall()
