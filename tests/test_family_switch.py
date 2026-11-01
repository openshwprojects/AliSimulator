"""
Fast check of a chip-family switch (simulator.loadFile -> _switch_family),
no firmware run: every simulator starts as the M3801 family, and loading an
image of another family must leave that family's devices only.  One
simulator loads, in turn, the R265 Lite's M3822P image (M3821), dump.bin
(M3801), the Globo HD-XS2 update (M3503) and the Ferguson Ariva T50 update
(M3602, whose board reads the family's own chip ID -- the Cabletech ones read
0x3603).  Checks after each load: the family is the image's own
(the exact class: an M3503 is an M3602 subclass, yet loading an M3602 image
after it switches, with the chip ID 0x3602); no register handler of the
previous family's devices is left (the M3801's demodulator, demultiplexer
and real-time clock; the M3821's DDR training, SPI stream, DMA rings ...),
while the common ones (UART, GE, I2C masters) stay; the M3821's boot SRAM
at 0x1FE00000 gives the flash mirror back, read-only at the physical
address, and its SPI stream mode and extra self-completing register go; the
M3602's RAM mirror above the RAM's size exists only while an M36xx family
is loaded; the M3503's cache-as-RAM window at 0x0FFF8000 is the flash's
again (read-only, its code hook gone), and its internal demodulator's chip
ID registers read 0 again.  Then the Opticum X110TS update, a
C3603 board of the same family: its chip word carries the product bits and
its S3501 demodulator answers its chip ID on the I2C bus -- and is gone again
when the T50 is loaded after it (same family) or dump.bin (M3801).  A
T760i image puts its board's ATBM7812 demodulator (its sidecar's
demodModel) at 0x40; the next image's board has none.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from unicorn import UC_PROT_ALL, UC_PROT_EXEC, UC_PROT_READ

from simulator import AliMipsSimulator, flash_size_for

IMAGES = ("M3822P.bin", "dump.bin", "Sw_Globo_HD-XS2_SmartHD_1.3.5_2015-05-08.abs", "ArivaT50_20111118_V102B214.abs",
          "Software_Patch_X110TS_X110TSE_1.4.0C_PVR_UNI_ENG_2015-05-04.abs", "Ferguson_T760i_V1.5B4-14092021.abs",
          "A53_20190813_V1.33B7.abs", "A54_20190926_V1.3B1.abs",
          "FERGUSON ARIVA 255 COMBO/Ferguson_A255_V1.32B4.abs",
          "AMIKO HD8260+/8260_Edision_Piccollo_ v.2468.abs",
          "OPTICUM HD X4 220/OPTICUM_HD_X4_220_ps_lemontree_1.3.37.abs",
          "OPTICUM XS65 TWIN/140_TWIN_RETAIL_PL.abs",
          "ECHOLINK EL-700 FTA/flash ECHOLINK EL700FTA mx29lv160.bin",
          "OPTICUM X80 PREMIUM/dump opticum x80 premium.bin")
ok = True


def check(cond, msg):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    ok &= bool(cond)


def owners(sim):
    """The objects whose bound methods handle device register accesses."""
    out = set()
    for table in (sim._mmio_rd, sim._mmio_wr):
        for handlers in table.values():
            for h in handlers:
                out.add(id(getattr(h, "__self__", None)))
    return out


def devices(chip):
    """The device objects a family installed (its attributes that handle registers)."""
    return [v for v in vars(chip).values() if hasattr(v, "__dict__") and v is not chip.sim]


def region(sim, address):
    """(begin, end, perms) of the Unicorn mapping holding a physical address, or None."""
    return next(((b, e, p) for b, e, p in sim.mu.mem_regions() if b <= address <= e), None)


def flash_bytes(sim, address, n=16):
    off = sim._flash_offset(address)
    return bytes(sim.rom_image[off:off + n])


print("=== Test: switching chip families (loadFile) ===")
sim = AliMipsSimulator(rom_size=max(flash_size_for(d) for d in IMAGES), log_handler=lambda m: None)
sim.setSPIDump(False)
first = sim.chip
check(type(first).__name__ == "M3801" and id(first.rtc) in owners(sim) and id(first.demod) in owners(sim),
      "a new simulator has the M3801 family, its RTC and demodulator handlers registered")
common = {id(sim)} | {id(m) for m in sim.i2c_masters}

sim.loadFile(IMAGES[0])
m3821 = sim.chip
check(type(m3821).__name__ == "M3821", f"M3822P.bin: the M3821 family ({type(m3821).__name__})")
left = [type(d).__name__ for d in devices(first) if id(d) in owners(sim)]
check(not left, f"no handler of the M3801's devices is left ({left or 'none'})")
check(common <= owners(sim), "the common handlers (the simulator's own, the I2C masters) stay")
check(sim._spi_stream is m3821.spi and "_SELF_COMPLETING" in vars(sim),
      "the M3821's SPI stream mode and its self-completing start bit are set")
check(bytes(sim.mu.mem_read(0x9FE00800, 16)) == bytes(sim.rom_image[0x800:0x810]),
      "its boot SRAM at 0x9FE00000 holds the bootloader the boot ROM copied")

sim.loadFile(IMAGES[1])
m3801 = sim.chip
check(type(m3801).__name__ == "M3801" and m3801 is not first, "dump.bin: a new M3801 family")
left = [type(d).__name__ for d in devices(m3821) if id(d) in owners(sim)]
check(not left, f"no handler of the M3821's devices is left ({left or 'none'})")
check(id(m3801.rtc) in owners(sim) and id(m3801.dmx) in owners(sim), "the M3801's RTC and demultiplexer are back")
check(sim._spi_stream is None and "_SELF_COMPLETING" not in vars(sim) and 0x2A06C not in sim._mmio_rd,
      "the M3821's SPI stream mode and extra self-completing register (0xB802A06F) are gone")
r = region(sim, 0x1FE00000)
check(bytes(sim.mu.mem_read(0x9FE00000, 16)) == flash_bytes(sim, 0x1FE00000) and r and r[2] == UC_PROT_READ | UC_PROT_EXEC,
      f"0x1FE00000 shows the flash mirror again, read-only at the physical address (perms {r and r[2]})")
check(region(sim, 0x08000000) is None, "no RAM mirror above the RAM's 128 MB (an M36xx family's)")

sim.loadFile(IMAGES[2])
m3503 = sim.chip
r = region(sim, 0x0FFF8000)
check(type(m3503).__name__ == "M3503" and m3503.car.active and r and r[2] == UC_PROT_ALL,
      f"the Globo HD-XS2: the M3503 family, its cache-as-RAM window writable (perms {r and r[2]})")
check(region(sim, 0x08000000) is not None, "the M36xx RAM mirror above the RAM's size is mapped")

sim.loadFile(IMAGES[3])
m3602 = sim.chip
chip_word = int.from_bytes(sim.peek(0xB8000000, 4), "little")
check(type(m3602).__name__ == "M3602" and chip_word >> 16 == 0x3602,
      f"the T50 after the M3503: the M3602 family itself, chip ID 0x{chip_word >> 16:04X}")
r = region(sim, 0x0FFF8000)
check(not m3503.car.active and r and r[2] == UC_PROT_READ | UC_PROT_EXEC
      and bytes(sim.mu.mem_read(0x0FFF8000, 16)) == flash_bytes(sim, 0x0FFF8000),
      f"the cache-as-RAM window is the flash's again (perms {r and r[2]}), its code hook gone")
check(region(sim, 0x08000000) is not None, "the RAM mirror is mapped again for the M3602")
left = [type(d).__name__ for d in devices(m3503) if id(d) in owners(sim)]
check(not left, f"no handler of the M3503's devices is left ({left or 'none'})")
check(sim.peek(0xB80280A3, 4) == bytes(4),
      f"the M3503's internal demodulator's chip ID is gone with it ({sim.peek(0xB80280A3, 4).hex()})")


def chip_word():
    return int.from_bytes(sim.peek(0xB8000000, 4), "little")


def demod_id():
    """The chip ID registers (0xA3..0xA6) of the demodulator at I2C 0x33, or None without one."""
    demod = sim.i2c_devices.get(0x33)
    return demod.write(bytes([0xA3])) and demod.read(4) if demod else None


sim.loadFile(IMAGES[4])
check(sim.chip is m3602 and chip_word() == 0x36030500 and demod_id() == bytes([0x01, 0x35, 0xC0, 0x00]),
      f"the X110TS (same family): chip word 0x{chip_word():08X}, a product with the DVB-S2 demodulator, "
      f"whose S3501 answers at I2C 0x33 ({demod_id() and demod_id().hex()})")
sim.loadFile(IMAGES[3])
check(chip_word() == 0x36020000 and demod_id() is None,
      f"the T50 after it: chip word 0x{chip_word():08X}, no demodulator at 0x33")
sim.loadFile(IMAGES[4])
sim.loadFile(IMAGES[1])
check(type(sim.chip).__name__ == "M3801" and demod_id() is None,
      "dump.bin after the X110TS (the M3801 family): its S3501 is gone with the M3602 family")
sim.loadFile(IMAGES[5])
atbm = sim.i2c_devices.get(0x40)
check(type(sim.chip).__name__ == "C3505" and type(atbm).__name__ == "ATBM7812" and atbm.read(1) == b"\xA8",
      f"the T760i: its board's ATBM7812 demodulator at 0x40 ({type(atbm).__name__})")
sim.loadFile(IMAGES[1])
check(0x40 not in sim.i2c_devices, "dump.bin after it: no demodulator at 0x40")
sim.loadFile(IMAGES[6])
c3503 = sim.chip
check(type(c3503).__name__ == "C3503" and chip_word() == 0x3503C000
      and bytes(c3503.otp.data[0x210:0x214]) == (5 << 20).to_bytes(4, "little")
      and sim.peek(0xB804C0A3, 4) == bytes([0x01, 0x35, 0xC0, 0x00])
      and sim.peek(0xB80280A3, 4) == bytes(4),
      f"the Ariva 53 (C3503C): chip word 0x{chip_word():08X}, OTP product 5, internal demodulator at 0xB804C000")
sim.loadFile(IMAGES[7])
check(sim.chip is c3503 and chip_word() == 0x3503D000 and bytes(c3503.otp.data[0x210:0x214]) == bytes(4),
      f"the Ariva 54 (same family, C3503D): chip word 0x{chip_word():08X}, OTP 0x210 blank again")
sim.loadFile(IMAGES[1])
left = [type(d).__name__ for d in devices(c3503) if id(d) in owners(sim)]
check(not left and sim.peek(0xB804C0A3, 4) == bytes(4),
      f"dump.bin after the C3503: no handler left ({left or 'none'}), 0xB804C0A3 cleared")
sim.loadFile(IMAGES[8])
c3505 = sim.chip
avl = sim.i2c_devices.get(0x14)
check(type(c3505).__name__ == "C3505" and sim.ram_size == 0x10000000 and not sim._upper_ram_mapped
      and type(avl).__name__ == "AVL6862" and (avl.write(b"\x04\x00\x00") and avl.read(4) == b"\x68\x62\x49\x55")
      and any(m.name == "SCB3" for m in sim.i2c_masters),
      "the Ariva 255 Combo (256 MB C3505): 256 MB DDR, SCB3 registered, AVL6862 at 0x14")
sim.loadFile(IMAGES[5])
check(sim.chip is c3505 and sim.ram_size == 0x08000000 and 0x14 not in sim.i2c_devices and 0x40 in sim.i2c_devices,
      "the T760i after it (same family, 128 MB): RAM back to 128 MB, ATBM7812 replaces AVL6862")
sim.loadFile(IMAGES[1])
left = [type(d).__name__ for d in devices(c3505) if id(d) in owners(sim)]
check(not left and id(c3505) not in owners(sim) and sim.ram_size == 0x08000000
      and not any(m.name == "SCB3" for m in sim.i2c_masters),
      f"dump.bin after the C3505: no handler left ({left or 'none'}), SCB3 gone, RAM 128 MB")
sim.loadFile(IMAGES[9])
m3503_256 = sim.chip
avl6762 = sim.i2c_devices.get(0x14)
check(type(m3503_256).__name__ == "M3503" and chip_word() == 0x35030001
      and sim.ram_size == 0x10000000 and not sim._upper_ram_mapped
      and type(avl6762).__name__ == "AVL6762"
      and (avl6762.write(b"\x10\x80\x00") and bytes([avl6762.read(1)[0] for _ in range(4)]) == b"\x00\x00\x00\x0E")
      and any(type(d).__name__ == "GpioI2cBus" for d in sim.gpio_devices)
      and any(m.name == "SCB3" for m in sim.i2c_masters),
      "the Amiko HD8260+ (256 MB M3503): chip word 0x35030001 (rev B), 256 MB DDR, SCB3 registered, AVL6762 at 0x14 + GPIO 7/8 I2C")
sim.loadFile(IMAGES[2])
check(sim.chip is m3503_256 and chip_word() == 0x35030000 and sim.ram_size == 0x08000000 and 0x14 not in sim.i2c_devices
      and not sim.gpio_devices and region(sim, 0x08000000) is not None,
      "the Globo HD-XS2 after it (same family, 128 MB): chip word 0x35030000 (rev A), RAM back to 128 MB with M36xx mirror, GPIO I2C cleared")
sim.loadFile(IMAGES[10])
check(type(sim.chip).__name__ == "M3602" and sim.ram_size == 0x08000000 and demod_id() == bytes([0x01, 0x35, 0xC0, 0x00])
      and any(type(d).__name__ == "LemontreeDecoder" for d in sim.gpio_devices),
      "the Opticum HD X4 220 (M3602B): S3501 at 0x33 and headless LemontreeDecoder on GPIO 62 / 171")
sim.loadFile(IMAGES[11])
check(type(sim.chip).__name__ == "M3503" and chip_word() == 0x35030001 and sim.ram_size == 0x10000000
      and demod_id() == bytes([0x01, 0x35, 0xC0, 0x00])
      and any(type(d).__name__ == "GpioI2cBus" for d in sim.gpio_devices),
      "the Opticum XS65 Twin (256 MB M3503): sidecar S3501 at 0x33 survives M3503.start() alongside internal demod")
import dump_catalog
vip3 = "Edision.vip3.0A050800_emu_1.6.60.abs"
dump_catalog.set_override(vip3, False)
try:
    sim.loadFile(vip3)
    check(type(sim.chip).__name__ == "M3602" and chip_word() == 0x36030500
          and demod_id() == bytes([0x01, 0x35, 0xC0, 0x00]),
          f"the Edision Argus VIP3 without sidecar: M3602.default_chip_id() selects C3603 (0x{chip_word():08X}) from M3606 chunks")
finally:
    dump_catalog.set_override(vip3, None)
sim.loadFile(IMAGES[1])
left = [type(d).__name__ for d in devices(m3503_256) if id(d) in owners(sim)]
check(not left and id(m3503_256) not in owners(sim) and sim.ram_size == 0x08000000
      and not sim.gpio_devices and not any(m.name == "SCB3" for m in sim.i2c_masters),
      f"dump.bin after the 256 MB M3503 and X4 220: no handler left ({left or 'none'}), GPIO devices and SCB3 gone")
sim.loadFile(IMAGES[12])
m3329 = sim.chip
check(type(m3329).__name__ == "M3329" and sim.flash_device is m3329.flash and m3329.flash.ids[1] == 0x49
      and sim.count_hz == 10_000_000 and sim._ic_en == 0xB800003C and sim.irc_base == 0x1100
      and id(m3329.uart2) in owners(sim) and any(type(d).__name__ == "GpioI2cBus" for d in sim.gpio_devices),
      "the Echolink EL-700 FTA (parallel-NOR M3329): MX29LV160B flash, UART2, 10 MHz Count, IC 0x38/0x3C, IRC 0x1100, GPIO 10/9 I2C")
m3329.flash._set_autoselect(True)
sim.loadFile(IMAGES[13])
check(sim.chip is m3329 and chip_word() == 0x310100F0 and sim.flash_device is None and m3329.flash is None
      and bytes(sim.mu.mem_read(0x9FC00000, 16)) == bytes(sim.rom_image[:16]),
      "the Opticum X80 Premium after it (same family, SPI M3329): parallel flash disconnected, autoselect cleared, chip word 0x310100F0")
sim.loadFile(IMAGES[1])
left = [type(d).__name__ for d in devices(m3329) if id(d) in owners(sim)]
check(type(sim.chip).__name__ == "M3801" and not left and sim.flash_device is None
      and sim.count_hz == 100_000_000 and sim._ic_en == 0xB8000038 and sim.irc_base == 0x18100,
      f"dump.bin after the M3329: no handler left ({left or 'none'}), 100 MHz Count, IC 0x30/0x38, IRC 0x18100 restored")
print(f"\n[{'PASS' if ok else 'FAIL'}] chip family switch")
sys.exit(0 if ok else 1)
