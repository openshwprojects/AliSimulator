"""
Fast check of a chip-family switch (simulator.loadFile -> _switch_family),
no firmware run: every simulator starts as the M3801 family, and loading an
image of another family must leave that family's devices only.  One
simulator loads, in turn, the R265 Lite's M3822P image (M3821), dump.bin
(M3801), the Globo HD-XS2 update (M3503) and the Cabletech URZ0083 v1.2.5
update (M3602).  Checks after each load: the family is the image's own
(the exact class: an M3503 is an M3602 subclass, yet loading an M3602 image
after it switches, with the chip ID 0x3602); no register handler of the
previous family's devices is left (the M3801's demodulator, demultiplexer
and real-time clock; the M3821's DDR training, SPI stream, DMA rings ...),
while the common ones (UART, GE, I2C masters) stay; the M3821's boot SRAM
at 0x1FE00000 gives the flash mirror back, read-only at the physical
address, and its SPI stream mode and extra self-completing register go; the
M3602's RAM mirror above the RAM's size exists only while an M36xx family
is loaded; the M3503's cache-as-RAM window at 0x0FFF8000 is the flash's
again (read-only, its code hook gone).  Then the Opticum X110TS update, a
C3603 board of the same family: its chip word carries the product bits and
its S3501 demodulator answers its chip ID on the I2C bus -- and is gone again
when the URZ0083 is loaded after it (same family) or dump.bin (M3801).  A
T760i image puts its board's ATBM7812 demodulator (its sidecar's
demodModel) at 0x40; the next image's board has none.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from unicorn import UC_PROT_ALL, UC_PROT_EXEC, UC_PROT_READ

from simulator import AliMipsSimulator, flash_size_for

IMAGES = ("M3822P.bin", "dump.bin", "Sw_Globo_HD-XS2_SmartHD_1.3.5_2015-05-08.abs", "URZ0083_V1.2.5.abs",
          "Software_Patch_X110TS_X110TSE_1.4.0C_PVR_UNI_ENG_2015-05-04.abs", "Ferguson_T760i_V1.5B4-14092021.abs")
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
      f"URZ0083 v1.2.5 after the M3503: the M3602 family itself, chip ID 0x{chip_word >> 16:04X}")
r = region(sim, 0x0FFF8000)
check(not m3503.car.active and r and r[2] == UC_PROT_READ | UC_PROT_EXEC
      and bytes(sim.mu.mem_read(0x0FFF8000, 16)) == flash_bytes(sim, 0x0FFF8000),
      f"the cache-as-RAM window is the flash's again (perms {r and r[2]}), its code hook gone")
check(region(sim, 0x08000000) is not None, "the RAM mirror is mapped again for the M3602")
left = [type(d).__name__ for d in devices(m3503) if id(d) in owners(sim)]
check(not left, f"no handler of the M3503's devices is left ({left or 'none'})")


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
      f"the URZ0083 after it: chip word 0x{chip_word():08X}, no demodulator at 0x33")
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
print(f"\n[{'PASS' if ok else 'FAIL'}] chip family switch")
sys.exit(0 if ok else 1)
