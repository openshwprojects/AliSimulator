"""
Test: a flash larger than 4 MB continues linearly above its window's top
(simulator._map_flash_linear_tail): physical 0x10000000 onwards shows flash
offset 0x400000 onwards, as the newer M3503 / C3505 bootloaders read it for
their 'dump' (from 0xAFC00000 upwards, across 0xB0000000).

  tail     - an 8 MB and a 16 MB image: 0xB0000000 / 0x90000000 /
             0x10000000 read flash offset 0x400000, the last byte reads the
             flash's last byte, and the window below keeps the SDK's segment
             layout (0xAFC00000 = offset 0)
  4mb      - a 4 MB image has nothing mapped there (as before)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for   # noqa: E402

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== The flash's linear tail above 0x10000000 ===")
for name in ("Amiko_HD8140C_SE_1.1.04_emu.abs", "AMIKO_CHD8270_2.3.40_emu.abs"):
    rom = flash_size_for(name)
    sim = AliMipsSimulator(rom_size=rom, log_handler=lambda m: None)
    sim.setSPIDump(False)
    sim.loadFile(name)
    flash = bytes(sim.rom_image[:rom])
    tail = flash[0x400000:]
    reads = {a: bytes(sim.mu.mem_read(a, 64)) for a in (0xB0000000, 0x90000000, 0x10000000)}
    check(all(v == tail[:64] for v in reads.values()), f"{name} ({rom >> 20} MB): 0x10000000 in every view is offset 0x400000")
    check(bytes(sim.mu.mem_read(0xB0000000 + len(tail) - 16, 16)) == flash[-16:], "the tail ends at the flash's last byte")
    check(bytes(sim.mu.mem_read(0xAFC00000, 64)) == flash[:64], "0xAFC00000 is still offset 0")

sim = AliMipsSimulator(rom_size=flash_size_for("dump_maciej.bin"), log_handler=lambda m: None)
sim.loadFile("dump_maciej.bin")
try:
    sim.mu.mem_read(0xB0000000, 4)
    check(False, "4 MB flash: 0xB0000000 is unmapped")
except Exception:
    check(True, "4 MB flash: 0xB0000000 is unmapped, as before")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] the linear tail maps the flash beyond 4 MB")
