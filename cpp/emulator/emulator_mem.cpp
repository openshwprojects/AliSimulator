#include "emulator.h"

// ============================================================================
// Memory Access
// ============================================================================

uint8_t *Emulator::resolve_addr(uint32_t addr, bool write) {
  if (uint8_t *page = fast_page[addr >> 16]) {
    return page + (addr & 0xFFFF);
  }
  // MMIO at 0xB8000000
  if (addr >= 0xB8000000 && addr < 0xB8000000 + MMIO_SIZE) {
    return &mmio[addr - 0xB8000000];
  }
  // MMIO at 0x98000000
  if (addr >= 0x98000000 && addr < 0x98000000 + MMIO_SIZE) {
    return &mmio[addr - 0x98000000];
  }
  // MMIO at 0x18000000
  if (addr >= 0x18000000 && addr < 0x18000000 + MMIO_SIZE) {
    return &mmio[addr - 0x18000000];
  }

  return nullptr;
}

uint8_t Emulator::mem_read8_slow(uint32_t addr) {
  // Check MMIO read hooks
  uint32_t mmio_off = 0xFFFFFFFF;
  if (addr >= 0xB8000000 && addr < 0xB8000000 + MMIO_SIZE)
    mmio_off = addr - 0xB8000000;
  else if (addr >= 0x98000000 && addr < 0x98000000 + MMIO_SIZE)
    mmio_off = addr - 0x98000000;
  else if (addr >= 0x18000000 && addr < 0x18000000 + MMIO_SIZE)
    mmio_off = addr - 0x18000000;

  if (mmio_off != 0xFFFFFFFF) {
    return mmio_read_hook(mmio_off);
  }

  log("WARNING: Read8 from unmapped address 0x%08X (PC=0x%08X)", addr, pc);
  return 0;
}

uint16_t Emulator::mem_read16_slow(uint32_t addr) {
  uint8_t *p = resolve_addr(addr);
  if (!p) {
    log("WARNING: Read16 from unmapped address 0x%08X (PC=0x%08X)", addr, pc);
    return 0;
  }
  return *(uint16_t *)p; // Little-endian host assumed
}

uint32_t Emulator::mem_read32_slow(uint32_t addr) {
  uint8_t *p = resolve_addr(addr);
  if (!p) {
    log("WARNING: Read32 from unmapped address 0x%08X (PC=0x%08X)", addr, pc);
    return 0;
  }
  return *(uint32_t *)p; // Little-endian host assumed
}

void Emulator::mem_write8_slow(uint32_t addr, uint8_t val) {
  // Check MMIO write hooks
  uint32_t mmio_off = 0xFFFFFFFF;
  if (addr >= 0xB8000000 && addr < 0xB8000000 + MMIO_SIZE)
    mmio_off = addr - 0xB8000000;
  else if (addr >= 0x98000000 && addr < 0x98000000 + MMIO_SIZE)
    mmio_off = addr - 0x98000000;
  else if (addr >= 0x18000000 && addr < 0x18000000 + MMIO_SIZE)
    mmio_off = addr - 0x18000000;

  if (mmio_off != 0xFFFFFFFF) {
    mmio[mmio_off] = val;
    mmio_write_hook(mmio_off, val);
    return;
  }

  log("WARNING: Write8 to unmapped address 0x%08X = 0x%02X (PC=0x%08X)", addr,
      val, pc);
}

void Emulator::mem_write16_slow(uint32_t addr, uint16_t val) {
  uint8_t *p = resolve_addr(addr, true);
  if (!p) {
    log("WARNING: Write16 to unmapped address 0x%08X = 0x%04X (PC=0x%08X)",
        addr, val, pc);
    return;
  }
  *(uint16_t *)p = val;

  // Check MMIO
  uint32_t mmio_off = 0xFFFFFFFF;
  if (addr >= 0xB8000000 && addr < 0xB8000000 + MMIO_SIZE)
    mmio_off = addr - 0xB8000000;
  else if (addr >= 0x98000000 && addr < 0x98000000 + MMIO_SIZE)
    mmio_off = addr - 0x98000000;
  else if (addr >= 0x18000000 && addr < 0x18000000 + MMIO_SIZE)
    mmio_off = addr - 0x18000000;

  if (mmio_off != 0xFFFFFFFF) {
    mmio_write_hook(mmio_off, val & 0xFF);
    mmio_write_hook(mmio_off + 1, (val >> 8) & 0xFF);
  }
}

void Emulator::mem_write32_slow(uint32_t addr, uint32_t val) {
  uint8_t *p = resolve_addr(addr, true);
  if (!p) {
    log("WARNING: Write32 to unmapped address 0x%08X = 0x%08X (PC=0x%08X)",
        addr, val, pc);
    return;
  }
  *(uint32_t *)p = val;

  // Check MMIO
  uint32_t mmio_off = 0xFFFFFFFF;
  if (addr >= 0xB8000000 && addr < 0xB8000000 + MMIO_SIZE)
    mmio_off = addr - 0xB8000000;
  else if (addr >= 0x98000000 && addr < 0x98000000 + MMIO_SIZE)
    mmio_off = addr - 0x98000000;
  else if (addr >= 0x18000000 && addr < 0x18000000 + MMIO_SIZE)
    mmio_off = addr - 0x18000000;

  if (mmio_off != 0xFFFFFFFF) {
    for (int i = 0; i < 4; i++) {
      mmio_write_hook(mmio_off + i, (val >> (i * 8)) & 0xFF);
    }
  }
}

// ============================================================================
// MMIO Hooks
// ============================================================================

void Emulator::mmio_write_hook(uint32_t mmio_offset, uint8_t val) {
  // UART TX data register at 0x18300
  if (mmio_offset == 0x18300) {
    if (uart_callback) {
      uart_callback((char)val);
    } else {
      putchar(val);
      fflush(stdout);
    }
    // Set UART LSR "transmitter empty" bit
    mmio[0x18305] = 0x20;
    return;
  }

  // ALi SPI Flash Controller registers at +0x2E090..0x2E09F / +0x00090..0x0009F
  uint32_t grp = mmio_offset & 0xFFFF0;
  if (grp == 0x2E090 || grp == 0x00090) {
    uint32_t reg = mmio_offset & 0xF;
    mmio[0x00090 | reg] = val;
    mmio[0x2E090 | reg] = val;
    if (reg == 0x8) { // SF_INS
      spi_ins = val;
      if (val == 0x9F) { // JEDEC Read ID (W25Q32 4MB: EF 40 16)
        rom[0] = 0xEF;
        rom[1] = 0x40;
        rom[2] = 0x16;
        rom[3] = 0x00;
        spi_injected = true;
      } else if (val == 0x05) { // Read Status Register (0 = ready)
        memset(rom, 0, 4);
        spi_injected = true;
      } else if (val == 0xAB) { // Electronic ID (0x15)
        memset(rom, 0x15, 4);
        spi_injected = true;
      } else if (val == 0x90) { // Manufacturer/Device ID
        rom[0] = 0xEF;
        rom[1] = 0x16;
        rom[2] = 0xEF;
        rom[3] = 0x16;
        spi_injected = true;
      } else if (spi_injected) {
        memcpy(rom, rom_head, 4);
        spi_injected = false;
      }
    } else if (reg == 0x9) {
      spi_fmt = val;
    } else if (reg == 0xA) {
      spi_dum = val;
    } else if (reg == 0xB) {
      spi_cfg = val;
    }
  }
}

uint8_t Emulator::mmio_read_hook(uint32_t mmio_offset) {
  // UART LSR — always ready
  if (mmio_offset == 0x18305) {
    return 0x20;
  }
  uint32_t grp = mmio_offset & 0xFFFF0;
  if (grp == 0x2E090 || grp == 0x00090) {
    uint32_t reg = mmio_offset & 0xF;
    if (reg == 0x8)
      return spi_ins;
    if (reg == 0x9)
      return spi_fmt;
    if (reg == 0xA)
      return spi_dum;
    if (reg == 0xB)
      return spi_cfg;
  }
  // Default: return stored value
  return mmio[mmio_offset];
}
