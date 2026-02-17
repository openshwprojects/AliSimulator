#include "emulator.h"

// ============================================================================
// Memory Access
// ============================================================================

uint8_t *Emulator::resolve_addr(uint32_t addr, bool write) {
  // ROM: 0xAFC00000 - 0xB03FFFFF
  if (addr >= ROM_BASE && addr < ROM_BASE + ROM_SIZE) {
    return &rom[addr - ROM_BASE];
  }
  // ROM mirror: 0x0FC00000 - 0x103FFFFF
  if (addr >= ROM_MIRROR && addr < ROM_MIRROR + ROM_SIZE) {
    return &rom[addr - ROM_MIRROR];
  }

  // RAM at 0x80000000
  if (addr >= 0x80000000 && addr < 0x80000000 + RAM_SIZE) {
    return &ram[addr - 0x80000000];
  }
  // RAM at 0xA0000000
  if (addr >= 0xA0000000 && addr < 0xA0000000 + RAM_SIZE) {
    return &ram[addr - 0xA0000000];
  }
  // RAM at 0x00000000
  if (addr < RAM_SIZE) {
    return &ram[addr];
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

uint8_t Emulator::mem_read8(uint32_t addr) {
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

  uint8_t *p = resolve_addr(addr);
  if (!p) {
    log("WARNING: Read8 from unmapped address 0x%08X (PC=0x%08X)", addr, pc);
    return 0;
  }
  return *p;
}

uint16_t Emulator::mem_read16(uint32_t addr) {
  uint8_t *p = resolve_addr(addr);
  if (!p) {
    log("WARNING: Read16 from unmapped address 0x%08X (PC=0x%08X)", addr, pc);
    return 0;
  }
  return *(uint16_t *)p; // Little-endian host assumed
}

uint32_t Emulator::mem_read32(uint32_t addr) {
  uint8_t *p = resolve_addr(addr);
  if (!p) {
    log("WARNING: Read32 from unmapped address 0x%08X (PC=0x%08X)", addr, pc);
    return 0;
  }
  return *(uint32_t *)p; // Little-endian host assumed
}

void Emulator::mem_write8(uint32_t addr, uint8_t val) {
  // Check MMIO write hooks
  uint32_t mmio_off = 0xFFFFFFFF;
  if (addr >= 0xB8000000 && addr < 0xB8000000 + MMIO_SIZE)
    mmio_off = addr - 0xB8000000;
  else if (addr >= 0x98000000 && addr < 0x98000000 + MMIO_SIZE)
    mmio_off = addr - 0x98000000;
  else if (addr >= 0x18000000 && addr < 0x18000000 + MMIO_SIZE)
    mmio_off = addr - 0x18000000;

  if (mmio_off != 0xFFFFFFFF) {
    mmio_write_hook(mmio_off, val);
  }

  uint8_t *p = resolve_addr(addr, true);
  if (!p) {
    log("WARNING: Write8 to unmapped address 0x%08X = 0x%02X (PC=0x%08X)", addr,
        val, pc);
    return;
  }
  *p = val;
}

void Emulator::mem_write16(uint32_t addr, uint16_t val) {
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

void Emulator::mem_write32(uint32_t addr, uint32_t val) {
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
  }
}

uint8_t Emulator::mmio_read_hook(uint32_t mmio_offset) {
  // UART LSR — always ready
  if (mmio_offset == 0x18305) {
    return 0x20;
  }
  // Default: return stored value
  return mmio[mmio_offset];
}
