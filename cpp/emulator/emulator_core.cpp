#include "emulator.h"
#include <cstdarg>
#include <cstdlib>

// ============================================================================
// Constructor / Destructor
// ============================================================================

static uint8_t *s_pool_rom = nullptr;
static uint32_t s_pool_rom_dirty = 0;
static uint8_t *s_pool_ram = nullptr;
static uint8_t *s_pool_mmio = nullptr;

Emulator::Emulator() {
  memset(regs, 0, sizeof(regs));
  pc = 0;
  next_pc = 0;
  hi = lo = 0;
  isa_mode = false;
  next_isa_mode = false;

  cp0_status = 0x10400000; // CU0=1, BEV=1
  cp0_cause = 0;
  cp0_epc = 0;
  cp0_count = 0;
  cp0_compare = 0;
  cp0_ebase = 0x80000000;

  memset(fpr, 0, sizeof(fpr));
  fcsr = 0;
  fpu_cc = false;

  in_delay_slot = false;
  instruction_count = 0;
  stopped = false;
  rom_loaded_size = 0;
  memset(rom_head, 0, sizeof(rom_head));
  spi_injected = false;
  spi_ins = 0x03;
  spi_fmt = 0x0D;
  spi_dum = 0;
  spi_cfg = 0;

  if (s_pool_rom) {
    rom = s_pool_rom;
    s_pool_rom = nullptr;
    rom_loaded_size = s_pool_rom_dirty;
  } else {
    rom = static_cast<uint8_t *>(calloc(1, ROM_SIZE));
  }
  if (s_pool_ram) {
    ram = s_pool_ram;
    s_pool_ram = nullptr;
    memset(ram, 0, 0x02200000);
  } else {
    ram = static_cast<uint8_t *>(calloc(1, RAM_SIZE));
  }
  if (s_pool_mmio) {
    mmio = s_pool_mmio;
    s_pool_mmio = nullptr;
    memset(mmio, 0, 0x40000);
  } else {
    mmio = static_cast<uint8_t *>(calloc(1, MMIO_SIZE));
  }

  memset(fast_page, 0, sizeof(fast_page));
  static const uint32_t kRomBases[] = {
      0x0FC00000, 0x1FC00000, 0x8FC00000,
      0x9FC00000, 0xAFC00000, 0xBFC00000,
  };
  for (uint32_t base : kRomBases) {
    uint32_t max_win = 0x10000000 - (base & 0x0FFFFFFF);
    uint32_t limit = ROM_SIZE < max_win ? ROM_SIZE : max_win;
    for (uint32_t off = 0; off < limit; off += 0x10000) {
      fast_page[(base + off) >> 16] = rom + off;
    }
  }
  for (uint32_t off = 0; off < RAM_SIZE; off += 0x10000) {
    fast_page[off >> 16] = ram + off;
    fast_page[(0x80000000 + off) >> 16] = ram + off;
    fast_page[(0xA0000000 + off) >> 16] = ram + off;
  }

  // Pre-initialize UART LSR to "transmitter ready"
  // UART base is at MMIO offset 0x18300, LSR at +5 = 0x18305
  mmio[0x18305] = 0x20;

  // Chip ID at MMIO offset 0x0002 = 0x3811 (little-endian)
  mmio[0x0002] = 0x11;
  mmio[0x0003] = 0x38;
}

Emulator::~Emulator() {
  if (spi_injected && rom) {
    memcpy(rom, rom_head, 4);
    spi_injected = false;
  }
  if (!s_pool_rom) {
    s_pool_rom = rom;
    s_pool_rom_dirty = rom_loaded_size;
  } else {
    free(rom);
  }
  if (!s_pool_ram) {
    s_pool_ram = ram;
  } else {
    free(ram);
  }
  if (!s_pool_mmio) {
    s_pool_mmio = mmio;
  } else {
    free(mmio);
  }
}

// ============================================================================
// Logging
// ============================================================================

void Emulator::log(const char *fmt, ...) {
  char buf[1024];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  if (log_callback) {
    log_callback(buf);
  } else {
    printf("%s\n", buf);
  }
}

// ============================================================================
// Public API
// ============================================================================

void Emulator::setUartHandler(std::function<void(char)> handler) {
  uart_callback = handler;
}

void Emulator::setLogHandler(std::function<void(const char *)> handler) {
  log_callback = handler;
}

void Emulator::loadFile(const char *filename) {
  FILE *f = fopen(filename, "rb");
  if (!f && (strncmp(filename, "../", 3) == 0 || strncmp(filename, "..\\", 3) == 0)) {
    const char *rel = filename + 3;
    const char *prefixes[] = {"", "../../", "../../../"};
    for (const char *p : prefixes) {
      std::string alt = std::string(p) + rel;
      f = fopen(alt.c_str(), "rb");
      if (f)
        break;
    }
  }
  if (!f) {
    log("ERROR: Cannot open file: %s", filename);
    return;
  }

  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (size > (long)ROM_SIZE) {
    log("WARNING: File size %ld exceeds ROM size %u, truncating", size,
        ROM_SIZE);
    size = ROM_SIZE;
  }

  fread(rom, 1, size, f);
  fclose(f);
  if ((uint32_t)size < rom_loaded_size) {
    memset(rom + size, 0, rom_loaded_size - (uint32_t)size);
  }

  rom_loaded_size = (uint32_t)size;
  memcpy(rom_head, rom, 4);
  spi_injected = false;
  spi_ins = 0x03;
  spi_fmt = 0x0D;
  pc = ROM_BASE;
  next_pc = pc + 4;
  isa_mode = false;
  next_isa_mode = false;
  instruction_count = 0;
  stopped = false;

  log("Loaded %s (%u bytes), PC = 0x%08X", filename, rom_loaded_size, pc);
}

int Emulator::run(int max_instructions) {
  log("Starting emulation at 0x%08X, max %d instructions", pc,
      max_instructions);
  stopped = false;

  uint32_t fetch_tag = 0xFFFFFFFF;
  uint8_t *fetch_page = nullptr;

  while (!stopped && instruction_count < max_instructions) {
    uint32_t tag = pc >> 16;
    if (tag != fetch_tag) {
      fetch_tag = tag;
      fetch_page = fast_page[tag];
    }

    if (!isa_mode) {
      uint32_t insn = fetch_page ? *(uint32_t *)(fetch_page + (pc & 0xFFFF))
                                 : mem_read32_slow(pc);
      pc = next_pc;
      isa_mode = next_isa_mode;
      next_pc = pc + (isa_mode ? 2 : 4);
      execute_instruction(insn);
    } else {
      uint32_t insn_pc = pc;
      uint16_t insn16 = fetch_page ? *(uint16_t *)(fetch_page + (pc & 0xFFFF))
                                   : mem_read16_slow(pc);
      pc = next_pc;
      isa_mode = next_isa_mode;
      next_pc = pc + (isa_mode ? 2 : 4);
      execute_mips16(insn16, insn_pc);
    }

    regs[0] = 0;
    cp0_count += 2;
    instruction_count++;
  }

  log("Emulation stopped after %d instructions, PC = 0x%08X", instruction_count,
      pc);
  return instruction_count;
}

// ============================================================================
// Public Memory Access
// ============================================================================

uint8_t Emulator::readMem8(uint32_t addr) { return mem_read8(addr); }

uint32_t Emulator::readMem32(uint32_t addr) { return mem_read32(addr); }

int Emulator::readMem(uint32_t addr, uint8_t *buf, int size) {
  for (int i = 0; i < size; i++) {
    uint8_t *p = resolve_addr(addr + i);
    if (!p)
      return i;
    buf[i] = *p;
  }
  return size;
}

// ============================================================================
// Run Until
// ============================================================================

int Emulator::runUntil(uint32_t stop_addr, int max_instructions) {
  stopped = false;
  int count = 0;
  stop_addr &= ~1u;

  uint32_t fetch_tag = 0xFFFFFFFF;
  uint8_t *fetch_page = nullptr;

  while (!stopped && count < max_instructions) {
    if (pc == stop_addr)
      break;

    uint32_t tag = pc >> 16;
    if (tag != fetch_tag) {
      fetch_tag = tag;
      fetch_page = fast_page[tag];
    }

    if (!isa_mode) {
      uint32_t insn = fetch_page ? *(uint32_t *)(fetch_page + (pc & 0xFFFF))
                                 : mem_read32_slow(pc);
      pc = next_pc;
      isa_mode = next_isa_mode;
      next_pc = pc + (isa_mode ? 2 : 4);
      execute_instruction(insn);
    } else {
      uint32_t insn_pc = pc;
      uint16_t insn16 = fetch_page ? *(uint16_t *)(fetch_page + (pc & 0xFFFF))
                                   : mem_read16_slow(pc);
      pc = next_pc;
      isa_mode = next_isa_mode;
      next_pc = pc + (isa_mode ? 2 : 4);
      execute_mips16(insn16, insn_pc);
    }

    regs[0] = 0;
    cp0_count += 2;
    instruction_count++;
    count++;
  }

  return count;
}
