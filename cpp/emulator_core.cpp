#include "emulator.h"
#include <cstdarg>
#include <cstdlib>

// ============================================================================
// Constructor / Destructor
// ============================================================================

Emulator::Emulator() {
  memset(regs, 0, sizeof(regs));
  pc = 0;
  next_pc = 0;
  hi = lo = 0;

  cp0_status = 0x10400000; // CU0=1, BEV=1
  cp0_cause = 0;
  cp0_epc = 0;
  cp0_count = 0;
  cp0_compare = 0;

  memset(fpr, 0, sizeof(fpr));
  fcsr = 0;
  fpu_cc = false;

  in_delay_slot = false;
  instruction_count = 0;
  stopped = false;
  rom_loaded_size = 0;

  rom = new uint8_t[ROM_SIZE]();
  ram = new uint8_t[RAM_SIZE]();
  mmio = new uint8_t[MMIO_SIZE]();

  // Pre-initialize UART LSR to "transmitter ready"
  // UART base is at MMIO offset 0x18300, LSR at +5 = 0x18305
  mmio[0x18305] = 0x20;

  // Chip ID at MMIO offset 0x0002 = 0x3811 (little-endian)
  mmio[0x0002] = 0x11;
  mmio[0x0003] = 0x38;
}

Emulator::~Emulator() {
  delete[] rom;
  delete[] ram;
  delete[] mmio;
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

  rom_loaded_size = (uint32_t)size;
  pc = ROM_BASE;
  next_pc = pc + 4;
  instruction_count = 0;
  stopped = false;

  log("Loaded %s (%u bytes), PC = 0x%08X", filename, rom_loaded_size, pc);
}

int Emulator::run(int max_instructions) {
  log("Starting emulation at 0x%08X, max %d instructions", pc,
      max_instructions);
  stopped = false;

  while (!stopped && instruction_count < max_instructions) {
    // Fetch
    uint32_t insn = mem_read32(pc);

    // Advance PC (delay slot logic)
    uint32_t current_pc = pc;
    uint32_t current_next_pc = next_pc;
    pc = next_pc;
    next_pc = pc + 4;

    // Execute (may modify pc/next_pc for branches)
    execute_instruction(insn);

    // $0 is always zero
    regs[0] = 0;

    // Increment CP0 Count
    cp0_count += 2;

    instruction_count++;
  }

  log("Emulation stopped after %d instructions, PC = 0x%08X", instruction_count,
      pc);
  return instruction_count;
}
