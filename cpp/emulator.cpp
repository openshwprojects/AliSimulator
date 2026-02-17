#include "emulator.h"
#include <cmath>
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

// ============================================================================
// Branch Helpers
// ============================================================================

void Emulator::do_branch(uint32_t target) {
  // In MIPS, branches take effect after the delay slot.
  // At this point pc has already been advanced to pc+4 (the delay slot).
  // The delay slot will execute next, and then we go to target.
  // So we set next_pc = target. The delay slot instruction at 'pc' will run,
  // and after it, pc will become next_pc = target.
  next_pc = target;
  in_delay_slot = true;
}

void Emulator::do_branch_likely(uint32_t target, bool condition) {
  // Branch likely: if condition is true, execute delay slot and branch.
  // If condition is false, NULLIFY the delay slot (skip it).
  if (condition) {
    next_pc = target;
    in_delay_slot = true;
  } else {
    // Skip the delay slot entirely
    pc = pc + 4; // skip delay slot
    next_pc = pc + 4;
  }
}

// ============================================================================
// Unimplemented
// ============================================================================

void Emulator::unimplemented(uint32_t insn, const char *desc) {
  log("UNIMPLEMENTED @ PC=0x%08X: %s (insn=0x%08X)", pc - 4, desc, insn);
  stopped = true;
}

// ============================================================================
// Instruction Execution
// ============================================================================

void Emulator::execute_instruction(uint32_t insn) {
  uint32_t opcode = (insn >> 26) & 0x3F;

  switch (opcode) {
  case 0x00:
    exec_r_type(insn);
    break;     // SPECIAL
  case 0x01: { // REGIMM (bltz, bgez, bltzal, bgezal, etc.)
    uint32_t rt = (insn >> 16) & 0x1F;
    uint32_t rs = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t target = pc + (offset << 2); // pc already points to delay slot
    int32_t rs_val = (int32_t)regs[rs];

    switch (rt) {
    case 0x00: // BLTZ
      if (rs_val < 0)
        do_branch(target);
      break;
    case 0x01: // BGEZ
      if (rs_val >= 0)
        do_branch(target);
      break;
    case 0x02: // BLTZL
      do_branch_likely(target, rs_val < 0);
      break;
    case 0x03: // BGEZL
      do_branch_likely(target, rs_val >= 0);
      break;
    case 0x10:           // BLTZAL
      regs[31] = pc + 4; // return address (after delay slot)
      if (rs_val < 0)
        do_branch(target);
      break;
    case 0x11: // BGEZAL
      regs[31] = pc + 4;
      if (rs_val >= 0)
        do_branch(target);
      break;
    default:
      unimplemented(insn, "REGIMM unknown");
      break;
    }
    break;
  }
  case 0x02: // J
  case 0x03: // JAL
    exec_j_type(insn, opcode);
    break;
  case 0x04:
  case 0x05:
  case 0x06:
  case 0x07: // BEQ, BNE, BLEZ, BGTZ
  case 0x08:
  case 0x09:
  case 0x0A:
  case 0x0B: // ADDI, ADDIU, SLTI, SLTIU
  case 0x0C:
  case 0x0D:
  case 0x0E:
  case 0x0F: // ANDI, ORI, XORI, LUI
    exec_i_type(insn, opcode);
    break;
  case 0x10:
    exec_cop0(insn);
    break; // COP0
  case 0x11:
    exec_cop1(insn);
    break;     // COP1 (FPU)
  case 0x14: { // BEQL
    uint32_t rs = (insn >> 21) & 0x1F;
    uint32_t rt = (insn >> 16) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t target = pc + (offset << 2);
    do_branch_likely(target, regs[rs] == regs[rt]);
    break;
  }
  case 0x15: { // BNEL
    uint32_t rs = (insn >> 21) & 0x1F;
    uint32_t rt = (insn >> 16) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t target = pc + (offset << 2);
    do_branch_likely(target, regs[rs] != regs[rt]);
    break;
  }
  case 0x16: { // BLEZL
    uint32_t rs = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t target = pc + (offset << 2);
    do_branch_likely(target, (int32_t)regs[rs] <= 0);
    break;
  }
  case 0x17: { // BGTZL
    uint32_t rs = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t target = pc + (offset << 2);
    do_branch_likely(target, (int32_t)regs[rs] > 0);
    break;
  }
  case 0x1C:
    exec_special2(insn);
    break; // SPECIAL2 (mul, clz, clo)
  case 0x1F:
    exec_special3(insn);
    break; // SPECIAL3 (ext, ins, etc.)
  case 0x20:
  case 0x21:
  case 0x22:
  case 0x23: // LB, LH, LWL, LW
  case 0x24:
  case 0x25:
  case 0x26: // LBU, LHU, LWR
  case 0x28:
  case 0x29:
  case 0x2A:
  case 0x2B: // SB, SH, SWL, SW
  case 0x2E: // SWR
    exec_i_type(insn, opcode);
    break;
  case 0x30: // LL (Load Linked)
    exec_i_type(insn, opcode);
    break;
  case 0x31: { // LWC1
    uint32_t ft = (insn >> 16) & 0x1F;
    uint32_t base = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t addr = regs[base] + offset;
    fpr[ft].w = mem_read32(addr);
    break;
  }
  case 0x38: // SC (Store Conditional)
    exec_i_type(insn, opcode);
    break;
  case 0x39: { // SWC1
    uint32_t ft = (insn >> 16) & 0x1F;
    uint32_t base = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t addr = regs[base] + offset;
    mem_write32(addr, fpr[ft].w);
    break;
  }
  case 0x33: { // PREF (prefetch hint — NOP in emulator)
    break;
  }
  case 0x35: { // LDC1 (Load Double to FPU)
    uint32_t ft = (insn >> 16) & 0x1F;
    uint32_t base = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t addr = regs[base] + offset;
    fpr[ft & ~1].w = mem_read32(addr);    // low word
    fpr[ft | 1].w = mem_read32(addr + 4); // high word
    break;
  }
  case 0x3D: { // SDC1 (Store Double from FPU)
    uint32_t ft = (insn >> 16) & 0x1F;
    uint32_t base = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t addr = regs[base] + offset;
    mem_write32(addr, fpr[ft & ~1].w);    // low word
    mem_write32(addr + 4, fpr[ft | 1].w); // high word
    break;
  }
  default:
    unimplemented(insn, "unknown opcode");
    break;
  }
}

// ============================================================================
// R-Type (opcode = 0x00, SPECIAL)
// ============================================================================

void Emulator::exec_r_type(uint32_t insn) {
  uint32_t rs = (insn >> 21) & 0x1F;
  uint32_t rt = (insn >> 16) & 0x1F;
  uint32_t rd = (insn >> 11) & 0x1F;
  uint32_t sa = (insn >> 6) & 0x1F;
  uint32_t func = insn & 0x3F;

  switch (func) {
  case 0x00: // SLL
    regs[rd] = regs[rt] << sa;
    break;
  case 0x02: // SRL
    regs[rd] = regs[rt] >> sa;
    break;
  case 0x03: // SRA
    regs[rd] = (uint32_t)((int32_t)regs[rt] >> sa);
    break;
  case 0x04: // SLLV
    regs[rd] = regs[rt] << (regs[rs] & 0x1F);
    break;
  case 0x06: // SRLV
    regs[rd] = regs[rt] >> (regs[rs] & 0x1F);
    break;
  case 0x07: // SRAV
    regs[rd] = (uint32_t)((int32_t)regs[rt] >> (regs[rs] & 0x1F));
    break;
  case 0x08: // JR
    do_branch(regs[rs]);
    break;
  case 0x09:           // JALR
    regs[rd] = pc + 4; // return address after delay slot
    do_branch(regs[rs]);
    break;
  case 0x0A: // MOVZ
    if (regs[rt] == 0)
      regs[rd] = regs[rs];
    break;
  case 0x0B: // MOVN
    if (regs[rt] != 0)
      regs[rd] = regs[rs];
    break;
  case 0x0C: // SYSCALL
    log("SYSCALL at PC=0x%08X", pc - 4);
    break;
  case 0x0D: // BREAK
    log("BREAK at PC=0x%08X", pc - 4);
    stopped = true;
    break;
  case 0x0F: // SYNC
    break;   // NOP for emulator
  case 0x10: // MFHI
    regs[rd] = hi;
    break;
  case 0x11: // MTHI
    hi = regs[rs];
    break;
  case 0x12: // MFLO
    regs[rd] = lo;
    break;
  case 0x13: // MTLO
    lo = regs[rs];
    break;
  case 0x18: { // MULT
    int64_t result = (int64_t)(int32_t)regs[rs] * (int64_t)(int32_t)regs[rt];
    lo = (uint32_t)(result & 0xFFFFFFFF);
    hi = (uint32_t)((result >> 32) & 0xFFFFFFFF);
    break;
  }
  case 0x19: { // MULTU
    uint64_t result = (uint64_t)regs[rs] * (uint64_t)regs[rt];
    lo = (uint32_t)(result & 0xFFFFFFFF);
    hi = (uint32_t)((result >> 32) & 0xFFFFFFFF);
    break;
  }
  case 0x1A: { // DIV
    if (regs[rt] != 0) {
      lo = (uint32_t)((int32_t)regs[rs] / (int32_t)regs[rt]);
      hi = (uint32_t)((int32_t)regs[rs] % (int32_t)regs[rt]);
    }
    break;
  }
  case 0x1B: { // DIVU
    if (regs[rt] != 0) {
      lo = regs[rs] / regs[rt];
      hi = regs[rs] % regs[rt];
    }
    break;
  }
  case 0x20: // ADD (with overflow trap — we ignore overflow)
    regs[rd] = regs[rs] + regs[rt];
    break;
  case 0x21: // ADDU
    regs[rd] = regs[rs] + regs[rt];
    break;
  case 0x22: // SUB
    regs[rd] = regs[rs] - regs[rt];
    break;
  case 0x23: // SUBU
    regs[rd] = regs[rs] - regs[rt];
    break;
  case 0x24: // AND
    regs[rd] = regs[rs] & regs[rt];
    break;
  case 0x25: // OR
    regs[rd] = regs[rs] | regs[rt];
    break;
  case 0x26: // XOR
    regs[rd] = regs[rs] ^ regs[rt];
    break;
  case 0x27: // NOR
    regs[rd] = ~(regs[rs] | regs[rt]);
    break;
  case 0x2A: // SLT
    regs[rd] = ((int32_t)regs[rs] < (int32_t)regs[rt]) ? 1 : 0;
    break;
  case 0x2B: // SLTU
    regs[rd] = (regs[rs] < regs[rt]) ? 1 : 0;
    break;
  case 0x30: // TGE (trap if greater/equal — ignore traps in emulation)
    break;
  case 0x34: // TEQ (trap — ignore)
    break;
  default:
    unimplemented(insn, "R-type unknown func");
    break;
  }
}

// ============================================================================
// I-Type instructions
// ============================================================================

void Emulator::exec_i_type(uint32_t insn, uint32_t opcode) {
  uint32_t rs = (insn >> 21) & 0x1F;
  uint32_t rt = (insn >> 16) & 0x1F;
  int32_t imm_signed = (int16_t)(insn & 0xFFFF);
  uint32_t imm_unsigned = insn & 0xFFFF;

  switch (opcode) {
  // --- Branches ---
  case 0x04: { // BEQ
    uint32_t target = pc + (imm_signed << 2);
    if (regs[rs] == regs[rt])
      do_branch(target);
    break;
  }
  case 0x05: { // BNE
    uint32_t target = pc + (imm_signed << 2);
    if (regs[rs] != regs[rt])
      do_branch(target);
    break;
  }
  case 0x06: { // BLEZ
    uint32_t target = pc + (imm_signed << 2);
    if ((int32_t)regs[rs] <= 0)
      do_branch(target);
    break;
  }
  case 0x07: { // BGTZ
    uint32_t target = pc + (imm_signed << 2);
    if ((int32_t)regs[rs] > 0)
      do_branch(target);
    break;
  }

  // --- Arithmetic/Logic Immediates ---
  case 0x08: // ADDI (overflow trap ignored)
    regs[rt] = regs[rs] + imm_signed;
    break;
  case 0x09: // ADDIU
    regs[rt] = regs[rs] + imm_signed;
    break;
  case 0x0A: // SLTI
    regs[rt] = ((int32_t)regs[rs] < imm_signed) ? 1 : 0;
    break;
  case 0x0B: // SLTIU
    regs[rt] = (regs[rs] < (uint32_t)imm_signed) ? 1 : 0;
    break;
  case 0x0C: // ANDI
    regs[rt] = regs[rs] & imm_unsigned;
    break;
  case 0x0D: // ORI
    regs[rt] = regs[rs] | imm_unsigned;
    break;
  case 0x0E: // XORI
    regs[rt] = regs[rs] ^ imm_unsigned;
    break;
  case 0x0F: // LUI
    regs[rt] = imm_unsigned << 16;
    break;

  // --- Loads ---
  case 0x20: { // LB
    uint32_t addr = regs[rs] + imm_signed;
    regs[rt] = (uint32_t)(int32_t)(int8_t)mem_read8(addr);
    break;
  }
  case 0x21: { // LH
    uint32_t addr = regs[rs] + imm_signed;
    regs[rt] = (uint32_t)(int32_t)(int16_t)mem_read16(addr);
    break;
  }
  case 0x22: { // LWL
    uint32_t addr = regs[rs] + imm_signed;
    uint32_t aligned = addr & ~3;
    uint32_t word = mem_read32(aligned);
    int shift = (addr & 3);
    // Little-endian LWL
    switch (shift) {
    case 0:
      regs[rt] = (regs[rt] & 0x00FFFFFF) | (word << 24);
      break;
    case 1:
      regs[rt] = (regs[rt] & 0x0000FFFF) | (word << 16);
      break;
    case 2:
      regs[rt] = (regs[rt] & 0x000000FF) | (word << 8);
      break;
    case 3:
      regs[rt] = word;
      break;
    }
    break;
  }
  case 0x23: { // LW
    uint32_t addr = regs[rs] + imm_signed;
    regs[rt] = mem_read32(addr);
    break;
  }
  case 0x24: { // LBU
    uint32_t addr = regs[rs] + imm_signed;
    regs[rt] = mem_read8(addr);
    break;
  }
  case 0x25: { // LHU
    uint32_t addr = regs[rs] + imm_signed;
    regs[rt] = mem_read16(addr);
    break;
  }
  case 0x26: { // LWR
    uint32_t addr = regs[rs] + imm_signed;
    uint32_t aligned = addr & ~3;
    uint32_t word = mem_read32(aligned);
    int shift = (addr & 3);
    // Little-endian LWR
    switch (shift) {
    case 0:
      regs[rt] = word;
      break;
    case 1:
      regs[rt] = (regs[rt] & 0xFF000000) | (word >> 8);
      break;
    case 2:
      regs[rt] = (regs[rt] & 0xFFFF0000) | (word >> 16);
      break;
    case 3:
      regs[rt] = (regs[rt] & 0xFFFFFF00) | (word >> 24);
      break;
    }
    break;
  }

  // --- Stores ---
  case 0x28: { // SB
    uint32_t addr = regs[rs] + imm_signed;
    mem_write8(addr, (uint8_t)(regs[rt] & 0xFF));
    break;
  }
  case 0x29: { // SH
    uint32_t addr = regs[rs] + imm_signed;
    mem_write16(addr, (uint16_t)(regs[rt] & 0xFFFF));
    break;
  }
  case 0x2A: { // SWL
    uint32_t addr = regs[rs] + imm_signed;
    uint32_t aligned = addr & ~3;
    uint32_t word = mem_read32(aligned);
    int shift = (addr & 3);
    switch (shift) {
    case 0:
      word = (word & 0xFFFFFF00) | (regs[rt] >> 24);
      break;
    case 1:
      word = (word & 0xFFFF0000) | (regs[rt] >> 16);
      break;
    case 2:
      word = (word & 0xFF000000) | (regs[rt] >> 8);
      break;
    case 3:
      word = regs[rt];
      break;
    }
    mem_write32(aligned, word);
    break;
  }
  case 0x2B: { // SW
    uint32_t addr = regs[rs] + imm_signed;
    mem_write32(addr, regs[rt]);
    break;
  }
  case 0x2E: { // SWR
    uint32_t addr = regs[rs] + imm_signed;
    uint32_t aligned = addr & ~3;
    uint32_t word = mem_read32(aligned);
    int shift = (addr & 3);
    switch (shift) {
    case 0:
      word = regs[rt];
      break;
    case 1:
      word = (word & 0x000000FF) | (regs[rt] << 8);
      break;
    case 2:
      word = (word & 0x0000FFFF) | (regs[rt] << 16);
      break;
    case 3:
      word = (word & 0x00FFFFFF) | (regs[rt] << 24);
      break;
    }
    mem_write32(aligned, word);
    break;
  }

  // --- Atomic ---
  case 0x30: { // LL (Load Linked — treat as LW for now)
    uint32_t addr = regs[rs] + imm_signed;
    regs[rt] = mem_read32(addr);
    break;
  }
  case 0x38: { // SC (Store Conditional — always succeed)
    uint32_t addr = regs[rs] + imm_signed;
    mem_write32(addr, regs[rt]);
    regs[rt] = 1; // Always succeed
    break;
  }

  default:
    unimplemented(insn, "I-type unknown");
    break;
  }
}

// ============================================================================
// J-Type
// ============================================================================

void Emulator::exec_j_type(uint32_t insn, uint32_t opcode) {
  uint32_t target_raw = insn & 0x03FFFFFF;
  // Target = top 4 bits of delay-slot PC | (target_raw << 2)
  uint32_t target = (pc & 0xF0000000) | (target_raw << 2);

  if (opcode == 0x03) { // JAL
    regs[31] = pc + 4;  // return address (after delay slot)
  }
  do_branch(target);
}

// ============================================================================
// COP0
// ============================================================================

void Emulator::exec_cop0(uint32_t insn) {
  uint32_t rs = (insn >> 21) & 0x1F;
  uint32_t rt = (insn >> 16) & 0x1F;
  uint32_t rd = (insn >> 11) & 0x1F;

  switch (rs) {
  case 0x00: // MFC0: rt = CP0[rd]
    switch (rd) {
    case 9:
      regs[rt] = cp0_count;
      break;
    case 11:
      regs[rt] = cp0_compare;
      break;
    case 12:
      regs[rt] = cp0_status;
      break;
    case 13:
      regs[rt] = cp0_cause;
      break;
    case 14:
      regs[rt] = cp0_epc;
      break;
    case 15:
      regs[rt] = 0x00019300;
      break; // PRId (MIPS 24K)
    case 16:
      regs[rt] = 0x80000000;
      break; // Config0
    default:
      regs[rt] = 0;
      break;
    }
    break;
  case 0x04: // MTC0: CP0[rd] = rt
    switch (rd) {
    case 9:
      cp0_count = regs[rt];
      break;
    case 11:
      cp0_compare = regs[rt];
      break;
    case 12:
      cp0_status = regs[rt];
      break;
    case 13:
      cp0_cause = regs[rt];
      break;
    case 14:
      cp0_epc = regs[rt];
      break;
    default:
      break; // Ignore writes to unimplemented CP0 regs
    }
    break;
  case 0x10: // CO (ERET, TLBWI, etc.)
    if ((insn & 0x3F) == 0x18) {
      // ERET
      pc = cp0_epc;
      next_pc = pc + 4;
    } else if ((insn & 0x3F) == 0x20) {
      // WAIT — just NOP
    }
    // Other TLB ops — ignore
    break;
  default:
    unimplemented(insn, "COP0 unknown rs");
    break;
  }
}

// ============================================================================
// COP1 (FPU)
// ============================================================================

void Emulator::exec_cop1(uint32_t insn) {
  uint32_t fmt = (insn >> 21) & 0x1F;
  uint32_t ft = (insn >> 16) & 0x1F;
  uint32_t fs = (insn >> 11) & 0x1F;
  uint32_t fd = (insn >> 6) & 0x1F;
  uint32_t func = insn & 0x3F;

  switch (fmt) {
  case 0x00: // MFC1: rt = FPR[fs]
    regs[ft] = fpr[fs].w;
    break;
  case 0x04: // MTC1: FPR[fs] = rt
    fpr[fs].w = regs[ft];
    break;
  case 0x02: // CFC1: rt = FCSR (if fs==31)
    if (fs == 31)
      regs[ft] = fcsr;
    else if (fs == 0)
      regs[ft] = 0; // FIR
    break;
  case 0x06: // CTC1: FCSR = rt (if fs==31)
    if (fs == 31) {
      fcsr = regs[ft];
      fpu_cc = (fcsr >> 23) & 1;
    }
    break;
  case 0x08: { // BC1 (branch on FPU condition)
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t target = pc + (offset << 2);
    bool cc = fpu_cc;
    switch (ft & 0x03) {
    case 0x00: // BC1F
      if (!cc)
        do_branch(target);
      break;
    case 0x01: // BC1T
      if (cc)
        do_branch(target);
      break;
    case 0x02: // BC1FL
      do_branch_likely(target, !cc);
      break;
    case 0x03: // BC1TL
      do_branch_likely(target, cc);
      break;
    }
    break;
  }
  case 0x10: { // FMT = S (single precision)
    float fs_val = fpr[fs].f;
    float ft_val = fpr[ft].f;

    switch (func) {
    case 0x00:
      fpr[fd].f = fs_val + ft_val;
      break; // ADD.S
    case 0x01:
      fpr[fd].f = fs_val - ft_val;
      break; // SUB.S
    case 0x02:
      fpr[fd].f = fs_val * ft_val;
      break;   // MUL.S
    case 0x03: // DIV.S
      if (ft_val != 0.0f)
        fpr[fd].f = fs_val / ft_val;
      break;
    case 0x04:
      fpr[fd].f = sqrtf(fs_val);
      break; // SQRT.S
    case 0x05:
      fpr[fd].f = fabsf(fs_val);
      break; // ABS.S
    case 0x06:
      fpr[fd].f = fs_val;
      break; // MOV.S
    case 0x07:
      fpr[fd].f = -fs_val;
      break;     // NEG.S
    case 0x0C: { // ROUND.W.S
      int32_t r = (int32_t)roundf(fs_val);
      fpr[fd].w = (uint32_t)r;
      break;
    }
    case 0x0D: { // TRUNC.W.S
      int32_t r = (int32_t)fs_val;
      fpr[fd].w = (uint32_t)r;
      break;
    }
    case 0x0E: { // CEIL.W.S
      int32_t r = (int32_t)ceilf(fs_val);
      fpr[fd].w = (uint32_t)r;
      break;
    }
    case 0x0F: { // FLOOR.W.S
      int32_t r = (int32_t)floorf(fs_val);
      fpr[fd].w = (uint32_t)r;
      break;
    }
    case 0x21: { // CVT.D.S — convert single to double
      write_fpr_double(fd, (double)fs_val);
      break;
    }
    case 0x24: { // CVT.W.S
      int32_t r = (int32_t)fs_val;
      fpr[fd].w = (uint32_t)r;
      break;
    }
    // Condition codes (C.cond.S)
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
    case 0x37:
    case 0x38:
    case 0x39:
    case 0x3A:
    case 0x3B:
    case 0x3C:
    case 0x3D:
    case 0x3E:
    case 0x3F: {
      uint32_t cond = func & 0x0F;
      bool result = false;
      bool unordered = (fs_val != fs_val) || (ft_val != ft_val); // NaN check
      if (unordered) {
        result = (cond & 0x01) != 0; // UN bit
      } else {
        bool eq = (fs_val == ft_val);
        bool lt = (fs_val < ft_val);
        if ((cond & 0x04) && lt)
          result = true; // LT bit
        if ((cond & 0x02) && eq)
          result = true; // EQ bit
      }
      fpu_cc = result;
      if (result)
        fcsr |= (1 << 23);
      else
        fcsr &= ~(1 << 23);
      break;
    }
    default:
      unimplemented(insn, "COP1 S-format unknown func");
      break;
    }
    break;
  }
  case 0x11: { // FMT = D (double precision)
    double fs_dval = read_fpr_double(fs);
    double ft_dval = read_fpr_double(ft);

    switch (func) {
    case 0x00:
      write_fpr_double(fd, fs_dval + ft_dval);
      break; // ADD.D
    case 0x01:
      write_fpr_double(fd, fs_dval - ft_dval);
      break; // SUB.D
    case 0x02:
      write_fpr_double(fd, fs_dval * ft_dval);
      break;   // MUL.D
    case 0x03: // DIV.D
      if (ft_dval != 0.0)
        write_fpr_double(fd, fs_dval / ft_dval);
      break;
    case 0x04:
      write_fpr_double(fd, sqrt(fs_dval));
      break; // SQRT.D
    case 0x05:
      write_fpr_double(fd, fabs(fs_dval));
      break; // ABS.D
    case 0x06:
      write_fpr_double(fd, fs_dval);
      break; // MOV.D
    case 0x07:
      write_fpr_double(fd, -fs_dval);
      break;     // NEG.D
    case 0x0C: { // ROUND.W.D
      int32_t r = (int32_t)round(fs_dval);
      fpr[fd].w = (uint32_t)r;
      break;
    }
    case 0x0D: { // TRUNC.W.D
      int32_t r = (int32_t)fs_dval;
      fpr[fd].w = (uint32_t)r;
      break;
    }
    case 0x0E: { // CEIL.W.D
      int32_t r = (int32_t)ceil(fs_dval);
      fpr[fd].w = (uint32_t)r;
      break;
    }
    case 0x0F: { // FLOOR.W.D
      int32_t r = (int32_t)floor(fs_dval);
      fpr[fd].w = (uint32_t)r;
      break;
    }
    case 0x20: { // CVT.S.D
      fpr[fd].f = (float)fs_dval;
      break;
    }
    case 0x24: { // CVT.W.D
      int32_t r = (int32_t)fs_dval;
      fpr[fd].w = (uint32_t)r;
      break;
    }
    // Condition codes (C.cond.D)
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
    case 0x37:
    case 0x38:
    case 0x39:
    case 0x3A:
    case 0x3B:
    case 0x3C:
    case 0x3D:
    case 0x3E:
    case 0x3F: {
      uint32_t cond = func & 0x0F;
      bool result = false;
      bool unordered = (fs_dval != fs_dval) || (ft_dval != ft_dval);
      if (unordered) {
        result = (cond & 0x01) != 0;
      } else {
        bool eq = (fs_dval == ft_dval);
        bool lt = (fs_dval < ft_dval);
        if ((cond & 0x04) && lt)
          result = true;
        if ((cond & 0x02) && eq)
          result = true;
      }
      fpu_cc = result;
      if (result)
        fcsr |= (1 << 23);
      else
        fcsr &= ~(1 << 23);
      break;
    }
    default:
      unimplemented(insn, "COP1 D-format unknown func");
      break;
    }
    break;
  }
  case 0x14: { // FMT = W (word, integer in FPR)
    switch (func) {
    case 0x20: { // CVT.S.W
      int32_t int_val = (int32_t)fpr[fs].w;
      fpr[fd].f = (float)int_val;
      break;
    }
    case 0x21: { // CVT.D.W — double from int
      int32_t int_val = (int32_t)fpr[fs].w;
      write_fpr_double(fd, (double)int_val);
      break;
    }
    default:
      unimplemented(insn, "COP1 W-format unknown func");
      break;
    }
    break;
  }
  default:
    unimplemented(insn, "COP1 unknown fmt");
    break;
  }
}

// ============================================================================
// SPECIAL2 (opcode 0x1C)
// ============================================================================

void Emulator::exec_special2(uint32_t insn) {
  uint32_t rs = (insn >> 21) & 0x1F;
  uint32_t rt = (insn >> 16) & 0x1F;
  uint32_t rd = (insn >> 11) & 0x1F;
  uint32_t func = insn & 0x3F;

  switch (func) {
  case 0x02: // MUL (rd = rs * rt, no HI/LO)
    regs[rd] = (uint32_t)((int32_t)regs[rs] * (int32_t)regs[rt]);
    break;
  case 0x00: { // MADD
    int64_t hilo = ((int64_t)(int32_t)hi << 32) | (uint32_t)lo;
    hilo += (int64_t)(int32_t)regs[rs] * (int64_t)(int32_t)regs[rt];
    lo = (uint32_t)(hilo & 0xFFFFFFFF);
    hi = (uint32_t)((hilo >> 32) & 0xFFFFFFFF);
    break;
  }
  case 0x01: { // MADDU
    uint64_t hilo = ((uint64_t)hi << 32) | (uint32_t)lo;
    hilo += (uint64_t)regs[rs] * (uint64_t)regs[rt];
    lo = (uint32_t)(hilo & 0xFFFFFFFF);
    hi = (uint32_t)((hilo >> 32) & 0xFFFFFFFF);
    break;
  }
  case 0x04: { // MSUB
    int64_t hilo = ((int64_t)(int32_t)hi << 32) | (uint32_t)lo;
    hilo -= (int64_t)(int32_t)regs[rs] * (int64_t)(int32_t)regs[rt];
    lo = (uint32_t)(hilo & 0xFFFFFFFF);
    hi = (uint32_t)((hilo >> 32) & 0xFFFFFFFF);
    break;
  }
  case 0x20: { // CLZ
    if (regs[rs] == 0)
      regs[rd] = 32;
    else {
      uint32_t n = 0, val = regs[rs];
      while (!(val & 0x80000000)) {
        n++;
        val <<= 1;
      }
      regs[rd] = n;
    }
    break;
  }
  case 0x21: { // CLO
    uint32_t val = regs[rs];
    if (val == 0xFFFFFFFF)
      regs[rd] = 32;
    else {
      uint32_t n = 0;
      while (val & 0x80000000) {
        n++;
        val <<= 1;
      }
      regs[rd] = n;
    }
    break;
  }
  default:
    unimplemented(insn, "SPECIAL2 unknown func");
    break;
  }
}

// ============================================================================
// SPECIAL3 (opcode 0x1F)
// ============================================================================

void Emulator::exec_special3(uint32_t insn) {
  uint32_t rs = (insn >> 21) & 0x1F;
  uint32_t rt = (insn >> 16) & 0x1F;
  uint32_t msbd = (insn >> 11) & 0x1F;
  uint32_t lsb = (insn >> 6) & 0x1F;
  uint32_t func = insn & 0x3F;

  switch (func) {
  case 0x00: { // EXT (Extract Bit Field)
    uint32_t size = msbd + 1;
    uint32_t mask = (size == 32) ? 0xFFFFFFFF : ((1u << size) - 1);
    regs[rt] = (regs[rs] >> lsb) & mask;
    break;
  }
  case 0x04: { // INS (Insert Bit Field)
    uint32_t msb = msbd;
    uint32_t size = msb - lsb + 1;
    uint32_t mask = (size == 32) ? 0xFFFFFFFF : ((1u << size) - 1);
    regs[rt] = (regs[rt] & ~(mask << lsb)) | ((regs[rs] & mask) << lsb);
    break;
  }
  case 0x3B: { // RDHWR (read hardware register)
    uint32_t rd = (insn >> 11) & 0x1F;
    switch (rd) {
    case 29:
      regs[rt] = 0;
      break; // ULR (User local register)
    default:
      regs[rt] = 0;
      break;
    }
    break;
  }
  case 0x20: { // BSHFL
    uint32_t rd = (insn >> 11) & 0x1F;
    uint32_t sa = (insn >> 6) & 0x1F;
    switch (sa) {
    case 0x02: { // WSBH (Word Swap Bytes Within Halfwords)
      uint32_t val = regs[rt];
      regs[rd] = ((val & 0x00FF00FF) << 8) | ((val & 0xFF00FF00) >> 8);
      break;
    }
    case 0x10: // SEB (Sign Extend Byte)
      regs[(insn >> 11) & 0x1F] = (uint32_t)(int32_t)(int8_t)(regs[rt] & 0xFF);
      break;
    case 0x18: // SEH (Sign Extend Halfword)
      regs[(insn >> 11) & 0x1F] =
          (uint32_t)(int32_t)(int16_t)(regs[rt] & 0xFFFF);
      break;
    default:
      unimplemented(insn, "BSHFL unknown sa");
      break;
    }
    break;
  }
  default:
    unimplemented(insn, "SPECIAL3 unknown func");
    break;
  }
}
