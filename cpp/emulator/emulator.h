#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>

class Emulator {
public:
  Emulator();
  ~Emulator();

  // Load a binary file into ROM at base_addr
  void loadFile(const char *filename);

  // Run up to max_instructions, returns number executed
  int run(int max_instructions = 10000000);

  // Set UART output callback
  void setUartHandler(std::function<void(char)> handler);

  // Set log callback (for emulator status messages)
  void setLogHandler(std::function<void(const char *)> handler);

  // Read a GPR
  uint32_t getReg(int index) const { return regs[index]; }

  // Read PC
  uint32_t getPC() const { return pc; }

  // Instruction count
  int getInstructionCount() const { return instruction_count; }

  // Read memory at virtual address (returns 0 for unmapped)
  uint8_t readMem8(uint32_t addr);
  uint32_t readMem32(uint32_t addr);
  // Read a block of memory into a buffer, returns bytes read
  int readMem(uint32_t addr, uint8_t *buf, int size);

  // Run until PC reaches stop_addr (or max_instructions), returns instruction
  // count
  int runUntil(uint32_t stop_addr, int max_instructions = 1000000);

private:
  // ---- CPU State ----
  uint32_t regs[32]; // General Purpose Registers ($0 is always 0)
  uint32_t pc;       // Program Counter
  uint32_t next_pc;  // Next PC (for delay slot handling)
  uint32_t hi, lo;   // HI/LO for mult/div

  // CP0 registers
  uint32_t cp0_status;  // CP0 reg 12
  uint32_t cp0_cause;   // CP0 reg 13
  uint32_t cp0_epc;     // CP0 reg 14
  uint32_t cp0_count;   // CP0 reg 9
  uint32_t cp0_compare; // CP0 reg 11

  // FPU state
  union FPR {
    float f;
    uint32_t w;
  };
  FPR fpr[32];   // FP registers
  uint32_t fcsr; // FP control/status register (condition bit in bit 23)
  bool fpu_cc;   // FP condition code (cached from FCSR bit 23)

  // Double-precision helpers (MIPS uses even/odd register pairs)
  double read_fpr_double(int reg) {
    uint64_t val = ((uint64_t)fpr[reg | 1].w << 32) | fpr[reg & ~1].w;
    double d;
    memcpy(&d, &val, 8);
    return d;
  }
  void write_fpr_double(int reg, double d) {
    uint64_t val;
    memcpy(&val, &d, 8);
    fpr[reg & ~1].w = (uint32_t)(val & 0xFFFFFFFF);
    fpr[reg | 1].w = (uint32_t)(val >> 32);
  }

  bool in_delay_slot; // True if current instruction is in a delay slot
  int instruction_count;
  bool stopped;

  // ---- Memory ----
  static const uint32_t ROM_BASE = 0xAFC00000;
  static const uint32_t ROM_MIRROR = 0x0FC00000;
  static const uint32_t ROM_SIZE = 8 * 1024 * 1024;

  static const uint32_t RAM_SIZE = 128 * 1024 * 1024;
  // RAM is aliased at 0x00000000, 0x80000000, 0xA0000000

  static const uint32_t MMIO_BASE = 0x18000000;
  static const uint32_t MMIO_SIZE = 0x01000000;
  // MMIO aliased at 0x18000000, 0x98000000, 0xB8000000

  uint8_t *rom;             // ROM buffer (ROM_SIZE bytes)
  uint8_t *ram;             // RAM buffer (RAM_SIZE bytes)
  uint8_t *mmio;            // MMIO buffer (MMIO_SIZE bytes)
  uint32_t rom_loaded_size; // Actual size of loaded binary

  // ---- Callbacks ----
  std::function<void(char)> uart_callback;
  std::function<void(const char *)> log_callback;

  // ---- Internal ----
  void log(const char *fmt, ...);

  // Memory access (returns false on unmapped access)
  uint8_t mem_read8(uint32_t addr);
  uint16_t mem_read16(uint32_t addr);
  uint32_t mem_read32(uint32_t addr);
  void mem_write8(uint32_t addr, uint8_t val);
  void mem_write16(uint32_t addr, uint16_t val);
  void mem_write32(uint32_t addr, uint32_t val);

  // Address decoder: returns pointer to the byte, or nullptr if unmapped
  uint8_t *resolve_addr(uint32_t addr, bool write = false);

  // Handle MMIO side effects on write
  void mmio_write_hook(uint32_t mmio_offset, uint8_t val);

  // Handle MMIO side effects on read
  uint8_t mmio_read_hook(uint32_t mmio_offset);

  // Execute one instruction at pc; updates pc/next_pc
  void execute_instruction(uint32_t insn);

  // Instruction class handlers
  void exec_r_type(uint32_t insn);
  void exec_i_type(uint32_t insn, uint32_t opcode);
  void exec_j_type(uint32_t insn, uint32_t opcode);
  void exec_cop0(uint32_t insn);
  void exec_cop1(uint32_t insn);
  void exec_special2(uint32_t insn);
  void exec_special3(uint32_t insn);

  // Branch helper: sets next_pc for after the delay slot
  void do_branch(uint32_t target);
  void do_branch_likely(uint32_t target, bool condition);

  // Unimplemented instruction trap
  void unimplemented(uint32_t insn, const char *desc);
};
