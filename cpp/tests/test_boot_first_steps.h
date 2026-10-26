#pragma once

#include "test_board.h"
#include <cstdio>

// Reimplementation of test_boot_first_steps.py and test_boot_first_jump.py
// Verifies the reset vector branch at 0xAFC00000 -> 0xAFC00490 and the
// instruction encodings at the entry of the first boot routine.
inline bool TestBootFirstSteps() {
  Board b;
  if (!b.load("dump.bin")) return false;

  if (b.core.pc != 0xAFC00000) {
    printf("  " RED "FAIL: Initial PC=0x%08X (expected 0xAFC00000)" RESET "\n",
           b.core.pc);
    return false;
  }

  // Verify reset vector instructions: b 0xafc00490 (0x10000123); nop (0x00000000)
  uint32_t insn0 = b.core.load<uint32_t>(0xAFC00000);
  uint32_t insn1 = b.core.load<uint32_t>(0xAFC00004);
  if (insn0 != 0x10000123 || insn1 != 0x00000000) {
    printf("  " RED "FAIL: Reset vector words 0x%08X 0x%08X" RESET "\n", insn0,
           insn1);
    return false;
  }

  // Verify ROM mirror aliasing at 0x0FC00000 and 0x8FC00000
  if (b.core.load<uint32_t>(0x0FC00000) != insn0 ||
      b.core.load<uint32_t>(0x8FC00000) != insn0) {
    printf("  " RED "FAIL: ROM mirror mismatch at 0x0FC00000 / 0x8FC00000" RESET
           "\n");
    return false;
  }

  // Step 2 instructions (branch + delay slot) to reach 0xAFC00490
  int steps = b.run_until(0xFFFFFFFF, 2);
  if (steps != 2 || b.core.pc != 0xAFC00490) {
    printf("  " RED "FAIL: After 2 steps PC=0x%08X (steps=%d)" RESET "\n",
           b.core.pc, steps);
    return false;
  }

  // Verify instruction encodings at 0xAFC00490..0xAFC004A0
  struct ExpectedWord {
    uint32_t addr;
    uint32_t word;
  };
  static const ExpectedWord kExpected[] = {
      {0xAFC00490, 0x0FF00D05}, // jal 0xafc03414
      {0xAFC00494, 0x00000000}, // nop
      {0xAFC00498, 0x24080010}, // addiu $t0, $zero, 0x10
      {0xAFC0049C, 0x1500FFFF}, // bnez $t0, 0xafc0049c
      {0xAFC004A0, 0x2508FFFF}, // addiu $t0, $t0, -1
  };
  for (const auto &e : kExpected) {
    uint32_t got = b.core.load<uint32_t>(e.addr);
    if (got != e.word) {
      printf("  " RED "FAIL: [0x%08X] = 0x%08X (expected 0x%08X)" RESET "\n",
             e.addr, got, e.word);
      return false;
    }
  }

  printf("  Reset vector -> 0xAFC00490 in 2 steps, ROM mirrors & encodings verified\n");
  return true;
}
