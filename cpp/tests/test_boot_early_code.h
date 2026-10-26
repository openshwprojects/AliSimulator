#pragma once

#include "test_board.h"
#include <cstdio>

// Reimplementation of test_boot_early_code.py
// Verifies the early boot subroutine call (jal 0xafc03414), the 17-pass countdown
// delay loop at 0xAFC00498..0xAFC004A0, and the MMIO strap configuration at
// 0xB8000074 before jumping to 0xAFC005A8.
inline bool TestBootEarlyCode() {
  Board b;
  if (!b.load("dump.bin")) return false;

  // Run until 0xAFC00498 (right after jal 0xafc03414 returns)
  int pre_steps = b.run_until(0xAFC00498, 10000);
  if (b.core.pc != 0xAFC00498) {
    printf("  " RED "FAIL: Did not reach 0xAFC00498 (PC=0x%08X)" RESET "\n",
           b.core.pc);
    return false;
  }

  // Run through the 17-pass countdown loop (addiu $t0, 0x10; 17x [bnez + delay-slot addiu -1])
  int loop_steps = b.run_until(0xAFC004A4, 1000);
  if (b.core.pc != 0xAFC004A4 || loop_steps != 35 ||
      b.core.gpr[8] != 0xFFFFFFFF) {
    printf("  " RED "FAIL: Countdown loop took %d steps (expected 35), $t0=0x%08X" RESET "\n",
           loop_steps, b.core.gpr[8]);
    return false;
  }

  // Run through the CP0 and MMIO 0xB8000074 strap configuration to 0xAFC005A8
  int cfg_steps = b.run_until(0xAFC005A8, 1000);
  if (b.core.pc != 0xAFC005A8) {
    printf("  " RED "FAIL: Did not reach 0xAFC005A8 (PC=0x%08X)" RESET "\n",
           b.core.pc);
    return false;
  }

  // Verify registers and MMIO strap word at 0xB8000074
  uint32_t t2 = b.core.gpr[10]; // $t2 = 0xB8000000
  uint32_t t9 = b.core.gpr[25]; // $t9 = 0xAFC00080
  uint32_t strap = b.core.load<uint32_t>(0xB8000074);
  if (t2 != 0xB8000000 || t9 != 0xAFC00080 || (strap & 0x006000C0) == 0) {
    printf("  " RED "FAIL: Unexpected state at 0xAFC005A8: $t2=0x%08X, $t9=0x%08X, [0xB8000074]=0x%08X" RESET "\n",
           t2, t9, strap);
    return false;
  }

  printf("  Early boot verified: pre=%d, loop=%d, cfg=%d steps, [0xB8000074]=0x%08X\n",
         pre_steps, loop_steps, cfg_steps, strap);
  return true;
}
