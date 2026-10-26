#pragma once

#include "test_board.h"
#include <cstdio>
#include <cstring>

// MIPS32 JALX -> MIPS16e -> MIPS32 JRC, extended SAVE/RESTORE of
// caller arguments and saved registers, extended LI, ADDU, CMPI, BTEQZ,
// and ADDIU8. Register and stack assertions verify the complete round trip.
inline bool TestMips16eExecution() {
  Board b;
  if (!b.load("ali_sdk.bin")) return false;

  // Set up initial stack pointer and caller registers in MIPS32 at 0x80010000:
  //   0x80010000: lui   $sp, 0x8002          (0x3C1D8002)
  //   0x80010004: addiu $a0, $zero, 0x42     (0x24040042)
  //   0x80010008: addiu $s0, $zero, 0x1111   (0x24101111)
  //   0x8001000C: addiu $s1, $zero, 0x2222   (0x24112222)
  //   0x80010010: jalx  0x80010100           (0x74004040 -> target 0x80010100, toggles to MIPS16e)
  //   0x80010014: nop                        (0x00000000)
  //   0x80010018: addiu $v1, $v0, 10         (0x2443000A -> executes back in MIPS32!)
  //   0x8001001C: nop                        (0x00000000 -> stop_addr)
  const uint32_t mips32_code[] = {
      0x3C1D8002, 0x24040042, 0x24101111, 0x24112222,
      0x74004040, 0x00000000, 0x2443000A, 0x00000000,
  };
  for (size_t i = 0; i < sizeof(mips32_code) / 4; i++) {
    b.core.store<uint32_t>(0x80010000 + (uint32_t)(4 * i), mips32_code[i]);
  }

  // MIPS16e routine at 0x80010100:
  //   1. Extended SAVE a0, 0x20, ra, s0-s1:  0xF004, 0x64F4
  //   2. Extended LI s0(0), 0x1234:          0xF222, 0x6814 (ext_15_11=0x02, ext_10_5=0x11, imm5=0x14 -> 0x1234)
  //   3. LI s1(1), 0x10:                     0x6910
  //   4. RRR ADDU v0(2), s0(0), s1(1):       (0x1C << 11) | (0 << 8) | (1 << 5) | (2 << 2) | 1 = 0xE029 -> 0x1244
  //   5. CMPI v0(2), 0xFF (not equal -> T=1): 0x72FF
  //   6. BTEQZ +2 (skip next if T==0; not taken since T!=0): 0x6001
  //   7. ADDIU8 v0(2), 0x0C -> 0x1250:       0x4A0C
  //   8. Extended RESTORE 0x20, ra, s0-s1:   0xF000, 0x6474 (restores s0=0x1111, s1=0x2222, ra=0x80010018, sp=0x80020000)
  //   9. JRC ra (compact jump back to MIPS32 0x80010018): 0xE8A0
  const uint16_t mips16_code[] = {
      0xF004, 0x64F4, // save a0, 0x20, ra, s0-s1
      0xF222, 0x6814, // li s0, 0x1234
      0x6910,         // li s1, 0x10
      0xE029,         // addu v0, s0, s1 (0x1244)
      0x72FF,         // cmpi v0, 0xFF
      0x6001,         // bteqz +2 (not taken)
      0x4A0C,         // addiu v0, 0x0C (0x1250)
      0xF000, 0x6474, // restore 0x20, ra, s0-s1
      0xE8A0,         // jrc ra
  };
  for (size_t i = 0; i < sizeof(mips16_code) / 2; i += 2) {
    uint32_t w = mips16_code[i];
    if (i + 1 < sizeof(mips16_code) / 2)
      w |= ((uint32_t)mips16_code[i + 1] << 16);
    b.core.store<uint32_t>(0x80010100 + (uint32_t)(2 * i), w);
  }

  b.core.pc = 0x80010000;
  int steps = b.run_until(0x8001001C, 100);

  if (b.core.pc != 0x8001001C || b.core.m16 != false) {
    printf("  " RED "FAIL: PC=0x%08X (ISA=%d), expected 0x8001001C (ISA=0)" RESET "\n",
           b.core.pc, b.core.m16);
    return false;
  }
  if (b.core.gpr[2] != 0x1250 || b.core.gpr[3] != 0x125A) {
    printf("  " RED "FAIL: $v0=0x%08X (exp 0x1250), $v1=0x%08X (exp 0x125A)" RESET "\n",
           b.core.gpr[2], b.core.gpr[3]);
    return false;
  }
  if (b.core.gpr[16] != 0x1111 || b.core.gpr[17] != 0x2222 ||
      b.core.gpr[29] != 0x80020000 || b.core.load<uint32_t>(0x80020000) != 0x42) {
    printf("  " RED "FAIL: SAVE/RESTORE state mismatch ($s0=0x%X, $s1=0x%X, $sp=0x%X, [sp]=0x%X)" RESET "\n",
           b.core.gpr[16], b.core.gpr[17], b.core.gpr[29],
           b.core.load<uint32_t>(0x80020000));
    return false;
  }

  printf("  MIPS32 <-> MIPS16e JALX/SAVE/RESTORE/EXTEND/ALU/JRC verified (%d steps)\n",
         steps);
  return true;
}
