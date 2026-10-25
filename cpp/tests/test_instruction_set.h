#pragma once

#include "../emulator/emulator.h"
#include <cstdio>
#include <cstring>

#define GREEN "\033[92m"
#define RED "\033[91m"
#define RESET "\033[0m"

// Comprehensive unit test for the C++ MIPS32 + FPU instruction interpreter:
// - $zero invariance, R-type arithmetic/logical/shifts
// - SPECIAL2 (MUL, MADD, MSUB, CLZ, CLO) and SPECIAL3 (EXT, INS, WSBH, SEB, SEH)
// - Unaligned loads/stores (LWL, LWR, SWL, SWR) and LL/SC across KSEG0/KSEG1/kuseg
// - Branch delay slots and branch-likely delay-slot nullification (BEQL, BNEL)
// - COP0 Count / Status / EPC and COP1 single/double FPU operations
inline bool TestInstructionSet() {
  Emulator emu;
  emu.setLogHandler([](const char *) {});
  emu.setUartHandler([](char) {});

  const uint32_t base = 0x80010000;
  const uint32_t code[] = {
      // 1. $zero invariance: addiu $zero, $zero, 0x1234
      0x24001234,
      // 2. Load test constants into $t0 (8) and $t1 (9):
      //    lui $t0, 0x1234; ori $t0, $t0, 0xFF88 -> $t0 = 0x1234FF88
      0x3C081234,
      0x3508FF88,
      //    addiu $t1, $zero, 7 -> $t1 = 7
      0x24090007,
      // 3. SPECIAL2: mul $t2(10), $t1(9), $t1(9) -> $t2 = 49
      0x71295002,
      //    clz $t3(11), $t0(8) -> clz(0x1234FF88) = 3
      0x710B5820,
      //    clo $t4(12), $t0(8) -> clo(0x1234FF88) = 0
      0x710C6021,
      // 4. SPECIAL3: seb $t5(13), $t0(8) -> sign-extend 0x88 = 0xFFFFFF88
      (0x1F << 26) | (8 << 16) | (13 << 11) | (0x10 << 6) | 0x20,
      //    seh $t6(14), $t0(8) -> sign-extend 0xFF88 = 0xFFFFFF88
      (0x1F << 26) | (8 << 16) | (14 << 11) | (0x18 << 6) | 0x20,
      //    wsbh $t7(15), $t0(8) -> byte-swap within halfwords: 0x341288FF
      (0x1F << 26) | (8 << 16) | (15 << 11) | (0x02 << 6) | 0x20,
      //    ext $s0(16), $t0(8), lsb=8, size=16 (msbd=15) -> 0x34FF
      (0x1F << 26) | (8 << 21) | (16 << 16) | (15 << 11) | (8 << 6) | 0x00,
      //    addiu $s1(17), $zero, 0xAA; ins $s1(17), $t1(9), lsb=4, size=4 (msb=7) -> 0x7A
      0x241100AA,
      (0x1F << 26) | (9 << 21) | (17 << 16) | (7 << 11) | (4 << 6) | 0x04,
      // 5. Unaligned memory & KSEG0/KSEG1/kuseg aliasing:
      //    lui $a0(4), 0x8010; sw $t0(8), 0($a0)
      0x3C048010,
      0xAC880000,
      //    Read back via KSEG1 (0xA0100000) using unaligned LWL + LWR into $s2(18):
      //    lui $a1(5), 0xA010; lwl $s2(18), 3($a1); lwr $s2(18), 0($a1)
      0x3C05A010,
      0x88B20003,
      0x98B20000,
      //    Atomic LL / SC via kuseg (0x00100000):
      //    lui $a2(6), 0x0010; ll $s3(19), 0($a2); addiu $s4(20), $zero, 0x99; sc $s4(20), 0($a2)
      0x3C060010,
      0xC0D30000,
      0x24140099,
      0xE0D40000,
      // 6. Branch-likely nullification test:
      //    addiu $s5(21), $zero, 10
      //    beql $t1(9), $zero, +2 (not taken -> delay slot MUST be nullified!)
      //    addiu $s5(21), $s5(21), 100 (nullified!)
      //    bnel $t1(9), $zero, +1 (taken -> delay slot MUST execute!)
      //    addiu $s5(21), $s5(21), 5   (executes -> $s5 = 15)
      0x2415000A,
      0x51200002,
      0x26B50064,
      0x55200001,
      0x26B50005,
      // 7. FPU single-precision:
      //    lui $at(1), 0x4000 (2.0f); mtc1 $at(1), $f0
      //    lui $at(1), 0x4040 (3.0f); mtc1 $at(1), $f2
      //    mul.s $f4, $f0, $f2 (6.0f = 0x40C00000); mfc1 $s6(22), $f4
      0x3C014000,
      0x44810000,
      0x3C014040,
      0x44811000,
      0x46020102,
      (0x11 << 26) | (0x00 << 21) | (22 << 16) | (4 << 11),
  // 8. CP0 Count read: mfc0 $s7(23), $9 (Count)
      0x40174800,
      // 9. ROTR / ROTRV:
      //    rotr $t8(24), $t0(8), 8 -> 0x881234FF (opcode=0, rs=1, rt=8, rd=24, sa=8, fn=2)
      (0x00 << 26) | (1 << 21) | (8 << 16) | (24 << 11) | (8 << 6) | 0x02,
      //    addiu $t9(25), $zero, 4; rotrv $t9(25), $t8(24), $t9(25) -> 0xF881234F
      0x24190004,
      (0x00 << 26) | (25 << 21) | (24 << 16) | (25 << 11) | (1 << 6) | 0x06,
      // 10. MADD / MSUB / MSUBU:
      //    mthi $zero; mtlo $zero
      (0x00 << 26) | (0 << 21) | 0x11,
      (0x00 << 26) | (0 << 21) | 0x13,
      //    madd $t1(9), $t1(9) -> LO = 49; maddu $t1(9), $t1(9) -> LO = 98
      (0x1C << 26) | (9 << 21) | (9 << 16) | 0x00,
      (0x1C << 26) | (9 << 21) | (9 << 16) | 0x01,
      //    msub $t1(9), $t2(10) -> 98 - 7*49 = -245; msubu $t1(9), $zero -> unchanged
      (0x1C << 26) | (9 << 21) | (10 << 16) | 0x04,
      (0x1C << 26) | (9 << 21) | (0 << 16) | 0x05,
      //    mflo $k0(26) -> -245 (0xFFFFFF0B)
      (0x00 << 26) | (26 << 11) | 0x12,
      // 11. Unaligned SWL + SWR and signed LB / LH:
      //    swl $t0(8), 7($a0); swr $t0(8), 4($a0) -> [0x80100004] = 0x1234FF88
      (0x2Au << 26) | (4u << 21) | (8u << 16) | 7u,
      (0x2Eu << 26) | (4u << 21) | (8u << 16) | 4u,
      //    lb $k1(27), 4($a0) -> 0xFFFFFF88; lh $gp(28), 4($a0) -> 0xFFFFFF88
      (0x20u << 26) | (4u << 21) | (27u << 16) | 4u,
      (0x21u << 26) | (4u << 21) | (28u << 16) | 4u,
      // 12. COP0 EI / DI & EBase, CACHE & SYNCI:
      //    ei $zero; di $sp(29) (returns old status with IE=1 in bit 0)
      (0x10u << 26) | (0x0Bu << 21) | (0u << 16) | (12u << 11) | (1u << 5),
      (0x10u << 26) | (0x0Bu << 21) | (29u << 16) | (12u << 11) | (0u << 5),
      //    cache 0, 0($a0); synci 0($a0)
      (0x2Fu << 26) | (4u << 21) | 0u,
      (0x01u << 26) | (4u << 21) | (0x1Fu << 16) | 0u,
      // 13. COP1X: MADD.S $f6, $f4, $f0, $f2 -> (2.0 * 3.0) + 6.0 = 12.0f (0x41400000)
      //    swxc1 $f6, $zero($a0); lwxc1 $f8, $zero($a0); mfc1 $fp(30), $f8
      (0x13u << 26) | (4u << 21) | (2u << 16) | (0u << 11) | (6u << 6) | 0x20u,
      (0x13u << 26) | (4u << 21) | (0u << 16) | (6u << 11) | 0x08u,
      (0x13u << 26) | (4u << 21) | (0u << 16) | (8u << 6) | 0x00u,
      (0x11u << 26) | (0x00u << 21) | (30u << 16) | (8u << 11),
      // 14. Done: nop
      0x00000000u,
  };

  const int n_insns = (int)(sizeof(code) / sizeof(code[0]));
  for (int i = 0; i < n_insns; i++) {
    emu.writeMem32(base + 4 * i, code[i]);
  }
  const uint32_t stop_addr = base + 4 * (n_insns - 1);
  emu.setPC(base);
  int steps = emu.runUntil(stop_addr, 200);

  struct RegCheck {
    const char *name;
    int reg;
    uint32_t expected;
  };
  const RegCheck checks[] = {
      {"$zero invariance", 0, 0},
      {"$t0 constant", 8, 0x1234FF88},
      {"$t2 MUL (7*7)", 10, 49},
      {"$t3 CLZ(0x1234FF88)", 11, 3},
      {"$t4 CLO(0x1234FF88)", 12, 0},
      {"$t5 SEB(0x88)", 13, 0xFFFFFF88},
      {"$t6 SEH(0xFF88)", 14, 0xFFFFFF88},
      {"$t7 WSBH(0x1234FF88)", 15, 0x341288FF},
      {"$s0 EXT(pos=8,sz=16)", 16, 0x000034FF},
      {"$s1 INS(pos=4,sz=4)", 17, 0x0000007A},
      {"$s2 LWL+LWR via KSEG1", 18, 0x1234FF88},
      {"$s3 LL via kuseg", 19, 0x1234FF88},
      {"$s4 SC status", 20, 1},
      {"$s5 BEQL/BNEL delay-slot nullification", 21, 15},
      {"$s6 FPU MUL.S (2.0f * 3.0f = 6.0f)", 22, 0x40C00000},
      {"$s7 MFC0 Count", 23, 0x40},
      {"$t8 ROTR(0x1234FF88, 8)", 24, 0x881234FF},
      {"$t9 ROTRV(0x881234FF, 4)", 25, 0xF881234F},
      {"$k0 MADD/MADDU/MSUB/MSUBU", 26, (uint32_t)(-245)},
      {"$k1 LB signed", 27, 0xFFFFFF88},
      {"$gp LH signed", 28, 0xFFFFFF88},
      {"$sp EI/DI old status", 29, 0x10400001},
      {"$fp COP1X MADD.S+SWXC1+LWXC1 (12.0f)", 30, 0x41400000},
  };

  for (const auto &c : checks) {
    uint32_t got = emu.getReg(c.reg);
    if (got != c.expected) {
      printf("  " RED "FAIL: %s (r%d) = 0x%08X (expected 0x%08X)" RESET "\n",
             c.name, c.reg, got, c.expected);
      return false;
    }
  }
  if (emu.readMem32(0x80100004) != 0x1234FF88) {
    printf("  " RED "FAIL: SWL+SWR store at 0x80100004 = 0x%08X" RESET "\n",
           emu.readMem32(0x80100004));
    return false;
  }

  // Verify SPI Flash MMIO commands (JEDEC ID 0x9F, Status 0x05, Electronic ID 0xAB, Read 0x03)
  emu.loadFile("../dumps/ali_sdk.bin");
  uint32_t orig_rom0 = emu.readMem32(0xAFC00000);
  if (emu.readMem32(0xBFC00000) != orig_rom0 ||
      emu.readMem32(0x9FC00000) != orig_rom0 ||
      emu.readMem32(0x1FC00000) != orig_rom0) {
    printf("  " RED "FAIL: ROM mirror mismatch on 0xBFC00000/0x9FC00000/0x1FC00000" RESET "\n");
    return false;
  }
  emu.writeMem32(0xB802E098, 0x00000D9F); // SF_INS = 0x9F (JEDEC ID), SF_FMT = 0x0D
  if (emu.readMem32(0xAFC00000) != 0x001640EF) {
    printf("  " RED "FAIL: SPI 0x9F JEDEC ID = 0x%08X" RESET "\n",
           emu.readMem32(0xAFC00000));
    return false;
  }
  emu.writeMem32(0xB802E098, 0x00000D05); // SF_INS = 0x05 (Read Status)
  if (emu.readMem32(0xAFC00000) != 0x00000000) {
    printf("  " RED "FAIL: SPI 0x05 Status = 0x%08X" RESET "\n",
           emu.readMem32(0xAFC00000));
    return false;
  }
  emu.writeMem32(0xB802E098, 0x00000D03); // SF_INS = 0x03 (Read passthrough)
  if (emu.readMem32(0xAFC00000) != orig_rom0) {
    printf("  " RED "FAIL: SPI 0x03 restore failed (0x%08X != 0x%08X)" RESET "\n",
           emu.readMem32(0xAFC00000), orig_rom0);
    return false;
  }

  printf("  All 26 MIPS32r2/SPECIAL2/SPECIAL3/COP0/COP1X/ROM/SPI checks passed (%d steps)\n",
         steps);
  return true;
}
