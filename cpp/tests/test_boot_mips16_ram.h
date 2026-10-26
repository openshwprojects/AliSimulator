#pragma once

#include "test_board.h"
#include <cstdio>
#include <cstring>
#include <string>

// Reimplementation of test_boot_decodes_mips16.py & test_boot_81e870fc_decodes_mips16.py
// Verifies that the C++ emulator executes dump.bin past 0xAFC007F4 into RAM
// (0x81E8E170), transitions to MIPS16e via JALX 0x81E8CE14, reaches the MIPS16e
// routines at 0x81E84280 and 0x81E870FC, prints "APP  init!" and "bl_flash_init!"
// over UART, and exercises the SPI flash controller.
inline bool TestBootMips16Ram() {
  Board b;
  if (!b.load("dump.bin")) return false;

  // 1. Run until the MIPS32 -> RAM entry point at 0x81E8E170
  b.run_until(0x81E8E170, 200000);
  if (b.core.pc != 0x81E8E170 || b.core.m16 != false) {
    printf("  " RED "FAIL: Did not reach RAM entry 0x81E8E170 (PC=0x%08X)" RESET "\n",
           b.core.pc);
    return false;
  }

  // 2. Run across JALX 0x81E8CE14 into MIPS16e mode and reach 0x81E84280
  b.run_until(0x81E84280, 10000);
  if (b.core.pc != 0x81E84280 || b.core.m16 != true) {
    printf("  " RED "FAIL: Did not reach MIPS16e 0x81E84280 (PC=0x%08X, ISA=%d)" RESET "\n",
           b.core.pc, b.core.m16);
    return false;
  }

  // 3. Continue through UART ("APP  init!", "bl_flash_init!") & SPI init to 0x81E870FC
  b.run_until(0x81E870FC, 1000000);
  if (b.core.pc != 0x81E870FC || b.core.m16 != true) {
    printf("  " RED "FAIL: Did not reach MIPS16e 0x81E870FC (PC=0x%08X, ISA=%d, insns=%d)" RESET "\n",
           b.core.pc, b.core.m16, (int)b.core.icount);
    return false;
  }

  std::string uart_out;
  for (char c : b.uart)
    if (c != '\r') uart_out.push_back(c);

  if (uart_out.find("APP  init!") == std::string::npos ||
      uart_out.find("bl_flash_init!") == std::string::npos) {
    printf("  " RED "FAIL: Missing expected UART output (got: '%s')" RESET "\n",
           uart_out.c_str());
    return false;
  }

  printf("  Reached MIPS16e 0x81E84280 & 0x81E870FC (%d total insns), UART: \"APP  init! / bl_flash_init!\"\n",
         (int)b.core.icount);
  return true;
}
