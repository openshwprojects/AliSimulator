#pragma once

#include "../emulator/emulator.h"
#include <cstdio>
#include <cstring>
#include <string>

#define GREEN "\033[92m"
#define RED "\033[91m"
#define RESET "\033[0m"

// Reimplementation of test_boot_decodes_mips16.py & test_boot_81e870fc_decodes_mips16.py
// Verifies that the C++ emulator executes dump.bin past 0xAFC007F4 into RAM
// (0x81E8E170), transitions to MIPS16e via JALX 0x81E8CE14, reaches the MIPS16e
// routines at 0x81E84280 and 0x81E870FC, prints "APP  init!" and "bl_flash_init!"
// over UART, and exercises the SPI flash controller.
inline bool TestBootMips16Ram() {
  Emulator emu;
  std::string uart_out;

  emu.setLogHandler([](const char *msg) {
    if (strstr(msg, "UNIMPLEMENTED"))
      printf("  [EMU] %s\n", msg);
  });
  emu.setUartHandler([&uart_out](char c) {
    if (c != '\r')
      uart_out.push_back(c);
  });

  emu.loadFile("../dumps/dump.bin");

  // 1. Run until the MIPS32 -> RAM entry point at 0x81E8E170
  emu.runUntil(0x81E8E170, 200000);
  if (emu.getPC() != 0x81E8E170 || emu.getIsaMode() != false) {
    printf("  " RED "FAIL: Did not reach RAM entry 0x81E8E170 (PC=0x%08X)" RESET "\n",
           emu.getPC());
    return false;
  }

  // 2. Run across JALX 0x81E8CE14 into MIPS16e mode and reach 0x81E84280
  emu.runUntil(0x81E84280, 10000);
  if (emu.getPC() != 0x81E84280 || emu.getIsaMode() != true) {
    printf("  " RED "FAIL: Did not reach MIPS16e 0x81E84280 (PC=0x%08X, ISA=%d)" RESET "\n",
           emu.getPC(), emu.getIsaMode());
    return false;
  }

  // 3. Continue through UART ("APP  init!", "bl_flash_init!") & SPI init to 0x81E870FC
  emu.runUntil(0x81E870FC, 1000000);
  if (emu.getPC() != 0x81E870FC || emu.getIsaMode() != true) {
    printf("  " RED "FAIL: Did not reach MIPS16e 0x81E870FC (PC=0x%08X, ISA=%d, insns=%d)" RESET "\n",
           emu.getPC(), emu.getIsaMode(), emu.getInstructionCount());
    return false;
  }

  if (uart_out.find("APP  init!") == std::string::npos ||
      uart_out.find("bl_flash_init!") == std::string::npos) {
    printf("  " RED "FAIL: Missing expected UART output (got: '%s')" RESET "\n",
           uart_out.c_str());
    return false;
  }

  printf("  Reached MIPS16e 0x81E84280 & 0x81E870FC (%d total insns), UART: \"APP  init! / bl_flash_init!\"\n",
         emu.getInstructionCount());
  return true;
}
