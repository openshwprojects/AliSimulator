#pragma once

#include "../emulator/emulator.h"
#include <cstdio>
#include <cstring>

#define GREEN "\033[92m"
#define RED "\033[91m"
#define RESET "\033[0m"

// Reimplementation of test_boot_dump_copies_to_ram.py
// Loads dump.bin, runs until PC=0xAFC007F4, verifies that
// the bootloader copied code from ROM (KSEG0) into RAM.
inline bool TestBootDumpCopiesToRam() {
  Emulator emu;

  emu.setLogHandler([](const char *msg) {
    if (strstr(msg, "UNIMPLEMENTED") || strstr(msg, "WARNING"))
      printf("  [EMU] %s\n", msg);
  });

  // Suppress UART output for this test
  emu.setUartHandler([](char) {});

  emu.loadFile("../dump.bin");

  // Check address where ROM data should be copied to RAM
  const uint32_t check_addr = 0x81e8e170;
  const int check_size = 32;

  // Verify memory is initially zero
  uint8_t mem_before[32];
  emu.readMem(check_addr, mem_before, check_size);

  bool initially_zero = true;
  for (int i = 0; i < check_size; i++) {
    if (mem_before[i] != 0) {
      initially_zero = false;
      break;
    }
  }

  if (!initially_zero) {
    printf("  " RED "FAIL: Memory at 0x%08X was not zero initially!" RESET "\n",
           check_addr);
    return false;
  }

  printf("  Initial memory check passed (all zeros)\n");

  // Run until stop address
  const uint32_t stop_addr = 0xafc007f4;
  printf("  Running until 0x%08X...\n", stop_addr);

  int steps = emu.runUntil(stop_addr);
  printf("  Stopped at PC=0x%08X after %d instructions\n", emu.getPC(), steps);

  // Read memory after execution
  uint8_t mem_after[32];
  emu.readMem(check_addr, mem_after, check_size);

  // Expected bytes from Python test
  static const uint8_t expected[] = {
      0xe8, 0xff, 0xbd, 0x27, 0x10, 0x00, 0xbf, 0xaf, 0xea, 0x81, 0x04,
      0x3c, 0xf0, 0x83, 0x84, 0x24, 0xe9, 0x81, 0x01, 0x3c, 0x50, 0x27,
      0x24, 0xac, 0x85, 0x33, 0x7a, 0x0c, 0x00, 0x00, 0x00, 0x00};

  // Print actual bytes
  printf("  Bytes: ");
  for (int i = 0; i < check_size; i++)
    printf("%02x", mem_after[i]);
  printf("\n");

  if (memcmp(mem_after, expected, check_size) == 0) {
    return true;
  } else {
    printf("  Expected: ");
    for (int i = 0; i < check_size; i++)
      printf("%02x", expected[i]);
    printf("\n");
    return false;
  }
}
