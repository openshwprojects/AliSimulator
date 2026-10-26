#pragma once

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "../emulator/alicore.h"

using namespace ali;

#define GREEN "\033[92m"
#define RED "\033[91m"
#define RESET "\033[0m"

static std::vector<uint8_t> read_file(const char *name) {
  std::vector<uint8_t> out;
  FILE *f = nullptr;
  // (run from the repository, cpp\ or cpp\build\)
  for (const char *dir : {"dumps/", "../dumps/", "../../dumps/"}) {
    std::string path = std::string(dir) + name;
    f = fopen(path.c_str(), "rb");
    if (f) break;
  }
  if (!f) return out;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  out.resize((size_t)n);
  if (n > 0 && fread(out.data(), 1, (size_t)n, f) != (size_t)n) out.clear();
  fclose(f);
  return out;
}

// A minimal board: 128 MB of RAM, a 4 MB flash in the 0x0F000000 / 0x1F000000
// windows, the device window with the UART (THR -> text, LSR ready) and the chip ID.
struct Board {
  Core core;
  std::vector<uint8_t> ram, rom, mmio, image;
  std::string uart;
  bool echo = false;

  static uint64_t dev(void *user, int write, uint32_t off, uint32_t size, uint64_t value) {
    Board *b = (Board *)user;
    if (write) {
      if (off == 0x18300) {
        b->uart.push_back((char)value);
        if (b->echo) { putchar((int)(value & 0xFF)); fflush(stdout); }
      }
      memcpy(&b->mmio[off], &value, size);
      return 0;
    }
    if (off == 0x18305) return 0x20;   // UART LSR: always ready (the init stores 0 there)
    uint64_t v = 0;
    memcpy(&v, &b->mmio[off], size);
    return v;
  }

  bool load(const char *path) {
    std::vector<uint8_t> img = read_file(path);
    if (img.empty()) { printf("  %s not found\n", path); return false; }
    ram.assign(128u << 20, 0);
    rom.assign(4u << 20, 0xFF);
    memcpy(rom.data(), img.data(), std::min(img.size(), rom.size()));
    mmio.assign(16u << 20, 0);
    core.map_ptr(0, ram.size(), PROT_ALL, ram.data());
    for (uint32_t win : {0x0F000000u, 0x1F000000u})
      for (uint32_t slot = 0; slot < 0x01000000u; slot += 0x400000u)
        core.map_ptr(win + slot, rom.size(), PROT_READ | PROT_EXEC, rom.data());
    mmio[0x18305] = 0x20;   // UART LSR: THR empty
    mmio[0x0002] = 0x11;    // chip ID 0x3811
    mmio[0x0003] = 0x38;
    core.set_device_window(0x18000000, mmio.data(), (uint32_t)mmio.size(), dev, this);
    core.set_dev_flags(0x18300, 1, Core::DF_WRITE);
    core.set_dev_flags(0x18305, 1, Core::DF_READ);
    // the SPI flash controller (native): its registers, the flash windows
    image = rom;
    const uint32_t windows[2] = {0x0F000000u, 0x1F000000u};
    core.set_flash_cmd(false, windows, 2);
    core.spi.jedec[2] = 0x16;
    core.spi_config(true, rom.data(), image.data(), (uint32_t)rom.size());
    for (uint32_t base : {0x00098u, 0x2E098u}) core.set_dev_flags(base, 4, Core::DF_NATIVE);
    core.pc = 0xAFC00000;
    return true;
  }

  // Keep the current ISA and report logical instruction counts, including any
  // loop passes the core safely skips. CPU/memory faults return -1.
  int run_until(uint32_t until, uint64_t count) {
    uint64_t before = core.icount;
    int err = core.emu_start(core.pc | (core.m16 ? 1u : 0u), until, 0, count);
    if (err != ERR_OK) {
      printf("  core error %d at PC=0x%08X: %s\n", err, core.fault_pc, core.last_message.c_str());
      return -1;
    }
    return (int)(core.icount - before);
  }
};

