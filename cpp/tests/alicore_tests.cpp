// The C++ core's own tests, without Python: a minimal ALi board (RAM, the flash
// windows, the device window with the UART) runs the repository's test program
// and a bootloader.  (The full machine -- every device model -- is the Python
// simulator's; src/cpp_core.py puts it on this core: python run_all_tests.py --engine cpp.)
//   build\alicore_tests.exe            run the tests
//   build\alicore_tests.exe bench N    the interpreter's speed on dump_maciej.bin's bootloader
#define _CRT_SECURE_NO_WARNINGS
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "test_board.h"
#include "test_boot_first_steps.h"
#include "test_boot_early_code.h"
#include "test_instruction_set.h"
#include "test_mips16e_execution.h"
#include "test_boot_mips16_ram.h"

static bool test_boot_dump_copies_to_ram() {
  Board b;
  if (!b.load("dump.bin")) { printf("  dump.bin not found\n"); return false; }
  uint8_t before[32], after[32];
  b.core.host_read(0x81e8e170 & 0x1FFFFFFF, before, 32);
  for (uint8_t x : before)
    if (x) { printf("  memory not zero at start\n"); return false; }
  int e = b.core.emu_start(0xAFC00000, 0xAFC007F4, 0, 50000000);
  printf("  stopped at PC=0x%08X after %llu instructions (err %d)\n", b.core.pc,
         (unsigned long long)b.core.executed, e);
  b.core.host_read(0x81e8e170 & 0x1FFFFFFF, after, 32);
  static const uint8_t expected[32] = {0xe8, 0xff, 0xbd, 0x27, 0x10, 0x00, 0xbf, 0xaf, 0xea, 0x81, 0x04,
                                       0x3c, 0xf0, 0x83, 0x84, 0x24, 0xe9, 0x81, 0x01, 0x3c, 0x50, 0x27,
                                       0x24, 0xac, 0x85, 0x33, 0x7a, 0x0c, 0x00, 0x00, 0x00, 0x00};
  return b.core.pc == 0xAFC007F4 && memcmp(after, expected, 32) == 0;
}

static bool test_ali_sdk_hello_world() {
  Board b;
  if (!b.load("ali_sdk.bin")) { printf("  ali_sdk.bin not found\n"); return false; }
  b.core.emu_start(0xAFC00000, 0xFFFFFFFF, 0, 60000);
  std::string out;
  for (char c : b.uart)
    if (c != '\r') out.push_back(c);
  static const char *expected =
      "Booting...\nMain function\nstack end: 82000000\nstack start: 82008000\nheap start: 81000954\n"
      "heap end: 81008954\ncause: 0\nx: 1.230000 y: 1.250000\nresult: 25.729999\ncause: 0\nchip id raw: 3811\nMenu!\n";
  size_t start = out.find("Booting");
  bool ok = start != std::string::npos && out.compare(start, strlen(expected), expected) == 0;
  if (!ok) printf("  UART: %s\n", out.c_str());
  return ok;
}

static int bench(double seconds, const char *dump) {
  Board b;
  if (!b.load(dump)) { printf("%s not found\n", dump); return 1; }
  auto t0 = std::chrono::steady_clock::now();
  uint64_t total = 0;
  for (;;) {
    b.core.emu_start(b.core.pc | (b.core.m16 ? 1 : 0), 0xFFFFFFFF, 0, 10000000);
    total = b.core.executed;
    if (b.core.stop_reason() == STOP_ERROR) {
      printf("stopped: error %d at 0x%08X\n", b.core.last_error(), b.core.fault_pc);
      break;
    }
    double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (dt >= seconds) break;
  }
  double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  printf("%llu instructions in %.2f s: %.1f M instructions/s, PC=0x%08X (%s), %llu SPI commands\nUART: %s\n",
         (unsigned long long)total, dt, total / dt / 1e6, b.core.pc, b.core.m16 ? "MIPS16" : "MIPS32",
         (unsigned long long)b.core.spi.commands, b.uart.c_str());
  return 0;
}

// The interpreter on a tight ALU loop: its cost per instruction without memory or devices.
static int micro(double seconds) {
  Board b;
  b.ram.assign(16u << 20, 0);
  b.core.map_ptr(0, b.ram.size(), PROT_ALL, b.ram.data());
  const uint32_t code[] = {
      0x25080001,   // loop: addiu t0, t0, 1
      0x01284821,   //       addu t1, t1, t0
      0x01495026,   //       xor t2, t2, t1
      0x000A58C0,   //       sll t3, t2, 3
      0x8D6D0000 & 0, // (nop)
      0x150CFFFA,   //       bne t0, t4, loop
      0x00000000,   //       nop
  };
  memcpy(&b.ram[0x1000], code, sizeof(code));
  b.core.gpr[12] = 0xFFFFFFFF;
  auto t0 = std::chrono::steady_clock::now();
  uint64_t n = 0;
  b.core.pc = 0x80001000;
  for (;;) {
    b.core.emu_start(b.core.pc, 0xFFFFFFFF, 0, 50000000);
    n = b.core.executed;
    double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (dt >= seconds || b.core.stop_reason() == STOP_ERROR) break;
  }
  double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  printf("micro: %llu instructions in %.2f s: %.1f M instructions/s\n", (unsigned long long)n, dt, n / dt / 1e6);
  return 0;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "micro") == 0) return micro(argc >= 3 ? atof(argv[2]) : 5.0);
  if (argc >= 2 && strcmp(argv[1], "bench") == 0)
    return bench(argc >= 3 ? atof(argv[2]) : 10.0, argc >= 4 ? argv[3] : "dump_maciej.bin");
  struct { const char *name; bool (*fn)(); } tests[] = {
      {"BootDumpCopiesToRam", test_boot_dump_copies_to_ram},
      {"AliSdkHelloWorld", test_ali_sdk_hello_world},
      {"BootFirstSteps", TestBootFirstSteps},
      {"BootEarlyCode", TestBootEarlyCode},
      {"InstructionSet", TestInstructionSet},
      {"Mips16eExecution", TestMips16eExecution},
      {"BootMips16Ram", TestBootMips16Ram},
  };
  int failed = 0, n = (int)(sizeof(tests) / sizeof(tests[0]));
  for (int i = 0; i < n; i++) {
    printf("=== [%d/%d] %s ===\n", i + 1, n, tests[i].name);
    bool ok = false;
    try {
      ok = tests[i].fn();
    } catch (const Fault &fault) {
      printf("  unexpected memory/CPU fault: %d\n", fault.err);
    }
    printf(ok ? GREEN "  PASSED\n" RESET : RED "  FAILED\n" RESET);
    failed += !ok;
  }
  printf("%d/%d passed\n", n - failed, n);
  return failed ? 1 : 0;
}
