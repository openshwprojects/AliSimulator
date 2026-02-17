#include "tests/test_ali_sdk_hello_world.h"
#include "tests/test_boot_dump_copies_to_ram.h"
#include <cstdio>

#define GREEN "\033[92m"
#define RED "\033[91m"
#define RESET "\033[0m"

struct TestEntry {
  const char *name;
  bool (*func)();
};

int main() {
  TestEntry tests[] = {
      {"TestAliSDKHelloWorld", TestAliSDKHelloWorld},
      {"TestBootDumpCopiesToRam", TestBootDumpCopiesToRam},
  };

  int total = sizeof(tests) / sizeof(tests[0]);
  int passed = 0;
  int failed = 0;

  printf("Running %d tests...\n\n", total);

  for (int i = 0; i < total; i++) {
    printf("=== [%d/%d] %s ===\n", i + 1, total, tests[i].name);
    bool result = tests[i].func();

    if (result) {
      printf(GREEN "  PASSED: %s" RESET "\n\n", tests[i].name);
      passed++;
    } else {
      printf(RED "  FAILED: %s" RESET "\n\n", tests[i].name);
      failed++;
    }
  }

  printf("========================================\n");
  printf("Results: %d/%d passed", passed, total);
  if (failed > 0)
    printf(", " RED "%d failed" RESET, failed);
  printf("\n");

  return failed > 0 ? 1 : 0;
}
