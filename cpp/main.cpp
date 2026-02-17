#include "emulator.h"
#include <cstdio>
#include <cstring>
#include <string>

// ANSI colors
#define GREEN "\033[92m"
#define RED "\033[91m"
#define RESET "\033[0m"

static const char *EXPECTED_OUTPUT = "Booting...\n"
                                     "Main function\n"
                                     "stack end: 82000000\n"
                                     "stack start: 82008000\n"
                                     "heap start: 81000954\n"
                                     "heap end: 81008954\n"
                                     "cause: 0\n"
                                     "x: 1.230000 y: 1.250000\n"
                                     "result: 25.729999\n"
                                     "cause: 0\n"
                                     "chip id raw: 3811\n"
                                     "Menu!\n";

class RealTimeVerifier {
public:
  RealTimeVerifier(const char *expected)
      : m_expected(expected), m_index(0), m_failed(false), m_started(false) {
    m_expected_len = strlen(expected);
  }

  void on_uart(char ch) {
    // Ignore \r to simplify matching against \n
    if (ch == '\r')
      return;

    if (!m_started) {
      if (m_expected_len > 0 && ch == m_expected[0]) {
        m_started = true;
      } else {
        return; // Ignore garbage before start
      }
    }

    bool match = false;
    if (m_index < m_expected_len) {
      if (ch == m_expected[m_index]) {
        match = true;
      }
    }

    if (match) {
      printf(GREEN "%c" RESET, ch);
      m_index++;
    } else {
      printf(RED "%c" RESET, ch);
      if (m_index < m_expected_len) {
        printf(RED "[EXP:'%c'/0x%02X]" RESET, m_expected[m_index],
               (unsigned char)m_expected[m_index]);
      }
      m_failed = true;
      m_index++;
    }
    fflush(stdout);
  }

  bool finish() {
    printf(RESET "\n");
    if (m_failed) {
      printf("\n" RED "TEST FAILED (Mismatch occurred)" RESET "\n");
      return false;
    } else if (m_index == 0) {
      printf("\n" RED "TEST FAILED (No Output)" RESET "\n");
      return false;
    } else if (m_index < m_expected_len) {
      printf("\n" RED
             "TEST PARTIAL (Missing end of output, got %d/%d chars)" RESET "\n",
             (int)m_index, (int)m_expected_len);
      return false;
    } else {
      printf("\n" GREEN "TEST PASSED" RESET "\n");
      return true;
    }
  }

private:
  const char *m_expected;
  size_t m_expected_len;
  size_t m_index;
  bool m_failed;
  bool m_started;
};

int main() {
  RealTimeVerifier verifier(EXPECTED_OUTPUT);

  Emulator emu;

  emu.setLogHandler([](const char *msg) {
    if (strstr(msg, "UNIMPLEMENTED"))
      printf("[EMU] %s\n", msg);
  });

  emu.setUartHandler([&verifier](char ch) { verifier.on_uart(ch); });

  emu.loadFile("../ali_sdk.bin");

  // 60k is enough — slightly more than Python/Unicorn due to delay slot
  // counting
  emu.run(60000);

  bool passed = verifier.finish();
  return passed ? 0 : 1;
}
