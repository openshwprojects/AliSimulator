#pragma once

#include "../emulator/emulator.h"
#include <cstdio>
#include <cstring>

// ANSI colors
#define GREEN "\033[92m"
#define RED "\033[91m"
#define RESET "\033[0m"

class RealTimeVerifier {
public:
  RealTimeVerifier(const char *expected)
      : m_expected(expected), m_index(0), m_failed(false), m_started(false) {
    m_expected_len = strlen(expected);
  }

  void on_uart(char ch) {
    if (ch == '\r')
      return;

    if (!m_started) {
      if (m_expected_len > 0 && ch == m_expected[0]) {
        m_started = true;
      } else {
        return;
      }
    }

    bool match = (m_index < m_expected_len && ch == m_expected[m_index]);

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
    if (m_failed)
      return false;
    if (m_index == 0)
      return false;
    if (m_index < m_expected_len)
      return false;
    return true;
  }

private:
  const char *m_expected;
  size_t m_expected_len;
  size_t m_index;
  bool m_failed;
  bool m_started;
};

inline bool TestAliSDKHelloWorld() {
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

  RealTimeVerifier verifier(EXPECTED_OUTPUT);
  Emulator emu;

  emu.setLogHandler([](const char *msg) {
    if (strstr(msg, "UNIMPLEMENTED"))
      printf("[EMU] %s\n", msg);
  });

  emu.setUartHandler([&verifier](char ch) { verifier.on_uart(ch); });

  emu.loadFile("../ali_sdk.bin");
  emu.run(60000);

  return verifier.finish();
}
