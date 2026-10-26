#!/bin/sh
# Builds the C++ core on Linux / macOS (g++ or clang++): build/libalicore.so (the
# library src/cpp_core.py loads) and build/alicore_tests (its own tests).
# The Windows build is build.bat (MSVC).
#   cpp/build.sh [folder]   into that folder instead of cpp/build/ (a development
#                           copy: ALISIM_CPP_DLL=<folder>/libalicore.so loads it)
#   CXX=clang++ cpp/build.sh   another compiler
set -e
cd "$(dirname "$0")"
OUT="${1:-build}"
CXX="${CXX:-g++}"
mkdir -p "$OUT"
CXXFLAGS="-O2 -std=c++17 -DNDEBUG -fPIC -fvisibility=hidden -Iemulator -Wall -Wno-unused-function"
SRC="emulator/alicore.cpp emulator/alicore_exec.cpp emulator/alicore_fpu.cpp"
$CXX $CXXFLAGS -shared $SRC emulator/alicore_api.cpp -o "$OUT/libalicore.so" > "$OUT/build.log" 2>&1 || {
  cat "$OUT/build.log"; echo "BUILD FAILED"; exit 1; }
$CXX $CXXFLAGS $SRC tests/alicore_tests.cpp -o "$OUT/alicore_tests" >> "$OUT/build.log" 2>&1 || {
  cat "$OUT/build.log"; echo "BUILD FAILED"; exit 1; }
echo "built $OUT/libalicore.so and $OUT/alicore_tests"
