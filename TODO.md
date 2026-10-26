# TODO / hand-over: the C++ engine (state of 2026-10-22)

## Merge validation (2026-10-25)

Wrap-up on 2026-10-26: the user needed to leave while final console validation
was running. Both matrix processes remain active and save each result. The
helper `report/merge-validation/finish_when_ready.py` waits for those existing
runs and invokes `finalize_reports.py` only if both finish without failures.
Read `report/merge-validation/wrapup-status.json` for the final state and
`finish-when-ready.log` for report verification output. Until its status is
`complete`, do not claim every test is passing. A PC shutdown interrupts
these processes; the recovery commands below resume from saved checkpoints.

`main` now includes the four upstream commits through `217d815`. Local work
was merged back and remains uncommitted. The original local snapshot is
`stash@{0}` (`e4016fcd77447ea18d61c81f5abbf311b5c2e232`,
"codex pre-merge local work 2026-10-25"); keep it until the combined work is
committed. Git has no unresolved conflicts.

The newer alicore engine is retained. All five additional upstream native
tests were ported to it through `cpp/tests/test_board.h`; the rebuilt native
suite passes 7/7. The Python adapter now initializes the new ROM/MMIO views
and SmartCard model, handles the extended UART register range and chip
override, and preserves SPI state when switching native/Python handlers.
New regression checks cover those SPI transitions. The console tests retain
both upstream command coverage and the local natural runtime lifecycle.

The full runner discovers 128 scripts per engine (93 without `--slow`). Both
full runs were interrupted by a PC crash. Original logs are
`report/merge-validation/unicorn.log` and `report/merge-validation/cpp.log`.
After restarting, all seven native tests passed again
(`report/merge-validation/native-after-restart.log`). The ignored recovery
runner `report/merge-validation/resume_tests.py --engine unicorn|cpp --jobs 2`
recovered 14 passing Unicorn and 68 passing C++ results (including saved
retests) and resumes the remaining scripts. It writes an atomic result after
each test under `report/merge-validation/checkpoint/<engine>/`; restart the
same command to resume again. Current logs are `unicorn-resumed.log` and
`cpp-resumed.log` in that directory. Failed original results are preserved,
including a Unicorn Globo signal calibration failure and a C++ Python DLL
import failure just before the PC crash; both passed on the resumed run.
Both engines completed their initial 128-script recovery. Final console
validation is in progress after the harness fixes described below; existing
aggregate reports are not yet final.

The R265 Lite 1.1.5 console test exposed an
8M-instruction boot assumption: it now waits for the application banner with
a 60M cap and 500k steps, above the exact-count threshold. Its focused retest
passes 30/30 on both engines, with result records under
`report/merge-validation/retests/`. The same boot settings are used in the
multi-receiver console test. The latter also now waits for the Maciej
firmware to finish initializing its UART listener before activation, and
checks `comtest` in a separate simulator instance: that factory handshake
queues an upgrade action which otherwise fires after EXIT. All existing
command, RCU, EXIT/reactivation, and multi-receiver assertions are retained.
Its focused run passes on both engines. Structured records are saved as
`retests/{cpp,unicorn}-test_uart_console.json`.

The resumed Unicorn R265 Lite signal regression reached all eight navigation
steps but compared the final screen while the scan was still at 1%
(14.82% pixel mismatch). Only that test now requests a bounded 300-second
`nav_settle_s` wait, using the existing exact expected-screen polling;
all pixel and navigation assertions remain unchanged. Focused Unicorn
and C++ retests passed with exact final images (736 s and 171 s). Both
completed before the new settling wait was needed, so the earlier stall
remains unexplained. Passing records are imported into both checkpoints;
the original failed checkpoint and images are preserved. Logs and structured
results are under `report/merge-validation/retests/`.

X110TS 1.4.0C console exposed an unsafe harness takeover: the old
2M-instruction wait could expire before reaching idle, then forcibly replace
a firmware task holding a flash mutex. The shared harness now allows up to
30M instructions and verifies arrival at idle before changing PC/SP or
masking scheduling; failure uses the existing bounded fresh-boot retry.
Its CHANNELS command now allows 64 slices instead of 16: a populated listing
emitted 73,920 characters in 46 slices, with quiet database scans between
sections. All 30 assertions remain unchanged.

R265 Lite 1.2.0 has a different OSAL idle layout. Generic discovery chose a
flash error halt at 0x800A30F0; natural execution confirmed actual idle at
0x803879EC. The harness accepts an explicitly supplied idle address and
validates its alignment, RAM bounds and branch/nop instructions. This test
also supplies a readiness predicate: the chunk storage device must be
published, open, have a read handler and have consistent initialized bounds.
The initializer publishes the pointer before opening it, so pointer-only
readiness is insufficient. Readiness and idle arrival are required together
before takeover. This prevents MAINCODE entering the firmware's fatal path
with an uninitialized storage handle. Original 45.5M boot is retained;
additional natural execution is bounded at 30M instructions in 500k steps.

X110TS 1.1.8 RC4 also exposed early takeover: one Unicorn run had no expected
application banner, failed MAINCODE and reached the 600-second watchdog.
Its test now retains the original 10M minimum boot, then checks the expected
banner every 10M instructions up to 60M. The existing banner assertion is
retained. The failed run and all earlier diagnostics remain in checkpoint
history and logs.

All 18 console scripts are being rerun on both engines after the final
harness change, with logs `unicorn-console-final.log` and
`cpp-console-final.log`. Earlier console validation logs use the suffix
`-console-validation.log`. The recovery helper now also hashes shared
console dependencies, so old console checkpoints cannot count as current
evidence. The 110 other scripts per engine have valid checkpoints. Do not edit test sources while
their matrix execution is active: checkpoint source hashes are saved after
execution. The ignored `report/merge-validation/finalize_reports.py`
verifies all 128 current test/dependency hashes and results per engine,
then builds the final comparison only when every result is passing or
explicitly not applicable. Existing aggregate reports are not yet final.

Separate pre-existing issue found during review: host physical MMIO accesses
through `sim.mu.mem_read/mem_write` before the first execution/sync can bypass
C++ device callbacks because its device flags are pushed by `_cpp_sync`.
This predates the merge; the current device test accesses MMIO after running.

The remaining sections below describe the earlier 2026-10-22 work.

The task (from the user): pick up the old C++ draft and get it 100 % up to speed
with the Python/Unicorn simulator, run the tests on it, optimize it, compare
per dump which engine is faster, improve the C++ path again, compare again.
"The C++ emu must cover all we have."

**Nothing is committed.** Commit or push only when the user asks. Everything
below is in the working tree of `W:\GIT\AliSimulator` (branch `main`).

---------------------------------------------------------------------------

## 1. What exists now

### The engine
* `cpp/emulator/alicore.h`, `alicore.cpp`, `alicore_exec.cpp`, `alicore_fpu.cpp`,
  `alicore_api.cpp` -- the new core (a rewrite; the old draft
  `emulator*.cpp`, `main.cpp`, `hello.vcxproj`, `build_and_run.bat`,
  `cpp/tests/test_*.h` were **deleted**: restorable with
  `git checkout -- cpp/`). MIPS32r2 + MIPS16e + FPU interpreter behind
  Unicorn's memory/hook model, native CP0 timer/interrupts, native SPI flash
  controller, decoded-block cache, loop skipping (below), deterministic clock.
* `cpp/tests/alicore_tests.cpp` -- the core's own tests (`alicore_tests.exe`:
  2/2 pass; `alicore_tests.exe bench 5`, `alicore_tests.exe micro 3`).
* `cpp/build.bat [folder]` -- MSVC (VS 2022) build into `cpp/build/` (default)
  or another folder (`build-dev` was used for development while suites ran on
  `build/`; `ALISIM_CPP_DLL=cpp\build-dev\alicore.dll` selects it).
  From bash: `cmd //c "cpp\\build.bat"`. `cpp/.gitignore` now ignores
  `build/`, `build-*/`.
* `src/cpp_core.py` -- ctypes binding, `CppUc` (Unicorn look-alike). DLL is
  loaded from a shadow copy `%TEMP%\alisim_cpp\alicore_<size>_<mtime>.dll`
  (one per build, made via tmp + os.replace; `ALISIM_CPP_NOSHADOW=1` loads the
  DLL itself). `mem_read` of plain regions reads host memory in place
  (`ali_direct`).
* `src/simulator_cpp.py` -- `CppAliMipsSimulator(AliMipsSimulator)`; selected by
  `AliMipsSimulator(engine='cpp')` or env `ALISIM_ENGINE=cpp`
  (`simulator.default_engine()`, `__new__` dispatch in `simulator.py`).
* `tests/engine_check.py` -- `CPP`, `not_applicable()`, `unicorn_only()`.
* `tests/test_cpp_loop_skip.py` -- exactness of the loop skipping (skip on vs
  off: same registers, same Count at loop exit); N/A on Unicorn.
* `tools/cpp_lockstep.py`, `tools/cpp_bisect.py`, `tools/cpp_fuzz.py` --
  checks against Unicorn. `tools/engine_compare.py A.json B.json` -- two
  `results.json` side by side (per-test times, app-started / OSD-visible
  milestones, dump names read from the test sources).
* `run_all_tests.py --engine cpp` (report in `report/cpp/`), N/A status.
* README: new section "## The C++ engine (cpp/, simulator_cpp.py)" (before
  "## Interrupts"), Layout bullets for `cpp/` and `tools/`, a paragraph in
  "## Tests". **The section ends with a placeholder `COMPARISON`** -- fill it
  (see 3.1).
* Memory notes: `~/.claude/projects/W--GIT-AliSimulator/memory/alisim-cpp-engine.md`.

### Time model (C++ engine)
vtime = icount / 50 M (`ALISIM_CPP_IPS`), Count = 2 per instruction,
fast-mode `instruction_count` = vtime x 0.75 M/s (`ALISIM_CPP_RATE`), a
Python-handled device access costs 250 instructions (`ALISIM_CPP_ACCESS_COST`).
Timed slices are up to `batch_timeout_us` (100 ms) of emulation time; timer
interrupts are delivered inside the core. A slice service may define `due()`
(next emulation time it needs to run) and the C++ engine ends the slice
there (`video_m36.VideoOutput.due`; without it the T50 hung).
RTOS `delay()` HLE (Python hooks) is **off by default on cpp**
(`ALISIM_CPP_DELAY_HLE=1` turns it on): the core skips the polling loops
itself, faster than the hooks.

### Round 1 (earlier in the session, before the first comparison)
Block cache, native SPI, idle/spin skip, DLL shadow copy, engine-aware tests,
delay HLE off on cpp, page-table refresh only for touched pages (init 0.5 s ->
0.06 s), core profiler (`ALISIM_CPP_PROFILE=<file>|1`,
`ALISIM_CPP_PROFILE_CODE=1` adds the hot blocks' disassembly).

### Round 2 (after comparison 1)
* Blocks chain inside `run_blocks<true>` (no return to `run_loop` per block),
  multiplicative block-table hash, inline code compare (`same_code`), generic
  ops (`gen32_op`/`gen16_op`) out of line (exec32 was force-inlined into the
  block runner -> 9K-line function), catch handler finds the faulting op via
  `cur_pc_`.
* `mfc0 Count` (`U_MFC0_COUNT`) and register traps TGE..TNE (`U_TRAP`, the
  `teq` after `divu`) are block ops, not barriers / generic ops.
* Count-poll skip: a loop that reads Count gets one pass recorded; the largest
  number of whole passes after which it still goes on is found by replaying
  that pass at later times (`poll_probe`, rolled back; slow accesses throw,
  plain device reads allowed), registers written before read and before the
  first possible exit may differ (`pass_ignorable`, `rec_ign_`); known loops
  cached per head (`PollLoop`, validated block by block: `poll_seq_valid`).
* Counting-loop fast-forward (`Block::Ff`, `analyze_ff`, `ff_passes`):
  cache-maintenance loops etc. jump to their last pass (closed form).
* Spin check interval adaptive (1 -> 32 passes); plain device reads (no
  `DF_READ`/`DF_NATIVE`) don't count as slow.
* GPIO DO/DIR stores (`DF_GPIO_DO`/`DF_GPIO_DIR`) logged natively, handed to
  the decoders in order (`_cpp_gpio`, drained by `_cpp_dev` before a device
  access, `host_sync()` before any other host call and at run end).
* Chunk events (LZMA/delay-routine scans) now also from the block path
  (`get_block` reports a new chunk, returns null, loop retries).
* Retired blocks freed only at the top of `run_loop` (`retire`, `free_retired`).
* Fixed the shadow-copy race (random access violations / "module not found"
  under `--jobs 2`).
* Shared Python (both engines): `_hook_gpio_di_read` and `_ic_set_line` read /
  write the device buffer in place (`_mmio_word`, `_mmio_view`) instead of
  `uc.mem_read/mem_write`; `PanelDecoder._gpio_changed` walks only changed
  bits; screen tests count colours with packed RGB (`count_colours`, ~70x
  faster than `np.unique(axis=0)`); `tools/screen_survey.py` likewise.
* `CppAliMipsSimulator._ic_lines` read from a Python copy.

### Verification done
* Default suite (`run_all_tests.py --engine cpp --jobs 2`): all applicable pass
  (71 + 1 N/A) on the round-2 core (snapshot 2); Unicorn default suite 71/71
  earlier.
* Slow suite, round 2 (snapshot 3): **C++ all 102 applicable pass (1 N/A);
  Unicorn all 102 applicable pass (1 N/A)**.
* `tools/cpp_bisect.py <dump> 30000000`: identical on dump_maciej.bin,
  dump.bin, SRT_Prima_VIII (final core). `tools/cpp_fuzz.py 20000 --only m32
  --seed 7`: 0 differences.
* `tests/test_cpp_loop_skip.py`: 300 random counting loops + 2 delay() kinds
  exact.

---------------------------------------------------------------------------

## 2. Results (both runs `--slow --jobs 2`, from frozen snapshots)

Data: `report/comparison/` (gitignored): `cmp1_uni.json`, `cmp1_cpp.json`,
`cmp2_uni.json`, `cmp2_cpp.json`, `combined.md` (the per-test table:
Unicorn / C++ round 1 / C++ round 2 / Unicorn with round-2 shared code),
`combine.py` (regenerates it: `python report/comparison/combine.py 5`).
Two runs side by side:
`python tools/engine_compare.py report/comparison/cmp2_uni.json report/comparison/cmp2_cpp.json --min 5`.

| | suite test time (all tests, summed; not wall time) | test time summed (tests >= 5 s) |
|---|---:|---:|
| Comparison 1: Unicorn | 6860 s | 6770 s |
| Comparison 1: C++ round 1 | 4840 s (T50 timed out: 2400 s) | 4777 s |
| Comparison 2: Unicorn (round-2 shared code) | 5627 s | 5564 s |
| Comparison 2: C++ round 2 | **1125 s** | **1006 s** |

* Comparison 1: C++ faster on 42 of 49 tests (3-9x on most screen
  regressions); slower on T50 (hung: the `due()` fix), and on short dual-CPU /
  app-start tests and Python-API-heavy unit tests.
* C++ round 1 -> round 2: every test faster, 4.3x in suite test time
  (x110ts 183 -> 25 s, hdxs2 128 -> 18 s, t760i 119 -> 19 s, t750i 98 -> 14 s,
  urz0086 79 -> 13 s, cabletech 93 -> 49 s, r265lite_signal 305 -> 150 s,
  T50 2400 (hang) -> 12 s).
* Comparison 2: C++ 5.0x faster in suite test time, faster on 45 of 49;
  per screen regression typically 5-12x (tht501 12.4x, prima8 10.9x,
  urz0086 10.6x, m3329 10.1x, dump.bin 9.5x ... r265lite_120 2.4x,
  r265lite_signal 3.4x).
* Still faster on Unicorn: `test_native_status` (12 vs 23 s),
  `test_device_models` (10 vs 21 s), `test_delay_hle` (4 vs 17 s; it turns the
  Python delay HLE on, which cpp normally doesn't use),
  `run_dump_maciej_without_uart_interrupt` (2.6 vs 3.3 s) -- all bound by
  per-call ctypes overhead of the binding (CP0 shadow properties, device
  callbacks), not by the core.
* Note: the machine (i7-6700HQ) was shared with other work during both runs;
  absolute numbers are noisy, ratios are robust.

---------------------------------------------------------------------------

## 3. What to do next

### Done in the session of 2026-10-22 (afternoon)
* README: the `COMPARISON` placeholder replaced by the summary of section 2;
  the `--slow` paragraph now says 103 tests, ~19 min of test time on C++
  (loaded machine; re-measure on an idle one). Note: `total_time` in
  results.json (and the 5627 / 1125 s below) is test time summed, not wall time.
* `tests/test_cpp_loop_skip.py`: one simulator reused for all 602 runs (reset
  between runs: clock, skip counters, registers): ~60 s -> 12 s alone, 22 s in
  the suite under `--jobs 2`. Passes.
* Binding overhead: `ali_timer_wait` (one call for `_timer_wait_us`, was ~7
  ctypes calls); the code hook now passes the instruction's ISA
  (`CodeHookCb(..., m16)`, `CppUc.hook_m16`) so the exact-mode hook no longer
  reads `F_M16` back per instruction. Core rebuilt (`cpp/build/`), 2/2.
* Default suites before these binding edits: C++ 71 + 1 N/A, Unicorn 71 + 1
  N/A, all pass. Hook/timer tests (native_status, delay_hle, device_models,
  isa_mode_tracking, cp0_timer_interrupt, step_over_breakpoint,
  cpp_loop_skip, jalx_debug) pass on the new core.
* GUIs on the C++ engine: `tv_gui.py`'s emulation loop run headless 20 s of
  firmware on dump_maciej.bin (app banner, 350 GE commands, 571-colour frame,
  an IR key) in 9.8 s wall; the TV GUI window itself started and stayed up
  45 s; the debugger GUI's calls (code hook with emu_stop, step, poke/peek,
  continue, a breakpoint hook stopping on its 3rd hit) work.
* Snapshot junctions (`dumps`, `refs` in snap2 / snap3) removed; the repo's
  dumps / refs checked intact. `cpp/build-dev/` was deleted then rebuilt for
  development (gitignored; may go again).
* C++ default suite rerun on the rebuilt core: 71 + 1 N/A, all pass.
* Timed one at a time afterwards (machine still noisy: Unicorn's
  native_status took 27 s here, 12 s in comparison 2):
  native_status C++ 22 s / Unicorn 27 s, delay_hle 21 / 6 s,
  device_models 31 / 13 s. The two binding edits did not visibly close the
  gap on delay_hle / device_models: their cost is the Python delay hooks
  (`_hook_delay`, ~240 K calls) and ~1 M `_cpp_dev` device callbacks (GE
  stress test). Next lever: fewer crossings, not cheaper ones (see 3.3).
* `W:\alisim_snap1..3` deleted (on the user's request, after the junctions
  were removed); the repo's dumps / refs intact.
* **CI runs both engines and publishes a comparison** (user: "yes, do it"):
  - `cpp/build.sh` (g++ / clang++ -> `cpp/build/libalicore.so` +
    `alicore_tests`); `src/cpp_core.py` loads `alicore.dll` on Windows,
    `libalicore.so` elsewhere (`LIB_NAME`, `BUILD_HINT`). g++ 9.4 under WSL
    Ubuntu: no warnings, 2/2 core tests.
  - `.github/workflows/tests.yml`: matrix job `test` (unicorn -> report/,
    cpp -> report/cpp/, in parallel), job `report` (both reports in one tree,
    `tools/engine_compare.py --html report/comparison.html`, the markdown
    table in the run's summary page, Pages artifact), `deploy`.
  - `run_all_tests.py --link "Label=href"` (header links; meta.engine /
    meta.links; the C++ page's title says "C++ engine"); `tests/report.py`
    renders them. `engine_compare.py --html/--link`: summary tiles, sortable
    table, log-scale speed-up bars, light/dark, phone width checked.
  - Fixed: `test_native_status.py`'s `ForcedErl` subclass is never sent to
    the C++ engine (`__new__` only dispatches `AliMipsSimulator` itself), so
    in the C++ suite its forced-ERL cases ran on Unicorn and failed on slow
    hosts (WSL, profiler). Now `unicorn_only` there.
  - Fixed: a `\b` (backspace) in run_all_tests.py's "not built" message.
  - Verified under WSL (Python 3.8 venv `~/alisim-ci-venv`): C++ default
    suite 70/71 before the test fix, the fixed test passes.
  - **Not yet seen on GitHub**: needs a commit + push; nothing committed.
  - Linux (WSL, g++ core) slow suite on the C++ engine: 102 + 1 N/A, all
    pass, 1090 s wall with `--jobs 2`.
* **UART console test** `tests/run_dump_maciej_console.py` (default suite):
  all 18 commands of dump_maciej's console + startconsole, 26 checks; C++
  7 s, Unicorn 45 s, Linux C++ 12 s. Findings: the console task reads the
  UART from ~18 s after power-on (earlier bytes wait in the driver's ring
  buffer: no simulator bug); after EXIT a line sent within ~20 ms is still
  taken (a race in the firmware: wait before testing "deactivated");
  TOUCH/READ/DELETE only reach their error path (no USB storage modelled);
  TIME's "set new time?" wants an unknown key ('n' -> "Wrong value!").
* **Bottlenecks found (profiles of the 3 slowest C++ tests)**: Python device
  work is ~40-50 % of their time:
  - interrupt-controller status reads (`_hook_ic_status_read`): 387 K - 717 K
    Python calls per test, two `lw` in the RTOS's ISR dispatcher; the core
    knows `ic_lines_`, so it could serve the status word natively (cheap win).
  - panel bit-banging (TM1628 / TM1650): ~2 M GPIO edges + 700 K DI reads
    (Cabletech, T650i) -> a native decoder (discuss first: duplicated logic).
  - demod / tuner status polls through `chips/base._read` (T650i: 670 K).
  - GE model (R265 Lite: ~1 M device callbacks, `ge_m36f._execute`).
  - core side: short `delay()` loops calling `get_count()` (R265: ~15 % of
    executed instructions) still run most passes; 8.7 G instructions really
    executed in the R265 signal test.
* **Full slow suites, final tree (2026-10-22 evening, Windows, `--jobs 2`)**:
  C++ 103 + 1 N/A, all pass, no boot retries. Unicorn 102 + 1 N/A pass,
  1 FAIL: `run_dump_r265lite_120_app_banner.py` -- every boot attempt (1 +
  4 retries) stopped with Unicorn's spurious UC_ERR_READ_UNMAPPED (plus
  native access violations in mem_map_ptr / _calibrate_hflags printed by
  faulthandler: 617 in the Unicorn log, 0 in the C++ one); run alone it
  passes twice, each time after one failed boot (131 s instead of ~30 s).
  `run_dump_capture_screen.py` also needed one retry on Unicorn. Unicorn
  flakiness, not today's changes (no Unicorn-path code changed); it can turn
  the Unicorn CI job red. Root cause not investigated.
* **Device survey (2026-10-22 evening)**: every image under dumps/ (50) for
  60 s of firmware time on the C++ engine, panel + tuner attached, all device
  register reads in 0xB8000000..0xB803FFFF observed (script kept in the
  session scratchpad: device_survey.py + survey_summary.py; could become
  tools/device_survey.py). No errors, no complaint lines (timeout / fail /
  error ...) in any UART output; 41 drew (the rest: ali_sdk no display,
  M3822P damaged, M3329 draws by CPU, T760i x4 and R265 Lite x2 draw after
  60 s). Polled registers with no model, never written, reading 0:
  - 0xB8000070 strap pins (SDK flash/smartcard drivers read it): 0 is a
    valid strap -- fine.
  - 0xB801841C: the second UART (0xB8018400, SDK sci_16550_reg[1]), not
    modelled; nothing is connected to it.
  - 0xB802A008 (40 images, ~50 reads/s), 0xB800E950..E960 (URZ0083 family,
    THT501, S60), 0xB8028004/F8/113/137 (HD-XS2, ESR-250): unidentified
    blocks, periodic reads, firmwares carry on.
  - 0xB8003005/08/0D (M3329; on the M36xx the S3501 DVB-S2 demod base) and
    0xB8005014 on the M3329: read exactly 20 000 times -> a busy-wait that
    runs to its timeout on an unmodelled block (costs time; its screen test
    passes).
  - Not modelled at all (known): USB storage (console TOUCH/READ/DELETE),
    the internal M3501 demod (ESR-250), the second UART.
* `tools/cpp_fuzz.py`: m32 20 000 -> 0 differences but 545 s; m16 -> 30
  differences, all known Unicorn quirks (its native crashes, unmapped vs
  unaligned order, unaligned PC-relative loads it allows) -> not CI-ready
  without an allow-list.

### 3.1 Finish the write-up (small)
* README "## The C++ engine": replace the `COMPARISON` placeholder (last
  bullet) with a short summary of section 2 above (suite times, typical
  per-dump speed-ups, where Unicorn still wins and why) and how to reproduce
  (`run_all_tests.py --slow --jobs 2 --engine cpp` / `--engine unicorn`, then
  `tools/engine_compare.py report/results.json report/cpp/results.json`).
* README "## Tests": the `--slow` paragraph says "102 tests, about 45
  minutes"; it is now 103 tests (`test_cpp_loop_skip.py` added) and the
  Unicorn slow suite took ~94 min of test time (summed; not wall) on a loaded
  machine (5627 s); the C++ one ~19 min (1125 s). (done, see above) Re-measure on an idle machine
  before writing durations.
* Give the user the per-dump table (`report/comparison/combined.md`).

### 3.2 Re-verify after the last edits (made after snapshot 3)
These changes were not in the comparison-2 run:
* `tests/test_cpp_loop_skip.py`: programs now end in `SPIN` (a nop/`b`/nop
  block) instead of `IDLE`; passes. **It still takes ~56-64 s** -- too slow
  for the default suite. Cause is mostly 600 simulator constructions
  (300 cases x skip on/off) plus runs; cut it down: fewer cases (e.g. 100),
  shorter runs (e.g. 200 K instructions), or one simulator reused per case
  (reset PC/registers/Count instead of a new `AliMipsSimulator`).
* `cpp/emulator/alicore.h` header comment (comment only; `cpp/build/alicore.dll`
  is the final build -- rebuild anyway before committing to be sure source
  and binary match: `cmd //c "cpp\\build.bat"`, then `cpp\build\alicore_tests.exe`).
* `tools/engine_compare.py` dump-name lookup.
Run the default suite on both engines:
`python run_all_tests.py --engine cpp --jobs 2` and `python run_all_tests.py --jobs 2`.
Run screen tests from the repo root (a run with cwd=`tests/` leaves PNGs
there; the ignore rules only cover the repo root).

### 3.3 Possible further speed work (C++ path)
* Binding overhead (the tests Unicorn still wins): many `CppAliMipsSimulator`
  properties (`cp0_status`, `_timer_wait_us`, `_slice_armed_end`, ...) do one
  ctypes call each; `test_delay_hle` makes ~3.9 M `CppUc.get` calls. Options:
  one call returning a struct of the CP0/timer state; Python-side copies for
  values only Python changes (as done for `_ic_lines`); a cheaper `_cpp_dev`
  path (the GE stress test in `test_device_models`: ~1 M device callbacks).
* Engine-neutral Python hot spots now dominate several tests: the GE model
  (`ge_m36f.run_list/_execute/_decode/_encode`, ~100 s of
  `run_dump_r265lite_signal_capture_screen`), the panel decoders
  (`tm1628/tm1650 on_gpio_write`, ~2 M edges in cabletech). A native panel
  decoder in the core would remove most of cabletech's Python time but
  duplicates device logic -- discuss with the user first.
* Core: blocks are short in real firmware (~4-5 instructions); ideas:
  page write-tracking instead of the per-entry code compare, direct block
  successor links, native uops for LWL/LWR/SWL/SWR (memcpy), ADD/ADDI/SUB
  (overflow traps), COP1 ops inside blocks (FPU code still runs one
  instruction at a time).
* Profile any slow test: `ALISIM_ENGINE=cpp ALISIM_CPP_PROFILE=prof.txt
  ALISIM_CPP_PROFILE_CODE=1 python tests/<test>.py` -> per-core header
  (executed vs skipped: idle / spin / Count polls / counting loops), top
  blocks with code, top Python device accesses.

### 3.4 Coverage gaps to check
* The GUIs (`src/tv_gui.py`, `src/gui_simulator.py`) were not run on the C++
  engine (they only use code hooks, `emu_stop`, register/memory reads, which
  `CppUc` supports; `ALISIM_ENGINE=cpp python src/tv_gui.py <dump>`).
* `sim.count_clock` / slice stopper options are Unicorn-engine concepts; the
  C++ engine's clock is always the instruction count (documented).

### 3.5 Clean-up before committing
* Snapshots used for the comparison runs: `W:\alisim_snap1` (full copy, ~900
  MB), `W:\alisim_snap2`, `W:\alisim_snap3`. **snap2 and snap3 contain
  directory junctions `dumps` and `refs` pointing into the repo: remove the
  junctions first with `cmd /c rmdir W:\alisim_snap2\dumps` (and `refs`, same
  for snap3) -- `rm -rf` through a junction could delete the repo's dumps.**
  Then delete the snapshot folders.
* `cpp/build-dev/` (development build, gitignored) can go; keep `cpp/build/`.
* `cpp/x64/` and `cpp/trace_cpp.log` (26 MB) are the old draft's ignored
  leftovers from February -- not ours; ask before deleting.
* Line endings: `run_all_tests.py`, `src/simulator.py`,
  `src/tm1650_decoder.py`, `cpp/.gitignore` are CRLF in git -- keep them CRLF
  (patch scripts writing `newline='\n'` turned them into whole-file diffs once;
  fixed). Check with `git ls-files --eol <file>` and `git diff --stat`.
* Bash heredocs in this environment collapse `\\` (and `\b` became a
  backspace character twice): write patch scripts with the Write tool, and
  scan for control characters before committing.
* Suggested commits (when asked): (1) the C++ core + binding + simulator_cpp +
  build script, (2) engine selection in simulator.py / run_all_tests.py /
  tests (engine_check, engine-aware tests, test_cpp_loop_skip), (3) shared
  speed-ups (GPIO DI / IC line in place, `_gpio_changed`, colour count,
  `video_m36.due`), (4) tools (lockstep/bisect/fuzz/engine_compare), (5)
  README; removal of the old draft.

---------------------------------------------------------------------------

## 4. Quick reference

```
cmd //c "cpp\\build.bat"                      # build cpp/build/alicore.dll + alicore_tests.exe
cpp\build\alicore_tests.exe                   # core tests (2/2)
python run_all_tests.py --engine cpp --jobs 2           # default suite on C++
python run_all_tests.py --engine cpp --slow --jobs 2 --timeout 2400
python tools/cpp_bisect.py dump_maciej.bin 30000000     # vs Unicorn
python tools/cpp_fuzz.py 20000 --only m32               # random instructions vs Unicorn
python tools/engine_compare.py report/results.json report/cpp/results.json --min 5
ALISIM_ENGINE=cpp ALISIM_CPP_PROFILE=1 python tests/run_dump_maciej_capture_screen.py
```
Env: `ALISIM_ENGINE`, `ALISIM_CPP_DLL`, `ALISIM_CPP_NOSHADOW`, `ALISIM_CPP_IPS`,
`ALISIM_CPP_RATE`, `ALISIM_CPP_ACCESS_COST`, `ALISIM_CPP_DELAY_HLE`,
`ALISIM_CPP_PROFILE`, `ALISIM_CPP_PROFILE_CODE`.
