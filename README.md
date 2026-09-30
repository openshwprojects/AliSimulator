# AliSimulator

Unicorn-based simulator for ALi M3329 (MIPS32 + MIPS16e) satellite receiver firmware dumps.

## Execution modes (simulator.py)

* **Fast mode (default)** - Unicorn runs the code natively in wall-clock slices.
  Python is only involved through small ranged hooks: the CP0 instruction sites
  (MFC0/MTC0/ERET of Count, Compare, Status, Cause, EPC, found by scanning
  memory), breakpoints / `stop_instr`, and the first execution of each RAM
  chunk (which triggers a rescan for new CP0 sites). `instruction_count` and
  `max_instructions` are *estimates* in this mode (rate measured at start-up),
  and the simulated CP0 Count follows wall-clock time (`count_hz`).
* **Exact mode** - `sim.hook_every_instruction = True` (the GUI sets this)
  installs a per-instruction hook: exact instruction counts, instruction
  history / loop counts, `trace_instructions`, `verify_isa_mode`. About 100x
  slower.

Single steps always use the exact hook. Both modes read the real ISA mode
(MIPS32 / MIPS16) from the CPU, so restarts never guess the mode.

## Things learned the hard way

* Unicorn 2.1.4 executes MIPS16e natively; the ISA mode is bit 0 of the PC
  passed to `emu_start()` / `reg_write(PC)` and is read back from the saved
  CPU context (`is_mips16_mode()`).
* Unicorn's MIPS timer is compiled out: `mfc0 Count` reads 0 natively, so
  Count is emulated through the CP0 site hooks.
* The firmware uses kuseg addresses (0x18000058, 0x0FC00000); QEMU only maps
  kuseg 1:1 with Status.ERL set, so the native Status always carries ERL.
* SPI flash responses and command-trigger stores land in the flash window;
  `rom_image` keeps the pristine flash contents and every transient write is
  reverted before the firmware can read it (this corruption of flash word 0
  was what made `expand()` crash before).
* Never mix counted (`count=`) and wall-clock (`timeout=`) `emu_start` slices
  once hundreds of code hooks exist: counted slices then stall for minutes.

## Tests

Run the scripts individually (`python run_dump_maciej_to_bl_verify_sw.py`,
`python run_dump_to_end.py`, `python test_boot_decodes_mips16.py`, ...) or all
of them with `python run_all_tests.py` (a few minutes). `python run_all_tests.py
--slow` adds `run_dump_maciej_to_main_app.py`, which boots dump_maciej.bin
through expand() into the main application (about 5 minutes) and checks the
decompressed image against an offline LZMA decompression of the flash chunk.

Mechanism tests that need no firmware dump: `test_isa_mode_tracking.py`
(MIPS32/MIPS16 switches, breakpoints inside MIPS16 code),
`test_flash_window_isolation.py` (SPI responses vs flash contents, page program,
sector erase), `test_cp0_count_emulation.py` and
`test_mips16_decoder_encodings.py`.
