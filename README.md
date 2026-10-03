# AliSimulator

Unicorn-based simulator for ALi M3329 (MIPS32 + MIPS16e) satellite receiver firmware dumps.

## Execution modes (simulator.py)

* **Fast mode (default)** - Unicorn runs the code natively in slices that end
  at a deadline (`batch_timeout_us`, or the next CP0 timer interrupt). Every
  hooked CP0 instruction checks the deadline and ends the slice synchronously;
  a re-armable stopper is the backstop for code without CP0 instructions
  (`slice_stopper.py`; on 64-bit Windows a high-resolution waitable timer
  whose callback is `uc_emu_stop` itself, elsewhere a Python thread;
  `sim.slice_stopper = 'unicorn'` falls back to `emu_start(timeout=)`, which
  on Windows is 15-150 ms coarse and lacks the EXL / context-switch
  protections described under "Things learned").
  Python is only involved through small ranged hooks: the CP0 instruction sites
  (MFC0/MTC0/ERET of Count, Compare, Status, Cause, EPC, found by scanning
  memory), breakpoints / `stop_instr`, and the first execution of each RAM
  chunk (which triggers a rescan for new CP0 sites). `instruction_count` and
  `max_instructions` are *estimates* in this mode (rate measured at start-up),
  and the simulated CP0 Count follows emulation time at `count_hz`: the CPU
  time of the emulation thread inside `emu_start` (`thread_clock.py`;
  `sim.count_clock = 'wall'` uses wall time instead). Time the thread spends
  preempted by other processes therefore does not advance Count: firmware
  relies on "nothing ticks within the next millisecond" in places (the RTOS's
  first task dispatch writes Count=0 / Compare=+1 ms and then runs ~50
  instructions with interrupts enabled), and a host stall used to break that.
* **Exact mode** - `sim.hook_every_instruction = True` (the GUI sets this)
  installs a per-instruction hook: exact instruction counts, instruction
  history / loop counts, `trace_instructions`, `verify_isa_mode`. About 100x
  slower.

Single steps always use the exact hook. Both modes read the real ISA mode
(MIPS32 / MIPS16) from the CPU, so restarts never guess the mode.

## Interrupts

* **CP0 timer** (`sim.timer_enabled`, default on): when Count passes Compare
  the simulator latches Cause.TI / IP7 (an edge, cleared only by writing
  Compare, as on the 24K core) and takes the interrupt when Status has IE=1,
  EXL=0, ERL=0 and IM7=1: EPC = PC (bit 0 = MIPS16), Cause.ExcCode = 0,
  Status.EXL set, vector 0x80000180 (0x80000200 with Cause.IV=1; 0xBFC00380 /
  0xBFC00400 while BEV=1). The firmwares' RTOS (TDS) runs its 1 ms tick from
  it; before, the applications parked forever in the idle task's `b .`.
  `sim.timer_irq_count` counts deliveries.
  * Exact mode takes the interrupt at the exact instruction (Count = 2 per
    instruction, so one firmware tick is 168,750 instructions, ~7 s in the GUI).
  * Fast mode takes it between slices: a slice ends at the next Compare
    deadline and the handler's MTC0 Compare / ERET move that deadline. With
    the native stopper this delivers ~80% of the programmed rate per second of
    emulation time (~200-250 of 296 ticks/s for the firmware's tick at
    `count_hz` = 100 MHz; fewer per wall-clock second on a loaded host, since
    emulation time is the thread's CPU time); the firmware's clock keeps time
    anyway because it is derived from Count deltas. The slice deadline is
    wall-clock while Count is CPU time, so when the thread is preempted a slice
    ends before Count reaches Compare and a short follow-up slice delivers the
    tick.
  * A Compare written after Count already passed it (a host stall inside the
    tick handler) fires at once instead of after a 43 s Count wrap.
  * Fast mode only: after an ERET the guest runs at least `irq_min_gap_us`
    (200 us) before the next timer interrupt. Hooked CP0 instructions cost
    ~50 us of host time each, which Count sees, so without this a handler
    that takes longer than the tick period would starve the interrupted code.
* **Software interrupts** (Cause.IP1..0 written by the firmware) use the same
  path. MFC0 Cause returns the live value; MTC0 Cause only changes the
  writable bits (IP1..0, IV, WP, DC).
* **UART receive** (`setUartReceiveData`): a one-shot IP3 interrupt through the
  ALi interrupt controller. IP3 is ORed into Cause (a pending IP7 stays
  visible). While RX bytes remain queued, the ERET that ends the UART
  interrupt re-arms it 100 instructions later; timer ERETs do not.

Interrupts are never injected inside a CP0-site hook (the kernel has k0/k1 live
there), in a branch delay slot (also not after an asynchronous stop that left
the CPU between a branch and its delay slot), or before a MIPS16 compact jump /
PC-relative branch (Unicorn ignores or faults on a hook PC write there: the
slice is stopped after the branch and `run()` delivers).

Debugging with interrupts: single steps (`step()`, `runStep()`, the GUI's Step
Into, and `run()` stepping off a breakpoint) never take an interrupt; a pending
one is taken by the next `run()`. The GUI's Step Over (of a call) and Step Out
run to a temporary breakpoint with `run()`, so they do take interrupts.
Breakpoints inside the tick handler fire on every tick; set
`sim.timer_enabled = False` to stop the ticks while debugging (switching it on
again delivers a Compare passed in the meantime).
`[ERET]` log lines, which now mostly come from timer ticks, are logged for the
first 64 ERETs and then every 1000th; `[TIMER IRQ]` for the first 8 ticks and
then every 1000th.

## Things learned the hard way

* Unicorn 2.1.4 executes MIPS16e natively; the ISA mode is bit 0 of the PC
  passed to `emu_start()` / `reg_write(PC)` and is read back from the saved
  CPU context (`is_mips16_mode()`).
* Unicorn's MIPS timer is compiled out: `mfc0 Count` reads 0 natively, so
  Count, Compare and the timer interrupt are emulated through the CP0 site
  hooks.
* A `reg_write(PC)` from a code hook is ignored in a branch delay slot and on
  MIPS16 JRC/JALRC, and raises "Unhandled CPU exception" (or is ignored) on
  MIPS16 B/BEQZ/BNEZ/BTEQZ/BTNEZ: those complete inside the instruction.
* The firmware uses kuseg addresses (0x18000058, 0x0FC00000); QEMU only maps
  kuseg 1:1 with Status.ERL set, so the native Status always carries ERL.
* SPI flash responses and command-trigger stores land in the flash window;
  `rom_image` keeps the pristine flash contents and every transient write is
  reverted before the firmware can read it (this corruption of flash word 0
  was what made `expand()` crash before).
* Never mix counted (`count=`) and wall-clock (`timeout=`) `emu_start` slices
  once hundreds of code hooks exist: counted slices then stall for minutes.
* An asynchronous stop (slice deadline, Unicorn's timeout, a GUI pause) is
  noticed right after a load / store and rewinds the PC to it, so that access
  and its memory hook run again on resume. For the device registers whose
  access has a side effect (UART THR / URBR, SPI response reads) the hooks
  recognise the re-execution and serve / skip the same data; before, this
  duplicated UART output characters ('bbl_flash_init!') and lost RX bytes.
  A stop counts as a rewind only if the PC is on the access and the registers
  are unchanged (a later pass of a loop changes some register), and pending
  replays are kept per (PC, SP), so an interrupt handler or another task using
  the same putc / getc does not take them.
* Unicorn 2.1.4 bug: after a load / store with a memory hook (i.e. a device
  register) in a branch delay slot, the branch target's first instruction runs
  twice. The shipped dumps never do this (checked over 80M instructions); the
  simulator logs a `[WARN] device access in a branch delay slot` once per PC.
* Unicorn 2.1.4 bug: translating an unhooked straight-line block of ~375 or
  more instructions (also a jump into zero-filled RAM) crashes with an access
  violation. Fast mode reports it as a RuntimeError; exact mode is not
  affected (a hook on every instruction keeps blocks short).
* `emu_start(timeout=)` on Windows creates a thread per call that polls with
  a 15.6 ms timer and is joined at the end, hence `slice_stopper.py`.
* Unicorn race: `uc_emu_stop()` from another thread sets `stop_request` before
  it calls `cpu_exit()`, and the code-hook dispatcher skips *all* hooks while
  `stop_request` is set (in a branch delay slot it does not even exit first).
  A hooked CP0 instruction reached in that window runs natively: `mfc0 Count`
  reads 0, `eret` jumps to ErrorEPC = 0 (ERL is forced), `mtc0 Status` drops
  the forced ERL. So fast-mode slices end synchronously: every hooked CP0
  instruction checks the slice deadline, the asynchronous stopper is only a
  backstop 1 ms later (50 ms while EXL is set, i.e. in exception / context
  switch code), and a slice ends synchronously when the guest itself enters
  EXL. The stopper's disarm waits for a callback in flight, so a stale stop
  cannot hit the next slice. A native `mtc0 Status` or `eret` that still slips
  through is visible (the forced ERL is gone) and is repaired at the slice
  boundary (adopted / redone, also when the native `eret` faulted at address 0)
  and logged as `[WARN] native ...`; `sim.native_cp0_repairs` counts them. A
  native MFC0 (Status reads the forced ERL, EPC / Count / Cause read Unicorn's
  stale registers) or MTC0 Compare / EPC / Count / Cause is *not* visible and
  not repaired; these have become rare (heavy-load soaks: none observed), and
  exact mode is immune. The full fix would be to stop forcing ERL (identity-map
  kuseg with a wired TLB entry instead) and to mirror EPC / Count into
  Unicorn's own CP0 registers.

## Tests

Run the scripts individually (`python run_dump_maciej_to_bl_verify_sw.py`,
`python run_dump_to_end.py`, `python test_boot_decodes_mips16.py`, ...) or all
of them with `python run_all_tests.py` (a few minutes). `python run_all_tests.py
--slow` adds `run_dump_maciej_to_main_app.py`, which boots dump_maciej.bin
through expand() into the main application (about 5 minutes), checks the
decompressed image against an offline LZMA decompression of the flash chunk,
and checks that the application's RTOS runs on timer ticks (it prints its
init banner, compared exactly). `run_dump_to_main_app.py` and
`run_dump_Prima_to_main_app.py` (about 10 s each, in the default run) do the
same for dump.bin and SRT Prima: their whole UART output -- bootloader lines
plus the application's 'MC: APP  init ok' / SDK / Libcore / Application
banner -- must match byte for byte, timer interrupts must be taken, and the
application must keep running. Before the CP0 timer existed these
applications parked in the RTOS idle task right after 'success!'.

Mechanism tests that need no firmware dump: `test_isa_mode_tracking.py`
(MIPS32/MIPS16 switches, breakpoints inside MIPS16 code),
`test_flash_window_isolation.py` (SPI responses vs flash contents, page program,
sector erase), `test_cp0_count_emulation.py`, `test_cp0_timer_interrupt.py`
(timer latch, masking, MIPS16 EPC, late Compare, software interrupts) and
`test_mips16_decoder_encodings.py`.
