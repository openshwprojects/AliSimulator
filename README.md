# AliSimulator

Unicorn-based simulator for ALi set-top-box firmware dumps (MIPS32 + MIPS16e).
The main targets, dump.bin and dump_maciej.bin, are DVB-T (terrestrial)
receivers built for the ALi M3801 ("M3801 DVBT" in their maincode chunk
headers); SRT Prima is from the same family. The firmware identifies the
silicon as an S3811: its chip-ID function reads 0xB8000002 and knows 0x3811 but
no 0x3801, and the simulator reports 0x3811, revision 0. The Echosonic dump
(M3510A, DVB-S2) and the sat_main_ali3329 dump (M3329) are other chips, per
their file names.

## Layout

* `src/` -- the simulator (`simulator.py`, `mips16_decoder.py`, the slice
  stopper and clocks) and the device models (`ge_m36f.py`, `gma_capture.py`,
  the panel decoders, `front_panel.py`, `ir_remote.py`, `i2c_scb.py`), plus the two GUIs:
  `python src/tv_gui.py <dump>` (the TV: OSD, panel, remote) and
  `python src/gui_simulator.py` (the debugger).
* `src/chips/` -- the chip families, one module each (`m3801.py`, `m3821.py`):
  what differs between ALi generations (the chip ID, how the CPU gets from
  reset to the flash's bootloader, extra memory, that generation's devices).
  `loadFile()` picks the family from the image's bootloader chunk header; the
  M3801 is the default and everything `simulator.py` models by itself. The
  M3821 / M3822P (the DVB-T2 boxes: `dumps/Opticum Blue R265 Lite/`) adds the
  boot ROM's step (the bootloader copied into a boot SRAM at 0x1FE00000, entry
  0x9FE00800), a DDR-training model, the chip-ID variant word, the SPI flash
  controller's byte-stream mode and DMA engine, an 8-channel descriptor-ring
  DMA engine (0xB800F000), the sound engine's read index and the status bits
  the application polls; with the box's official firmware images (1.1.5 and
  1.2.0) the bootloader, the LZMA decompression and the application's start-up
  run to its UART banner and its main loop, remote keys reach it through the
  same IR controller as the M3801's, its HD2015 panel chip decodes as a TM1650,
  and it draws its home menu through the M3801's own GE and display layer
  (`run_dump_r265lite_capture_screen.py`; the dumped flash's own main code is
  damaged, see the notes there). The
  simulator itself gained CP0 EBase for it (the application moves the
  exception vectors).
* `dumps/` -- the firmware images, each with a `<name>.txt` note on where it
  came from; a box that came with more (photos, an INFO file) has its own
  folder; `dumps/other/` holds images of other ALi chips. Tests and tools name
  a dump by its file name and `simulator.resolve_dump()` finds it in here.
* `tests/` -- the self-tests: `test_*.py` (fast, no firmware or seconds of
  it) and `run_dump_*.py` (the firmware runs), with their helpers
  (`screen_regression.py`, `uart_regression.py`, `app_reach_check.py`,
  `report_artifacts.py`, `report.py`). Run one
  from anywhere (`python tests/run_dump_globo_capture_screen.py`), or all with
  `python run_all_tests.py` at the root.
* `tests/expected/` -- the expected screens of the screen regressions
  (`<dump>_screen.png`, `<dump>_nav.png`), remade with `--make-expected`.
* `docs/` -- pictures (the Opticum wizard's screens).
* `tools/` -- one-off exploration and tracing scripts, kept for reference.
* `cpp/` -- the C++ port of the emulator core (work in progress).
* `refs/` (not in git) -- the ALi SDK sources and libraries the firmware was
  built from, for reading. `report/` (not in git) is the test report.

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
  Python is only involved through small ranged code hooks -- the CP0
  instruction sites (MFC0/MTC0/ERET of Count, Compare, Status, Cause, EPC,
  found by scanning memory), breakpoints / `stop_instr`, and the first
  execution of each RAM chunk (which triggers a rescan for new CP0 sites) --
  and through the device registers: the 0x18000000 window is an `mmio_map`
  region whose accesses call the device handlers (registered with `_mmio_on`;
  tests observe them with `sim.add_mmio_hook()`), and stores to the
  write-protected flash window fault into the SPI flash emulation. The only
  Unicorn memory hook, the flash read hook that serves SPI command responses,
  exists only around SPI command mode (see "Things learned"); otherwise RAM
  loads and stores run at Unicorn's full speed. `setSPIDump(True)` logs SPI
  commands without it; `setSPIDump(True, flash_reads=True)` also logs
  normal-mode flash reads and keeps it installed (slower). Python code should
  read / write device registers with `sim.peek()` / `sim.poke()` (or the
  0xB8000000 view): `mu.mem_read` of the physical 0x18xxxxxx window runs the
  device handlers (e.g. pops a UART RX byte); the GUI's watches use peek / poke.
  `instruction_count` and
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
* **Modelled device lines** of the ALi interrupt controller (levels, currently
  only the graphics engine on line 4): an asserted line shows in its
  0xB8000030 / 34 status bit and, while enabled in 0xB8000038 / 3C, raises IP3
  (taken like the timer interrupt; `sim.ic_irq_count` counts them). The
  firmware's dispatcher serves the lowest set status bit and reboots on an IP3
  without one, so the line drops only when the device is acknowledged. A
  device that raises its line from a register access ends a fast-mode slice at
  the next hooked CP0 instruction (or by the 1 ms backstop), not with
  `emu_stop()` inside the access (Unicorn would finish the translation block
  with its CP0 hooks skipped).

## Simulated devices

Besides UART, SPI flash, GPIO and the CP0 timer:

* **Flash size**: `AliMipsSimulator(rom_size=...)` takes 1 to 16 MB;
  `flash_size_for(path)` picks it from a dump (4 MB unless the file is larger;
  the Ferguson Ariva T650i's image is 8 MB). A part larger than 4 MB is laid
  out the way the SDK's flash driver addresses it: offset 0 stays at
  0xAFC00000 (and the reset vector 0xBFC00000), and its 4 MB segment n sits
  4 MB × n below (offset 0x700000 at 0xAFB00000). The JEDEC id reports the
  size (EF 40 16 for 4 MB, EF 40 17 for 8 MB) and, for an 8 MB part, the RES
  electronic id (0x16) the bootloaders' device tables match.

* **Front panel** (`front_panel.py` picks the decoder per dump): the LED
  driver chip the firmware bit-bangs over GPIO. dump_maciej.bin and the Globo
  N3 have a **TM1650** on I2C (SCL = GPIO 31, SDA = GPIO 9; `tm1650_decoder.py`:
  4-digit display, key matrix KI1-7 × DIG1-4 answered on SDA). The Cabletech
  URZ0083Q has a **TM1628-class 3-wire chip** (CLK = GPIO 31, DIO = GPIO 9,
  STB = GPIO 11; `tm1628_decoder.py`: 14-byte display RAM with the board's own
  digit / segment wiring -- " ON " at boot, "noCH" without channels -- and the
  5-byte key read answered on DIO the way the firmware samples it, after each
  CLK falling edge; its wizard reacts to KS9/K1 = down, KS9/K2 = up and
  KS10/K1 = power). The Cabletech URZ0195's uPD16312-class chip (STB = GPIO 14,
  LED port command; its digits in grids 4, 2, 3, 1 with their own segment
  wiring, read off its firmware's font table: " ON ", "----", then the channel
  number "0004") and the Strong SRT 8115's chip (the Cabletech's pins) speak
  the same protocol. The Ferguson Ariva T650i has an FD650K
  (TM1650-compatible, the usual pins) whose digits are registers 0x6C, 0x6E,
  0x6A, 0x68 from the left, with the segments on its own bits (read off the
  font table its application builds in RAM): " On ", "Strt", "Find".
  `press_key()` on either decoder
  presses a matrix position; `src/tv_gui.py` shows the display and the matrix as
  buttons. The Cabletech firmwares scan their flash database for 12-17 minutes
  (about 90k timer ticks) before the first screen.

* **I2C masters** (`i2c_scb.py`, the SDK's "SCB": 0xB8018200 and 0xB8018700
  on the M3801, 0xB8018B00 on the M3821; the tuner and the other board chips
  hang on them, the LED driver does not). A transfer completes at once and its
  slave is looked up in `sim.i2c_devices` ({7-bit address: device};
  `RegisterSlave` is a chip with a register file). An address nobody models
  gets no ACK, which the driver reports as an error at once instead of
  timing out and retrying ten times, as it did before the model. With
  `sim.i2c_ack_all` every address answers and reads give zeros, so a tuner
  driver runs its whole register sequence, which the `[I2C]` log lines show --
  the way to tell which tuner a board has: dump.bin's application wakes one
  at 0x60 at start (registers 0x0B and 0x12 set to 1) and only writes its
  register table at the first tune.
* **PMU** (`pmu_m36`, 0xB8018D00): the applications set bit 0x80 of +2 and poll
  bit 0x20 with udelay(2000), up to 36,848 times (6-7 minutes, then ignored).
  Bit 0x20 reads set once 0x80 was written. The 13-bit calibration value read
  afterwards stays 0 (only another chip revision uses it).
* **VCAP** (`VCAP_M36F`, 0xB800F000): the video-output open sets bit 0 of +0x4B
  and spins until the hardware clears it, without a timeout. The bit reads
  back cleared.
* **Video engine** (the decoder hardware, 0xB8004200): when a channel starts
  playing, the decoder driver resets the VE and checks its status word (+0x28,
  or +0x88 on another chip revision) for busy / event bits 8-25; any set bit
  sends the firmware down its fatal path (reboot into the bootloader). Those
  bits read clear — there are no VE events here. Without this, dump.bin
  rebooted two minutes after its first screen (the status word still held the
  0x318 the driver had written at init) and started over.
* **Ethernet MAC** (`ETHERNET_MAC_0`, 0xB802C000; the Ferguson Ariva T650i's
  network driver): the software-reset bit 3 of +0 reads back clear, and an
  MDIO access started at +0x7C (bit 31) completes at once and reads 0xFFFF
  from +0x82, what a bus without a PHY returns. Without them the driver spun
  on the reset bit forever, and then waited a second of firmware time for
  every PHY register it probed, holding the UI back for minutes.
* **Graphics engine** (`GE_M36F`, 0xB800A000): nothing is drawn. A command
  written to +4 (1, 2 or 3) completes at once and sets its bit in the
  interrupt status +8 (0x4, 0x1, 0x2; write 1 to clear), which drives
  interrupt-controller line 4. The driver's ISR acknowledges +8 and wakes the
  drawing task through an event flag. Without it every GE operation of
  dump_maciej's UI ended in its 0.5-6 s timeout and a GE reset. `sim.ge_ops`
  counts commands. dump.bin and SRT Prima issue no GE commands in their first
  minute.

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
  and its device handler (memory hook or `mmio_map` callback alike) run again
  on resume. For the device registers whose access has a side effect (UART
  THR / URBR, SPI response reads, GE commands) the handlers recognise the
  re-execution and serve / skip the same data; before, this
  duplicated UART output characters ('bbl_flash_init!') and lost RX bytes.
  A stop counts as a rewind only if the instruction at the stop PC is a load /
  store of the noted register, lies in the translation block the access ran in
  (straight-line code from that block's start), and the registers are
  unchanged (a later pass of a loop changes some register). The access itself
  cannot tell its PC: inside an `mmio_map` callback Unicorn reports the start
  of the translation block (registers are current), so a pending replay is
  keyed by the exact PC of the stop, which is where the resumed translation
  block starts. Pending replays are kept per (PC, SP), so an interrupt handler
  or another task using the same putc / getc does not take them. (Observed:
  asynchronous stops are noticed at device accesses, not at block entries.)
* Unicorn 2.1.4: while any `UC_HOOK_MEM_READ` (`_WRITE`) hook exists, whatever
  its range, every load (store) is translated to the slow path, which scans
  the whole hook list per access. With the ~60 device hooks the simulator used
  to register, RAM-heavy code ran about 3x slower (dump_maciej's unoptimised
  LZMA bootloader: ~200 s of emulation instead of ~64 s). The decision is made
  per translation block when it is translated: a hook added later is ignored
  by blocks translated before it (they read the flash window without it), and
  blocks translated while one existed stay slow after it is removed, until the
  translation cache is flushed. Code hooks and invalid-access /
  protection-fault hooks cost nothing, but a protection fault only fires on a
  TLB miss (once per page), so it cannot serve every read. Hence `mmio_map`
  for the device registers, write protection for the flash window, and the
  flash read hook only during SPI command mode: entering command mode stops
  the CPU right at the SF_INS store (a stop requested inside a device access
  takes effect before the next instruction; the store re-executes and is
  recognised as a replay), the next `emu_start()` installs the hook and
  flushes the translation cache, and leaving command mode removes it the same
  way once no command has come for `flash_hook_idle_s` (0.05 s of emulation
  time: sparse commands, as during the bootloader's decompression, cost two
  flushes each, but dense sequences keep the hook — dump.bin's application
  reads its flash database byte by byte, ~750k commands, 5x faster this way;
  0 toggles it around every command). Two native Unicorn crashes
  (access violations, 7-30% of the boots) came with an earlier version: memory
  hooks added / removed from a device callback while the CPU ran, and Python
  writes (`uc.mem_write`) into the read-only guest flash mapping from a hook
  while the CPU ran (Unicorn toggles the region's protection; with only that
  left, 1 of 30 Prima boots still crashed; 0 of 105 since). Both are avoided: hooks change only
  between `emu_start()` calls, and Python writes the ROM through its writable
  0xAFC00000 view. Memory hooks and faults report physical addresses
  (0xB8018300 -> 0x18018300), and the guest only reaches the physical mappings.
* Unicorn 2.1.4 bug: after a load / store with a memory hook or a protection
  fault in a branch delay slot, the branch target's first instruction runs
  twice. `mmio_map` accesses are not affected (unless a debugging script adds
  a memory hook over the device window), so this concerns the flash window;
  the shipped dumps never access it in a delay slot (checked over 80M
  instructions), and the simulator logs a `[WARN] device access in a branch
  delay slot` once per PC for flash stores and command-mode reads.
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

Run the scripts individually (`python tests/run_dump_maciej_to_bl_verify_sw.py`,
`python tests/run_dump_to_end.py`, `python tests/test_boot_decodes_mips16.py`, ...)
or all of them with `python run_all_tests.py` (a few minutes). `python run_all_tests.py
--slow` adds `run_dump_maciej_to_main_app.py`, which boots dump_maciej.bin
through expand() into the main application (about 2 minutes, a minute of it
the bootloader's unoptimised LZMA decompression), checks the
decompressed image against an offline LZMA decompression of the flash chunk,
and checks that the application's RTOS runs on timer ticks (it prints its
init banner, compared exactly). `run_dump_to_main_app.py` and
`run_dump_Prima_to_main_app.py` (about 20 s each, in the default run) do the
same for dump.bin and SRT Prima: their whole UART output -- bootloader lines
plus the application's 'MC: APP  init ok' / SDK / Libcore / Application
banner -- must match byte for byte, timer interrupts must be taken, and the
application must keep running. Before the CP0 timer existed these
applications parked in the RTOS idle task right after 'success!'. All three
then check that the init got past the PMU handshake and the VCAP busy bit
(a few reads of each; unmodelled: thousands of PMU polls, then an endless VCAP
spin), and the slow dump_maciej test also that its UI's graphics-engine
commands complete through the GE interrupt without timeouts.

The screen regressions (`--slow`) boot a dump until its OSD is drawn, capture
the display layer and compare it pixel for pixel with the expected screen, a PNG
kept in `tests/expected/` (`screen_regression.py` is the shared body; an
expected screen is remade with `--make-expected`; `gma_capture.py` composites the GMA layers' regions, and
for a firmware whose output mode is not 720p -- the Prima VIII and the SRT
8115 drive PAL, the Cabletechs 1080i (the URZ0195's 2012 firmware from the
start, the URZ0083Q and URZ0194S once their wizard is up: its default "Tryb
Wyświetlania" is 1080i@50HZ), so the display engine scales the OSD layer to
the output and the region heads hold output coordinates -- it undoes that
scaling, read from the display engine's timing register, so the capture shows
the whole OSD where the TV shows it; each capture logs the output mode): `run_dump_maciej_capture_screen.py` (the Opticum's wizard,
about 4 minutes), `run_dump_globo_capture_screen.py` (the Globo N3's no-signal
banner, about 6), `run_dump_capture_screen.py` (dump.bin's channel banner after
its 10-minute flash scan, about 15) and `run_dump_cabletech_capture_screen.py`
(the URZ0083Q's first-install wizard after its 12-17 minute database scan,
with the TM1628 panel reading "noCH") `run_dump_srt8115_capture_screen.py`
(the Strong SRT 8115's no-signal screen, about 15) and
`run_dump_urz0194s_capture_screen.py` (the Cabletech URZ0194S, the URZ0083Q's
family with a newer application: the same wizard after an 11-minute scan) and
`run_dump_urz0195_capture_screen.py` (the Cabletech URZ0195 with its 2012
firmware, which draws its channel banner and no-signal screen seconds after
starting, with the panel reading "0004", about 12 minutes; the 2013 firmware
of the same box has not drawn anything yet) and
`run_dump_prima8_capture_screen.py` (the Strong Prima VIII flash dump -- unlike
the manufacturer's update of the same box it carries a channel database --
whose Bulgarian channel banner is up 3 minutes after the start, about 6
minutes; the channel it names depends on timing, within the tolerance) and
`run_dump_t650i_capture_screen.py` (the Ferguson Ariva T650i's 8 MB update
image: with its empty channel database it runs the first-install automatic
search and ends on "nie znaleziono kanału!", the panel reading "Find", about
25 minutes). `run_dump_maciej_remote.py` drives the
Opticum's wizard with the IR remote through the language and aspect-ratio
pages into the channel search and checks that the progress screen keeps
changing. The screen regressions take a `navigation` sequence too: remote keys
(through the emulated IR receiver and the firmware's own key table) or front
panel keys (through the panel decoder) pressed after the first screen, each
required to change the screen, the last screen compared with a second expected
screen (`*_nav.png`; each step waits for its own change to appear and then
for the GE to go quiet, and the final capture waits until the screen has become
the expected one, so a slow machine or CI runner only takes longer): the Globo opens its main menu, moves the highlight and
returns to live TV; the Cabletech URZ0083Q moves its wizard highlight with its panel
keys and the URZ0194S steps its wizard's Region value with its (the whole
wizard switches language); the SRT 8115 opens and closes its main menu; the
URZ0195 (2012) opens its channel list with OK and moves the highlight down
(its panel keys do nothing); the T650i closes its "no channel found"
dialog (its "edytuj kanały" menu then opens by itself) and opens the
favourites list from there. The Prima VIII has no navigation yet: with no
signal its firmware steps through its channel list by itself and acts on
remote keys only between those re-tunes (its EPG, popups and banner toggle
were each seen once). dump.bin has no navigation yet: its firmware drains the IR FIFO and takes the interrupt, but
none of the frame encodings tried (its key table, its bootloader's wake-code
user codes 01 FE / 80 7F) changes its screen. How a firmware's key table
maps to the NEC frame bytes differs between SDK generations
(`ir_remote.IR_CODINGS`, chosen from the dump's name: standard NEC with
bit-reversed, inverted bytes for the Opticum / Globo, the plain bytes for the
Cabletech URZ0083Q / URZ0194S, an extended-NEC address for the SRT 8115, the
Prima VIII, the URZ0195's 2012 firmware and the Ferguson T650i; a firmware may also number its
virtual keys differently, see `ir_remote.VKEY_FALLBACKS`). `--jobs 2` runs two tests at a time (the simulations are independent;
firmware time follows each emulation thread's own CPU time), which is what the
workflow does.

Mechanism tests that need no firmware dump: `test_isa_mode_tracking.py`
(MIPS32/MIPS16 switches, breakpoints inside MIPS16 code),
`test_flash_window_isolation.py` (SPI responses vs flash contents, page program,
sector erase), `test_cp0_count_emulation.py`, `test_cp0_timer_interrupt.py`
(timer latch, masking, MIPS16 EPC, late Compare, software interrupts),
`test_device_models.py` (PMU, VCAP, graphics engine command -> interrupt ->
acknowledge, masked line, partial acknowledge, controller write-back, command
stores replayed after asynchronous stops, add_mmio_hook, peek / poke),
`test_spi_command_mode.py` (SPI command responses read in the same block as
the SF_INS store, with the flash read hook installed between slices, also
toggled hundreds of times) and `test_mips16_decoder_encodings.py`.
`run_all_tests.py` runs every test in its own Python process, so a native
crash fails that test only.

### Test report

`run_all_tests.py` also writes `report/index.html` (`report.py`): one
self-contained page with every test's verdict, wall time, description (the
script's docstring), its `[PASS]` / `[FAIL]` lines, its whole output, and the
images it rendered -- OSD screen captures embedded as PNG, each on its own row
at the card's width, and front-panel LED displays drawn as 7-segment SVG, a
display beside the capture the test reported it with. A test attaches those through
`report_artifacts.py`: `image(path, caption)` for a PNG it saved (into
`report_artifacts.out_dir()`, which the runner points at `report/img/<test>/`)
and `panel(digits, caption, text)` for a display's segment bytes; the lines
they print are picked up by the runner, so a test still runs on its own
unchanged. Filter the cards by dump, kind (unit / regression / slow) and data
(renders, crashed, timed out); `-k name` runs a subset, `--timeout seconds`
kills a hung test.

The GitHub Actions workflow (`.github/workflows/tests.yml`) runs
`run_all_tests.py --slow` on every push, uploads `report/` as a workflow
artifact and publishes it to GitHub Pages (the repository's Pages source must
be set to "GitHub Actions" once, under Settings > Pages); the page is updated
even when tests fail, and the job's result still reflects the tests.
