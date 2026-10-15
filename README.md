# AliSimulator

Unicorn-based simulator for ALi set-top-box firmware dumps (MIPS32 + MIPS16e).
The main targets, dump.bin and dump_maciej.bin, are DVB-T (terrestrial)
receivers built for the ALi M3801 ("M3801 DVBT" in their maincode chunk
headers); SRT Prima is from the same family. The firmware identifies the
silicon as an S3811: its chip-ID function reads 0xB8000002 and knows 0x3811 but
no 0x3801, and the simulator reports 0x3811, revision 0. The Echosonic dump
(M3510A, DVB-S2) and the sat_main_ali3329 dump (M3329) are other chips, per
their file names; both have families of their own now (the M3510A runs as the
M3503).

## Layout

* `src/` -- the simulator (`simulator.py`, `mips16_decoder.py`, the slice
  stopper and clocks) and the device models (`ge_m36f.py`, `ge_m3602.py`, `gma_capture.py`,
  `crypto_engine.py`, `parallel_flash.py`,
  the panel decoders, `front_panel.py`, `ir_remote.py`, `i2c_scb.py`), plus the two GUIs:
  `python src/tv_gui.py <dump>` (the TV: OSD, panel, remote) and
  `python src/gui_simulator.py` (the debugger).
* `src/chips/` -- the chip families, one module each (`m3602.py`, `m3801.py`,
  `m3821.py`): what differs between ALi generations (the chip ID, how the CPU
  gets from reset to the flash's bootloader, extra memory, that generation's
  devices). `loadFile()` picks the family from the image's chunk headers; the
  M3801 is the default and everything `simulator.py` models by itself. A
  simulator starts as the M3801, and switching to another family drops the
  previous one's devices: the register handlers go back to the simulator's
  own, and `ChipFamily.uninstall()` gives back the memory, hooks and
  simulator attributes the family changed (`test_family_switch.py`). The
  M36xx generation before it (M3601E / M3602 / M3606: the Cabletech URZ0083
  and URZ0086, Kruger&Matz KM0183 / KM0186, Thomson THT501 and Ferguson T50
  update images, recognised by their HDCPKey chunk's "Demo s3602", and the
  Opticum S60 (M3601S) and X110TS (M3606) satellite updates, recognised by
  the chip named in their main-code chunk's version) boots the
  same way and finds its first peripherals where the M3801's are, but its
  firmware wants an M36xx chip ID -- with the M3801's 0x3811 the
  applications start over through the bootloader. The family's own is
  0x3602 (the T50's); the other boards read 0x3603, which their sidecars
  give (`device.chipId`): the X110TS's application reboots unless it reads
  it, the M3601E boxes' (URZ0083, KM0183, THT501) and the S60's run into
  their USB host start's assertion right after their boot logo without it,
  and the URZ0086's and KM0186's idle without decoding theirs. Under 0x3603
  all their bootloaders but the X110TS's read the flash with the quad I/O
  read 0xEB, which the simulator serves like a plain read now -- before,
  their chunk headers read as zeros. The T50's
  bootloader probes the RAM 128 MB up, where the family shows it again, and
  knows its 4 MB flash only by the electronic ID in the last byte of the
  0xAB read (0x15), which the simulator answers as the real part does now:
  before, its flash driver attached no device and the bootloader rebooted
  before the application. Its application draws with the M3602's own
  graphics engine at 0xB800C000 (`ge_m3602.py`, the SDK's `ge_hal.c`: command
  lists in RAM; fills, copies and scaled copies through a palette) into a
  912 x 640 CLUT8 screen, which the engine scales into the AYCbCr8888 layer of
  its PAL output (0xB80061A0..AC, `gma_capture.m3602_layers`), and its UI
  waits for its boot logo: its decoder, driving an HD and an SD output,
  reports the first picture shown only once both outputs' field handlers
  have asked for it -- the SD output's (the DEO at 0xB8020000) interrupt,
  with its field at bit 19, is `video_m36.py`'s too, as is the HD output's
  status bit 0 the driver polls before it switches TV systems. It then shows
  its "Welcome" installation wizard (`run_dump_t50_capture_screen.py`). The
  M3601E boxes (URZ0083, KM0183, THT501) decode
  a boot logo first and wait until it is shown: `video_m36.py` finishes the
  video engine's pictures at once and raises the video output's field
  interrupts, whose field bit must alternate for the driver to move on. All
  14 of their images then draw their first-install wizard
  (`run_dump_urz0083_capture_screen.py`; the application,
  `run_dump_urz0083_app_runs.py`); the M3606 ones (URZ0086, KM0186), whose
  SEE runs those drivers -- the models are wired onto the SEE core and
  interrupt the core whose controller has the line enabled --, draw theirs
  too (`run_dump_urz0086_capture_screen.py`), and the S60 shows its "No
  Signal!" message (`run_dump_s60_capture_screen.py`). At a channel change
  the S60's decoder driver resets the video engine (bit 1 of 0xB8000080)
  and then reads +0x228, on the M36xx the VLD's bit offset, as a status
  word: any of bits 8..25 set sends it to its fatal path, a reboot into the
  bootloader. The model left the last picture's offset there, and the box
  started over a few seconds after a key in 7 of 11 runs of its regression;
  the engine's reset now puts it back to 0. The M3606's bootloader starts its SEE co-processor --
  the second MIPS core of ALi's dual-CPU chips, which runs the audio / video
  decoders' and the display's drivers -- and waits for it: `chips/see.py`
  runs the SEE's boot code for that handshake on a light Unicorn instance
  sharing the RAM and the register block, and the SEE's own program, which
  the application starts later, on a second simulated core (`SeeCore`: an
  `AliMipsSimulator` sharing the first one's memory, with its own CP0 state,
  CPU number and interrupt controller, its turns between the first core's
  slices). The two programs' remote calls go through the shared memory, the
  mailbox registers and the doorbells, in both register layouts the SDKs
  use (`run_dump_urz0086_see_start.py`: the URZ0086's application attaches
  its drivers through ~70 calls the SEE answers; the X110TS's too,
  `run_dump_x110ts_see_start.py`, and its OSD shows its channel banner and
  then its "No Signal!" box, `run_dump_x110ts_capture_screen.py` -- the
  chip ID 0x3603 is the SDK's C3603, which reads a product with its DVB-S2
  demodulator, and that S3501 answers its chip ID on the I2C bus). The
  SEE's programs also read the chip's random number generator (`Trng`): a
  FIFO of its results that drops repeats never filled with the registers as
  plain memory, and its task never slept.
  The M3503 (`chips/m3503.py`, the Globo HD-XS2 / Opticum Blue XS65
  satellite updates in `dumps/GLOBO HD-XS2/`, recognised by the bootloader's
  version) is this family with the chip ID 0x3503 and the T750i's kind of
  bootloader: it runs from the flash window with its stack in locked D-cache
  lines until the DDR is up (`CacheAsRam`); it starts its SEE the same way,
  and its application runs with the SEE's program
  (`run_dump_hdxs2_app_starts.py`). The chip's DVB-S2 demodulator is on the
  chip: the CPU reads its registers at 0xB8028000 + the register number, and
  its chip ID registers answer the S3501's ID (`InternalDemod`). Before it
  goes on, the application asks the SEE (HLD_DSC.16) to hash its own code
  with the crypto engine at 0xB8034000 -- the DMA feeding its SHA-256 unit,
  whose done bit interrupts the SEE on line 44 (`crypto_engine.py`); without
  that engine the call never returned and nothing was drawn. Both images of
  the 1.3.5 pack then draw: the SmartHD one its main menu, the Reta one its
  first-install wizard (`run_dump_hdxs2_capture_screen.py`,
  `run_dump_hdxs2_reta_capture_screen.py`). The
  Echosonic Mini ESR-250's M3510A (`dumps/other/`, bootloader "3510-r1362")
  runs as this family -- the same XIP bootloader, whose set-up branches on
  the chip ID 0x3503 -- and its single-CPU application draws its Quick Setup
  menu once that demodulator answers: a task of it kept the OSD layer off
  until the NIM device reported an S3501's chip ID
  (`run_dump_esr250_capture_screen.py`).
  The C3505 (`chips/c3505.py`, the Ferguson T760i update images) is the
  M3821's boot-ROM path with its own chip ID 0x3505 and one more ready bit
  (0xB8000300 bit 8); its bootloader is the R265 Lite's generic build, so the
  family is recognised by the unpacked main code naming the C3505. Its
  application runs with its SEE program (`run_dump_t760i_app_starts.py`)
  and, with its board's AltoBeam ATBM7812 demodulator answering its chip ID
  (`demods.py`, the sidecar's `demodModel`), opens its first-install wizard
  and its channel search through the newer display engine's layer
  (`run_dump_t760i_capture_screen.py`).
  The Ferguson T750i's M3821 boots without the
  boot ROM's step: an XIP bootloader of the M3801's kind whose stack sits in
  locked D-cache lines at the top of the flash window's cached view until
  the DDR is up (`CacheAsRam`: RAM over that range until the bootloader runs
  from RAM); it starts its SEE the same way, and its application runs with
  the SEE's program, opens its database and starts drawing
  (`run_dump_t750i_app_starts.py`; the chip reads as revision B). The
  M3821 / M3822P (the DVB-T2 boxes: `dumps/Opticum Blue R265 Lite/`) adds the
  boot ROM's step (the bootloader copied into a boot SRAM at 0x1FE00000, entry
  0x9FE00800), a DDR-training model, the chip-ID variant word, the SPI flash
  controller's byte-stream mode and DMA engine, an 8-channel descriptor-ring
  DMA engine (0xB800F000), the sound engine's read index and the status bits
  the application polls; with the box's official firmware images (1.1.5 and
  1.2.0) the bootloader, the LZMA decompression and the application's start-up
  run to its UART banner and its main loop, remote keys reach it through the
  same IR controller as the M3801's, its HD2015 panel chip decodes as a TM1650
  (the application's open-drain bus: its texts and its three buttons),
  and both applications draw their home menu through the M3801's own GE and
  display layer (`run_dump_r265lite_capture_screen.py`,
  `run_dump_r265lite_120_capture_screen.py`; firmware 1.2.0's first waits for
  a start bit of the block at 0xB802A000 to clear, most likely an HDMI DDC
  transfer; the dumped flash's own
  main code is damaged, see its sidecar). The
  simulator itself gained CP0 EBase for it (the application moves the
  exception vectors). The family also models the chip's OTP memory
  (`m3821.Otp` at 0xB8042000: 1 KB read a word at a time, burnt a byte at a
  time) with what a board's sidecar says it holds (`device.otp`; none does
  yet): the Fergusons' firmwares look for a signature there every minute of
  play and show "STB not signed!" while it is blank, as on an unsigned box;
  a non-blank stand-in sends their start-up down the signed path (an RSA
  check), where the simulator crashed.
  The M3329 (`chips/m3329.py`, the 2005 board in `dumps/other/`, an M3327
  platform chip recognised by its bootloader chunk's ID 0xE3000010) is the
  oldest: its bootloader reads the chip revision from the chip word's low
  byte (0xF0: the newest that needs no boot-ROM call), its SDRAM controller
  takes commands, its UART is at 0xB8001300, its interrupt controller keeps
  status and enables at 0xB8000038 / 3C (`set_ic_layout`), and its
  application runs in place from a parallel NOR flash, which its driver
  identifies with the AMD autoselect command (`parallel_flash.py`: an
  MX29LV400B; the probe stores its reset in a branch delay slot, see "Things
  learned"). Its video decoder and output interrupt are the M36xx's
  (`video_m36.py`, line 9), its IR receiver the later chips' at 0xB8001100
  (line 7; the remote's codes come from the firmware's own table,
  `M3329.remote_frame`), and its OSD (OSD_M3327C) is drawn by the CPU into
  bitmaps that chains of region headers in RAM place on its PAL output, through
  palettes written to a port (`gma_capture.m3327_regions`). After searching
  its channel database byte by byte (~250 M instructions) it shows its
  channel banner, then MENU its Channel menu (`run_dump_m3329_capture_screen.py`).
  Its kernel ticks every 108000 Count cycles, so the family's Count runs at
  10 MHz -- at 100 MHz the tick took most of the emulated time.
* `dumps/` -- the firmware images, each with a `<name>.json` sidecar: the
  box (SoC, demodulator, tuner, flash part, front-panel chip and pins, IR
  coding), the image (dump or update, version, size, SHA-1, chunk layout),
  where it came from (URL, author, whether a login is needed), what the
  simulator makes of it, and `desc`, the notes as paragraphs
  (`src/dump_catalog.py` reads them; `tests/test_dump_catalog.py` checks each
  against its file and the code's panel / IR tables; `tools/dump_table.py`
  renders them all as `dumps/README.md`). A box that came with more (photos,
  an INFO file) has its own folder; `dumps/other/` holds images of other ALi
  chips. Tests and tools name a dump by its file name and
  `simulator.resolve_dump()` finds it in here.
* `tests/` -- the self-tests: `test_*.py` (fast, no firmware or seconds of
  it) and `run_dump_*.py` (the firmware runs), with their helpers
  (`screen_regression.py`, `uart_regression.py`, `app_reach_check.py`,
  `report_artifacts.py`, `report.py`). Run one
  from anywhere (`python tests/run_dump_globo_capture_screen.py`), or all with
  `python run_all_tests.py` at the root.
* `tests/expected/` -- the expected screens of the screen regressions
  (`<dump>_screen.png`, `<dump>_nav.png`), remade with `--make-expected`.
* `docs/` -- pictures (the Opticum wizard's screens).
* `tools/` -- `dump_table.py` (above), `screen_survey.py` (boots every
  image, or those whose path holds a given word, each in its own process,
  until its screen shows something, and reports how soon, the GE command
  count and the front panel's texts, flagging an image whose sidecar says
  otherwise -- the screen regressions check one image per family in depth;
  `--jobs 2`, `--out DIR` for the screens), and one-off exploration and
  tracing scripts, kept for reference.
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
  **Idle skipping** (`sim.idle_skip`, default on): when a slice ends in the
  RTOS's idle task -- a `b .` with a nop in its delay slot, interrupts enabled
  -- run() moves the emulation time (Count, and the estimated instruction
  count at the measured rate) on to the next timer interrupt instead of
  spinning there, in steps of at most `batch_timeout_us` (the slice services
  see the time pass) and never past the run's instruction budget; a code
  hook on the loop ends the slices that reach it. Instruction counts thus stay
  a measure of emulation time and every test's timeline is what it was, only
  the waiting costs no host time: a third of dump_maciej's first 150 M
  instructions. `tv_gui.py` keeps such a firmware from running ahead of the
  wall clock.
  **Mailbox polls** (`sim.poll_skip`, default on): a core waiting for the
  other one in the dual-CPU SDK's tight poll of a mailbox register (`lw rt,
  off(rs); beq / bne rt, rX, back; nop` on 0xB8000200 / 204 or 0xB8040200 /
  204: the T760i's main CPU on the SEE's 0xB8040204, its SEE on 0xB8000200,
  a third of all their device reads) reads the same value until the other
  core has stored, and that core only runs between this one's slices: the
  spin is idle time, moved on like an idle loop's -- with interrupts enabled
  to the next one, else to the end of the turn --, and a code hook on the
  load ends the slices that reach it while the poll holds; only while a
  second core runs (`test_poll_skip.py`). A poll is recognised at every
  slice boundary, at its load or its branch, before an interrupt is taken
  there: a tick ends most slices, and its handler returns into the poll. The
  T760i's SEE turns over its first 150 M instructions took 32 s instead of
  44 s; the dual-CPU screen regressions, whose time goes to other phases,
  gain 1-2%.
  **The bootloaders' LZMA decoder** (`sim.lzma_hle`, default on): the ALi SDK
  boot library unpacks the main code (and the SEE's) with the LZMA SDK 4.0x
  `LzmaDecode()` compiled without optimisation, a function call per decoded
  bit -- emulated, dump_maciej's 7.3 MB took 40 s and the Ferguson T750i's
  3.4 + 8.6 MB 72 s of wall time. 47 of the 50 images carry that routine byte
  for byte (its first 43 instructions, `_LZMA_DECODE_SIG`); found in the flash
  image and by each RAM chunk's first-execution scan, its entry is hooked:
  the stream is decoded with Python's `lzma` module (0.1-0.2 s), written to
  the output buffer (whose CP0 sites are scanned at once), `*outSizeProcessed`
  set and 0 returned to the caller. The call is charged the time the emulated
  decoder took, `lzma_insns_per_byte` (4.0) of the instruction count per output
  byte, which run() moves on like idle time (`busy_pending`; interrupts wait
  for it), so the boot's timeline stays what it was: dump_maciej prints its
  bootloader's "success!" at 30.5 M instructions (29.9 M emulated) after 2 s
  instead of 41 s, the T750i at 50.5 M (50.3 M) after 4 s instead of 75 s.
  Anything unexpected -- the arguments, a stream the module rejects or that
  ends early, output outside the RAM, exact mode, a breakpoint in the decoder
  -- leaves the call to the emulated decoder (`test_lzma_hle.py`). `tv_gui.py`
  sets `lzma_insns_per_byte = 0`: no firmware time for it, a quick boot.
  **The RTOS's microsecond delay** (`sim.delay_hle`, default on): the TDS
  RTOS's `delay(us)` polls a `get_count()` (one MFC0 Count) until `us` times
  the Count ticks per microsecond it derives from the CPU clock variable have
  passed -- two hooked CP0 instructions or more per call, ~25 us of host time
  --, and the drivers' polling loops call `delay(1)` hundreds of thousands of
  times (dump_maciej 327,000 times in its first 150 M instructions, the S60
  436,000), a few hundred calls waiting milliseconds. Found by its 24 words
  in each RAM chunk's first-execution scan (`_DELAY_SIG_RE`: the call target
  and the clock's gp offset masked; both calls must go to a `get_count()`),
  the routine gets two hooks. At its entry a wait that ends within the
  running slice (before the next tick, within run()'s limits) is moved on in
  emulation time inside the hook, and the call returns with v0 / v1 as the
  routine leaves them; a longer one runs, and at its loop's `get_count()`
  call the time moves on to the end of the slice -- where run() takes the
  tick, inside the wait as on the hardware -- and then to the end of the wait.
  Outside a timed slice only waits up to `delay_hle_max_s` (200 us) are
  skipped; exact mode, a breakpoint or the stop address in the routine, other
  code at its entry leave it to run (`test_delay_hle.py`). dump_maciej's
  screen regression takes 46 s instead of 50 s, and the S60 draws its OSD
  after 26 s instead of 43 s of wall time (43 s of firmware time instead of
  51 s: its driver loops' `delay(1)` lasts ~10 us instead of ~25 us). Four
  builds of the routine are known (`_DELAYS`): besides that one, the newer
  SDK's (the T760i's: the whole argument, the loop ending only past the
  ticks, an EHB in its `get_count()`), its bootloader's (the ticks per
  microsecond in a variable of their own) and its SEE program's (the clock
  divided by 2,000,000); the SEE's code, above the first 32 MB, gets the same
  first-execution chunk scans as the RAM below. The T760i's first 150 M
  instructions took 75 s instead of 86 s.
  Cost per hooked CP0 instruction: ~9-12 us (the binding's reg_read /
  reg_write / mem_read are bypassed: direct `uc_reg_*` calls, code words read
  from the RAM buffer); an MTC0 Status that only disables interrupts or
  rewrites the value does not re-plan the slice, and the same MTC0 again after
  nothing but NOPs (the RTOS's interrupt disable writes Status twice) is
  passed over by the first one's hook. Under the native Status the TDS
  RTOS's interrupt disable is not hooked at all (`skip_irq_disable`): its two
  MTC0 Status store the Status it has just read with IE cleared, which can
  bring no interrupt, and run() takes the native Status over at every slice
  boundary -- the enable's hook stays. That is ~40% of the hooks: dump_maciej's
  first 150 M instructions ran 0.74 M hooks instead of 1.22 M, in 57 s
  instead of 68 s (`test_native_status.py`; the newer SDK's disable, with
  EHBs among its NOPs, and the R265 Lite 1.2.0's, with five NOPs -- its
  screen regression 171 s instead of 210 s -- too). The enable's MTC0 then
  gets a lean hook (`_hook_irq_enable`): with the shadow's IE still set its
  follow has nothing to do, so it returns at once unless a slice deadline
  has passed (an interrupt came due in the disabled section: then the full
  hook) -- the T650i's first 150 M instructions ran 40 s instead of 42.5 s. (Interpreting the ALU code between
  close CP0 instructions in Python, to take them in one hook, cost more than
  the hooks it saved: ~2.5 us per instruction.) Periodic CP0-site rescans
  read the RAM buffer in place (numpy over the words' top bytes), and the
  tick's vector page is rescanned only when it changed.
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
    ~10 us of host time each (~50 us before 2026-10-15), which Count sees, so
    without this a handler that takes longer than the tick period would starve
    the interrupted code. (An idle loop has nothing to run in that gap: idle
    skipping moves the time on to its end.)
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
  number "0004") speaks the same protocol, and the Strong SRT 8115 has the
  URZ0083Q's panel outright (the same pins, digit wiring and font table:
  " ON ", "----", then the channel number), whose panel code looks the key
  bytes up in a small table -- byte 4 = 1, 2, 8: up, down, power; the
  URZ0083Q's has up and down the other way round. The Ferguson Ariva T650i has an FD650K
  (TM1650-compatible, the usual pins) whose digits are registers 0x6C, 0x6E,
  0x6A, 0x68 from the left, with the segments on its own bits (read off the
  font table its application builds in RAM): " On ", "Strt", "Find"; the
  T750i and T760i have the same panel on other banks (SCL / SDA = GPIO 128 /
  129 and 107 / 110). The three Fergusons' PAN_FD650K driver turns eight
  positions, DIG1 / DIG2 of KI4..KI7, into the panel codes their UIs map (a
  switch on the key byte): down, exit, left, menu, right, power, up, OK -- on
  the T750i's and T760i's first-install wizards exit opens the main menu's
  channel-editing page and down moves its highlight. The decoders get the
  pins' levels on every write of a
  bank's DO or DIR register -- an output pin at its DO bit, an input pin high,
  the pull-up -- because some drivers bit-bang the bus open-drain, DO kept 0
  and only the direction switched: the Opticum Blue R265 Lite's application
  (HD2015, SCL = GPIO 57, SDA = GPIO 58) does, and it checks that both lines
  read high before every START. While released lines read 0 it took the bus
  for busy and never reached its chip; now the TM1650 model drives SDA low
  only while it acknowledges or sends a 0 bit, and the application writes
  " on ", "Strt", "noCH" and reads its three buttons (KI1/DIG4 and KI7/DIG4
  step its menu, KI2/DIG4 is power). GPIO numbers are the SDK driver's:
  banks 0xB8000054, 0D4, 0F4, 354, 454 for GPIO 0..159 (older SDKs' third
  bank, 0xB80000E8, is watched too).
  The Strong Prima VIII has no LED driver -- its CH455 driver talks to a
  software I2C bus with no pins -- but two **buttons straight on GPIO 31
  (channel up) and 9 (channel down)**, pulled up, which its application polls
  (`gpio_keys.py`: the pins read released unless pressed; the simulator's
  default for an input nothing drives is 0, a stand-in for an I2C slave's ACK,
  which held both buttons down and made the box step through its channels by
  itself).
  `press_key()` on any decoder
  presses a matrix position (or a button); `src/tv_gui.py` shows the display and the matrix as
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
  the way to tell which tuner a board has (each dump's sidecar names it:
  mostly the MaxLinear MxL603 family, an MxL5007T in the 2012 URZ0195
  firmware, a Rafael R820T in the Globo N3). The C3603 (the X110TS) has its
  S3501 DVB-S2 demodulator at 0x33 (`demods.S3501`, a `RegisterSlave`
  with its chip ID in registers 0xA3..0xA6; `chips/m3602.py` puts it on the
  bus for that chip). A demodulator a board's sidecar names
  (`device.demodModel`, `demods.py`) is put on the bus when the image loads
  (`sim.attach_demod()`): the T760i's AltoBeam ATBM7812 at 0x40, 16-bit
  register addresses, its chip ID 0xA8 in register 0 -- without it the
  driver retried its power-on for ~125 M instructions -- and the UNI S60's
  S3501, without which its driver reset the tuner 11 times and gave up.
  A board whose firmware bit-bangs an I2C bus over GPIO pins to its chips
  names it in its sidecar (`device.gpioI2c`: SCL / SDA); loadFile puts a
  `gpio_i2c.GpioI2cBus` on those pins that forwards the transfers to the same
  `sim.i2c_devices` -- the URZ0086 / KM0186 boards' second tuner, on GPIO 44
  / 43 (the first answers on SCB0). `device.gpioPullUps` lists the input
  pins a board pulls up (they read high; an input nothing models reads 0):
  the X110TS's LNB and DVB-T fault lines, which it read as short circuits,
  and the S60's USB power switch's fault flag (GPIO 25).
* **Tuners and signal** (`tuners.py`): chip models of the MxL603 family,
  the MxL5007T and the R820T that keep what the driver writes and report
  their synthesizers locked (MaxLinear: lock registers 0x2B / 0xD8 read
  through the 0xFB prefix; R820T: status read from register 0, bit-reversed,
  PLL lock in register 2). `sim.attach_tuner()` puts the dump's tuner (its
  sidecar's `tunerModel`) on the bus; `sim.set_signal(True)` does that and
  makes the chip family's demodulator report lock: the M3801's internal
  COFDM demodulator (`chips/m3801.py`, registers at 0xB803E000, whose
  `get_lock()` tests bit 5 of register 0x1D) and the M3821's DVB-T / T2 one
  (`chips/m3821.py`, at 0xB804C000: the standard in register 0x2FF, DVB-T
  lock in bit 6 of 0x1D, the T2 state in 0x67 and 0x11D). Each model's
  `frequency()` decodes what the driver tuned it to (MxL603 / MxL5007T: the
  channel word / 64 MHz; R820T: the PLL with the firmware's crystal and IF,
  "calibrating" while the antenna input is off for its image-rejection
  calibration), and `sim.tuner_info()` gives that as one line. The signal is
  on every frequency, or with `sim.set_signal(True, frequencies=[...])` on
  those only, as an antenna receives a few multiplexes: the demodulators
  report lock, and the demultiplexer model feeds its stream, only while the
  tuner model is tuned within 1 MHz of one (`sim.tuned_to_signal()`; a
  terrestrial channel raster is 7 or 8 MHz), so a channel search finds those
  channels and nothing elsewhere. The screen
  regressions attach the dump's tuner without a signal (`screen_regression`'s
  `tuner=True`), so they keep their no-signal screens and every capture in the
  report shows the frequency it was taken at; the simulator itself attaches
  nothing unless asked. A lock alone has
  no transport stream behind it: the Globo N3 with a signal shows its
  channel banner and then a clear black picture instead of its red "Brak
  sygnału" box (`run_dump_globo_signal.py`), and the R265 Lite's manual scan
  page shows 100 % signal strength and 30 % quality instead of 0 % and 0 %
  (`run_dump_r265lite_signal_capture_screen.py`, which then adds the stream
  below and runs the search).
* **Demultiplexer and transport stream** (`dmx_m36.py`, `transport_stream.py`):
  a lock alone is not a channel: after a tune the firmware filters the
  programme tables (PAT, PMT, SDT, EIT ...) and shows what they carry.
  `dmx_m36.Demux` models the DMX0
  demultiplexer the M3801 and M3601E firmwares program at 0xB8022000 (DMX1 at
  0xB8024000), and the M3821 generation's too (its driver, "DMX_S3601_0" as
  on the M3801, writes each PID filter as one entry -- type bits 0, the PID's
  header bytes, no mask -- and polls the ring instead of taking the
  interrupt): 48 PID filters loaded through a RAM port (+0x60 type and
  filter, +0x62 go, +0x64 mask / value: the driver writes mask `1F FF` and the
  PID), the filter enable bits (+0x40), one "united" ring of 188-byte packets
  whose physical base, length and interrupt threshold the driver writes
  (+0xC0, +0x140, +0x142: the Comsat uses 0x03A078A0, 6144 packets, 80),
  the hardware's write pointer and the driver's read pointer (+0x1C0 /
  +0x1C2), the threshold interrupt on line 7 (OS IRQ 15; +0x300 enable,
  +0x310 status, read to clear), the self-clearing reset (+0x03). The
  register protocol comes from the SDK's driver objects (`refs/MainCode/ddk/
  libcore_hd.a`: `dmx_hal.o`, `dmx_tasks.o`, `dmx_sec.o`), the base from the
  firmwares. `sim.attach_mux()` puts a transport stream behind it: a
  `transport_stream.Mux` of one made-up service ("AliSimulator TV") whose
  PAT, CAT, PMT, SDT, NIT, TDT (the clock) and EIT (now / next) go into the
  ring as TS packets with continuity counters and MPEG-2 CRCs, each PID at
  its own rate, for every PID the firmware has a filter on. The multiplex
  adapts to the firmware: the first filter on a non-standard PID after the
  PAT's is its channel's PMT PID, and the service moves there with the
  programme number, name and video PID of that channel read from the dump's
  own channel database (`transport_stream.channel_records`: the lib_db
  P_NODE records of the userdb / defaultdb chunks, found by their bit-field
  words -- video and PCR PID in one, programme number and PMT PID in the
  next -- and their UTF-16 names, which the database stores one byte short;
  dump.bin's "Polsat Sport News" is programme 0x1A on PMT PID 0x321, "TVP
  Opole" 0x11 on 0x6A5). Without a record the programme number is searched
  for in the firmware's section filters in RAM. State of play: dump.bin takes
  all of it -- it filters the TDT, its channel's PMT, CAT, SDT, NIT, EIT and
  video / audio PIDs, consumes every packet, sets the chip's real-time clock
  (below) to the TDT's time, and its banner shows that date and time
  ("10/10 13:00": 12:00 UTC in the tests, its time zone +1 h) and the model's
  EIT ("Now: 13:00-14:00 TVP Opole now", "Next: 14:00-15:00 TVP Opole next"
  under "TVP3 Opole", "no information" for the present event when the banner
  comes before its section; `run_dump_signal_capture_screen.py` captures it,
  `docs/dump_bin_banner_with_eit.png` is a first capture under the unset
  clock's "28/11 01:00") -- then the banner
  times out and the channel stays, a clear black picture with no source for
  the video and audio streams. After the tune it polls the demodulator:
  state register 0x3B 400 times in 8 s, wanting 1, then 0x147 (non-zero),
  then, after its init command through register 0x12E, the event register
  0x02 for a done bit (up to 1000 times, 0x803A2060; read helper
  0x8039C7AC); the demodulator model answers all three with a signal (the
  Globo's signal test survives it). (Its stepping to the next channel every
  20 s or so, taken for a missing gate of its lock state machine, was its
  front-panel buttons on GPIO 31 / 9 read as pressed: `gpio_keys.py`.) Its
  remote's EPG key then opens the programme guide on that channel at "13:00
  10/10", the two events on its time line ("TVP Opole now" from 13:00, "TVP
  Opole next" from 14:00).
  The Opticum R265 Lite (the M3821) takes it in its channel search: it
  filters the PAT, SDT, NIT and the PMT the PAT names, consumes every packet
  and ends on "Zakończono wyszukiwanie kanałów" with "AliSimulator TV" among
  its TV channels, its clock at the TDT's "13:00, sobota 10 października"
  (`run_dump_r265lite_signal_capture_screen.py`); the Ferguson T750i (the
  same driver) in its automatic search, and in its manual search on CH05,
  after which it stores and plays the channel, its banner showing "10/10/2026
  14:00" and the stream's now / next events -- with "STB not signed!" popping
  up every minute of play, its OTP signature being blank (see the M3821
  above), which makes those screens too timing-dependent for a regression.
  `sim.dmx_info()` sums it up for the report; `screen_regression.run(...,
  mux=True)` boots a test with it.
* **Real-time clock** (`rtc_m36.py`, 0xB8018A00): the SDK's RTC driver
  loads the time with a word store to +00 (bit 31, then the year's two low
  bits, month, day, weekday, hour, minute, second) and reads the running
  time at +04 in the same layout; the S3811's later revision has the block
  at 0xB8018F00, which the simulator's revision 0 does not select.
  dump.bin's application keeps its calendar in clocks of its own, but what
  it shows -- the local time, the channel banner's date and time, the
  programme guide's time line -- is this register plus the time zone; it
  loads it at start with the time saved in its settings and again whenever
  a TDT arrives. Unmodelled it read 0, month 0 and day 0, which the
  firmware's MJD arithmetic turned into 28 November, so its guide started at
  "01:00 28/11" whatever the stream said, without an event in it. The model
  runs with emulation time from the load (the alarms at +0C / +10.. are
  RAM). It belongs to the M3801 family (`chips/m3801.py`); the code of the
  M36xx, M3821 and C3505 applications (URZ0086, KM0186, T750i, T760i)
  addresses the same block, but those families do not have the model.
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
  0x318 the driver had written at init) and started over. The M36xx's MPEG
  decoder (the SDK's `vdec_s3601`, run by the SEE on the M3606) keeps its VLD
  bit offset there instead -- written as the start, read back as the position
  -- so that family (`ChipFamily.ve_status`) reads the word as written: masked,
  the offset went back and the URZ0086 V1.1.1's SEE program stopped at its
  assertion that the video buffer's read pointer only moves on.
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
  kuseg 1:1 with Status.ERL set. Since 2026-10-15 (`native_status`, default) a
  wired TLB entry -- two 256 MB pages at physical 0, uncached, global, put in
  by a stub run once at start-up (`_setup_kuseg_tlb`) -- maps kuseg's lower
  512 MB 1:1 instead (none of the firmwares writes the TLB; Unicorn's 24KF
  has no segmentation control, its SegCtl registers read 0xFFFFFFFF), and the
  native Status is the guest's own: MFC0 Status runs natively (no CP0 site),
  MTC0 Status runs natively too while its hook follows the write
  (`_follow_status_write`: the shadow, the slice re-planned; the hook writes it
  itself and moves on only when the slice ends there), and run() takes the
  native Status over at each slice boundary. That halves the RTOS's interrupt
  disable / enable pair (61 -> 31 us). Before (and with `native_status = False`
  or a TLB entry that cannot be set up), the native Status carried a forced
  ERL and every MFC0 / MTC0 Status was emulated.
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
  A replayed store lands again after its handler, so a model that defers an
  effect to the next access (the SEE start, `chips/see.py`) must not run it in
  the replay's handler: the store then overwrote what the SEE's boot code had
  just written (0xB8000280 to 0x200), and the Globo HD-XS2's application,
  which starts the SEE's program only while 0x200 reads that, skipped it in
  one suite run in five (`test_see_start.py` replays the store). Nor at the
  end of the slice that stopped on the store, which comes before the replay
  (and an interrupt taken at that boundary can come in between).
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
  fault in a branch delay slot, the branch flags of the CPU's hflags stay
  set, so the next translation block -- at the branch's target -- runs as the
  delay slot of a branch to that same target, and its first instruction runs
  twice (a branch there means a branch in a delay slot: the M3329's flash
  probe ended at PC 0). `mmio_map` accesses are not affected (unless a
  debugging script adds a memory hook over the device window), so this
  concerns the flash window. The simulator stops the emulation at such an
  access -- the stop takes effect at the next block, after the branch -- and
  clears those flags before the next `emu_start()` (`_device_access`,
  `_clear_branch_flags`); it logs a `[DSLOT]` line once per PC.
  Swapping the window for an `mmio_map` region while the flash driver works
  was tried first and given up: code runs from the M3329's flash, and after
  an instruction fetch had faulted on an `mmio_map` region, the next
  `emu_start()` crashed natively, whatever was mapped there by then.
* Unicorn 2.1.4 bug: translating an unhooked straight-line block of ~375 or
  more instructions (also a jump into zero-filled RAM) crashes with an access
  violation. Fast mode reports it as a RuntimeError; exact mode is not
  affected (a hook on every instruction keeps blocks short). The SDK's
  application images start at 0x80000200 with 0xE00 zero bytes (~900 NOPs)
  before their first code, so 0x80000200..0x80000FFF run under a code hook
  that does nothing (`_hook_short_blocks`) while they hold such a run of zero
  words -- only then: other images keep code there (the URZ0086's BSS clear),
  which the hook's Python call per instruction slowed from 25 ms of emulation
  time to 1.7 s.
* Unicorn's own CP0 EBase reads 0x800003FF: CPU number 0x3FF. An `mfc0 EBase`
  that runs natively (not hooked yet) tells a dual-CPU firmware it is not
  CPU 0 -- the URZ0086's exception vector then takes its second-CPU path
  through a NULL pointer. An interrupt delivered to a vector in RAM therefore
  first scans that page for CP0 instructions (an application writes its
  vector shortly before its first timer tick, within the periodic rescan's
  window).
* A dual-CPU chip's second core (`chips/see.py` `SeeCore`) is a second
  `AliMipsSimulator` on the same RAM, flash and register buffers, run between
  the first core's slices until its emulation time catches up with the first
  core's: turns of so many instructions did not work (fast-mode counts are
  estimates; with the SEE's rate estimated low, a million-instruction turn
  took minutes). Its idle task's `b .` would spin away as much host time as
  the turn lasts, so `idle_skip` (first made for this core, on for every core
  now) moves the core's emulation time (and its Count) on to its next timer
  interrupt instead, and a code hook on the loop ends the slices that reach it
  -- most turns start in the tick handler, which returns into the loop (the
  URZ0086: 8 M instructions in 16 s instead of 22 s).
* A device register that is plain memory keeps what the firmware stores into
  it: the URZ0083's bootloader pulses bit 31 of the chip ID word, and its
  application then read its chip as 0xB602 and rebooted itself every ~38 M
  instructions -- the chip ID word is read-only now
  (`_hook_chip_id_store`).
* A stand-in has to look like the bus at rest too: input pins that read 0
  (an I2C slave's ACK, so writes "succeeded") made the R265 Lite's panel
  driver, which checks that SDA and SCL are high before a START, find its bus
  busy for ever -- and a decoder that only watched DO never saw its open-drain
  transactions anyway. Its buttons and texts appeared once released lines
  read high and DIR writes reached the decoder.
* A black capture is not always a missing display model: the X110TS drew its
  whole channel banner into a region the GMA layer pointed at, and a task of
  its application cleared the layer's enable bit again about ten times a
  second -- its own hardware check had failed (a satellite demodulator that
  did not answer, a chip product without one). Capturing with the layer's
  enable bit forced on shows what was drawn; tracing the stores to the
  layer's register shows who hides it.
* A reset loop is not always a failed check: the Ferguson T50's bootloader
  took its reboot path right after "APP  init ok" because no flash device
  was registered -- its 2009 flash table knows a 4 MB part only by the
  electronic ID in the last byte of the 0xAB read, and the simulator
  answered 0x00 there (a real W25Q32 answers 0x15). The first flash read of
  its program check then found no device and rebooted.
* A register layout fitted to one board can be wrong on the next: the
  M36xx video engine keeps bits 24..27 of its stream buffer's address in
  bits 27..30 of the register. Read as 0x02000000 plus the low 24 bits it
  pointed at the URZ0083's logo by chance and at zeros on the URZ0086,
  whose engine then consumed every bit it was given -- and in some runs
  the SEE's bit-buffer accounting stopped at its assertion.
* A popup in some captures only can be a check on a timer: a task of the
  S60 reads its USB power switch's fault flag (GPIO 25) and, while it reads
  low, cuts the port's power, shows "USB Short circuit!!" for 3 s and tries
  again ~10 s later -- a popup for 3 s of every ~14; bisecting pull-ups gave
  contradictory answers until the code that reads the pin was found.
* A UI that draws nothing may be waiting on a task, not on a device: the T50's
  control task waited for good on an event flag (found by logging every
  task's last call into the OS's wait functions, located in the image by the
  SDK's object code), set by a task that polled its decoder's "first picture
  shown" -- which came only once the second video output, which nothing
  modelled, had asked for the frame too. The SDK's headers name the fields
  (Request_Info's src_path) that the disassembly only shows as offsets.
* `emu_start(timeout=)` on Windows creates a thread per call that polls with
  a 15.6 ms timer and is joined at the end, hence `slice_stopper.py`.
* Unicorn race: `uc_emu_stop()` from another thread sets `stop_request` before
  it calls `cpu_exit()`, and the code-hook dispatcher skips *all* hooks while
  `stop_request` is set (in a branch delay slot it does not even exit first).
  A hooked CP0 instruction reached in that window runs natively: `mfc0 Count`
  reads 0, `eret` jumps to the native EPC, which nothing writes, 0 (under the
  forced ERL: to ErrorEPC = 0), `mtc0 Status` drops the forced ERL (with the
  native Status it is just the guest's write, taken over at the boundary). So
  fast-mode slices end synchronously: every hooked CP0
  instruction checks the slice deadline, the asynchronous stopper is only a
  backstop 1 ms later (50 ms while EXL is set, i.e. in exception / context
  switch code), and a slice ends synchronously when the guest itself enters
  EXL. The stopper's disarm waits for a callback in flight, so a stale stop
  cannot hit the next slice. A native `eret` that still slips through is
  visible (at address 0, EXL cleared natively but not in the shadow; under the
  forced ERL also a native `mtc0 Status`, the ERL gone) and is repaired at the
  slice boundary (redone / adopted) and logged as `[WARN] native ...`;
  `sim.native_cp0_repairs` counts them. A native MFC0 of EPC / Count / Cause
  (Unicorn's stale registers) or MTC0 Compare / EPC / Count / Cause is *not*
  visible and not repaired; these are rare, and exact mode is immune. (On
  2026-10-16, with four runs at a time, about one X110TS SEE run in 40 and
  one dump.bin signal run of the slow suite ended in an unmapped read with
  garbage registers, no native repair logged before it -- one of the
  invisible kinds; with the slice history recorded it did not happen in 60
  runs.  The regressions boot again once after a simulator crash in any
  phase: screen_regression.run, see_regression.run.) The kuseg TLB entry was
  half of the full fix proposed here before; mirroring EPC / Count into
  Unicorn's own CP0 registers is the other half.

## Tests

Run the scripts individually (`python tests/run_dump_maciej_to_bl_verify_sw.py`,
`python tests/run_dump_to_end.py`, `python tests/test_boot_decodes_mips16.py`, ...)
or all of them with `python run_all_tests.py` (a few minutes). `python run_all_tests.py
--slow` (100 tests, about 52 minutes with `--jobs 2`; 4.2 hours before the speed
work of 2026-10-15: idle skipping, cheaper CP0 hooks, the bootloaders' LZMA
decoder in Python, the native Status, waits in the firmware's time, the RTOS's
delay() and interrupt disable without hooks) adds
`run_dump_maciej_to_main_app.py`, which boots dump_maciej.bin
through expand() into the main application (about 20 s; the bootloader's
unoptimised LZMA decompression, which took a minute of that, runs in Python
now), checks the
decompressed image against an offline LZMA decompression of the flash chunk,
and checks that the application's RTOS runs on timer ticks (it prints its
init banner, compared exactly). `run_dump_to_main_app.py` and
`run_dump_Prima_to_main_app.py` (about 10-15 s each, in the default run) do the
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
expected screen is remade with `--make-expected`; its waits -- the settling
after the OSD appears and after each navigation step, `("wait", s)` -- are in
the firmware's own time, `sim._vtime()`, so the firmware's banners and timeouts
come out the same whatever the host's load and however much time the simulator
skips; `gma_capture.py` composites the GMA layers' regions --
and the layers of the newer display engine at 0xB8006900 / 6B00 the T750i's
drivers use, which no CPU store sets: the drivers hand the display engine
register lists in RAM (0xB8006080 / 90 / A0 / B0: the list, +4 load enable),
which it loads every frame, so the capture walks them --, and
for a firmware whose output mode is not 720p -- the Prima VIII and the SRT
8115 drive PAL, the Cabletechs 1080i (the URZ0195's 2012 firmware from the
start, the URZ0083Q and URZ0194S once their wizard is up: its default "Tryb
Wyświetlania" is 1080i@50HZ), so the display engine scales the OSD layer to
the output and the region heads hold output coordinates -- it undoes that
scaling, read from the display engine's timing register, so the capture shows
the whole OSD where the TV shows it; each capture logs the output mode; the
durations below are from a `--slow --jobs 2` run of 2026-10-15): `run_dump_maciej_capture_screen.py` (the Opticum's wizard,
about 1 minute), `run_dump_globo_capture_screen.py` (the Globo N3's no-signal
banner, about 4), `run_dump_t90_capture_screen.py` (the official 2015 update
of the same Opticum / Globo family, "OPTICUM HD T90/", the same no-signal box
and menu, about 4), `run_dump_capture_screen.py` (dump.bin's no-signal box
after its flash scan and channel banner, then its channel list and main menu
over the remote, about 6), `run_dump_signal_capture_screen.py` (the
same boot with a signal and the transport stream: the channel banner with the
multiplex's EIT text, captured as it is drawn -- 0.5 M instruction slices,
`settle_s=0` -- before it times out, about 2) and `run_dump_cabletech_capture_screen.py`
(the URZ0083Q's first-install wizard after its flash database scan, about 8 in
all, with the TM1628 panel reading "noCH") `run_dump_srt8115_capture_screen.py`
(the Strong SRT 8115's no-signal screen, about 5) and
`run_dump_urz0194s_capture_screen.py` (the Cabletech URZ0194S, the URZ0083Q's
family with a newer application: the same wizard after its scan, about 6) and
`run_dump_urz0195_capture_screen.py` (the Cabletech URZ0195 with its 2012
firmware, which draws its channel banner and no-signal screen seconds after
starting, with the panel reading "0004", about 4 minutes; the 2013 firmware
of the same box has a test of its own, below) and
`run_dump_prima8_capture_screen.py` (the Strong Prima VIII flash dump -- unlike
the manufacturer's update of the same box it carries a channel database --
whose Bulgarian channel banner comes up first, then its
"Няма сигнал!" no-signal box, about 4 minutes) and
`run_dump_t650i_capture_screen.py` (the Ferguson Ariva T650i's 8 MB update
image with a signal on UHF channel 34, 578 MHz, and the transport stream
behind it: with its empty channel database it runs the first-install
automatic search, which reads the multiplex's tables there and finds
"AliSimulator TV", and nothing on the other channels up to 858 MHz -- its
last search screen is compared, the panel reading "Find" --, about 13
minutes; without a signal the search ends on "nie znaleziono kanału!") and
`run_dump_x110ts_capture_screen.py` (the Opticum X110TS, an M3606
twin-tuner satellite PVR whose SEE program on the second core drives the
display: its channel banner, then its red "No Signal!" box, the main
menu the remote's MENU opens, and the front panel's down button moving its
highlight to Installation, about 4 minutes)
and `run_dump_t750i_capture_screen.py` (the Ferguson Ariva T750i, an M3821
with the dual-CPU build: its first-install wizard "Witamy" through the newer
display engine's layer, captured as it comes up, then the front panel's exit
key opens the main menu's "Edytuj kanały" page before the wizard's countdown
starts the channel search, its down key highlights the first item and the
remote's RIGHT turns to the menu's next page, about 2 minutes) and
`run_dump_t760i_capture_screen.py` (the Ferguson Ariva T760i, a C3505 with
its ATBM7812 demodulator: its wizard "Welcome" the same way, then the panel's
exit and down keys -- "Edit Channel", "Favorite" highlighted -- and the
remote's RIGHT, about 2) and
`run_dump_prima8_update_capture_screen.py` (the Strong Prima VIII's update
image, without the dump's channel database: its first-install wizard,
whose highlight the remote's DOWN moves, about 2) and
`run_dump_urz0195_2013_capture_screen.py` (the Cabletech URZ0195's 2013
firmware: its channel banner, then its "Brak sygnału!" screen, the panel
reading "0005", then the remote's OK opens its channel list and DOWN moves
the highlight, about 3) and `run_dump_urz0083_capture_screen.py` (the Cabletech
URZ0083, an M3601E: its boot logo decoded and shown, then its first-install
wizard "Welcome" in Polish, whose highlight the remote's DOWN moves, about
2) and `run_dump_tht501_capture_screen.py` (the Thomson THT501, the same
generation: its English wizard in a flat skin of seven colours, whose
highlight DOWN moves, about 2) and `run_dump_urz0086_capture_screen.py` (the Cabletech URZ0086, an M3606:
its SEE decodes the boot logo and its OSD driver draws the wizard "Witaj",
whose highlight DOWN moves, about 3) and `run_dump_s60_capture_screen.py`
(the Opticum HD S60, an M3601S: its "No Signal!" message, with its USB power
switch's fault flag on GPIO 25 pulled up, then the remote's OK opens its
channel list, and the remote's and then the front panel's DOWN move the
highlight, about 5) and
`run_dump_esr250_capture_screen.py` (the Echosonic Mini ESR-250, an M3510A
run as the M3503: its Quick Setup menu, whose highlight the remote's DOWN
moves and then its front panel's down key -- a TM1650-compatible chip on the
HD-XS2's pins reading "Strt", whose raw key bytes its UI's key map holds as
panel codes -- about 2) and `run_dump_t50_capture_screen.py` (the Ferguson Ariva
T50, an M3602: its boot logo shown on both outputs, then its installation
wizard "Welcome", drawn by the M3602's own GE and scaled to its PAL layer,
whose highlight DOWN moves, about 2) and `run_dump_hdxs2_capture_screen.py`
(the Globo HD-XS2's SmartHD image, an M3503 whose SEE hashes the
application on its crypto engine first: its main menu, whose highlight RIGHT
moves, about 3) and `run_dump_hdxs2_reta_capture_screen.py` (the Reta image
of the same pack: its first-install wizard, where DOWN picks German and the
wizard switches language, then the front panel's down button English, about
3) and `run_dump_m3329_capture_screen.py`
(the M3329 board: its channel banner, its panel showing the channel number,
then the panel's MENU button opens its Channel menu and the remote's DOWN
moves the highlight, about 2; its CPU draws the OSD, so this one watches the
screen instead of GE commands: `ge=False`).
`run_dump_maciej_remote.py` drives the
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
keys and then the remote's DOWN, and the URZ0194S steps its wizard's Region value with its (the whole
wizard switches language), then opens its main menu with the remote's MENU
and moves on with DOWN; the SRT 8115 opens its main menu, moves its
highlight with the front panel's down key and closes it; the
URZ0195 (2012) opens its channel list with OK and moves the highlight down
(its panel keys do nothing: neither URZ0195 firmware's key map has a panel
entry); the T650i, once its search, the programme-guide
download that gives up (the multiplex has no EIT schedule) and its live
picture are through (a `("wait", seconds)` step), opens its channel list
with OK: "1 AliSimulator TV", the multiplex's now / next events beside it;
the Prima VIII opens its EPG grid with its
virtual key 42 and closes it with EXIT (16) -- before its front-panel buttons
were modelled (`gpio_keys.py`) they read as pressed and stepped its channels
by themselves every second or two, and the remote's keys got lost in between.
dump.bin opens its channel list with OK and its main menu with MENU, each
closed with EXIT, and with a signal and the transport stream its programme
guide with EPG: its library (the T650i's) takes the extended-NEC coding --
its decoder keeps the frame's first address byte as the key table code's
high byte, so a standard NEC frame of its MENU (0xFBDD) was looked up as
0x04DD -- and its front-panel buttons (the Prima VIII's two on the same
pins, the SDK's key task: its virtual keys 12 / 13 there) had hidden that
behind their channel hopping. How a firmware's key table
maps to the NEC frame bytes differs between SDK generations
(`ir_remote.IR_CODINGS`, chosen from the dump's name: standard NEC with
bit-reversed, inverted bytes for the Opticum / Globo, an extended-NEC
address for the SRT 8115, the
Prima VIII (the flash dump and the update image), both URZ0195 firmwares, the Fergusons T650i, T750i and T760i, dump.bin and the
M3601E firmwares (URZ0083, KM0183, THT501), standard NEC whose table code keeps the first
address byte for the Echosonic ESR-250's 2015 firmware, the Opticum S60's and
the Cabletech URZ0083Q's and URZ0194S's -- whose remotes long seemed to stop
after one key: their MENU, 0x0017, is the same frame under the "plain bytes"
reading first chosen for them, rev8(~0x17) being 0x17, and every other key
came out as a code their tables do not hold -- and only the command half for the
Ferguson T50, whose control task drops a key unless the code's address half is its remote's
(extended NEC 0x01 / 0xFC); a firmware may also number its
virtual keys differently, see `ir_remote.VKEY_FALLBACKS`). `--jobs 2` runs two tests at a time (the simulations are independent;
firmware time follows each emulation thread's own CPU time), which is what the
workflow does.

Mechanism tests that need no firmware dump: `test_isa_mode_tracking.py`
(MIPS32/MIPS16 switches, breakpoints inside MIPS16 code),
`test_flash_window_isolation.py` (SPI responses vs flash contents, page program,
sector erase), `test_cp0_count_emulation.py`, `test_cp0_timer_interrupt.py`
(timer latch, masking, MIPS16 EPC, late Compare, software interrupts),
`test_device_models.py` (PMU, VCAP, the video engine's status bits and the
M36xx's engine reset, graphics engine command -> interrupt ->
acknowledge, masked line, partial acknowledge, controller write-back, command
stores replayed after asynchronous stops, add_mmio_hook, peek / poke),
`test_rtc_m36.py` (the real-time clock's register layout, its calendar
carries, a load read back and a second later),
`test_spi_command_mode.py` (SPI command responses read in the same block as
the SF_INS store, with the flash read hook installed between slices, also
toggled hundreds of times) and `test_mips16_decoder_encodings.py`.
`test_ge_m3602.py` runs the M3602 GE's commands (fill, copy, a scaled copy
through the palette inside a clip rectangle, a chained command) on a RAM
image and captures an M3602 display layer of a PAL output;
`test_ge_fast_paths.py` runs random GE_M36F commands -- copies (PTN and SRC
bypass) and fills in every packed and index format, with random layout bits,
clip rectangles, sub-byte surfaces, regions past the end of the RAM -- on
two copies of a RAM image, with and without the model's fast paths, and
compares them byte for byte (a plain copy in the surface's own format and a
one-colour fill skip the float ARGB path: the R265 Lite's channel search had
copied 200 Mpx of full-screen ARGB1555 surfaces through it, 34 s of its
regression; region reads and writes are one strided view, sub-byte writes
one `ufunc.at`);
`test_crypto_engine.py` hashes a DMA job with SHA-256 and a direct job
with SHA-1 on the crypto engine model and checks its interrupt.
`test_parallel_flash.py` runs the parallel NOR flash's commands (autoselect,
program, sector and chip erase, unlock bypass) and, on a simulator in both
modes, the M3329 driver's probe -- the reset in a branch delay slot -- and an
SPI flash's store in a delay slot, each instruction running once.
`test_otp_m3821.py` reads and burns the M3821's OTP model the way the
firmware's driver does, on the T750i's blank OTP.
`test_cp0_repeat.py` checks that skip of a repeated MTC0 (the same state as
in exact mode, the second hook skipped, a breakpoint in between honoured).
`test_lzma_hle.py` checks the bootloaders' LZMA decoder run in Python: the hook
on synthetic calls (the output, `*outSizeProcessed`, the return, the time
charged, an end marker before `outSize`) and every case it leaves to the
emulated decoder (a stream the module rejects, input cut short, a buffer too
small, output outside the RAM, exact mode, a breakpoint or the stop address
in the decoder, other code at the entry), the routine in the flash images and
a RAM chunk's scan, dump_maciej's main code decoded to what its stream holds
with its bootloader's "success!" at the emulated decoder's instruction count,
and both switches (no time charged, the emulated decoder).
`test_idle_skip.py` checks idle skipping on a ticking program waiting in
`b .`: the ticks at the programmed rate of emulation time with most of it
skipped and the instruction count following, the loop's hook, `idle_skip =
False`, budgets and `max_vtime` met exactly, no skip with interrupts disabled,
a UART byte arriving at its arming point, and the busy time charged for
Python's work (no interrupt while it is paid, the latched tick after it).
`test_native_status.py` checks the native Status against the forced ERL and
exact mode: kuseg stores and device reads with ERL clear, MFC0 Status native,
a tick that came due with interrupts off taken right after the enabling MTC0
Status, the same results in all three, the RTOS's interrupt disable left
unhooked (and a tick that came due after it still taken right after the
enable), a native ERET redone in both fast modes, a Status written behind
the hooks' back taken over.
`test_cp0_sites.py` checks the CP0-site scan (numpy and regex paths agree on
planted words; MFC0 Status a site only under the forced ERL), the vector page
scanned again only when it changed, the periodic rescan, CP0 instructions run
from the flash window, and the direct register access (`mips_asm.py` holds
the instruction encoders and loader these tests share).
`test_delay_hle.py` checks the RTOS delay's shortcut on copies of its four
builds: a short wait returned from at the entry with the routine's registers
and its Count ticks, a 50 ms one moved on through its loop slice by slice, 1 ms
ticks on time while short and long waits are called over and over (inside the
long ones, which still last their length), counted slices, each build's own
rules (the newer SDK's whole argument and one tick more, the bootloader's
ticks per microsecond, the SEE's division), the cases it leaves to the
routine (exact mode, a breakpoint in its `get_count()`, the stop address in its
loop, its code changed, `delay_hle` off) and the scan (not a copy whose calls
go elsewhere or differ, whose `get_count()` does more, nor a misaligned one).
`test_chip_families.py` and `test_family_switch.py` read firmware images
without running them: the family each image is recognised as, and one
simulator loading an M3821, an M3801, an M3503 and an M3602 image in turn
(only the loaded family's devices stay, the memory a family remapped comes
back, an M3602 image after an M3503 one is run as the M3602).
`run_all_tests.py` runs every test in its own Python process, so a native
crash fails that test only.

### Test report

`run_all_tests.py` also writes `report/index.html` (`report.py`): one
self-contained page with every test's verdict, wall time, description (the
script's docstring), its `[PASS]` / `[FAIL]` lines, its whole output, and the
images it rendered -- OSD screen captures embedded as PNG, each on its own row
with a column on its right: the tuner's frequency above the front-panel
display drawn as 7-segment SVG, both as they were when the screen was
captured (a click shows a screen at full size). The page starts with the
featured runs, opened: one full run per box, a script that declares
`FEATURED = {"device": ..., "chips": [...], "shows": [...]}` (read from its
source, not run), titled "<device> with <SoC> + <panel chip> + <tuner>" over
what the run shows ("Boots to screen, reacts to remote, shows channel
scan"), its screens first, its description and output folded. Every other
test follows as a closed card. A test attaches those through
`report_artifacts.py`: `image(path, caption, panel=, panel_text=, tuner=)` for
a PNG it saved (into
`report_artifacts.out_dir()`, which the runner points at `report/img/<test>/`)
with the box's state at that moment, and `panel(digits, caption, text)` for a
display on its own; the lines
they print are picked up by the runner, so a test still runs on its own
unchanged. Filter the other tests by dump, kind (unit / regression / slow)
and data (renders, crashed, timed out); `-k name` runs a subset, `--timeout
seconds` kills a hung test. The results also go to `report/results.json`;
`run_all_tests.py --report-only` renders the page again from them (with the
scripts' current docstrings and `FEATURED`) without running anything, for a
change to the page itself.

The GitHub Actions workflow (`.github/workflows/tests.yml`) runs
`run_all_tests.py --slow` on every push, uploads `report/` as a workflow
artifact and publishes it to GitHub Pages (the repository's Pages source must
be set to "GitHub Actions" once, under Settings > Pages); the page is updated
even when tests fail, and the job's result still reflects the tests.
