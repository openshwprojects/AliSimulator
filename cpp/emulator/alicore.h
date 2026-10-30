// AliSimulator C++ core: a MIPS32r2 / MIPS16e (24Kf) interpreter with the
// memory and hook model of Unicorn (so the Python simulator's device models
// and tests drive it unchanged, src/cpp_core.py) and the ALi machine's CPU
// side done natively: CP0 (Count / Compare timer, Status, Cause, EPC, EBase),
// interrupt delivery at exact instruction boundaries, the interrupt
// controller's IP3, the UART receive interrupt, the SPI flash controller, and a
// deterministic clock: emulation time is the instruction count (instructions
// per emulated second: ips), Count follows it at count_hz.  Speed: decoded
// blocks run chained; loops that wait are skipped exactly -- idle loops and
// spins to the next event, Count polls to the pass they end in (a recorded
// pass replayed at later times), counting loops to their last pass -- and
// GPIO stores go to the host in batches.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(_MSC_VER)
#define ALI_LIKELY(x) (x)
#define ALI_UNLIKELY(x) (x)
#define ALI_INLINE __forceinline
#define ALI_UNREACHABLE() __assume(0)
#else
#define ALI_UNREACHABLE() __builtin_unreachable()
#define ALI_LIKELY(x) __builtin_expect(!!(x), 1)
#define ALI_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALI_INLINE inline __attribute__((always_inline))
#endif

namespace ali {

// ---- Unicorn-compatible constants (unicorn_const.py / mips_const.py) ----
enum : uint32_t { PROT_NONE = 0, PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4, PROT_ALL = 7 };
enum : int {
  HOOK_INTR = 1, HOOK_CODE = 4, HOOK_BLOCK = 8,
  HOOK_MEM_READ_UNMAPPED = 16, HOOK_MEM_WRITE_UNMAPPED = 32, HOOK_MEM_FETCH_UNMAPPED = 64,
  HOOK_MEM_READ_PROT = 128, HOOK_MEM_WRITE_PROT = 256, HOOK_MEM_FETCH_PROT = 512,
  HOOK_MEM_READ = 1024, HOOK_MEM_WRITE = 2048, HOOK_MEM_FETCH = 4096,
};
enum : int {
  MEM_READ = 16, MEM_WRITE = 17, MEM_FETCH = 18, MEM_READ_UNMAPPED = 19, MEM_WRITE_UNMAPPED = 20,
  MEM_FETCH_UNMAPPED = 21, MEM_WRITE_PROT = 22, MEM_READ_PROT = 23, MEM_FETCH_PROT = 24,
};
enum : int {
  ERR_OK = 0, ERR_NOMEM = 1, ERR_READ_UNMAPPED = 6, ERR_WRITE_UNMAPPED = 7, ERR_FETCH_UNMAPPED = 8,
  ERR_HOOK = 9, ERR_INSN_INVALID = 10, ERR_MAP = 11, ERR_WRITE_PROT = 12, ERR_READ_PROT = 13,
  ERR_FETCH_PROT = 14, ERR_ARG = 15, ERR_READ_UNALIGNED = 16, ERR_WRITE_UNALIGNED = 17,
  ERR_FETCH_UNALIGNED = 18, ERR_EXCEPTION = 21,
};
// register ids: Unicorn's MIPS ids, plus the CP0 registers by (rd, sel) and the
// core's own state (REG_CP0_BASE + rd * 8 + sel)
enum : int {
  REG_PC = 1, REG_GPR0 = 2, REG_HI = 129, REG_LO = 130, REG_CP0_CONFIG3 = 137, REG_CP0_USERLOCAL = 138,
  REG_CP0_STATUS = 139, REG_FIR = 140, REG_FCSR = 141,
  REG_F0 = 1000,        // F0..F31 as 64-bit values (FR=1 view), 1000..1031
  REG_CP0_BASE = 2000,  // 2000 + rd * 8 + sel
};

// Why run() / emu_start() returned
enum StopReason : int {
  STOP_NONE = 0,
  STOP_COUNT = 1,      // the instruction count / limit was reached
  STOP_UNTIL = 2,      // the PC reached the end address
  STOP_REQUEST = 3,    // emu_stop()
  STOP_ERROR = 4,      // a memory fault or CPU exception (err holds the Unicorn error code)
  STOP_BREAKPOINT = 5, // a native breakpoint
  STOP_NULL = 6,       // a jump to address 0
  STOP_TIMEOUT = 7,    // the wall-clock timeout
  STOP_IDLE = 8,       // (internal)
};

// callbacks (C ABI, the user pointer first)
typedef uint64_t (*MmioReadCb)(void *user, uint64_t offset, uint32_t size);
typedef void (*MmioWriteCb)(void *user, uint64_t offset, uint32_t size, uint64_t value);
// (m16: the instruction's ISA, so the host need not read it back per instruction)
typedef void (*CodeHookCb)(void *user, uint64_t address, uint32_t size, uint32_t m16);
typedef void (*MemHookCb)(void *user, int access, uint64_t address, int size, int64_t value);
typedef int (*EventHookCb)(void *user, int access, uint64_t address, int size, int64_t value);
typedef void (*IntrHookCb)(void *user, uint32_t intno);
// GPIO pin levels for the host: count (DO register offset, levels) pairs
typedef void (*GpioCb)(void *user, const uint32_t *pairs, uint32_t count);
// The device window's accesses that need the host: write = 1 for a store; returns
// the value a load reads (a store's value is the callback's to put in place).
typedef uint64_t (*DevCb)(void *user, int write, uint32_t offset, uint32_t size, uint64_t value);
// Machine events for the host: kind (EVT_*), two arguments
typedef void (*EventCb)(void *user, int kind, uint64_t a, uint64_t b);
enum : int {
  EVT_UART_ERET = 1,   // an ERET ended the UART receive interrupt
  EVT_CODE_CHUNK = 2,  // first execution in a RAM chunk (a = its physical base, b = its size)
  EVT_FLASH_READ = 3,  // a load from the flash window while flash command mode is on (a = phys, b = size)
  EVT_FLASH_WRITE = 4, // (unused: stores go through the write-protect hooks)
  EVT_UART_IRQ = 5,    // the UART receive interrupt was delivered (a = EPC, b = vector)
};

struct Region {
  uint64_t base, size;
  uint32_t perms;
  uint8_t *ptr;   // RAM-like region: its bytes; null for an mmio region
  bool owned;
  bool mmio;
  MmioReadCb rd;
  MmioWriteCb wr;
  void *rd_user, *wr_user;
};

struct Hook {
  uint64_t id;
  int type;
  void *cb;
  void *user;
  uint64_t begin, end;  // begin > end: everywhere
  bool dead;
};

struct Fault {   // thrown out of an instruction: a memory fault or a CPU exception
  int err;
};

class Core {
 public:
  Core();
  ~Core();

  // ---- memory map (Unicorn semantics: addresses as mapped, no translation) ----
  int map_ptr(uint64_t base, uint64_t size, uint32_t perms, void *ptr);
  int map_alloc(uint64_t base, uint64_t size, uint32_t perms);
  int map_mmio(uint64_t base, uint64_t size, MmioReadCb rd, void *rd_user, MmioWriteCb wr, void *wr_user);
  int unmap(uint64_t base, uint64_t size);
  int protect(uint64_t base, uint64_t size, uint32_t perms);
  int host_read(uint64_t addr, void *buf, uint64_t size);
  uint8_t *direct(uint64_t addr, uint64_t *base, uint64_t *size);   // a plain region's memory (ali_direct)
  int host_write(uint64_t addr, const void *buf, uint64_t size);
  int regions(std::vector<Region> &out) const { out = regions_; return 0; }

  // The ALi device window (physical 0x18000000, 16 MB): its register buffer and the
  // host callback for the offsets flagged in devflags (DF_*)
  void set_device_window(uint32_t phys, uint8_t *buffer, uint32_t size, DevCb cb, void *user);
  enum : uint8_t { DF_READ = 1, DF_WRITE = 2, DF_WATCH = 4, DF_NATIVE = 8, DF_GPIO_DO = 16, DF_GPIO_DIR = 32 };
  void set_dev_flags(uint32_t offset, uint32_t count, uint8_t flags);   // replace
  uint8_t *devflags() { return devflags_; }

  // ---- registers ----
  int reg_read(int id, uint64_t *value);
  int reg_write(int id, uint64_t value);

  // ---- hooks ----
  int hook_add(int type, void *cb, void *user, uint64_t begin, uint64_t end, uint64_t *id);
  int hook_del(uint64_t id);

  // ---- execution ----
  // Unicorn's emu_start: from begin (bit 0: MIPS16) until the PC reaches until,
  // count instructions (0: no limit) or timeout_us of wall time.  Returns an
  // error code (ERR_*) like uc_emu_start.
  int emu_start(uint64_t begin, uint64_t until, uint64_t timeout_us, uint64_t count);
  void emu_stop() { stop_request_ = true; next_event_ = 0; }
  // The simulator's run: from the current PC (keeping a pending delay slot) until
  // icount reaches icount_limit; returns a StopReason.
  int run(uint64_t icount_limit);
  int last_error() const { return err_; }
  uint64_t next_event() const { return next_event_; }
  uint64_t limit() const { return limit_; }
  int stop_reason() const { return stop_reason_; }

  // ---- the ALi machine ----
  // time: icount advances 1 per instruction and by skipped time; Count = count at
  // icount_base + (icount - icount_base) * cnum / cden
  void set_count_ratio(uint64_t cnum, uint64_t cden);
  uint32_t count_now() const;
  void write_count(uint32_t value);
  void write_compare(uint32_t value);
  void timer_update();   // latch Cause.TI if Count passed Compare since the last check
  void set_timer_enabled(bool on);

  // interrupt controller: status / enable word offsets in the device window,
  // lines driven by the host's device models, the doorbell (ring byte offset,
  // shift; offset < 0 = none)
  void set_ic(uint32_t status_off, uint32_t enable_off, uint32_t ic_base);
  void set_ic_lines(uint64_t lines) { ic_lines_ = lines; poke_events(); }
  void set_doorbell(int32_t offset, int32_t shift) { doorbell_off_ = offset; doorbell_shift_ = shift; poke_events(); }
  bool ic_ip3() const;

  // UART receive interrupt (one-shot, see simulator.setUartReceiveData)
  void uart_arm(uint64_t at_icount, bool force) {
    uart_pending_ = true; uart_delivered_ = false; uart_at_ = at_icount; uart_force_ = force; poke_events();
  }

  bool irq_deliverable() const;
  uint32_t cause_value() const;
  uint32_t enter_interrupt(uint32_t epc);   // returns the vector
  void poke_events() { next_event_ = 0; }
  // A callback can change shared device bytes without using a setter. Remember
  // it until events() observes them, while keeping the existing event boundary.
  void note_host_callback() { dev_callback_dirty_ = true; }
  void enter_callback() { in_callback++; note_host_callback(); }
  void leave_callback() { in_callback--; note_host_callback(); }

  // ---- state (public: the C API and the host's properties read them) ----
  uint32_t gpr[32];
  uint32_t hi = 0, lo = 0;
  uint32_t pc = 0;
  bool m16 = false;          // ISA mode of the instruction at pc
  bool ds_active = false;    // the instruction at pc is a branch delay slot
  uint32_t ds_target = 0;    // ... and where the branch goes after it
  bool ds_m16 = false;

  // FPU (QEMU's model: 64-bit registers, FR=0 pairs them for doubles)
  uint64_t fpr[32];
  uint32_t fcsr = 0;
  uint32_t fir = 0x00739300;

  // CP0
  uint32_t cp0[32][8];       // plain storage for registers without special meaning
  uint32_t status = 0x10400000, cause = 0, epc = 0, error_epc = 0, ebase = 0x80000000, badvaddr = 0;
  uint32_t compare = 0;
  uint32_t count_base = 0;   // Count at icount_base
  uint64_t count_icount = 0;
  uint64_t cnum = 2, cden = 1;
  bool ti = false, timer_armed = false, timer_enabled = true;
  uint32_t timer_anchor = 0;
  bool count_observed_valid = false;
  uint32_t count_observed = 0;
  uint64_t timer_check_at = 0;     // icount of the next Compare crossing check
  uint32_t lladdr = 1, llval = 0;
  bool llbit = false;

  // interrupts
  uint64_t ic_lines_ = 0;
  uint32_t ic_status_off_ = 0x30, ic_enable_off_ = 0x38, ic_base_ = 0x30;
  int32_t doorbell_off_ = -1, doorbell_shift_ = 0;
  bool uart_ip3 = false;
  bool uart_pending_ = false, uart_delivered_ = false, uart_force_ = false;
  uint64_t uart_at_ = 0;
  uint64_t timer_irqs = 0, ic_irqs = 0, uart_irqs = 0;
  bool irqs_enabled = true;        // deliver interrupts at all (off while single-stepping)

  // counters / time
  uint64_t icount = 0;             // executed instructions + skipped ones
  uint64_t executed = 0;           // executed instructions only
  uint64_t idle_skipped = 0;       // instructions skipped in idle loops
  bool idle_skip = true;
  bool exact_mode = false;         // (no idle skipping)
  // Spin loops: a loop the block cache runs with no store and no device access
  // whose registers are the same after some passes waits for something only
  // an interrupt (or the other core, between turns) can change -- a tick counter,
  // a flag in shared RAM: the time moves on to the next event in whole passes.
  // (a repeat proves a cycle: the registers are compared after 1 pass, then, while
  // they differ, after 2, 4 ... LOOP_CHECK_MAX, to keep a busy loop's cost down)
  enum { LOOP_CHECK_MAX = 32 };
  uint32_t loop_interval_ = 1;
  bool spin_skip = true;
  uint64_t spin_skipped = 0;       // instructions skipped that way
  uint64_t stores_ = 0;            // guest stores so far
  uint64_t slow_ = 0;              // instructions not run in blocks, slow-path accesses
  uint32_t back_key_ = 0xFFFFFFFFu;  // where the last taken backward branch went (pc | m16)
  uint32_t loop_key_ = 0xFFFFFFFFu;
  uint32_t loop_passes_ = 0;
  uint64_t loop_stores_ = 0, loop_slow_ = 0, loop_icount_ = 0;
  bool loop_snap_ = false;
  uint32_t loop_regs_[34];
  void spin_check();
  // Count-polling loops (a delay(), a timeout): the same, but the passes read Count,
  // so the loop ends at a time of its own, not at the next event.  One pass is
  // recorded (its blocks), then the largest number of whole passes after which
  // the loop still goes on is found by replaying that pass at later times (each
  // replay rolled back: the pass stores nothing and reaches no device), and the
  // time moves on by that many passes.  The loop then ends in the very pass it
  // would have ended in (its condition only ever goes one way: time passed).
  uint64_t count_reads_ = 0;       // Count reads in blocks
  uint64_t loop_creads_ = 0;
  uint64_t poll_skipped = 0, poll_skips = 0;   // instructions / loops skipped that way
  bool probe_ = false;             // replaying a pass (no slow access may happen)
  bool loop_regs_match() const {
    return memcmp(loop_regs_, gpr, sizeof(gpr)) == 0 && loop_regs_[32] == hi && loop_regs_[33] == lo;
  }
  // the same, but for the registers in ign (bits 0..31, 32 HI, 33 LO)
  bool loop_regs_match_mask(uint64_t ign) const {
    if (!ign) return loop_regs_match();
    for (int r = 1; r < 32; r++)
      if (!(ign >> r & 1) && loop_regs_[r] != gpr[r]) return false;
    return ((ign >> 32 & 1) || loop_regs_[32] == hi) && ((ign >> 33 & 1) || loop_regs_[33] == lo);
  }
  // A Count-polling pass may leave a register different from pass to pass when the
  // pass writes it before reading it, and before it can leave the loop (a value
  // like `now` the poll keeps): such registers (rec_ign_) are not compared.
  uint64_t rec_ign_ = 0;
  bool loop_poll_tried_ = false;   // this loop's pass was recorded already
  uint32_t count_at(uint64_t ic) const {
    uint64_t ticks = (ic - count_icount) * cnum;
    // Integer ratios need no divide; retain the uint64_t wrap before division.
    if (cden != 1) ticks /= cden;
    return count_base + (uint32_t)ticks;
  }
  uint64_t spin_dbg[6] = {0, 0, 0, 0, 0, 0};   // checks, loop entries, skips cut by an event, replays, sum of their room, spins found
  // GPIO DO / DIR stores (DF_GPIO_*: the host's handler only passes the bank's pin
  // levels on -- panel and bus decoders): they land here, the levels after each
  // go to a log, handed to the host in order before any other call into it and
  // when a run returns (host_sync), so the decoders see the same sequence.
  enum { GPIO_LOG_MAX = 4096 };
  uint32_t gpio_log_[2 * GPIO_LOG_MAX];
  uint32_t gpio_n_ = 0;
  GpioCb gpio_cb_ = nullptr;
  void *gpio_user_ = nullptr;
  bool gpio_dev_drains_ = false;   // the device handler empties the log itself (one host call less)
  void flush_gpio();
  ALI_INLINE void host_sync() {
    if (ALI_UNLIKELY(gpio_n_ != 0)) flush_gpio();
  }
  // Profile (ali_prof): instructions run per block start / per instruction outside
  // blocks (pc | m16), and the device accesses handled in Python per instruction.
  std::unordered_map<uint32_t, uint64_t> *prof_insns_ = nullptr, *prof_dev_ = nullptr;
  // emulated time a device-window access that calls the host costs, in instructions
  // (a hardware register access is slow, and a poll loop on a host-modelled register
  // must see time pass: the Unicorn engine charged the host's own time for it)
  uint32_t host_access_cost = 0;

  // native breakpoints (sorted small vector) and the stop address
  std::vector<uint32_t> breakpoints;
  bool step_over_bp_once = false;  // the first instruction of a run ignores breakpoints there

  // events to the host
  EventCb event_cb = nullptr;
  void *event_user = nullptr;
  // RAM chunks whose first execution is reported (EVT_CODE_CHUNK): 1 MB chunks of
  // physical memory below chunk_limit, plus extra ranges
  std::vector<uint8_t> chunk_seen;
  uint32_t chunk_shift = 20;
  bool chunk_events = false;

  // the flash window's command mode (loads reported: EVT_FLASH_READ)
  void set_flash_cmd(bool on, const uint32_t *windows, int n);

  // The SPI flash controller done natively (simulator._hook_spi_* / _spi_*): its
  // registers SF_INS / FMT / DUM / CFG at +0x98..+0x9B of each base, the part's
  // answers in the flash window while a command other than a read is latched,
  // program / erase into the flash (the guest's view, rom, and the pristine
  // image the host keeps, image).  The registers' device-window offsets carry
  // DF_NATIVE.
  struct Spi {
    bool on = false;
    uint8_t ins = 0x03, fmt = 0x0D, dum = 0, cfg = 0, status = 0;
    bool wel = false;
    uint8_t resp[4] = {0, 0, 0, 0};
    int resp_len = 0, resp_idx = 0;
    uint8_t jedec[3] = {0xEF, 0x40, 0x16};
    uint8_t *rom = nullptr, *image = nullptr;
    uint32_t rom_size = 0;
    uint64_t commands = 0, programs = 0, erases = 0;
  } spi;
  void spi_config(bool on, uint8_t *rom, uint8_t *image, uint32_t rom_size);
  bool spi_passthrough() const {
    switch (spi.ins) { case 0x03: case 0x0B: case 0x3B: case 0x6B: case 0xBB: case 0xEB: return true; }
    return false;
  }
  void spi_write_ins(uint8_t cmd);
  uint32_t flash_offset(uint32_t pa) const {
    uint32_t rel = pa & 0x00FFFFFFu;
    uint32_t seg = (0xC00000u - (rel & 0xC00000u)) >> 22;
    return (((seg & 3u) << 22) | (rel & 0x3FFFFFu)) % (spi.rom_size ? spi.rom_size : 1);
  }
  bool in_flash_window(uint32_t pa) const {
    for (uint32_t w : flash_windows_)
      if (pa >= w && pa - w < 0x01000000u) return true;
    return false;
  }
  uint64_t spi_flash_load(uint32_t pa, uint32_t size);
  void spi_flash_store(uint32_t pa, uint32_t size, uint64_t value);
  uint64_t native_dev_load(uint32_t off, uint32_t size);
  void native_dev_store(uint32_t off, uint32_t size, uint64_t value);

  // diagnostics
  uint32_t fault_pc = 0;
  uint64_t fault_addr = 0;
  int fault_access = 0;
  std::string last_message;

  // in a host callback: PC writes redirect (Unicorn semantics)
  int in_callback = 0;
  bool pc_written = false;

  // the light instance a test harness runs single instructions on (for the fuzzer)
  int step_one();   // executes exactly one instruction, ignoring hooks / events

 private:
  friend struct Exec;
  // page tables, guest view: by virtual page, null = slow path
  uint8_t **vr_, **vw_, **vx_;
  // physical page tables (host-side lookups)
  Region **pregion_;     // region per physical page (null = unmapped)
  std::vector<Region> regions_;
  std::vector<Hook> hooks_;
  uint64_t next_hook_id_ = 1;
  // hook flags per virtual page: code hooks; physical page: mem hooks
  uint8_t *code_hook_page_;
  bool code_hook_all_ = false;     // a code hook without range
  bool mem_hooks_any_ = false;
  uint8_t *mem_hook_page_;          // physical pages with read / write / fetch mem hooks (bits 1/2/4)

  // device window
  uint32_t dev_phys_ = 0x18000000, dev_size_ = 0;
  uint8_t *dev_buf_ = nullptr;
  uint8_t *devflags_ = nullptr;
  DevCb dev_cb_ = nullptr;
  void *dev_user_ = nullptr;
  // A pointer mapping outside the device window may expose its bytes as code.
  // Such stores must leave the block before the following instruction is decoded.
  bool dev_store_alias_ = true;
  bool dev_callback_dirty_ = false;
  void refresh_device_aliases();
  bool plain_device_store(uint32_t off, uint32_t size) const;

  // flash command mode
  bool flash_cmd_ = false;
  std::vector<uint32_t> flash_windows_;

  // execution state
  volatile bool stop_request_ = false;
  uint64_t next_event_ = 0;
  uint64_t limit_ = 0;            // icount limit of the running call
  uint64_t until_ = ~0ull;
  int err_ = 0;
  int stop_reason_ = 0;
  uint64_t deadline_ms_ = 0;      // wall-clock deadline (emu_start timeout)
  uint64_t wall_check_at_ = 0;
  bool running_ = false;
  uint32_t fetch_page_ = 0xFFFFFFFF;
  bool hooks_done_ = false;       // the code hooks of the instruction at hooks_pc_ ran (an event came first)
  uint32_t hooks_pc_ = 0;
  uint8_t *fetch_ptr_ = nullptr;

  void rebuild_pages(uint64_t lo, uint64_t hi);
  void refresh_pages(uint64_t lo, uint64_t hi);
  void rebuild_all_pages();
  void rebuild_hook_pages();
  Region *find_region(uint64_t addr);
  void invalidate_fetch() { fetch_page_ = 0xFFFFFFFF; }

  int run_loop();
  bool events();                  // at an instruction boundary; true = stop
  void schedule();
  bool code_hooks(uint32_t address, uint32_t size);   // true = do not execute (stop / redirect)
  bool check_breakpoint(uint32_t address);
 public:
  bool code_hook_at(uint32_t address) const;   // a code hook or breakpoint covers this instruction
 private:
  void report_chunk(uint32_t phys);

 public:
  // ---- memory access from instructions (inline fast paths, slow paths in alicore.cpp) ----
  static ALI_INLINE uint32_t phys_of(uint32_t va) {
    return (va >= 0x80000000u && va < 0xC0000000u) ? (va & 0x1FFFFFFFu) : va;
  }
  template <typename T> ALI_INLINE T load(uint32_t va) {
    if (ALI_UNLIKELY(va & (sizeof(T) - 1))) fault_unaligned(va, MEM_READ);
    uint8_t *p = vr_[va >> 12];
    if (ALI_LIKELY(p != nullptr)) { T v; memcpy(&v, p + (va & 0xFFF), sizeof(T)); return v; }
    return (T)load_slow(va, sizeof(T));
  }
  template <typename T> ALI_INLINE void store(uint32_t va, T v) {
    if (ALI_UNLIKELY(va & (sizeof(T) - 1))) fault_unaligned(va, MEM_WRITE);
    stores_++;
    uint8_t *p = vw_[va >> 12];
    if (ALI_LIKELY(p != nullptr)) { memcpy(p + (va & 0xFFF), &v, sizeof(T)); return; }
    store_slow(va, sizeof(T), (uint64_t)v);
  }
  ALI_INLINE uint32_t fetch32(uint32_t va) {
    if (ALI_UNLIKELY((va >> 12) != fetch_page_)) fetch_page(va);
    uint32_t v; memcpy(&v, fetch_ptr_ + (va & 0xFFF), 4); return v;
  }
  ALI_INLINE uint16_t fetch16(uint32_t va) {
    if (ALI_UNLIKELY((va >> 12) != fetch_page_)) fetch_page(va);
    uint16_t v; memcpy(&v, fetch_ptr_ + (va & 0xFFF), 2); return v;
  }
  uint64_t load_slow(uint32_t va, uint32_t size);
  void store_slow(uint32_t va, uint32_t size, uint64_t value, bool plain_device = true);
  void fetch_page(uint32_t va);
  [[noreturn]] void fault_unaligned(uint32_t va, int access);
  [[noreturn]] void fault(int err, uint64_t addr, int access);
  [[noreturn]] void exception(int code);   // CPU exception: stop with ERR_EXCEPTION

  // CP0 / exceptions
  uint32_t cp0_read(int rd, int sel);
  void cp0_write(int rd, int sel, uint32_t v);
  void eret();
  bool fpu_usable() const { return (status & 0x20000000u) != 0; }

  // host-memory helpers for the device window
  uint64_t dev_load(uint32_t off, uint32_t size);
  void dev_store(uint32_t off, uint32_t size, uint64_t value, bool plain_device = false);

  // execution of one instruction (alicore_exec.cpp)
  void exec32(uint32_t insn);
  void exec16();
  void exec_cop1(uint32_t insn);
  void exec_cop1x(uint32_t insn);
  // the branch decided by the instruction executing now
  uint32_t npc_ = 0;        // the next PC when no branch is taken
  bool nm16_ = false;       // its ISA mode (MIPS16 compact jumps switch at once)
  bool br_taken_ = false;   // a branch with a delay slot was taken
  uint32_t br_target_ = 0;
  bool br_m16_ = false;
  uint32_t cur_pc_ = 0;     // address of the instruction executing now
  bool cur_ds_ = false;     // it is a delay slot
  uint32_t cur_branch_pc_ = 0;  // the branch whose delay slot it is

  // ---- the decoded-block cache (alicore_exec.cpp) ----
  // Straight-line code from a PC (in its ISA mode) up to and including a branch
  // and its delay slot (or a MIPS16 compact jump), at most BLOCK_MAX
  // instructions and never across a page, decoded once into micro-ops that
  // MIPS32 and MIPS16 code share.  A block keeps its raw bytes and is checked
  // against memory each time it is entered, so code that changes -- stores,
  // the host's writes, the other core of a dual-CPU chip -- is decoded again
  // without tracking writes.  Blocks run only when nothing can happen inside
  // them: no event before their end, no code hook or breakpoint on their page,
  // not in a delay slot; everything else (CP0, the FPU, ERET, idle loops)
  // ends a block and runs on the instruction-at-a-time path.
  enum { BLOCK_MAX = 32, BLOCK_TABLE = 1 << 15 };
  struct Uop {
    uint8_t op, d, s, t;
    uint32_t imm;
    uint32_t pc;
  };
  struct Block {
    uint32_t key;                 // pc | m16
    uint16_t n;                   // instructions (micro-ops)
    uint16_t bytes;               // code bytes they cover
    uint32_t end_pc;              // the PC after the block when it falls through
    bool loopy;                   // it ends in a branch / jump that can close a loop (not a call or return)
    // A loop of its own that only counts (a cache-maintenance loop: CACHE is a no-op
    // here): no-ops, induction steps (addiu r, r, c), at most one compare flag
    // (slt / sltu / slti / sltiu), then bne / beq back to its start.  How many more
    // passes it takes follows from the registers (Core::ff_passes).
    struct Ff {
      uint8_t mode = 0;           // 0: none, FF_NE: bne x, y; FF_FLAG: bne / beq flag, $0
      uint8_t x = 0, y = 0;       // the induction register compared, the other register
      uint8_t xoff = 0;           // 1 when x's step comes before the compare in a pass
      uint8_t flag = 0, cmp = 0;  // the flag register and its op (U_SLT ...)
      bool x_first = true;        // slt(x, y), else slt(y, x)
      bool want = true;           // the loop goes on while the flag is 1 (bne), 0 (beq)
      uint32_t y_imm = 0;         // slti / sltiu's immediate
      uint8_t nind = 0;
      uint8_t ind[8];             // induction registers ...
      uint32_t step[8];           // ... and their steps per pass
    } ff;
    uint8_t raw[BLOCK_MAX * 4];
    Uop ops[BLOCK_MAX];
  };
  enum { FF_NE = 1, FF_FLAG = 2 };
  uint64_t ff_skipped = 0;         // instructions such loops took, done at once
  uint64_t ff_passes(const Block *b) const;
  bool blocks_on = true;
  uint64_t block_runs = 0, block_builds = 0;
  enum { REC_MAX = 64 };
  Block *rec_[REC_MAX];            // the recorded pass of a Count-polling loop
  int rec_n_ = 0;
  bool rec_on_ = false, rec_over_ = false;
  // Count-polling loops seen before (a delay() called over and over): their pass
  // and the passes last skipped, so the next call skips from its first return
  // to the head (the replays still decide every skip)
  struct PollLoop {
    uint32_t key = 0xFFFFFFFFu;
    int n = 0;
    uint64_t last_k = 0, ign = 0;
    Block *seq[REC_MAX];
    uint32_t keys[REC_MAX];        // (their PCs: whether the table still holds them)
  };
  uint64_t pass_ignorable(bool &ok) const;
  enum { POLL_CACHE = 64 };
  PollLoop poll_cache_[POLL_CACHE];
  static uint32_t poll_slot(uint32_t key) { return (key * 0x9E3779B1u) >> 26; }
  uint64_t poll_skip(uint32_t head, uint64_t guess);
  bool poll_seq_valid(const PollLoop &pl);
  bool poll_probe(uint64_t k, uint32_t pass, uint32_t head);
  Block **btab_ = nullptr;
  Block *get_block(uint32_t pc, bool mode16);
  bool chunk_reported_ = false;    // the last get_block reported new code instead (the host may hook it)
  Block *build_block(uint32_t pc, bool mode16, uint8_t *page);
  // Blocks replaced or flushed are freed only between blocks (free_retired at the
  // loop's top): a host call inside a block (a device handler adding a hook)
  // may flush the table while that block still runs, and a recorded pass may
  // hold them (a retirement cancels it).
  std::vector<Block *> retired_;
  void retire(Block *b) {
    if (!b) return;
    retired_.push_back(b);
    rec_over_ = true;
    rec_n_ = 0;
  }
  void free_retired() {
    for (Block *b : retired_) delete b;
    retired_.clear();
  }
  void run_block(Block *b);        // one block
  void run_chain(Block *b);        // blocks one after the other, while nothing needs the loop
  template <bool CHAIN> void run_blocks(Block *b);
  void gen32_op(uint32_t insn, uint32_t pc);   // (a block's generic ops: out of line)
  void gen16_op(uint32_t pc);
  void flush_blocks();
};

}  // namespace ali
