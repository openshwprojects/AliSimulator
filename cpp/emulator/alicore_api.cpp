// AliSimulator C++ core: the C API (alicore.dll), used by src/cpp_core.py through ctypes.
#include "alicore.h"
#include "alicore_gfx.h"

#include <algorithm>

#ifdef _WIN32
#define ALI_API extern "C" __declspec(dllexport)
#else
#define ALI_API extern "C" __attribute__((visibility("default")))
#endif

using namespace ali;

// state fields (ali_get / ali_set)
enum Field : int {
  F_ICOUNT = 1, F_EXECUTED, F_STATUS, F_CAUSE, F_CAUSE_VALUE, F_EPC, F_EBASE, F_COMPARE, F_COUNT, F_TI,
  F_TIMER_ARMED, F_TIMER_ENABLED, F_TIMER_IRQS, F_IC_IRQS, F_UART_IRQS, F_IC_LINES, F_UART_IP3, F_UART_PENDING,
  F_UART_DELIVERED, F_UART_AT, F_UART_FORCE, F_IDLE_SKIP, F_EXACT, F_IRQS_ENABLED, F_M16, F_DS_ACTIVE,
  F_IDLE_SKIPPED, F_CNUM, F_CDEN, F_FAULT_PC, F_FAULT_ADDR, F_FAULT_ACCESS, F_STEP_OVER_BP, F_IRQ_DELIVERABLE,
  F_IC_IP3, F_TIMER_ANCHOR, F_LAST_ERROR, F_STOP_REASON, F_ERROR_EPC, F_COMPARE_WRITE, F_PC_MODE,
  F_COUNT_OBSERVED, F_COUNT_OBSERVED_VALID, F_CHUNK_EVENTS, F_DS_TARGET, F_DS_M16, F_BADVADDR, F_LLBIT,
  F_TIMER_CHECK_AT, F_COUNT_RAW_WRITE, F_HOST_ACCESS_COST, F_BLOCKS_ON, F_BLOCK_RUNS, F_BLOCK_BUILDS,
  F_NEXT_EVENT, F_LIMIT, F_SPIN_SKIPPED, F_SPIN_SKIP, F_POLL_SKIPPED, F_POLL_SKIPS, F_FF_SKIPPED, F_IC_LINES_HI,
  F_GPIO_DI_BUSY, F_GE_STATUS, F_GE_OPS, F_GE_RENDER, F_GE_PRIMS, F_GE_RESUME,
  F_DEMOD_LOCKED, F_DEMOD_READS, F_GE_IC_LINE, F_GE_M3602_CMDS,
};

ALI_API void *ali_new() { return new Core(); }
ALI_API void ali_free(void *c) { delete (Core *)c; }

ALI_API int ali_map_ptr(void *c, uint64_t base, uint64_t size, uint32_t perms, void *ptr) {
  return ((Core *)c)->map_ptr(base, size, perms, ptr);
}
ALI_API int ali_map_alloc(void *c, uint64_t base, uint64_t size, uint32_t perms) {
  return ((Core *)c)->map_alloc(base, size, perms);
}
ALI_API int ali_map_mmio(void *c, uint64_t base, uint64_t size, void *rd, void *rd_user, void *wr, void *wr_user) {
  return ((Core *)c)->map_mmio(base, size, (MmioReadCb)rd, rd_user, (MmioWriteCb)wr, wr_user);
}
ALI_API int ali_unmap(void *c, uint64_t base, uint64_t size) { return ((Core *)c)->unmap(base, size); }
ALI_API int ali_protect(void *c, uint64_t base, uint64_t size, uint32_t perms) {
  return ((Core *)c)->protect(base, size, perms);
}
ALI_API int ali_mem_read(void *c, uint64_t addr, void *buf, uint64_t size) {
  return ((Core *)c)->host_read(addr, buf, size);
}
ALI_API int ali_mem_write(void *c, uint64_t addr, const void *buf, uint64_t size) {
  return ((Core *)c)->host_write(addr, buf, size);
}
// The host memory of the plain region at addr (what a host read of it returns),
// with its base and size; null for mmio regions, the device window, nothing mapped.
ALI_API uint8_t *ali_direct(void *c, uint64_t addr, uint64_t *base, uint64_t *size) {
  return ((Core *)c)->direct(addr, base, size);
}
// the mapped regions as (begin, end inclusive, perms) triples; returns their number
ALI_API int ali_regions(void *c, uint64_t *out, int max) {
  std::vector<Region> rs;
  ((Core *)c)->regions(rs);
  std::sort(rs.begin(), rs.end(), [](const Region &a, const Region &b) { return a.base < b.base; });
  int n = 0;
  for (auto &r : rs) {
    if (n < max) {
      out[3 * n] = r.base;
      out[3 * n + 1] = r.base + r.size - 1;
      out[3 * n + 2] = r.perms;
    }
    n++;
  }
  return n;
}
ALI_API int ali_reg_read(void *c, int id, uint64_t *value) { return ((Core *)c)->reg_read(id, value); }
ALI_API int ali_reg_write(void *c, int id, uint64_t value) { return ((Core *)c)->reg_write(id, value); }
// several GPR / PC reads at once (ids), values into out
ALI_API int ali_reg_read_batch(void *c, const int *ids, uint64_t *out, int n) {
  for (int i = 0; i < n; i++) ((Core *)c)->reg_read(ids[i], &out[i]);
  return 0;
}
ALI_API int ali_hook_add(void *c, int type, void *cb, void *user, uint64_t begin, uint64_t end, uint64_t *id) {
  return ((Core *)c)->hook_add(type, cb, user, begin, end, id);
}
ALI_API int ali_hook_del(void *c, uint64_t id) { return ((Core *)c)->hook_del(id); }
ALI_API int ali_emu_start(void *c, uint64_t begin, uint64_t until, uint64_t timeout_us, uint64_t count) {
  return ((Core *)c)->emu_start(begin, until, timeout_us, count);
}
ALI_API void ali_emu_stop(void *c) { ((Core *)c)->emu_stop(); }
ALI_API int ali_run(void *c, uint64_t icount_limit) { return ((Core *)c)->run(icount_limit); }
ALI_API int ali_step_one(void *c) { return ((Core *)c)->step_one(); }

// Profile: on != 0 starts it (cleared), 0 stops it (dropped).
ALI_API void ali_prof(void *c, int on) {
  Core *k = (Core *)c;
  delete k->prof_insns_;
  delete k->prof_dev_;
  k->prof_insns_ = on ? new std::unordered_map<uint32_t, uint64_t>() : nullptr;
  k->prof_dev_ = on ? new std::unordered_map<uint32_t, uint64_t>() : nullptr;
}

// The profile's entries, largest first: which 0 = instructions (per block
// start or lone instruction), 1 = Python device accesses (per instruction).
ALI_API int ali_prof_top(void *c, int which, uint32_t *keys, uint64_t *counts, int max) {
  Core *k = (Core *)c;
  auto *m = which ? k->prof_dev_ : k->prof_insns_;
  if (!m) return 0;
  std::vector<std::pair<uint64_t, uint32_t>> v;
  v.reserve(m->size());
  for (auto &e : *m) v.push_back({e.second, e.first});
  std::sort(v.begin(), v.end(), [](auto &a, auto &b) { return a.first > b.first; });
  int n = (int)std::min<size_t>(v.size(), (size_t)max);
  for (int i = 0; i < n; i++) { keys[i] = v[i].second; counts[i] = v[i].first; }
  return n;
}

ALI_API void ali_set_device_window(void *c, uint32_t phys, void *buf, uint32_t size, void *cb, void *user) {
  ((Core *)c)->set_device_window(phys, (uint8_t *)buf, size, (DevCb)cb, user);
}
ALI_API void ali_set_dev_flags(void *c, uint32_t offset, uint32_t count, uint8_t flags) {
  ((Core *)c)->set_dev_flags(offset, count, flags);
}
// flags for a list of offsets (each gets flags[i])
ALI_API void ali_set_dev_flags_list(void *c, const uint32_t *offsets, const uint8_t *flags, int n) {
  for (int i = 0; i < n; i++) ((Core *)c)->set_dev_flags(offsets[i], 1, flags[i]);
}
ALI_API void ali_set_mmio_rules(void *c, const void *rules, uint32_t n_rules, const uint32_t *offsets,
                                const uint8_t *rflags, uint32_t n_offs) {
  ((Core *)c)->set_mmio_rules((const Core::MmioRule *)rules, n_rules, offsets, rflags, n_offs);
}
ALI_API void ali_set_event_cb(void *c, void *cb, void *user) {
  ((Core *)c)->event_cb = (EventCb)cb;
  ((Core *)c)->event_user = user;
}
ALI_API void ali_set_breakpoints(void *c, const uint32_t *addrs, int n) {
  Core *k = (Core *)c;
  k->breakpoints.assign(addrs, addrs + n);
  uint64_t dummy;
  k->hook_add(0, nullptr, nullptr, 1, 0, &dummy);   // (rebuilds the hook pages)
  k->hook_del(dummy);
}
ALI_API void ali_set_gpio_cb(void *c, void *cb, void *user) {
  Core *k = (Core *)c;
  k->host_sync();
  k->gpio_cb_ = (GpioCb)cb;
  k->gpio_user_ = user;
}
// The callback that receives the UART transmit bytes of DR_UART_TX stores, in bulk
// (cb = null drops them; the host then flags no offset DR_UART_TX).
ALI_API void ali_uart_tx_callback(void *c, void *cb, void *user) {
  Core *k = (Core *)c;
  k->host_sync();
  k->utx_cb_ = (UartTxCb)cb;
  k->utx_user_ = user;
}
// The GPIO log for a device handler that empties it itself (drains != 0): its
// count (the host sets it to 0 once handled) and its (offset, levels) pairs.
ALI_API void ali_gpio_log(void *c, int drains, uint32_t **count, uint32_t **pairs) {
  Core *k = (Core *)c;
  k->host_sync();
  k->gpio_dev_drains_ = drains != 0;
  *count = &k->gpio_n_;
  *pairs = k->gpio_log_;
}
// The GPIO stores the host's decoders want logged: on = 0 every store that changes
// a bank's levels (as before); on = 1 only those changing a watched pin (n
// (DO register offset, pin mask) pairs; a bank nobody watches is not logged).
ALI_API void ali_gpio_watch(void *c, int on, const uint32_t *offsets, const uint32_t *masks, int n) {
  Core *k = (Core *)c;
  k->host_sync();
  k->gpio_filter_ = on != 0;
  memset(k->gpio_watch_, 0, sizeof(k->gpio_watch_));
  memset(k->gpio_last_ok_, 0, sizeof(k->gpio_last_ok_));
  for (int i = 0; i < n; i++)
    if ((offsets[i] >> 2) < Core::GPIO_BANKS) k->gpio_watch_[offsets[i] >> 2] |= masks[i];
}
ALI_API void ali_gpio_di_config(void *c, const uint32_t *offsets, const uint32_t *masks, int n) {
  Core *k = (Core *)c;
  memset(k->gpio_di_high_, 0, sizeof(k->gpio_di_high_));
  for (int i = 0; i < n; i++)
    if ((offsets[i] >> 2) < Core::GPIO_BANKS) k->gpio_di_high_[offsets[i] >> 2] |= masks[i];
}
ALI_API void ali_ge_config(void *c, void *ram, uint32_t ram_size) {
  Core *k = (Core *)c;
  k->ge_.ram = (uint8_t *)ram;
  k->ge_.ram_size = ram_size;
  k->ge_.phys_mask = (ram_size && !(ram_size & (ram_size - 1u))) ? (ram_size - 1u) : 0x07FFFFFFu;
  memset(k->ge_.regs, 0, sizeof(k->ge_.regs));
  k->ge_.resume_valid = false;
  k->ge_.resume_idx = 0;
}
ALI_API void ali_ge_regs(void *c, int write, uint32_t *regs64) {
  Core *k = (Core *)c;
  if (write) memcpy(k->ge_.regs, regs64, sizeof(k->ge_.regs));
  else memcpy(regs64, k->ge_.regs, sizeof(k->ge_.regs));
}
ALI_API void ali_set_peer_core(void *c, void *peer) {
  Core *k = (Core *)c;
  Core *p = (Core *)peer;
  k->peer_core_ = p;
  if (p) p->peer_core_ = k;
}
// The bit-banged I2C bus in the core (on = 0: none): SCL / SDA as DO register
// offsets in the device window and bit numbers, the host's slave callback (I2cCb).
ALI_API void ali_gpio_i2c_config(void *c, int on, uint32_t scl_off, uint32_t scl_bit, uint32_t sda_off,
                                 uint32_t sda_bit, void *cb, void *user) {
  Core *k = (Core *)c;
  k->gi2c_config(on != 0, scl_off, scl_bit, sda_off, sda_bit);
  k->i2c_cb_ = (I2cCb)cb;
  k->i2c_user_ = user;
}
// The bus's state: 0 the level the slave drives on SDA (-1: released), 1 state
// (IDLE, ADDR, WRITE, READ, IGNORE), 2 phase (bits, ack, mack), 3 SCL rising edges
// in the byte, 4 level changes followed, 5 / 6 the CPU's SCL / SDA levels
ALI_API int64_t ali_gpio_i2c_get(void *c, int field) {
  Core *k = (Core *)c;
  const Core::GpioI2c &g = k->gi2c_;
  switch (field) {
    case 0: return k->gi2c_sda_out();
    case 1: return g.state;
    case 2: return g.phase;
    case 3: return g.nbits;
    case 4: return (int64_t)g.edges;
    case 5: return g.scl;
    case 6: return g.sda;
  }
  return 0;
}
ALI_API void ali_tm1650_config(void *c, int on, uint32_t scl_off, uint32_t scl_bit, uint32_t sda_off,
                               uint32_t sda_bit, int cb_all, void *cb, void *user) {
  Core *k = (Core *)c;
  k->tm1650_config(on != 0, scl_off, scl_bit, sda_off, sda_bit, cb_all != 0);
  k->tm1650_cb_ = (I2cCb)cb;
  k->tm1650_user_ = user;
}
ALI_API void ali_tm1650_set_key(void *c, uint32_t key_byte, uint32_t hold_reads) {
  Core *k = (Core *)c;
  k->tm1650_.key_byte = (uint8_t)(key_byte & 0xFFu);
  k->tm1650_.key_hold = hold_reads;
}
ALI_API int64_t ali_tm1650_get(void *c, int field) {
  Core *k = (Core *)c;
  Core::Tm1650 &t = k->tm1650_;
  switch (field) {
    case 0: return k->tm1650_sda_in();
    case 1: return t.state;
    case 2: return t.nbits;
    case 3: return (int64_t)t.events;
    case 4: return (int64_t)t.tx_count;
    case 5: return t.scl;
    case 6: return t.sda;
    case 7: return (int64_t)t.key_read_count;
    case 8: return t.key_byte;
    case 9: return t.key_hold;
    case 10: return (int64_t)t.key_reads_answered;
    case 11: case 12: case 13: case 14: return t.digits[field - 11];
  }
  return 0;
}
ALI_API void ali_tm1628_config(void *c, int on, uint32_t clk_off, uint32_t clk_bit, uint32_t dio_off,
                               uint32_t dio_bit, uint32_t stb_off, uint32_t stb_bit, int cb_all,
                               void *cb, void *user) {
  Core *k = (Core *)c;
  k->tm1628_config(on != 0, clk_off, clk_bit, dio_off, dio_bit, stb_off, stb_bit, cb_all != 0);
  k->tm1628_cb_ = (I2cCb)cb;
  k->tm1628_user_ = user;
}
ALI_API void ali_tm1628_set_key(void *c, const uint8_t *key_bytes, uint32_t hold_reads) {
  Core *k = (Core *)c;
  if (key_bytes) memcpy(k->tm1628_.key_bytes, key_bytes, 5);
  else memset(k->tm1628_.key_bytes, 0, 5);
  k->tm1628_.key_hold = hold_reads;
}
ALI_API int64_t ali_tm1628_get(void *c, int field) {
  Core *k = (Core *)c;
  Core::Tm1628 &t = k->tm1628_;
  switch (field) {
    case 0: return k->tm1628_dio_in();
    case 1: return t.in_frame ? 1 : 0;
    case 2: return t.key_read ? 1 : 0;
    case 3: return (int64_t)t.events;
    case 4: return (int64_t)t.frame_count;
    case 5: return t.prev_clk;
    case 6: return t.prev_stb;
    case 7: return (int64_t)t.key_read_count;
    case 8: return (int64_t)t.key_reads_answered;
    case 9: return t.key_hold;
    case 10: return t.address;
  }
  return 0;
}
ALI_API void ali_hc164_config(void *c, int on, uint32_t clk_off, uint32_t clk_bit,
                              uint32_t data_off, uint32_t data_bit,
                              const uint32_t *dig_offs, const uint32_t *dig_bits, uint32_t n_digits,
                              int active_low_segs, int active_low_digs, I2cCb cb, void *user) {
  Core *k = (Core *)c;
  k->hc164_cb_ = cb;
  k->hc164_user_ = user;
  k->hc164_config(on != 0, clk_off, clk_bit, data_off, data_bit, dig_offs, dig_bits, n_digits,
                  active_low_segs != 0, active_low_digs != 0);
}
ALI_API int64_t ali_hc164_get(void *c, int field) {
  Core *k = (Core *)c;
  Core::Hc164 &h = k->hc164_;
  switch (field) {
    case 0: return (int64_t)h.events;
    case 1: return (int64_t)h.frame_count;
    case 2: return h.sr;
    case 3: return h.clk;
    case 4: return h.data;
    default:
      if (field >= 10 && field < 18) return h.raw[field - 10];
      break;
  }
  return 0;
}
ALI_API void ali_lemontree_config(void *c, int on, uint32_t scl_off, uint32_t scl_bit,
                                  uint32_t sda_off, uint32_t sda_bit, int cb_all, I2cCb cb, void *user) {
  Core *k = (Core *)c;
  k->lemontree_cb_ = cb;
  k->lemontree_user_ = user;
  k->lemontree_config(on != 0, scl_off, scl_bit, sda_off, sda_bit, cb_all != 0);
}
ALI_API void ali_lemontree_set_key(void *c, uint32_t key_byte, uint32_t hold_reads) {
  Core *k = (Core *)c;
  k->lemontree_.key_byte = (uint8_t)key_byte;
  k->lemontree_.key_hold = hold_reads;
}
ALI_API int64_t ali_lemontree_get(void *c, int field) {
  Core *k = (Core *)c;
  Core::Lemontree &lt = k->lemontree_;
  switch (field) {
    case 0: return k->lemontree_sda_out();
    case 1: return lt.state;
    case 2: return lt.phase;
    case 3: return (int64_t)lt.events;
    case 4: return (int64_t)lt.frame_count;
    case 5: return (int64_t)lt.tx_count;
    case 6: return (int64_t)lt.key_read_count;
    case 7: return (int64_t)lt.key_reads_answered;
    case 8: return lt.key_hold;
    case 9: return lt.scl;
    case 10: return lt.sda;
  }
  return 0;
}
ALI_API void ali_set_chunks(void *c, int shift, uint32_t count) {
  Core *k = (Core *)c;
  k->chunk_shift = (uint32_t)shift;
  k->chunk_seen.assign(count, 0);
  k->chunk_events = count > 0;
  k->flush_blocks();
}
ALI_API void ali_chunk_mark(void *c, uint32_t index, int seen) {
  Core *k = (Core *)c;
  if (index < k->chunk_seen.size()) {
    if (!seen && k->chunk_seen[index]) k->flush_blocks();
    k->chunk_seen[index] = (uint8_t)seen;
  }
}
ALI_API void ali_set_flash_cmd(void *c, int on, const uint32_t *windows, int n) {
  ((Core *)c)->set_flash_cmd(on != 0, windows, n);
}
ALI_API void ali_set_count_ratio(void *c, uint64_t num, uint64_t den) { ((Core *)c)->set_count_ratio(num, den); }
ALI_API void ali_set_ic(void *c, uint32_t status_off, uint32_t enable_off, uint32_t ic_base) {
  ((Core *)c)->set_ic(status_off, enable_off, ic_base);
}
ALI_API void ali_set_doorbell(void *c, int32_t offset, int32_t shift) { ((Core *)c)->set_doorbell(offset, shift); }
ALI_API void ali_uart_arm(void *c, uint64_t at_icount, int force) { ((Core *)c)->uart_arm(at_icount, force != 0); }
ALI_API uint32_t ali_enter_interrupt(void *c, uint32_t epc) { return ((Core *)c)->enter_interrupt(epc); }
ALI_API void ali_timer_update(void *c) { ((Core *)c)->timer_update(); }
// Count ticks until the timer interrupt is due, after a timer update: -1 none
// due (timer off, no Compare written, interrupts masked), -2 one is pending and
// deliverable now (the host's _timer_wait_us in one call instead of seven)
ALI_API int64_t ali_timer_wait(void *c) {
  Core *k = (Core *)c;
  if (!(k->timer_enabled && k->timer_armed)) return -1;
  k->timer_update();
  uint32_t s = k->status;
  if (!(s & 0x8000) || (s & 0x4)) return -1;
  if (k->ti) return k->irq_deliverable() ? -2 : -1;
  return (int64_t)(uint32_t)(k->compare - k->count_now());
}
ALI_API void ali_poke(void *c) { ((Core *)c)->poke_events(); }
ALI_API uint32_t ali_cp0_read(void *c, int rd, int sel) { return ((Core *)c)->cp0_read(rd, sel); }
ALI_API void ali_cp0_write(void *c, int rd, int sel, uint32_t v) { ((Core *)c)->cp0_write(rd, sel, v); }
// a guest-view load / store of the running core (with device side effects): for tools
ALI_API int ali_guest_read32(void *c, uint32_t va, uint32_t *out) {
  try {
    *out = ((Core *)c)->load<uint32_t>(va);
    return 0;
  } catch (Fault &f) {
    return f.err;
  }
}
// the raw RAM of the guest's fast table for a virtual page (null if not plain memory)
ALI_API const char *ali_last_message(void *c) { return ((Core *)c)->last_message.c_str(); }

// the native SPI flash controller
ALI_API void ali_spi_config(void *c, int on, void *rom, void *image, uint32_t rom_size, uint32_t jedec) {
  Core *k = (Core *)c;
  k->spi.jedec[0] = (uint8_t)(jedec >> 16);
  k->spi.jedec[1] = (uint8_t)(jedec >> 8);
  k->spi.jedec[2] = (uint8_t)jedec;
  k->spi_config(on != 0, (uint8_t *)rom, (uint8_t *)image, rom_size);
}
enum SpiField : int { S_INS = 1, S_FMT, S_DUM, S_CFG, S_STATUS, S_WEL, S_RESP_LEN, S_RESP_IDX, S_ON, S_COMMANDS,
                      S_RESP0, S_RESP1, S_RESP2, S_RESP3, S_PROGRAMS, S_ERASES };
ALI_API uint64_t ali_spi_get(void *c, int f) {
  Core::Spi &s = ((Core *)c)->spi;
  switch (f) {
    case S_INS: return s.ins; case S_FMT: return s.fmt; case S_DUM: return s.dum; case S_CFG: return s.cfg;
    case S_STATUS: return s.status; case S_WEL: return s.wel; case S_RESP_LEN: return (uint64_t)s.resp_len;
    case S_RESP_IDX: return (uint64_t)s.resp_idx; case S_ON: return s.on; case S_COMMANDS: return s.commands;
    case S_RESP0: case S_RESP1: case S_RESP2: case S_RESP3: return s.resp[f - S_RESP0];
    case S_PROGRAMS: return s.programs; case S_ERASES: return s.erases;
  }
  return 0;
}
ALI_API void ali_spi_set(void *c, int f, uint64_t v) {
  Core::Spi &s = ((Core *)c)->spi;
  switch (f) {
    case S_INS: s.ins = (uint8_t)v; break; case S_FMT: s.fmt = (uint8_t)v; break;
    case S_DUM: s.dum = (uint8_t)v; break; case S_CFG: s.cfg = (uint8_t)v; break;
    case S_STATUS: s.status = (uint8_t)v; break; case S_WEL: s.wel = v != 0; break;
    case S_RESP_LEN: s.resp_len = (int)v; break; case S_RESP_IDX: s.resp_idx = (int)v; break;
    case S_RESP0: case S_RESP1: case S_RESP2: case S_RESP3: s.resp[f - S_RESP0] = (uint8_t)v; break;
  }
}

ALI_API uint64_t ali_get(void *c, int field) {
  Core *k = (Core *)c;
  switch (field) {
    case F_ICOUNT: return k->icount;
    case F_EXECUTED: return k->executed;
    case F_STATUS: return k->status;
    case F_CAUSE: return k->cause;
    case F_CAUSE_VALUE: return k->cause_value();
    case F_EPC: return k->epc;
    case F_EBASE: return k->ebase;
    case F_COMPARE: return k->compare;
    case F_COUNT: return k->count_now();
    case F_TI: return k->ti;
    case F_TIMER_ARMED: return k->timer_armed;
    case F_TIMER_ENABLED: return k->timer_enabled;
    case F_TIMER_IRQS: return k->timer_irqs;
    case F_IC_IRQS: return k->ic_irqs;
    case F_UART_IRQS: return k->uart_irqs;
    case F_IC_LINES: return k->ic_lines_;
    case F_IC_LINES_HI: return k->ic_lines_hi_;
    case F_UART_IP3: return k->uart_ip3;
    case F_UART_PENDING: return k->uart_pending_;
    case F_UART_DELIVERED: return k->uart_delivered_;
    case F_UART_AT: return k->uart_at_;
    case F_UART_FORCE: return k->uart_force_;
    case F_IDLE_SKIP: return k->idle_skip;
    case F_EXACT: return k->exact_mode;
    case F_IRQS_ENABLED: return k->irqs_enabled;
    case F_M16: return k->m16;
    case F_DS_ACTIVE: return k->ds_active;
    case F_IDLE_SKIPPED: return k->idle_skipped;
    case F_CNUM: return k->cnum;
    case F_CDEN: return k->cden;
    case F_FAULT_PC: return k->fault_pc;
    case F_FAULT_ADDR: return k->fault_addr;
    case F_FAULT_ACCESS: return (uint64_t)k->fault_access;
    case F_STEP_OVER_BP: return k->step_over_bp_once;
    case F_IRQ_DELIVERABLE: return k->irq_deliverable();
    case F_IC_IP3: return k->ic_ip3();
    case F_TIMER_ANCHOR: return k->timer_anchor;
    case F_LAST_ERROR: return (uint64_t)k->last_error();
    case F_STOP_REASON: return (uint64_t)k->stop_reason();
    case F_ERROR_EPC: return k->error_epc;
    case F_PC_MODE: return k->pc | (k->m16 ? 1u : 0u);
    case F_COUNT_OBSERVED: return k->count_observed;
    case F_COUNT_OBSERVED_VALID: return k->count_observed_valid;
    case F_CHUNK_EVENTS: return k->chunk_events;
    case F_DS_TARGET: return k->ds_target;
    case F_DS_M16: return k->ds_m16;
    case F_BADVADDR: return k->badvaddr;
    case F_LLBIT: return k->llbit;
    case F_TIMER_CHECK_AT: return k->timer_check_at;
    case F_HOST_ACCESS_COST: return k->host_access_cost;
    case F_BLOCKS_ON: return k->blocks_on;
    case F_BLOCK_RUNS: return k->block_runs;
    case F_BLOCK_BUILDS: return k->block_builds;
    case F_NEXT_EVENT: return k->next_event();
    case F_LIMIT: return k->limit();
    case F_SPIN_SKIPPED: return k->spin_skipped;
    case F_SPIN_SKIP: return k->spin_skip;
    case F_POLL_SKIPPED: return k->poll_skipped;
    case F_POLL_SKIPS: return k->poll_skips;
    case F_FF_SKIPPED: return k->ff_skipped;
    case F_GPIO_DI_BUSY: return k->gpio_di_busy_;
    case F_GE_STATUS: return k->ge_.status;
    case F_GE_OPS: return k->ge_.ops;
    case F_GE_RENDER: return k->ge_.render;
    case F_GE_PRIMS: return k->ge_.primitives;
    case F_GE_RESUME: return k->ge_.resume_valid ? (uint64_t)k->ge_.resume_idx : ~0ull;
    case F_DEMOD_LOCKED: return k->demod_locked_;
    case F_DEMOD_READS: return k->demod_reads_;
    case F_GE_IC_LINE: return k->ge_.ic_line;
    case F_GE_M3602_CMDS: return k->ge_.m3602_cmds;
    case 100: case 101: case 102: case 103: case 104: case 105: return k->spin_dbg[field - 100];
  }
  return 0;
}

ALI_API void ali_set(void *c, int field, uint64_t v) {
  Core *k = (Core *)c;
  uint32_t w = (uint32_t)v;
  switch (field) {
    case F_ICOUNT: k->icount = v; break;
    case F_EXECUTED: k->executed = v; break;
    case F_STATUS: k->status = w; break;
    case F_CAUSE: k->cause = w; break;
    case F_EPC: k->epc = w; break;
    case F_EBASE: k->ebase = w; break;
    case F_COMPARE: k->compare = w; break;
    case F_COUNT: k->write_count(w); break;
    case F_COUNT_RAW_WRITE: k->count_base = w; k->count_icount = k->icount; break;
    case F_TI: k->ti = v != 0; break;
    case F_TIMER_ARMED: k->timer_armed = v != 0; break;
    case F_TIMER_ENABLED: k->set_timer_enabled(v != 0); break;
    case F_TIMER_IRQS: k->timer_irqs = v; break;
    case F_IC_IRQS: k->ic_irqs = v; break;
    case F_UART_IRQS: k->uart_irqs = v; break;
    case F_IC_LINES: k->ic_lines_ = v; break;
    case F_IC_LINES_HI: k->ic_lines_hi_ = v; break;
    case F_UART_IP3: k->uart_ip3 = v != 0; break;
    case F_UART_PENDING: k->uart_pending_ = v != 0; break;
    case F_UART_DELIVERED: k->uart_delivered_ = v != 0; break;
    case F_UART_AT: k->uart_at_ = v; break;
    case F_UART_FORCE: k->uart_force_ = v != 0; break;
    case F_IDLE_SKIP: k->idle_skip = v != 0; break;
    case F_EXACT: k->exact_mode = v != 0; break;
    case F_IRQS_ENABLED: k->irqs_enabled = v != 0; break;
    case F_M16: k->m16 = v != 0; break;
    case F_DS_ACTIVE: k->ds_active = v != 0; break;
    case F_IDLE_SKIPPED: k->idle_skipped = v; break;
    case F_STEP_OVER_BP: k->step_over_bp_once = v != 0; break;
    case F_TIMER_ANCHOR: k->timer_anchor = w; break;
    case F_ERROR_EPC: k->error_epc = w; break;
    case F_COMPARE_WRITE: k->write_compare(w); break;
    case F_PC_MODE: k->pc = w & ~1u; k->m16 = w & 1; k->ds_active = false; break;
    case F_COUNT_OBSERVED: k->count_observed = w; break;
    case F_COUNT_OBSERVED_VALID: k->count_observed_valid = v != 0; break;
    case F_CHUNK_EVENTS: k->chunk_events = v != 0; if (v) k->flush_blocks(); break;
    case F_DS_TARGET: k->ds_target = w; break;
    case F_DS_M16: k->ds_m16 = v != 0; break;
    case F_BADVADDR: k->badvaddr = w; break;
    case F_TIMER_CHECK_AT: k->timer_check_at = v; break;
    case F_HOST_ACCESS_COST: k->host_access_cost = (uint32_t)v; break;
    case F_BLOCKS_ON: k->blocks_on = v != 0; break;
    case F_SPIN_SKIP: k->spin_skip = v != 0; break;
    case F_SPIN_SKIPPED: k->spin_skipped = v; break;
    case F_GPIO_DI_BUSY: k->gpio_di_busy_ = v != 0; break;
    case F_GE_STATUS: k->ge_.status = w; break;
    case F_GE_OPS: k->ge_.ops = v; break;
    case F_GE_RENDER: k->ge_.render = v != 0; break;
    case F_GE_PRIMS: k->ge_.primitives = v; break;
    case F_GE_RESUME: k->ge_.resume_valid = (v != ~0ull); k->ge_.resume_idx = w; break;
    case F_DEMOD_LOCKED: k->demod_locked_ = v != 0; break;
    case F_DEMOD_READS: k->demod_reads_ = v; break;
    case F_GE_IC_LINE: k->ge_.ic_line = w; break;
    case F_GE_M3602_CMDS: k->ge_.m3602_cmds = v; break;
  }
  k->poke_events();
}

ALI_API void ali_scb_config(void *c, int idx, int ic_line, int reset) {
  Core *k = (Core *)c;
  if (idx < 0 || idx >= 4) return;
  if (reset) k->scb_[idx].reset();
  k->scb_[idx].ic_line = (ic_line < 0) ? 0xFFu : (uint8_t)ic_line;
}

ALI_API uint32_t ali_scb_pull_tx(void *c, int idx, uint8_t *meta8, uint8_t *tx_out) {
  Core *k = (Core *)c;
  if (idx < 0 || idx >= 4) return 0;
  Core::ScbI2c &s = k->scb_[idx];
  meta8[0] = s.slave;
  meta8[1] = s.length;
  meta8[2] = s.length_hi;
  meta8[3] = s.sub[0];
  meta8[4] = s.sub[1];
  meta8[5] = s.sub[2];
  meta8[6] = s.sub[3];
  meta8[7] = s.sub_extra;
  uint32_t n = s.tx_len;
  if (n && tx_out) memcpy(tx_out, s.tx, n);
  s.tx_len = 0;
  return n;
}

ALI_API void ali_scb_push_rx(void *c, int idx, const uint8_t *rx_in, uint32_t rx_len, uint8_t flags, uint8_t isr1) {
  Core *k = (Core *)c;
  if (idx < 0 || idx >= 4) return;
  Core::ScbI2c &s = k->scb_[idx];
  for (uint32_t i = 0; i < rx_len; i++) {
    if ((uint16_t)(s.rx_tail - s.rx_head) < 256u) {
      s.rx[s.rx_tail++ & 0xFFu] = rx_in[i];
    }
  }
  s.flags = flags;
  s.isr1 = isr1;
  k->scb_sync_irq(idx);
}

ALI_API void ali_osd_pal(void *c, uint32_t *out512) {
  Core *k = (Core *)c;
  if (out512) memcpy(out512, k->osd_pal_, 512 * sizeof(uint32_t));
  else memset(k->osd_pal_, 0, sizeof(k->osd_pal_));
}

// Single-pass code scanner for LzmaDecode() (kind 1), RTOS delay() (kind 2),
// and dual-CPU mailbox poll loops (kind 3).
ALI_API uint32_t ali_scan_code(const void *buf, uint32_t len, uint32_t *out_offs,
                               uint8_t *out_kinds, uint32_t max_out, uint32_t mask) {
  if (!buf || len < 20) return 0;
  const uint8_t *b = (const uint8_t *)buf;
  const uint32_t *words = (const uint32_t *)buf;
  uint32_t n_words = len >> 2;
  uint32_t count = 0;
  static const uint8_t M16_LZMA[12] = {
    0xF3, 0x63, 0x18, 0x62, 0x17, 0xD1, 0x16, 0xD0, 0x1C, 0xD6, 0xED, 0xE6
  };
  static const uint8_t M16_LZMA_9[12] = {
    0x60, 0x9D, 0x1C, 0xF0, 0xF4, 0x64, 0x00, 0x6C, 0x22, 0xD3, 0x60, 0x9F
  };
  static const uint8_t M16_LZMA_9B[12] = {
    0x1C, 0xF0, 0xF4, 0x64, 0x27, 0x67, 0x40, 0x9F, 0x22, 0xD2, 0x60, 0x9D
  };
  static const uint8_t M16_LZO1X[12] = {
    0x0E, 0xF0, 0xB1, 0x64, 0x26, 0x67, 0xA1, 0xE4, 0x40, 0x9F, 0x49, 0xE6
  };
  static const uint8_t M16_LZMA_TOBUF[12] = {
    0x0E, 0xF0, 0xF7, 0x64, 0x40, 0x9E, 0x07, 0xD2, 0x12, 0x93, 0x60, 0x9B
  };
  auto emit = [&](uint32_t off, uint8_t kind) {
    if (count < max_out) {
      out_offs[count] = off;
      out_kinds[count] = kind;
    }
    count++;
  };
  for (uint32_t i = 0; i + 4 < n_words; i++) {
    uint32_t w0 = words[i];
    if (mask & 1u) {
      if ((w0 == 0x27BDFF78u && words[i + 1] == 0xAFBF0084u) ||
          (w0 == 0x27BDFF98u && words[i + 1] == 0xAFBF0064u) ||
          (w0 == 0x27BDFF50u && (words[i + 1] == 0xAFBF00A8u || words[i + 1] == 0xAFBF00ACu))) {
        if ((i << 2) + 108u <= len) emit(i << 2, 1);
      }
      if ((w0 & 0xFFFFu) == 0x63F3u && (i << 2) + 108u <= len &&
          memcmp(b + (i << 2), M16_LZMA, 12) == 0) {
        emit(i << 2, 1);
      }
      if ((w0 >> 16) == 0x63F3u && (i << 2) + 110u <= len &&
          memcmp(b + (i << 2) + 2, M16_LZMA, 12) == 0) {
        emit((i << 2) + 2, 1);
      }
      if ((w0 & 0xFFFFu) == 0x9D60u && (i << 2) + 44u <= len &&
          memcmp(b + (i << 2), M16_LZMA_9, 12) == 0) {
        emit(i << 2, 1);
      }
      if ((w0 >> 16) == 0x9D60u && (i << 2) + 46u <= len &&
          memcmp(b + (i << 2) + 2, M16_LZMA_9, 12) == 0) {
        emit((i << 2) + 2, 1);
      }
      if ((w0 & 0xFFFFu) == 0xF01Cu && (i << 2) + 44u <= len &&
          memcmp(b + (i << 2), M16_LZMA_9B, 12) == 0) {
        emit(i << 2, 1);
      }
      if ((w0 >> 16) == 0xF01Cu && (i << 2) + 46u <= len &&
          memcmp(b + (i << 2) + 2, M16_LZMA_9B, 12) == 0) {
        emit((i << 2) + 2, 1);
      }
      if ((w0 & 0xFFFFu) == 0xF00Eu && (i << 2) + 36u <= len &&
          (memcmp(b + (i << 2), M16_LZO1X, 12) == 0 || memcmp(b + (i << 2), M16_LZMA_TOBUF, 12) == 0)) {
        emit(i << 2, 1);
      }
      if ((w0 >> 16) == 0xF00Eu && (i << 2) + 38u <= len &&
          (memcmp(b + (i << 2) + 2, M16_LZO1X, 12) == 0 || memcmp(b + (i << 2) + 2, M16_LZMA_TOBUF, 12) == 0)) {
        emit((i << 2) + 2, 1);
      }
    }
    if ((mask & 2u) && w0 == 0x27BDFFE0u && (i << 2) + 72u <= len) {
      uint32_t w1 = words[i + 1], w2 = words[i + 2], w3 = words[i + 3];
      if ((w1 == 0xAFBF0018u && w2 == 0xAFB10014u && w3 == 0xAFB00010u) ||
          (w1 == 0xAFBF001Cu && w2 == 0xAFB20018u && w3 == 0xAFB10014u)) {
        emit(i << 2, 2);
      }
    }
    if ((mask & 4u) && (w0 & 0xFC00FFFBu) == 0x34000200u && (i << 2) + 20u <= len) {
      uint32_t rs = (w0 >> 16) & 31u;
      uint32_t j_end = std::min<uint32_t>((len - 16u) >> 2, i + 36u);
      for (uint32_t j = i + 1; j <= j_end; j++) {
        uint32_t lw = words[j];
        if ((lw & 0xFC00FFFFu) == 0x8C000000u && ((lw >> 21) & 31u) == rs) {
          emit(i << 2, 3);
          break;
        }
      }
    }
  }
  return count;
}

// ------------------------------------------------------------------
// 2D Graphics Engine (GE_M36F, GE_M3602) & GMA Display Capture Kernels
// ------------------------------------------------------------------
ALI_API int ali_ge_m36f_exec(void *ram, uint32_t ram_size, uint32_t phys_mask,
                             const uint32_t *regs, uint64_t *prims_io) {
  return ali_gfx::ge_m36f_exec_one((uint8_t *)ram, ram_size, phys_mask, regs, prims_io);
}

ALI_API uint32_t ali_ge_m36f_run_list(void *ram, uint32_t ram_size, uint32_t phys_mask,
                                      const uint32_t *words, uint32_t n_words,
                                      uint32_t *ge_regs, const uint32_t *live_regs,
                                      uint64_t *prims_io) {
  return ali_gfx::ge_m36f_run_list_cpp((uint8_t *)ram, ram_size, phys_mask, words, n_words,
                                       ge_regs, live_regs, prims_io);
}

ALI_API int ali_ge_m3602_run(void *ram, uint32_t ram_size, uint32_t *addr_io,
                             uint32_t *mask_io, uint64_t *cmds_io) {
  return ali_gfx::ge_m3602_run_cpp((uint8_t *)ram, ram_size, addr_io, mask_io, cmds_io);
}

ALI_API uint32_t ali_gma_count_colours(const void *rgb, uint32_t n_pixels) {
  return ali_gfx::gma_count_colours_cpp((const uint8_t *)rgb, n_pixels);
}

ALI_API uint32_t ali_gma_diff_rgb(const void *a, const void *b, uint32_t n_pixels, uint32_t *max_diff_out) {
  return ali_gfx::gma_diff_rgb_cpp((const uint8_t *)a, (const uint8_t *)b, n_pixels, max_diff_out);
}

ALI_API void ali_gma_blend(void *canvas, uint32_t cw, uint32_t ch,
                           const void *rgba, uint32_t rw, uint32_t rh,
                           int32_t x, int32_t y) {
  ali_gfx::gma_blend_cpp((float *)canvas, cw, ch, (const uint8_t *)rgba, rw, rh, x, y);
}

ALI_API void ali_gma_scale_u8(const void *src, uint32_t sw, uint32_t sh, uint32_t channels,
                              void *dst, const int32_t *rows, uint32_t dh,
                              const int32_t *cols, uint32_t dw) {
  ali_gfx::gma_scale_u8_cpp((const uint8_t *)src, sw, sh, channels, (uint8_t *)dst, rows, dh, cols, dw);
}

ALI_API int ali_lzo1x_decompress_safe(const void *src_p, uint32_t src_len,
                                      void *dst_p, uint32_t *dst_len) {
  if (!src_p || !dst_p || !dst_len) return -1;
  const uint8_t *const src = (const uint8_t *)src_p;
  uint8_t *const dst = (uint8_t *)dst_p;
  const uint8_t *ip = src;
  const uint8_t *const ip_end = src + src_len;
  uint8_t *op = dst;
  uint8_t *const op_end = dst + *dst_len;
  *dst_len = 0;

  uint32_t t;
  const uint8_t *m_pos;

  if (ip < ip_end && *ip > 17) {
    t = *ip++ - 17;
    if (t < 4) goto match_next;
    if ((uint32_t)(op_end - op) < t) goto output_overrun;
    if ((uint32_t)(ip_end - ip) < t + 1) goto input_overrun;
    do { *op++ = *ip++; } while (--t > 0);
    goto first_literal_run;
  }

  while (ip < ip_end) {
    t = *ip++;
    if (t >= 16) goto match;
    if (t == 0) {
      if ((uint32_t)(ip_end - ip) < 1) goto input_overrun;
      while (*ip == 0) {
        t += 255;
        ip++;
        if ((uint32_t)(ip_end - ip) < 1) goto input_overrun;
      }
      t += 15 + *ip++;
    }
    if ((uint32_t)(op_end - op) < t + 3) goto output_overrun;
    if ((uint32_t)(ip_end - ip) < t + 4) goto input_overrun;
    *op++ = *ip++; *op++ = *ip++; *op++ = *ip++;
    do { *op++ = *ip++; } while (--t > 0);

first_literal_run:
    t = *ip++;
    if (t >= 16) goto match;
    m_pos = op - (1 + 0x0800);
    m_pos -= t >> 2;
    m_pos -= (uint32_t)(*ip++) << 2;
    if (m_pos < dst) goto lookbehind_overrun;
    if ((uint32_t)(op_end - op) < 3) goto output_overrun;
    *op++ = *m_pos++; *op++ = *m_pos++; *op++ = *m_pos;
    goto match_done;

    for (;;) {
match:
      if (t >= 64) {
        m_pos = op - 1;
        m_pos -= (t >> 2) & 7;
        m_pos -= (uint32_t)(*ip++) << 3;
        t = (t >> 5) - 1;
        if (m_pos < dst) goto lookbehind_overrun;
        if ((uint32_t)(op_end - op) < t + 2) goto output_overrun;
        goto copy_match;
      } else if (t >= 32) {
        t &= 31;
        if (t == 0) {
          if ((uint32_t)(ip_end - ip) < 1) goto input_overrun;
          while (*ip == 0) {
            t += 255;
            ip++;
            if ((uint32_t)(ip_end - ip) < 1) goto input_overrun;
          }
          t += 31 + *ip++;
        }
        m_pos = op - 1;
        m_pos -= (ip[0] >> 2) + ((uint32_t)ip[1] << 6);
        ip += 2;
      } else if (t >= 16) {
        m_pos = op;
        m_pos -= (t & 8) << 11;
        t &= 7;
        if (t == 0) {
          if ((uint32_t)(ip_end - ip) < 1) goto input_overrun;
          while (*ip == 0) {
            t += 255;
            ip++;
            if ((uint32_t)(ip_end - ip) < 1) goto input_overrun;
          }
          t += 7 + *ip++;
        }
        m_pos -= (ip[0] >> 2) + ((uint32_t)ip[1] << 6);
        ip += 2;
        if (m_pos == op) goto eof_found;
        m_pos -= 0x4000;
      } else {
        m_pos = op - 1;
        m_pos -= t >> 2;
        m_pos -= (uint32_t)(*ip++) << 2;
        if (m_pos < dst) goto lookbehind_overrun;
        if ((uint32_t)(op_end - op) < 2) goto output_overrun;
        *op++ = *m_pos++; *op++ = *m_pos;
        goto match_done;
      }
      if (m_pos < dst) goto lookbehind_overrun;
      if ((uint32_t)(op_end - op) < t + 2) goto output_overrun;
copy_match:
      *op++ = *m_pos++; *op++ = *m_pos++;
      do { *op++ = *m_pos++; } while (--t > 0);
match_done:
      t = ip[-2] & 3;
      if (t == 0) break;
match_next:
      if ((uint32_t)(op_end - op) < t) goto output_overrun;
      if ((uint32_t)(ip_end - ip) < t + 1) goto input_overrun;
      do { *op++ = *ip++; } while (--t > 0);
      t = *ip++;
    }
  }
  *dst_len = (uint32_t)(op - dst);
  return -7;
eof_found:
  *dst_len = (uint32_t)(op - dst);
  return (ip == ip_end ? 0 : (ip < ip_end ? -8 : -4));
input_overrun:
  *dst_len = (uint32_t)(op - dst);
  return -4;
output_overrun:
  *dst_len = (uint32_t)(op - dst);
  return -5;
lookbehind_overrun:
  *dst_len = (uint32_t)(op - dst);
  return -6;
}
