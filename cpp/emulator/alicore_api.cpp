// AliSimulator C++ core: the C API (alicore.dll), used by src/cpp_core.py through ctypes.
#include "alicore.h"

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
  F_NEXT_EVENT, F_LIMIT, F_SPIN_SKIPPED, F_SPIN_SKIP, F_POLL_SKIPPED, F_POLL_SKIPS, F_FF_SKIPPED,
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
// The GPIO log for a device handler that empties it itself (drains != 0): its
// count (the host sets it to 0 once handled) and its (offset, levels) pairs.
ALI_API void ali_gpio_log(void *c, int drains, uint32_t **count, uint32_t **pairs) {
  Core *k = (Core *)c;
  k->host_sync();
  k->gpio_dev_drains_ = drains != 0;
  *count = &k->gpio_n_;
  *pairs = k->gpio_log_;
}
ALI_API void ali_set_chunks(void *c, int shift, uint32_t count) {
  Core *k = (Core *)c;
  k->chunk_shift = (uint32_t)shift;
  k->chunk_seen.assign(count, 0);
  k->chunk_events = count > 0;
  k->flush_blocks();      // (a block's first run reports its chunk: they run again first)
}
ALI_API void ali_chunk_mark(void *c, uint32_t index, int seen) {
  Core *k = (Core *)c;
  if (index < k->chunk_seen.size()) k->chunk_seen[index] = (uint8_t)seen;
  if (!seen) k->flush_blocks();
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
    case F_CHUNK_EVENTS: k->chunk_events = v != 0; break;
    case F_DS_TARGET: k->ds_target = w; break;
    case F_DS_M16: k->ds_m16 = v != 0; break;
    case F_BADVADDR: k->badvaddr = w; break;
    case F_TIMER_CHECK_AT: k->timer_check_at = v; break;
    case F_HOST_ACCESS_COST: k->host_access_cost = (uint32_t)v; break;
    case F_BLOCKS_ON: k->blocks_on = v != 0; break;
    case F_SPIN_SKIP: k->spin_skip = v != 0; break;
    case F_SPIN_SKIPPED: k->spin_skipped = v; break;
  }
  k->poke_events();
}
