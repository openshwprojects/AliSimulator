// AliSimulator C++ core: memory map, hooks, CP0, interrupts, the run loop.
// The instructions themselves are in alicore_exec.cpp.
#include "alicore.h"
#include "alicore_gfx.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>

namespace ali {

static const uint32_t NPAGES = 1u << 20;   // 4 KB pages of the 32-bit space

static uint64_t now_ms() {
  using namespace std::chrono;
  return (uint64_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

Core::Core() {
  memset(gpr, 0, sizeof(gpr));
  memset(fpr, 0, sizeof(fpr));
  memset(cp0, 0, sizeof(cp0));
  memset(gpio_watch_, 0, sizeof(gpio_watch_));
  memset(gpio_last_, 0, sizeof(gpio_last_));
  memset(gpio_last_ok_, 0, sizeof(gpio_last_ok_));
  memset(gpio_di_high_, 0, sizeof(gpio_di_high_));
  memset(osd_pal_, 0xFF, sizeof(osd_pal_));
  vr_ = new uint8_t *[NPAGES]();
  vw_ = new uint8_t *[NPAGES]();
  vx_ = new uint8_t *[NPAGES]();
  pregion_ = new Region *[NPAGES]();
  code_hook_page_ = new uint8_t[NPAGES]();
  mem_hook_page_ = new uint8_t[NPAGES]();
  // CP0 reset values of Unicorn's 24Kf (probed), the simulator's Status / EBase
  cp0[1][0] = 6;              // Random
  cp0[12][1] = 0xE0000000;    // IntCtl: IPTI = IPPCI = 7
  cp0[15][0] = 0x00019300;    // PRId
  cp0[16][0] = 0x80000482;    // Config0
  cp0[16][1] = 0x9E190C8F;    // Config1
  cp0[16][2] = 0x80000000;    // Config2
  cp0[19][0] = 0x80000000;    // WatchHi
  cp0[23][0] = 0x02008000;    // Debug
  cp0[25][1] = 0xFFFFFFFF;    // PerfCnt0
}

Core::~Core() {
  if (peer_core_ && peer_core_->peer_core_ == this) peer_core_->peer_core_ = nullptr;
  for (auto &r : regions_)
    if (r.owned) free(r.ptr);
  delete[] vr_;
  delete[] vw_;
  delete[] vx_;
  delete[] pregion_;
  delete[] code_hook_page_;
  delete[] mem_hook_page_;
  delete[] devflags_;
  delete[] devrules_;
  flush_blocks();
  free_retired();
  delete[] btab_;
}

// ------------------------------------------------------------------
// Memory map
// ------------------------------------------------------------------
Region *Core::find_region(uint64_t addr) {
  if (addr >= (1ull << 32)) return nullptr;
  return pregion_[addr >> 12];
}

int Core::map_ptr(uint64_t base, uint64_t size, uint32_t perms, void *ptr) {
  if (!size || (base & 0xFFF) || (size & 0xFFF) || base + size > (1ull << 32)) return ERR_ARG;
  for (uint64_t a = base; a < base + size; a += 0x1000)
    if (pregion_[a >> 12]) return ERR_MAP;
  Region r{};
  r.base = base; r.size = size; r.perms = perms; r.ptr = (uint8_t *)ptr; r.owned = false;
  regions_.push_back(r);
  refresh_pages(base, base + size);
  return ERR_OK;
}

int Core::map_alloc(uint64_t base, uint64_t size, uint32_t perms) {
  if (!size || (base & 0xFFF) || (size & 0xFFF)) return ERR_ARG;
  void *p = calloc(1, (size_t)size);
  if (!p) return ERR_NOMEM;
  int e = map_ptr(base, size, perms, p);
  if (e) { free(p); return e; }
  regions_.back().owned = true;
  return ERR_OK;
}

int Core::map_mmio(uint64_t base, uint64_t size, MmioReadCb rd, void *rd_user, MmioWriteCb wr, void *wr_user) {
  if (!size || (base & 0xFFF) || (size & 0xFFF) || base + size > (1ull << 32)) return ERR_ARG;
  for (uint64_t a = base; a < base + size; a += 0x1000)
    if (pregion_[a >> 12]) return ERR_MAP;
  Region r{};
  r.base = base; r.size = size; r.perms = PROT_ALL; r.mmio = true;
  r.rd = rd; r.wr = wr; r.rd_user = rd_user; r.wr_user = wr_user;
  regions_.push_back(r);
  refresh_pages(base, base + size);
  return ERR_OK;
}

int Core::unmap(uint64_t base, uint64_t size) {
  if ((base & 0xFFF) || (size & 0xFFF)) return ERR_ARG;
  uint64_t end = base + size;
  for (uint64_t a = base; a < end; a += 0x1000)
    if (!pregion_[a >> 12]) return ERR_ARG;   // Unicorn: UC_ERR_NOMEM for an unmapped hole; ARG is close enough
  std::vector<Region> out;
  for (auto &r : regions_) {
    uint64_t rend = r.base + r.size;
    if (rend <= base || r.base >= end) { out.push_back(r); continue; }
    // split: keep what lies outside [base, end)
    if (r.base < base) {
      Region a = r; a.size = base - r.base; a.owned = false; out.push_back(a);
    }
    if (rend > end) {
      Region b = r; b.base = end; b.size = rend - end; b.owned = false;
      if (!r.mmio && r.ptr) b.ptr = r.ptr + (end - r.base);
      out.push_back(b);
    }
    if (r.owned && r.base >= base && rend <= end) free(r.ptr);
    // (a partially unmapped owned region keeps its memory: leaked until exit, rare)
  }
  regions_ = out;
  refresh_pages(base, end);
  return ERR_OK;
}

int Core::protect(uint64_t base, uint64_t size, uint32_t perms) {
  if ((base & 0xFFF) || (size & 0xFFF)) return ERR_ARG;
  uint64_t end = base + size;
  std::vector<Region> out;
  for (auto &r : regions_) {
    uint64_t rend = r.base + r.size;
    if (rend <= base || r.base >= end) { out.push_back(r); continue; }
    uint64_t lo = std::max(r.base, base), hi = std::min(rend, end);
    if (r.base < lo) { Region a = r; a.size = lo - r.base; a.owned = false; out.push_back(a); }
    Region m = r; m.base = lo; m.size = hi - lo; m.perms = perms; m.owned = false;
    if (!r.mmio && r.ptr) m.ptr = r.ptr + (lo - r.base);
    out.push_back(m);
    if (rend > hi) {
      Region b = r; b.base = hi; b.size = rend - hi; b.owned = false;
      if (!r.mmio && r.ptr) b.ptr = r.ptr + (hi - r.base);
      out.push_back(b);
    }
  }
  regions_ = out;
  refresh_pages(base, end);
  return ERR_OK;
}

void Core::rebuild_all_pages() {
  memset(pregion_, 0, sizeof(Region *) * NPAGES);
  for (auto &r : regions_)
    for (uint64_t a = r.base; a < r.base + r.size; a += 0x1000) pregion_[a >> 12] = &r;
  memset(vr_, 0, sizeof(uint8_t *) * NPAGES);
  memset(vw_, 0, sizeof(uint8_t *) * NPAGES);
  memset(vx_, 0, sizeof(uint8_t *) * NPAGES);
  rebuild_pages(0, 1ull << 32);
  refresh_device_aliases();
}

// After a change to the physical pages lo..hi-1: every region's page entries
// again (the vector may have moved them), the guest's page pointers only there.
void Core::refresh_pages(uint64_t lo, uint64_t hi) {
  for (uint64_t a = lo & ~0xFFFull; a < hi; a += 0x1000) pregion_[a >> 12] = nullptr;
  for (auto &r : regions_)
    for (uint64_t a = r.base; a < r.base + r.size; a += 0x1000) pregion_[a >> 12] = &r;
  rebuild_pages(lo, hi);
  refresh_device_aliases();
}

// Device-buffer aliases outside its physical window can make a register store
// change an instruction in the current decoded block. Check when maps change,
// not on every store. Include protected regions too: a fetch-protection hook
// may allow their execution. Raw kseg0/1 mappings are not physical aliases;
// guest accesses there translate to the low 512 MB instead (phys_of).
void Core::refresh_device_aliases() {
  dev_store_alias_ = false;
  if (!dev_buf_) return;
  uintptr_t db = (uintptr_t)dev_buf_;
  for (const Region &r : regions_) {
    if (r.mmio || !r.ptr) continue;
    uintptr_t rb = (uintptr_t)r.ptr;
    uint64_t roff = rb < db ? db - rb : 0;
    uint64_t doff = rb > db ? rb - db : 0;
    if (roff >= r.size || doff >= dev_size_) continue;
    uint64_t lo = r.base + roff;
    uint64_t hi = lo + std::min<uint64_t>(r.size - roff, dev_size_ - doff);
    auto outside_device = [&](uint64_t first, uint64_t last) {
      uint64_t a = std::max(lo, first), z = std::min(hi, last);
      return a < z && (a < dev_phys_ || z > (uint64_t)dev_phys_ + dev_size_);
    };
    if (outside_device(0, 0x80000000ull) || outside_device(0xC0000000ull, 1ull << 32)) {
      dev_store_alias_ = true;
      return;
    }
  }
}

// The guest's fast page pointers for the physical pages lo..hi-1 (their kuseg,
// kseg0 and kseg1 aliases).  Null sends an access to the slow path: unmapped,
// mmio, the device window, protected, memory hooks, flash command mode.
void Core::rebuild_pages(uint64_t lo, uint64_t hi) {
  for (uint64_t pa = lo & ~0xFFFull; pa < hi; pa += 0x1000) {
    uint32_t p = (uint32_t)(pa >> 12);
    Region *r = pregion_[p];
    uint8_t *rd = nullptr, *wr = nullptr, *ex = nullptr;
    if (r && !r->mmio && r->ptr) {
      bool dev = dev_buf_ && pa >= dev_phys_ && pa < (uint64_t)dev_phys_ + dev_size_;
      bool flash = false;
      if (flash_cmd_ || spi.on)
        for (uint32_t w : flash_windows_)
          if (pa >= w && pa < (uint64_t)w + 0x01000000) flash = true;
      uint8_t *ptr = r->ptr + (pa - r->base);
      uint8_t mh = mem_hook_page_[p];
      if (!dev) {
        if ((r->perms & PROT_READ) && !(mh & 1) && !flash) rd = ptr;
        if ((r->perms & PROT_WRITE) && !(mh & 2)) wr = ptr;
        if ((r->perms & PROT_EXEC) && !(mh & 4)) ex = ptr;
      }
    }
    if (p < 0x80000) { vr_[p] = rd; vw_[p] = wr; vx_[p] = ex; }                 // kuseg 1:1
    if (p < 0x20000) {
      vr_[0x80000 + p] = rd; vw_[0x80000 + p] = wr; vx_[0x80000 + p] = ex;    // kseg0
      vr_[0xA0000 + p] = rd; vw_[0xA0000 + p] = wr; vx_[0xA0000 + p] = ex;    // kseg1
    }
  }
  invalidate_fetch();
}

void Core::set_device_window(uint32_t phys, uint8_t *buffer, uint32_t size, DevCb cb, void *user) {
  dev_phys_ = phys;
  dev_buf_ = buffer;
  dev_size_ = size;
  dev_cb_ = cb;
  dev_user_ = user;
  delete[] devflags_;
  devflags_ = new uint8_t[size]();
  delete[] devrules_;
  devrules_ = new uint8_t[size]();
  mmio_rule_count_ = 0;
  // the window is a region of its own (host accesses go through the same path)
  bool have = false;
  for (auto &r : regions_)
    if (r.base == phys) have = true;
  if (!have) {
    Region r{};
    r.base = phys; r.size = size; r.perms = PROT_ALL; r.ptr = buffer; r.owned = false;
    regions_.push_back(r);
  }
  refresh_pages(phys, (uint64_t)phys + size);
}

void Core::set_dev_flags(uint32_t offset, uint32_t count, uint8_t flags) {
  if (!devflags_ || offset >= dev_size_) return;
  count = std::min(count, dev_size_ - offset);
  memset(devflags_ + offset, flags, count);
}

void Core::set_mmio_rules(const MmioRule *rules, uint32_t n_rules, const uint32_t *offsets, const uint8_t *rflags,
                          uint32_t n_offs) {
  if (!devrules_) return;
  memset(devrules_, 0, dev_size_);
  mmio_rule_count_ = std::min<uint32_t>(n_rules, MMIO_RULES_MAX);
  if (mmio_rule_count_ && rules) memcpy(mmio_rules_, rules, mmio_rule_count_ * sizeof(MmioRule));
  for (uint32_t i = 0; i < n_offs; i++) {
    if (offsets[i] < dev_size_) devrules_[offsets[i]] = rflags[i];
  }
}

void Core::set_flash_cmd(bool on, const uint32_t *windows, int n) {
  bool changed = on != flash_cmd_;
  flash_windows_.assign(windows, windows + n);
  flash_cmd_ = on;
  if (changed)
    for (uint32_t w : flash_windows_) rebuild_pages(w, (uint64_t)w + 0x01000000);
}

uint8_t *Core::direct(uint64_t addr, uint64_t *base, uint64_t *size) {
  Region *r = find_region(addr);
  if (!r || r->mmio || !r->ptr) return nullptr;
  if (dev_buf_ && r->base < (uint64_t)dev_phys_ + dev_size_ && r->base + r->size > dev_phys_) return nullptr;
  *base = r->base;
  *size = r->size;
  return r->ptr;
}

// Host access (Unicorn's uc_mem_read / uc_mem_write): the address as mapped.
int Core::host_read(uint64_t addr, void *buf, uint64_t size) {
  uint8_t *out = (uint8_t *)buf;
  while (size) {
    Region *r = find_region(addr);
    if (!r) return ERR_READ_UNMAPPED;
    uint64_t n = std::min<uint64_t>(size, r->base + r->size - addr);
    if (r->mmio) {
      for (uint64_t i = 0; i < n;) {
        uint32_t chunk = (uint32_t)std::min<uint64_t>(n - i, 4);
        while (chunk > 1 && ((addr + i) & (chunk - 1))) chunk >>= 1;
        uint64_t v = 0;
        if (r->rd) {
          note_host_callback();
          v = r->rd(r->rd_user, addr + i - r->base, chunk);
          note_host_callback();
        }
        memcpy(out + i, &v, chunk);
        i += chunk;
      }
    } else if (dev_buf_ && addr >= dev_phys_ && addr < (uint64_t)dev_phys_ + dev_size_) {
      for (uint64_t i = 0; i < n;) {   // the physical window: the device side effects (as Unicorn's mmio_map)
        uint32_t chunk = (uint32_t)std::min<uint64_t>(n - i, 4);
        while (chunk > 1 && ((addr + i) & (chunk - 1))) chunk >>= 1;
        uint64_t v = dev_load((uint32_t)(addr + i - dev_phys_), chunk);
        memcpy(out + i, &v, chunk);
        i += chunk;
      }
    } else {
      memcpy(out, r->ptr + (addr - r->base), (size_t)n);
    }
    out += n; addr += n; size -= n;
  }
  host_sync();     // (a GPIO store from the host: its decoders now)
  return ERR_OK;
}

int Core::host_write(uint64_t addr, const void *buf, uint64_t size) {
  const uint8_t *in = (const uint8_t *)buf;
  stores_++;
  while (size) {
    Region *r = find_region(addr);
    if (!r) return ERR_WRITE_UNMAPPED;
    uint64_t n = std::min<uint64_t>(size, r->base + r->size - addr);
    if (r->mmio) {
      for (uint64_t i = 0; i < n;) {
        uint32_t chunk = (uint32_t)std::min<uint64_t>(n - i, 4);
        while (chunk > 1 && ((addr + i) & (chunk - 1))) chunk >>= 1;
        uint64_t v = 0;
        memcpy(&v, in + i, chunk);
        if (r->wr) {
          note_host_callback();
          r->wr(r->wr_user, addr + i - r->base, chunk, v);
          note_host_callback();
        }
        i += chunk;
      }
    } else if (dev_buf_ && addr >= dev_phys_ && addr < (uint64_t)dev_phys_ + dev_size_) {
      for (uint64_t i = 0; i < n;) {
        uint32_t chunk = (uint32_t)std::min<uint64_t>(n - i, 4);
        while (chunk > 1 && ((addr + i) & (chunk - 1))) chunk >>= 1;
        uint64_t v = 0;
        memcpy(&v, in + i, chunk);
        dev_store((uint32_t)(addr + i - dev_phys_), chunk, v);
        i += chunk;
      }
    } else {
      memcpy(r->ptr + (addr - r->base), in, (size_t)n);   // (Unicorn's uc_mem_write ignores protection)
    }
    in += n; addr += n; size -= n;
  }
  poke_events();      // (a host store can enable an interrupt: the controller's enables)
  host_sync();     // (a GPIO store from the host: its decoders now)
  return ERR_OK;
}

// ------------------------------------------------------------------
// Slow paths of guest accesses
// ------------------------------------------------------------------
void Core::fault(int err, uint64_t addr, int access) {
  fault_pc = cur_pc_;
  fault_addr = addr;
  fault_access = access;
  throw Fault{err};
}

void Core::fault_unaligned(uint32_t va, int access) {
  badvaddr = va;
  fault(access == MEM_WRITE ? ERR_WRITE_UNALIGNED : access == MEM_FETCH ? ERR_FETCH_UNALIGNED : ERR_READ_UNALIGNED,
        va, access);
}

void Core::exception(int code) {
  fault_pc = cur_pc_;
  fault_addr = (uint64_t)code;
  fault_access = 0;
  throw Fault{ERR_EXCEPTION};
}

// the invalid-access hooks of a type; true if one of them handled it
static int call_event_hooks(Core *c, std::vector<Hook> &hooks, int type, int access, uint64_t addr, int size,
                            int64_t value) {
  int handled = 0;
  for (size_t i = 0; i < hooks.size(); i++) {
    Hook &h = hooks[i];
    if (h.dead || !(h.type & type)) continue;
    if (h.begin <= h.end && (addr < h.begin || addr > h.end)) continue;
    c->host_sync();
    c->enter_callback();
    int r = ((EventHookCb)h.cb)(h.user, access, addr, size, value);
    c->leave_callback();
    if (r > handled) handled = r;   // (1: go on / let a store land, 2: handled, the store does not land)
  }
  return handled;
}

static void call_mem_hooks(Core *c, std::vector<Hook> &hooks, int type, int access, uint64_t addr, int size,
                           int64_t value) {
  for (size_t i = 0; i < hooks.size(); i++) {
    Hook &h = hooks[i];
    if (h.dead || !(h.type & type)) continue;
    if (h.begin <= h.end && (addr < h.begin || addr > h.end)) continue;
    c->host_sync();
    c->enter_callback();
    ((MemHookCb)h.cb)(h.user, access, addr, size, value);
    c->leave_callback();
  }
}

uint64_t Core::load_slow(uint32_t va, uint32_t size) {
  uint32_t pa = phys_of(va);
  // a plain device register read -- no read handler in the host, no native side
  // effect, no memory hook -- is like RAM for the loop checks: nothing changes it
  // during a spin, and a replayed pass may do it (anything else it may not)
  bool plain = dev_buf_ && pa >= dev_phys_ && pa - dev_phys_ + size <= dev_size_ &&
               !(devflags_[pa - dev_phys_] & (DF_READ | DF_GPIO_DI | DF_NATIVE | DF_IC_STATUS)) &&
               !(mem_hook_page_[pa >> 12] & 1);
  if (ALI_UNLIKELY(probe_)) {
    if (!plain) throw Fault{ERR_EXCEPTION};
    uint64_t v = 0;
    memcpy(&v, dev_buf_ + (pa - dev_phys_), size);
    return v;
  }
  if (!plain) slow_++;
  Region *r = pregion_[pa >> 12];
  if (!r) {
    if (call_event_hooks(this, hooks_, HOOK_MEM_READ_UNMAPPED, MEM_READ_UNMAPPED, pa, size, 0)) {
      r = pregion_[pa >> 12];
      if (r) return load_slow(va, size);
    }
    badvaddr = va;
    fault(ERR_READ_UNMAPPED, va, MEM_READ_UNMAPPED);
  }
  if (mem_hook_page_[pa >> 12] & 1) call_mem_hooks(this, hooks_, HOOK_MEM_READ, MEM_READ, pa, size, 0);
  if (dev_buf_ && pa >= dev_phys_ && pa - dev_phys_ < dev_size_) return dev_load(pa - dev_phys_, size);
  if (r->mmio) {
    enter_callback();
    host_sync();
    uint64_t v = r->rd ? r->rd(r->rd_user, pa - r->base, size) : 0;
    leave_callback();
    poke_events();
    return v;
  }
  if (!(r->perms & PROT_READ)) {
    if (!call_event_hooks(this, hooks_, HOOK_MEM_READ_PROT, MEM_READ_PROT, pa, size, 0)) {
      badvaddr = va;
      fault(ERR_READ_PROT, va, MEM_READ_PROT);
    }
  }
  if (spi.on && !(r->perms & PROT_WRITE) && in_flash_window(pa)) {
    if (!spi_passthrough()) return spi_flash_load(pa, size);
  } else if (flash_cmd_ && event_cb) {
    for (uint32_t w : flash_windows_)
      if (pa >= w && pa - w < 0x01000000u) {
        enter_callback();
        host_sync();
        event_cb(event_user, EVT_FLASH_READ, pa, size);
        leave_callback();
        r = pregion_[pa >> 12];
        if (!r || r->mmio) return 0;
        break;
      }
  }
  uint64_t v = 0;
  memcpy(&v, r->ptr + (pa - r->base), size);
  return v;
}

void Core::store_slow(uint32_t va, uint32_t size, uint64_t value, bool plain_device) {
  if (ALI_UNLIKELY(probe_)) throw Fault{ERR_EXCEPTION};
  slow_++;
  uint32_t pa = phys_of(va);
  Region *r = pregion_[pa >> 12];
  if (!r) {
    if (call_event_hooks(this, hooks_, HOOK_MEM_WRITE_UNMAPPED, MEM_WRITE_UNMAPPED, pa, size, (int64_t)value)) {
      r = pregion_[pa >> 12];
      if (r) { store_slow(va, size, value, false); return; }
    }
    badvaddr = va;
    fault(ERR_WRITE_UNMAPPED, va, MEM_WRITE_UNMAPPED);
  }
  if (mem_hook_page_[pa >> 12] & 2) {
    plain_device = false;  // remember the callback even if it removes its hook
    call_mem_hooks(this, hooks_, HOOK_MEM_WRITE, MEM_WRITE, pa, size, (int64_t)value);
  }
  if (dev_buf_ && pa >= dev_phys_ && pa - dev_phys_ < dev_size_) {
    dev_store(pa - dev_phys_, size, value, plain_device);
    return;
  }
  if (r->mmio) {
    enter_callback();
    host_sync();
    if (r->wr) r->wr(r->wr_user, pa - r->base, size, value);
    leave_callback();
    poke_events();
    return;
  }
  if (spi.on && !(r->perms & PROT_WRITE) && in_flash_window(pa)) {
    spi_flash_store(pa, size, value);     // (the store itself never lands: the flash keeps its bytes)
    return;
  }
  if (!(r->perms & PROT_WRITE)) {
    // (Unicorn: a write-protect hook that returns true lets the store land; 2: the
    // hook took care of it, nothing lands)
    int h = call_event_hooks(this, hooks_, HOOK_MEM_WRITE_PROT, MEM_WRITE_PROT, pa, size, (int64_t)value);
    if (!h) {
      badvaddr = va;
      fault(ERR_WRITE_PROT, va, MEM_WRITE_PROT);
    }
    if (h == 2) { poke_events(); return; }
    r = pregion_[pa >> 12];
    if (!r || r->mmio) return;
    poke_events();
  }
  memcpy(r->ptr + (pa - r->base), &value, size);
}

void Core::fetch_page(uint32_t va) {
  uint8_t *p = vx_[va >> 12];
  if (!p) {
    uint32_t pa = phys_of(va);
    Region *r = pregion_[pa >> 12];
    if (!r) {
      if (call_event_hooks(this, hooks_, HOOK_MEM_FETCH_UNMAPPED, MEM_FETCH_UNMAPPED, pa, 4, 0) &&
          pregion_[pa >> 12]) {
        fetch_page(va);
        return;
      }
      badvaddr = va;
      fault(ERR_FETCH_UNMAPPED, va, MEM_FETCH_UNMAPPED);
    }
    if (r->mmio || !r->ptr || (dev_buf_ && pa >= dev_phys_ && pa - dev_phys_ < dev_size_) ||
        !(r->perms & PROT_EXEC)) {
      if (!r->mmio && r->ptr && call_event_hooks(this, hooks_, HOOK_MEM_FETCH_PROT, MEM_FETCH_PROT, pa, 4, 0)) {
        p = r->ptr + ((pa & ~0xFFFu) - r->base);
      } else {
        badvaddr = va;
        fault(ERR_FETCH_PROT, va, MEM_FETCH_PROT);
      }
    } else {
      // executable, only a fetch memory hook kept it off the fast table
      p = r->ptr + ((pa & ~0xFFFu) - r->base);
    }
  }
  if (chunk_events) {
    uint32_t pa = phys_of(va);
    uint32_t c = pa >> chunk_shift;
    if (c < chunk_seen.size() && !chunk_seen[c]) report_chunk(pa);
    p = vx_[va >> 12] ? vx_[va >> 12] : p;   // (the host may have remapped)
  }
  fetch_page_ = va >> 12;
  fetch_ptr_ = p;
}

void Core::flush_gpio() {
  uint32_t n = gpio_n_;
  gpio_n_ = 0;
  if (!gpio_cb_ || !n) return;
  enter_callback();
  gpio_cb_(gpio_user_, gpio_log_, n);
  leave_callback();
}

void Core::report_chunk(uint32_t pa) {
  uint32_t c = pa >> chunk_shift;
  chunk_seen[c] = 1;
  if (event_cb) {
    host_sync();
    enter_callback();
    event_cb(event_user, EVT_CODE_CHUNK, (uint64_t)c << chunk_shift, 1ull << chunk_shift);
    leave_callback();
  }
}

uint64_t Core::dev_load(uint32_t off, uint32_t size) {
  if (devflags_[off] & DF_NATIVE) return native_dev_load(off, size);
  if (devflags_[off] & DF_IC_STATUS) {
    uint64_t words[2] = {ic_lines_, ic_lines_hi_};
    for (uint32_t w = 0; w < 4; w++) {
      uint32_t bits = (uint32_t)(words[w >> 1] >> (32 * (w & 1)));
      if (bits && ic_status_off_ + 4 * w + 4 <= dev_size_) {
        uint32_t cur;
        memcpy(&cur, dev_buf_ + ic_status_off_ + 4 * w, 4);
        cur |= bits;
        memcpy(dev_buf_ + ic_status_off_ + 4 * w, &cur, 4);
      }
    }
    icount += host_access_cost;
    poke_events();
    uint64_t v = 0;
    memcpy(&v, dev_buf_ + off, size);
    return v;
  }
  if ((devflags_[off] & (DF_GE | DF_READ)) == (DF_GE | DF_READ)) {
    uint32_t st_off = (off & ~0xFFFu) | 0x008u;
    if (st_off + 4u <= dev_size_) memcpy(dev_buf_ + st_off, &ge_.status, 4);
    icount += host_access_cost;
    poke_events();
    uint64_t v = 0;
    memcpy(&v, dev_buf_ + off, size);
    return v;
  }
  if ((devflags_[off] & DF_GPIO_DI) && gpio_n_ == 0 && !gpio_di_busy_) {
    uint32_t di_off = off & ~3u;
    if (di_off + 12u <= dev_size_) {
      uint32_t do_off = di_off + 4u;
      uint32_t do_val, dir_val;
      memcpy(&do_val, dev_buf_ + do_off, 4);
      memcpy(&dir_val, dev_buf_ + di_off + 8u, 4);
      uint32_t bank = (do_off & 0xFFFu) >> 2;
      uint32_t di_val = (do_val & dir_val) | (bank < GPIO_BANKS ? gpio_di_high_[bank] : 0u);
      if (gi2c_.on) {
        if ((do_off & 0xFFFu) == gi2c_.scl_off) di_val |= gi2c_.scl_mask;
        if ((do_off & 0xFFFu) == gi2c_.sda_off) {
          if (gi2c_sda_out() == 0) di_val &= ~gi2c_.sda_mask;
          else di_val |= gi2c_.sda_mask;
        }
      }
      if (tm1650_.on) {
        if ((do_off & 0xFFFu) == tm1650_.scl_off) di_val |= tm1650_.scl_mask;
        if ((do_off & 0xFFFu) == tm1650_.sda_off) {
          if (tm1650_sda_in() == 0) di_val &= ~tm1650_.sda_mask;
          else di_val |= tm1650_.sda_mask;
        }
      }
      if (tm1628_.on && tm1628_.key_read && tm1628_.in_frame) {
        if ((do_off & 0xFFFu) == tm1628_.dio_off) {
          if (tm1628_dio_in() == 0) di_val &= ~tm1628_.dio_mask;
          else di_val |= tm1628_.dio_mask;
        }
      }
      if (lemontree_.on) {
        if ((do_off & 0xFFFu) == lemontree_.scl_off) di_val |= lemontree_.scl_mask;
        if ((do_off & 0xFFFu) == lemontree_.sda_off) {
          if (lemontree_sda_out() == 0) di_val &= ~lemontree_.sda_mask;
          else di_val |= lemontree_.sda_mask;
        }
      }
      di_val = (di_val & ~dir_val) | (do_val & dir_val);
      memcpy(dev_buf_ + di_off, &di_val, 4);
    }
    icount += host_access_cost;
    poke_events();
    uint64_t v = 0;
    memcpy(&v, dev_buf_ + off, size);
    return v;
  }
  if ((devflags_[off] & DF_READ) && devrules_ && (devrules_[off] & DR_SCB)) {
    uint64_t v = scb_load(off, size);
    icount += host_access_cost;
    poke_events();
    return v;
  }
  if ((devflags_[off] & DF_READ) && devrules_ && (devrules_[off] & DR_READ) &&
      (!(devrules_[off] & DR_UART_IDLE) || (!uart_pending_ && !uart_ip3))) {
    bool counted_demod = false;
    for (uint32_t k = 0; k < mmio_rule_count_; k++) {
      const MmioRule &r = mmio_rules_[k];
      if (r.flags & RULE_DDR_TRAINING) {
        if (off < 0x3E08Cu || off >= 0x3E110u) continue;
      } else if (r.flags & RULE_EXACT_OFF) {
        if (r.offset != off) continue;
      } else {
        if (r.offset < off || r.offset >= off + size) continue;
      }
      if (r.offset >= dev_size_) continue;
      if (r.flags & RULE_VE_STATUS) {
        uint32_t w_off = r.offset & ~3u;
        if (w_off + 4 <= dev_size_) {
          uint32_t cur;
          memcpy(&cur, dev_buf_ + w_off, 4);
          if (cur & 0x037FFF00u) {
            cur &= ~0x037FFF00u;
            memcpy(dev_buf_ + w_off, &cur, 4);
          }
        }
      } else if (r.flags & RULE_MAC_MDIO) {
        if (0x2C084u <= dev_size_) {
          uint32_t v;
          memcpy(&v, dev_buf_ + 0x2C07Cu, 4);
          if (v & 0x80000000u) {
            uint32_t nv = v & 0x7FFFFFFFu;
            memcpy(dev_buf_ + 0x2C07Cu, &nv, 4);
            if (v & 0x08000000u) {
              dev_buf_[0x2C082u] = 0xFFu;
              dev_buf_[0x2C083u] = 0xFFu;
            }
          }
        }
      } else if (r.flags & RULE_MIRROR) {
        uint32_t src = (uint32_t)r.and_mask | ((uint32_t)r.or_mask << 8) | ((uint32_t)r.pad << 16);
        if (r.offset + r.req_mask <= dev_size_ && src + r.req_mask <= dev_size_)
          memcpy(dev_buf_ + r.offset, dev_buf_ + src, r.req_mask);
      } else if (r.flags & RULE_DDR_TRAINING) {
        static const uint32_t P0[8] = {0x0FF00FF0u, 0xFF00FF00u, 0x00FF00FFu, 0xF00FF00Fu,
                                       0x0FF00FF0u, 0x00FF00FFu, 0xFF00FF00u, 0x0FF00FF0u};
        static const uint32_t P1[8] = {0xA55AA55Au, 0xFF00FF00u, 0x00FF00FFu, 0x5AA55AA5u,
                                       0xA55AA55Au, 0x00FF00FFu, 0xFF00FF00u, 0xA55AA55Au};
        uint32_t w_off = off & ~3u;
        if (w_off == 0x3E08Cu && w_off + 4u <= dev_size_) {
          uint32_t w = 0xC0000040u;
          memcpy(dev_buf_ + w_off, &w, 4);
        } else if (w_off >= 0x3E090u && w_off < 0x3E110u && w_off + 4u <= dev_size_) {
          uint32_t rel = w_off - 0x3E090u;
          uint32_t lane = rel >> 5, word = (rel & 0x1Fu) >> 2;
          uint32_t w = (lane == 0) ? P0[word] : P1[word];
          memcpy(dev_buf_ + w_off, &w, 4);
        }
      } else if (r.flags & RULE_DEMOD) {
        if ((r.flags & RULE_DEMOD_COUNT) && !counted_demod) {
          demod_reads_++;
          counted_demod = true;
        }
        if (demod_locked_) {
          uint8_t b = dev_buf_[r.offset];
          if (r.flags & RULE_DEMOD_IFZERO) {
            if (b == 0) dev_buf_[r.offset] = r.or_mask;
          } else if (!r.req_mask || (b & r.req_mask)) {
            dev_buf_[r.offset] = (b & r.and_mask) | r.or_mask;
          }
        } else if (r.flags & RULE_DEMOD_CLR3F) {
          dev_buf_[r.offset] &= ~0x3Fu;
        }
      } else {
        uint8_t b = dev_buf_[r.offset];
        if (!r.req_mask || (b & r.req_mask)) dev_buf_[r.offset] = (b & r.and_mask) | r.or_mask;
      }
    }
    icount += host_access_cost;
    poke_events();
    uint64_t v = 0;
    memcpy(&v, dev_buf_ + off, size);
    return v;
  }
  if (devflags_[off] & (DF_READ | DF_GPIO_DI)) {
    if (ALI_UNLIKELY(prof_dev_ != nullptr)) (*prof_dev_)[cur_pc_ | (m16 ? 1u : 0u)]++;
    if (!gpio_dev_drains_) host_sync();
    enter_callback();
    uint64_t v = dev_cb_(dev_user_, 0, off, size, 0);
    leave_callback();
    icount += host_access_cost;
    poke_events();
    return v;
  }
  uint64_t v = 0;
  memcpy(&v, dev_buf_ + off, size);
  return v;
}

// Only an unobserved store to ordinary register bytes leaves the scheduled
// event deadline unchanged. IRQ enables and incoming doorbells are live even
// without a Python handler. Use the configured layout and the full access
// width; reserve status words too (including doorbell acknowledgements).
bool Core::plain_device_store(uint32_t off, uint32_t size) const {
  if (dev_callback_dirty_ || dev_store_alias_ || off >= dev_size_ || size > dev_size_ - off) return false;
  uint64_t end = (uint64_t)off + size;
  auto overlaps = [&](uint64_t first, uint64_t count) {
    return (uint64_t)off < first + count && first < end;
  };
  if (overlaps(ic_status_off_, 16) || overlaps(ic_enable_off_, 16) ||
      overlaps((uint64_t)ic_base_ + 0xF, 1) ||
      (doorbell_off_ >= 0 && overlaps((uint32_t)doorbell_off_, 1))) return false;
  for (uint32_t i = 0; i < size; i++)
    if (devflags_[off + i]) return false;
  return true;
}

void Core::dev_store(uint32_t off, uint32_t size, uint64_t value, bool plain_device) {
  uint8_t f = devflags_[off];
  if (f & DF_NATIVE) {
    native_dev_store(off, size, value);
  } else if (f & (DF_GPIO_DO | DF_GPIO_DIR)) {
    // (simulator._hook_gpio_write: the bank's levels -- an output pin at its DO
    // bit, an input pin high -- logged for the host)
    memcpy(dev_buf_ + off, &value, size);
    uint32_t do_off = (off & ~3u) - ((f & DF_GPIO_DO) ? 0u : 4u);
    uint32_t do_val, dir_val;
    memcpy(&do_val, dev_buf_ + do_off, 4);
    memcpy(&dir_val, dev_buf_ + do_off + 4, 4);
    uint32_t levels = (do_val & dir_val) | ~dir_val;
    uint32_t bank = do_off >> 2;
    bool log;
    if (gpio_filter_ && bank < GPIO_BANKS) {
      // (only a change of a pin the host's decoders watch)
      log = gpio_watch_[bank] && (!gpio_last_ok_[bank] || ((levels ^ gpio_last_[bank]) & gpio_watch_[bank]));
      if (log) { gpio_last_[bank] = levels; gpio_last_ok_[bank] = 1; }
    } else {
      log = gpio_n_ == 0 || gpio_log_[2 * (gpio_n_ - 1)] != do_off || gpio_log_[2 * (gpio_n_ - 1) + 1] != levels;
    }
    if (log) {
      gpio_log_[2 * gpio_n_] = do_off;
      gpio_log_[2 * gpio_n_ + 1] = levels;
      if (++gpio_n_ == GPIO_LOG_MAX) flush_gpio();
    }
    // (after the log: the host's decoders got each store before the bus, in its order)
    if (gi2c_.on && (do_off == gi2c_.scl_off || do_off == gi2c_.sda_off)) gi2c_levels(do_off, levels);
    if (tm1650_.on && (do_off == tm1650_.scl_off || do_off == tm1650_.sda_off)) tm1650_levels(do_off, levels);
    if (tm1628_.on && (do_off == tm1628_.clk_off || do_off == tm1628_.dio_off || do_off == tm1628_.stb_off))
      tm1628_levels(do_off, levels);
    if (hc164_.on) hc164_levels(do_off, levels);
    if (lemontree_.on && (do_off == lemontree_.scl_off || do_off == lemontree_.sda_off))
      lemontree_levels(do_off, levels);
    icount += host_access_cost;
  } else if ((f & (DF_GE | DF_WRITE)) == (DF_GE | DF_WRITE) && ge_store(off, size, value)) {
  } else if ((f & DF_WRITE) && devrules_ && (devrules_[off] & DR_SCB)) {
    scb_store(off, size, value);
    icount += host_access_cost;
  } else if ((f & DF_WRITE) && devrules_ && (devrules_[off] & DR_WRITE) &&
             (!(devrules_[off] & DR_VPO) || vpo_rule_store(off, size, value))) {
    if (!(devrules_[off] & (DR_VPO | DR_WRITE_IGNORE))) memcpy(dev_buf_ + off, &value, size);
    icount += host_access_cost;
  } else if (f & DF_WRITE) {
    if (ALI_UNLIKELY(prof_dev_ != nullptr)) (*prof_dev_)[cur_pc_ | (m16 ? 1u : 0u)]++;
    if (!gpio_dev_drains_) host_sync();
    enter_callback();
    dev_cb_(dev_user_, 1, off, size, value);
    leave_callback();
    icount += host_access_cost;
  } else {
    memcpy(dev_buf_ + off, &value, size);
    // No time charge or callback occurred. Keep an already pending event (or
    // stop request) and the timer/UART/limit deadline; only omit this store's
    // unnecessary invalidation. Every guest instruction and store still runs.
    if (plain_device && plain_device_store(off, size)) return;
  }
  poke_events();      // (the interrupt controller's enables, a doorbell)
}

// ------------------------------------------------------------------
// The bit-banged I2C bus (gpio_i2c.GpioI2cBus, step for step: its pin levels,
// its slave's acknowledges and read bits; the slaves themselves stay the host's)
// ------------------------------------------------------------------
void Core::gi2c_config(bool on, uint32_t scl_off, uint32_t scl_bit, uint32_t sda_off, uint32_t sda_bit) {
  host_sync();
  GpioI2c &g = gi2c_;
  g.on = on;
  g.scl_off = scl_off;
  g.sda_off = sda_off;
  g.scl_mask = 1u << (scl_bit & 31);
  g.sda_mask = 1u << (sda_bit & 31);
  g.scl = g.sda = 1;
  g.state = GI2C_IDLE;
  g.phase = GP_BITS;
  g.nbits = 0;
  g.byte = g.out = 0;
  g.reading = g.master_ack = g.device = false;
  g.written.clear();
  g.edges = 0;
}

int32_t Core::gi2c_host(int kind, uint32_t arg, const uint8_t *data, uint32_t n) {
  if (!i2c_cb_) return kind == I2C_READ ? -1 : 0;
  host_sync();        // (the GPIO log first: the host's decoders saw those stores before)
  enter_callback();
  int32_t r = i2c_cb_(i2c_user_, kind, arg, data, n);
  leave_callback();
  return r;
}

int Core::gi2c_sda_out() const {
  const GpioI2c &g = gi2c_;
  if (g.phase == GP_ACK && (g.state == GI2C_ADDR || g.state == GI2C_WRITE)) return 0;
  if (g.state == GI2C_READ && g.phase == GP_BITS) {
    int64_t i = g.scl ? (int64_t)g.nbits - 1 : (int64_t)g.nbits;   // held until SCL falls, then the next bit
    if (i >= 0 && i <= 7) return (g.out >> (7 - i)) & 1;
  }
  return -1;
}

void Core::gi2c_finish() {
  GpioI2c &g = gi2c_;
  if (g.state == GI2C_WRITE && g.device && !g.written.empty())
    gi2c_host(I2C_WRITE, 0, g.written.data(), (uint32_t)g.written.size());
  g.written.clear();
  g.device = false;
}

void Core::gi2c_load() {
  GpioI2c &g = gi2c_;
  int32_t got = g.device ? gi2c_host(I2C_READ, 0, nullptr, 0) : -1;
  if (got < 0) {
    g.state = GI2C_IGNORE;
    return;
  }
  g.out = (uint8_t)got;
}

void Core::gi2c_rising() {
  GpioI2c &g = gi2c_;
  if (g.state == GI2C_IDLE || g.state == GI2C_IGNORE) return;
  int out = gi2c_sda_out();
  uint8_t line = g.sda & (out < 0 ? 1 : (uint8_t)out);      // (wired-AND: the CPU's level and the slave's)
  if (g.phase == GP_BITS) {
    if (g.state != GI2C_READ) g.byte = (uint8_t)((g.byte << 1) | line);
    g.nbits++;
  } else if (g.phase == GP_MACK) {
    g.master_ack = line == 0;
  }
}

void Core::gi2c_falling() {
  GpioI2c &g = gi2c_;
  if (g.state == GI2C_IDLE || g.state == GI2C_IGNORE) return;
  if (g.phase == GP_BITS && g.nbits == 8) {
    if (g.state == GI2C_ADDR) {
      g.reading = g.byte & 1;
      g.device = gi2c_host(I2C_ADDRESS, g.byte, nullptr, 0) != 0;
      if (!g.device) g.state = GI2C_IGNORE;
      else g.phase = GP_ACK;
    } else if (g.state == GI2C_WRITE) {
      g.written.push_back(g.byte);
      g.phase = GP_ACK;
    } else {
      g.phase = GP_MACK;            // the master acknowledges (or not) the byte it read
    }
  } else if (g.phase == GP_ACK) {
    g.phase = GP_BITS;
    g.nbits = 0;
    g.byte = 0;
    if (g.reading && g.state == GI2C_ADDR) {
      g.state = GI2C_READ;
      gi2c_load();
    } else if (g.state == GI2C_ADDR) {
      g.state = GI2C_WRITE;
    }
  } else if (g.phase == GP_MACK) {
    g.phase = GP_BITS;
    g.nbits = 0;
    if (g.master_ack) gi2c_load();
    else g.state = GI2C_IGNORE;     // the last byte: the master sends its STOP next
  }
}

void Core::gi2c_levels(uint32_t off, uint32_t levels) {
  GpioI2c &g = gi2c_;
  uint8_t scl = g.scl, sda = g.sda;
  if (g.scl_off == g.sda_off) {
    scl = (levels & g.scl_mask) ? 1 : 0;
    sda = (levels & g.sda_mask) ? 1 : 0;
  } else if (off == g.scl_off) {
    scl = (levels & g.scl_mask) ? 1 : 0;
  } else {
    sda = (levels & g.sda_mask) ? 1 : 0;
  }
  if (scl == g.scl && sda == g.sda) return;
  g.edges++;
  if (scl != g.scl) {
    g.scl = scl;
    g.sda = sda;
    if (scl) {
      if (g.phase == GP_BITS) {
        if (g.state == GI2C_WRITE || g.state == GI2C_ADDR) {
          g.byte = (uint8_t)((g.byte << 1) | sda);
          g.nbits++;
        } else if (g.state == GI2C_READ) {
          g.nbits++;
        }
      } else {
        gi2c_rising();
      }
    } else if (g.phase != GP_BITS || g.nbits == 8) {
      gi2c_falling();
    }
  } else {
    g.sda = sda;
    if (scl && gi2c_sda_out() < 0) {          // the CPU's own edge while SCL is high
      gi2c_finish();
      if (sda) {                              // STOP
        g.state = GI2C_IDLE;
      } else {                                // START (a repeated one ends the transfer before it)
        g.state = GI2C_ADDR;
        g.phase = GP_BITS;
        g.nbits = 0;
        g.byte = 0;
      }
    }
  }
}

// ------------------------------------------------------------------
// Native TM1650 / FD650 2-wire LED + key-scan controller (tm1650_decoder.py)
// ------------------------------------------------------------------
void Core::tm1650_config(bool on, uint32_t scl_off, uint32_t scl_bit, uint32_t sda_off, uint32_t sda_bit, bool cb_all) {
  host_sync();
  Tm1650 &t = tm1650_;
  t.on = on;
  t.cb_all = cb_all;
  t.scl_off = scl_off;
  t.sda_off = sda_off;
  t.scl_mask = 1u << (scl_bit & 31);
  t.sda_mask = 1u << (sda_bit & 31);
  t.scl = t.sda = 1;
  t.state = TM_IDLE;
  t.nbits = 0;
  t.byte = 0;
  t.ack = false;
  t.key_byte = t.answer = t.last_key_value = 0;
  t.has_last_key = false;
  t.key_hold = 0;
  t.tx_serial = 0;
  t.answer_tx = ~0ull;
  t.key_reads_answered = t.key_read_count = 0;
  memset(t.digits, 0, sizeof(t.digits));
  memset(t.last_reg, 0, sizeof(t.last_reg));
  memset(t.last_ok, 0, sizeof(t.last_ok));
  t.bytes.clear();
  t.events = t.tx_count = 0;
}

bool Core::tm1650_chip_owns_sda() const {
  const Tm1650 &t = tm1650_;
  if (t.state != TM_DATA) return false;
  bool key_addr = (!t.bytes.empty() && (t.bytes[0] == 0x4F || t.bytes[0] == 0x49));
  if (t.ack) return t.bytes.size() == 1 || !key_addr;
  return (t.bytes.size() == 1 && key_addr) || t.nbits == 8;
}

int Core::tm1650_sda_in() {
  Tm1650 &t = tm1650_;
  if (!tm1650_chip_owns_sda()) return 1;
  bool key_bus = (t.bytes.size() == 1 && (t.bytes[0] == 0x4F || t.bytes[0] == 0x49));
  if (t.ack || !key_bus) return 0;
  if (t.answer_tx != t.tx_serial) {
    t.answer_tx = t.tx_serial;
    t.key_reads_answered++;
    t.answer = t.key_byte;
    if (t.key_hold > 0) {
      if (--t.key_hold == 0) t.key_byte &= ~0x40u;
    }
  }
  int bit = t.scl ? (8 - (int)t.nbits) : (7 - (int)t.nbits);
  return (bit >= 0 && bit <= 7) ? ((t.answer >> bit) & 1) : 1;
}

void Core::tm1650_decode() {
  Tm1650 &t = tm1650_;
  if (t.bytes.size() < 2) return;
  t.tx_count++;
  uint8_t addr = t.bytes[0], data = t.bytes[1];
  bool notify = t.cb_all;
  if (addr == 0x68 || addr == 0x6A || addr == 0x6C || addr == 0x6E) {
    uint32_t idx = (addr - 0x68) >> 1;
    t.digits[idx] = data;
    notify = true;
  } else if (addr == 0x4F || addr == 0x49) {
    t.key_read_count++;
    if (t.answer_tx == t.tx_serial) data = t.answer;
    if (!t.has_last_key || data != t.last_key_value) {
      t.has_last_key = true;
      t.last_key_value = data;
      notify = true;
    }
  } else {
    notify = true;
  }
  if (notify && tm1650_cb_) {
    uint8_t pair[2] = {addr, data};
    host_sync();
    enter_callback();
    tm1650_cb_(tm1650_user_, 0, ((uint32_t)addr << 8) | data, pair, 2);
    leave_callback();
  }
}

void Core::tm1650_process(uint8_t scl, uint8_t sda, bool scl_changed, bool sda_changed) {
  Tm1650 &t = tm1650_;
  if (t.state == TM_DATA) {
    if (scl_changed && scl == 0) t.ack = false;
    else if (sda_changed && scl == 1 && !scl_changed && tm1650_chip_owns_sda()) return;
  }
  if (t.state == TM_IDLE) {
    if (sda_changed && sda == 0 && scl == 1) {
      t.state = TM_DATA;
      t.nbits = 0;
      t.byte = 0;
      t.bytes.clear();
      t.ack = false;
      t.tx_serial++;
    }
    return;
  }
  if (t.state == TM_DATA) {
    if (scl_changed && scl == 1) {
      if (t.nbits < 8) {
        t.byte = (uint8_t)((t.byte << 1) | sda);
        t.nbits++;
      } else {
        t.bytes.push_back(t.byte);
        t.nbits = 0;
        t.byte = 0;
        t.ack = true;
      }
      return;
    }
    if (sda_changed && sda == 1 && scl == 1) {
      if (!t.bytes.empty()) {
        tm1650_decode();
        t.state = TM_IDLE;
        return;
      }
      t.nbits = 0;
      t.byte = 0;
      return;
    }
    if (sda_changed && sda == 0 && scl == 1) {
      if (!t.bytes.empty()) tm1650_decode();
      t.nbits = 0;
      t.byte = 0;
      t.bytes.clear();
      t.ack = false;
      t.tx_serial++;
      return;
    }
  }
}

void Core::tm1650_levels(uint32_t do_off, uint32_t levels) {
  Tm1650 &t = tm1650_;
  uint32_t mask = (do_off == t.scl_off ? t.scl_mask : 0u) | (do_off == t.sda_off ? t.sda_mask : 0u);
  int slot = (do_off == t.scl_off) ? 0 : 1;
  if (t.last_ok[slot] && ((levels ^ t.last_reg[slot]) & mask) == 0) return;
  if (!t.last_ok[slot] && levels == 0) {
    t.last_reg[slot] = 0;
    t.last_ok[slot] = 1;
    return;
  }
  t.last_reg[slot] = levels;
  t.last_ok[slot] = 1;
  t.events++;
  uint8_t scl = t.scl, sda = t.sda;
  bool scl_changed = false, sda_changed = false;
  if (do_off == t.scl_off) {
    uint8_t nscl = (levels & t.scl_mask) ? 1 : 0;
    if (nscl != t.scl) { scl = nscl; scl_changed = true; }
  }
  if (do_off == t.sda_off) {
    uint8_t nsda = (levels & t.sda_mask) ? 1 : 0;
    if (nsda != t.sda) { sda = nsda; sda_changed = true; }
  }
  if (scl_changed || sda_changed) {
    if (scl_changed && sda_changed) {
      if (scl == 1 && sda == 0 && t.sda == 1) {
        t.scl = scl; t.sda = sda;
        tm1650_process(scl, sda, false, true);
      } else if (scl == 1 && sda == 1 && t.sda == 0) {
        t.scl = scl; t.sda = sda;
        tm1650_process(scl, sda, false, true);
      } else {
        t.scl = scl; t.sda = sda;
      }
    } else {
      tm1650_process(scl, sda, scl_changed, sda_changed);
      t.scl = scl; t.sda = sda;
    }
  }
}

// ------------------------------------------------------------------
// Native TM1628 / PT6312 / uPD16312 3-wire LED/VFD + key-scan controller (tm1628_decoder.py)
// ------------------------------------------------------------------
void Core::tm1628_config(bool on, uint32_t clk_off, uint32_t clk_bit, uint32_t dio_off, uint32_t dio_bit,
                         uint32_t stb_off, uint32_t stb_bit, bool cb_all) {
  host_sync();
  Tm1628 &t = tm1628_;
  t.on = on;
  t.cb_all = cb_all;
  t.clk_off = clk_off;
  t.dio_off = dio_off;
  t.stb_off = stb_off;
  t.clk_mask = 1u << (clk_bit & 31);
  t.dio_mask = 1u << (dio_bit & 31);
  t.stb_mask = 1u << (stb_bit & 31);
  t.prev_clk = 1;
  t.prev_stb = 1;
  t.in_frame = false;
  t.key_read = false;
  t.nbits = 0;
  t.rises = 0;
  t.cur_byte = 0;
  t.frame.clear();
  memset(t.ram, 0, sizeof(t.ram));
  t.leds = 0;
  t.display_on = false;
  t.auto_increment = true;
  t.brightness = 0;
  t.address = 0;
  t.mode = -1;
  memset(t.key_bytes, 0, sizeof(t.key_bytes));
  memset(t.answer, 0, sizeof(t.answer));
  t.key_hold = 0;
  t.frame_serial = 0;
  t.answered_frame = ~0ull;
  t.key_reads_answered = t.frame_count = t.key_read_count = t.events = 0;
  memset(t.reg_val, 0, sizeof(t.reg_val));
  t.dio_levels = 0;
}

int Core::tm1628_dio_in() {
  Tm1628 &t = tm1628_;
  if (!t.key_read || !t.in_frame) return 0;
  if (t.answered_frame != t.frame_serial) {
    t.answered_frame = t.frame_serial;
    t.key_reads_answered++;
    memcpy(t.answer, t.key_bytes, 5);
    if (t.key_hold > 0) {
      if (--t.key_hold == 0) memset(t.key_bytes, 0, 5);
    }
  }
  uint32_t n = t.rises;
  if (n >= 40) return 0;
  return (t.answer[n >> 3] >> (n & 7)) & 1;
}

void Core::tm1628_end_frame() {
  Tm1628 &t = tm1628_;
  bool was_in_frame = t.in_frame;
  t.in_frame = false;
  t.nbits = 0;
  t.cur_byte = 0;
  if (!was_in_frame || t.frame.empty()) {
    t.frame.clear();
    return;
  }
  t.frame_count++;
  uint8_t cmd = t.frame[0];
  uint8_t kind = cmd & 0xC0u;
  bool notify = t.cb_all;
  if (kind == 0x00u) {
    int32_t m = cmd & 0x03;
    if (m != t.mode) { t.mode = m; notify = true; }
  } else if (kind == 0x40u) {
    if (cmd & 0x02u) {
      t.key_read_count++;
    } else if (cmd & 0x01u) {
      if (t.frame.size() > 1 && t.frame[1] != t.leds) {
        t.leds = t.frame[1];
        notify = true;
      }
    } else {
      bool ai = !(cmd & 0x04u);
      if (ai != t.auto_increment) {
        t.auto_increment = ai;
        notify = true;
      }
    }
  } else if (kind == 0xC0u) {
    t.address = cmd & 0x3Fu;
    for (size_t i = 1; i < t.frame.size(); i++) {
      uint32_t addr = t.address + (t.auto_increment ? (uint32_t)(i - 1) : 0u);
      if (addr < 48) {
        if (t.ram[addr] != t.frame[i]) {
          t.ram[addr] = t.frame[i];
          notify = true;
        }
      }
    }
  } else if (kind == 0x80u) {
    bool on = (cmd & 0x08u) != 0;
    uint8_t br = cmd & 0x07u;
    if (on != t.display_on || br != t.brightness) {
      t.display_on = on;
      t.brightness = br;
      notify = true;
    }
  }
  if (notify && tm1628_cb_) {
    host_sync();
    enter_callback();
    tm1628_cb_(tm1628_user_, 0, cmd, t.frame.data(), (uint32_t)t.frame.size());
    leave_callback();
  }
  t.frame.clear();
}

void Core::tm1628_levels(uint32_t do_off, uint32_t levels) {
  Tm1628 &t = tm1628_;
  int slot = (do_off == t.stb_off) ? 0 : (do_off == t.clk_off) ? 1 : 2;
  uint32_t changed = levels ^ t.reg_val[slot];
  if (!changed) return;
  t.reg_val[slot] = levels;
  if (do_off == t.dio_off) t.dio_levels = levels;
  t.events++;
  if (do_off == t.stb_off && (changed & t.stb_mask)) {
    uint8_t stb = (levels & t.stb_mask) ? 1 : 0;
    if (stb == 0) {
      t.in_frame = true;
      t.frame.clear();
      t.nbits = 0;
      t.cur_byte = 0;
      t.key_read = false;
      t.rises = 0;
      t.frame_serial++;
    } else {
      tm1628_end_frame();
    }
    t.prev_stb = stb;
  }
  if (do_off == t.clk_off && (changed & t.clk_mask)) {
    uint8_t clk = (levels & t.clk_mask) ? 1 : 0;
    if (clk && t.in_frame) {
      if (t.key_read) {
        t.rises++;
      } else {
        uint8_t dio = (t.dio_levels & t.dio_mask) ? 1 : 0;
        t.cur_byte |= (uint8_t)(dio << t.nbits);
        if (++t.nbits == 8) {
          uint8_t b = t.cur_byte;
          t.nbits = 0;
          t.cur_byte = 0;
          t.frame.push_back(b);
          if (t.frame.size() == 1 && (b & 0xC3u) == 0x42u) {
            t.key_read = true;
            t.rises = 0;
          }
        }
      }
    }
    t.prev_clk = clk;
  }
}

// ------------------------------------------------------------------
// Native 74HC164 2-wire shift-register + GPIO digit-strobe panel (hc164_decoder.py)
// ------------------------------------------------------------------
void Core::hc164_config(bool on, uint32_t clk_off, uint32_t clk_bit, uint32_t data_off, uint32_t data_bit,
                        const uint32_t *dig_offs, const uint32_t *dig_bits, uint32_t n_digits,
                        bool active_low_segs, bool active_low_digs) {
  host_sync();
  Hc164 &h = hc164_;
  h.on = on;
  h.active_low_segs = active_low_segs;
  h.active_low_digs = active_low_digs;
  h.clk_off = clk_off;
  h.clk_bit = clk_bit & 31;
  h.data_off = data_off;
  h.data_bit = data_bit & 31;
  h.clk_mask = 1u << h.clk_bit;
  h.data_mask = 1u << h.data_bit;
  if (n_digits > 8) n_digits = 8;
  h.n_digits = n_digits;
  uint8_t blank = active_low_segs ? 0xFF : 0x00;
  memset(h.raw, blank, sizeof(h.raw));
  h.sr = blank;
  h.clk = 1;
  h.data = 1;
  bool same_bank = (clk_off == data_off);
  h.all_dig_mask = 0;
  for (uint32_t i = 0; i < n_digits; i++) {
    h.dig_off[i] = dig_offs ? dig_offs[i] : clk_off;
    h.dig_bit[i] = dig_bits ? (dig_bits[i] & 31) : 0;
    h.dig_mask[i] = 1u << h.dig_bit[i];
    h.dig_levels[i] = active_low_digs ? 1 : 0;
    if (h.dig_off[i] != clk_off) same_bank = false;
    h.all_dig_mask |= h.dig_mask[i];
  }
  h.fast_bank = same_bank && (n_digits == 4);
  h.fast_off = clk_off;
  h.watch_mask = h.clk_mask | h.data_mask | h.all_dig_mask;
  h.prev_masked = 0;
  h.prev_masked_ok = false;
  memset(h.prev_levels, 0, sizeof(h.prev_levels));
  memset(h.prev_ok, 0, sizeof(h.prev_ok));
  h.frame_count = h.events = 0;
}

void Core::hc164_levels(uint32_t do_off, uint32_t levels) {
  Hc164 &h = hc164_;
  uint32_t off = do_off & 0xFFFu;
  if (h.fast_bank) {
    if (off != h.fast_off) return;
    uint32_t masked = levels & h.watch_mask;
    if (h.prev_masked_ok && masked == h.prev_masked) return;
    h.prev_masked = masked;
    h.prev_masked_ok = true;
    h.events++;
    uint8_t new_clk = (masked & h.clk_mask) ? 1 : 0;
    if (new_clk && !h.clk) {
      uint8_t bit = (masked & h.data_mask) ? 1 : 0;
      h.sr = (uint8_t)((h.sr << 1) | bit);
    }
    h.clk = new_clk;
    uint32_t dig_bits = masked & h.all_dig_mask;
    uint32_t active = h.active_low_digs ? (h.all_dig_mask ^ dig_bits) : dig_bits;
    int idx = -1;
    for (int i = 0; i < 4; i++) {
      if (active == h.dig_mask[i]) { idx = i; break; }
    }
    if (idx >= 0 && h.raw[idx] != h.sr) {
      h.raw[idx] = h.sr;
      h.frame_count++;
      if (hc164_cb_) {
        host_sync();
        enter_callback();
        hc164_cb_(hc164_user_, 0, (uint32_t)idx, h.raw, h.n_digits);
        leave_callback();
      }
    }
    return;
  }
  uint32_t slot = (off >> 2) & 15u;
  if (!h.prev_ok[slot]) {
    if (levels == 0) {
      h.prev_levels[slot] = 0;
      h.prev_ok[slot] = 1;
      return;
    }
    h.prev_levels[slot] = levels;
    h.prev_ok[slot] = 1;
  } else {
    if (levels == h.prev_levels[slot]) return;
    h.prev_levels[slot] = levels;
  }
  h.events++;
  if (off == h.data_off) h.data = (levels >> h.data_bit) & 1;
  if (off == h.clk_off) {
    uint8_t new_clk = (levels >> h.clk_bit) & 1;
    if (new_clk && !h.clk) h.sr = (uint8_t)((h.sr << 1) | h.data);
    h.clk = new_clk;
  }
  int active_idx = -1, active_count = 0;
  for (uint32_t i = 0; i < h.n_digits; i++) {
    if (off == h.dig_off[i]) h.dig_levels[i] = (levels >> h.dig_bit[i]) & 1;
    uint8_t lvl = h.dig_levels[i];
    bool is_on = h.active_low_digs ? (lvl == 0) : (lvl == 1);
    if (is_on) {
      active_idx = (int)i;
      active_count++;
    }
  }
  if (active_count == 1 && h.raw[active_idx] != h.sr) {
    h.raw[active_idx] = h.sr;
    h.frame_count++;
    if (hc164_cb_) {
      host_sync();
      enter_callback();
      hc164_cb_(hc164_user_, 0, (uint32_t)active_idx, h.raw, h.n_digits);
      leave_callback();
    }
  }
}

// ------------------------------------------------------------------
// Native Lemontree front-panel & EuP standby MCU at I2C 0x28 (lemontree_decoder.py)
// ------------------------------------------------------------------
static uint16_t lt_crc16_xmodem(const uint8_t *data, size_t n) {
  uint16_t crc = 0;
  for (size_t i = 0; i < n; i++) {
    crc ^= (uint16_t)data[i] << 8;
    for (int b = 0; b < 8; b++) {
      if (crc & 0x8000u) crc = (uint16_t)((crc << 1) ^ 0x1021u);
      else crc = (uint16_t)(crc << 1);
    }
  }
  return crc;
}

static bool lt_is_echo_op(uint8_t op) {
  switch (op) {
    case 0x12: case 0x14: case 0x50: case 0x52: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58:
    case 0x5E: case 0x60: case 0x62: case 0x64: case 0x66: case 0x6A: case 0x6B: case 0x6D: case 0x6E:
    case 0x6F: case 0x70: case 0x71: case 0x77: case 0x79: case 0x7A: case 0x83: case 0x84: case 0x85:
    case 0x90: case 0xA0:
      return true;
    default:
      return false;
  }
}

void Core::lemontree_config(bool on, uint32_t scl_off, uint32_t scl_bit, uint32_t sda_off, uint32_t sda_bit,
                            bool cb_all) {
  host_sync();
  Lemontree &lt = lemontree_;
  lt.on = on;
  lt.cb_all = cb_all;
  lt.scl_off = scl_off;
  lt.sda_off = sda_off;
  lt.scl_bit = scl_bit & 31;
  lt.sda_bit = sda_bit & 31;
  lt.scl_mask = 1u << lt.scl_bit;
  lt.sda_mask = 1u << lt.sda_bit;
  lt.scl = lt.sda = 1;
  lt.state = GI2C_IDLE;
  lt.phase = GP_BITS;
  lt.nbits = 0;
  lt.byte = lt.out = lt.cur_addr = 0;
  lt.reading = lt.master_ack = false;
  lt.written.clear();
  memset(lt.raw, 0, sizeof(lt.raw));
  memset(lt.tm1650_digits, 0, sizeof(lt.tm1650_digits));
  lt.has_tm1650 = lt.has_vfd = false;
  memset(lt.vfd_ram, 0, sizeof(lt.vfd_ram));
  uint8_t body[6] = {0x10, 0x04, 1, 0, 0, 0};
  uint16_t crc = lt_crc16_xmodem(body, 6);
  memcpy(lt.resp, body, 6);
  lt.resp[6] = (uint8_t)(crc & 0xFF);
  lt.resp[7] = (uint8_t)(crc >> 8);
  lt.resp_idx = 0;
  lt.key_byte = 0;
  lt.key_hold = 0;
  memset(lt.prev_reg, 0, sizeof(lt.prev_reg));
  memset(lt.prev_ok, 0, sizeof(lt.prev_ok));
  lt.events = lt.frame_count = lt.tx_count = lt.key_read_count = lt.key_reads_answered = 0;
}

int Core::lemontree_sda_out() const {
  const Lemontree &lt = lemontree_;
  if (lt.phase == GP_ACK && (lt.state == GI2C_ADDR || lt.state == GI2C_WRITE)) return 0;
  if (lt.state == GI2C_READ && lt.phase == GP_BITS) {
    int i = lt.scl ? (int)lt.nbits - 1 : (int)lt.nbits;
    if (i >= 0 && i <= 7) return (lt.out >> (7 - i)) & 1;
  }
  return -1;
}

void Core::lemontree_finish_write() {
  Lemontree &lt = lemontree_;
  if (lt.state != GI2C_WRITE || lt.written.empty()) return;
  if (lt.cur_addr == 0x28u) {
    lt.tx_count++;
    uint8_t op = lt.written[0];
    bool notify = lt.cb_all;
    if (op == 0x31u && lt.written.size() >= 6) {
      lt.has_vfd = false;
      lt.has_tm1650 = false;
      if (memcmp(lt.raw, &lt.written[2], 4) != 0 || lt.frame_count == 0) notify = true;
      memcpy(lt.raw, &lt.written[2], 4);
      lt.frame_count++;
    } else if (op == 0x33u && lt.written.size() >= 38 && lt.written[1] == 0x22u && lt.written[2] != 3u) {
      lt.has_tm1650 = false;
      lt.has_vfd = true;
      for (size_t idx = 4; idx < 36; idx += 2) {
        uint8_t addr = lt.written[idx], val = lt.written[idx + 1];
        if (addr >= 0xC0u && addr < 0xD8u) lt.vfd_ram[addr - 0xC0u] = val;
      }
      lt.frame_count++;
      notify = true;
    }
    uint8_t body[6] = {0x10, 0x04, 1, 0, 0, 0};
    if (op == 0x33u && lt.written.size() >= 3 && lt.written[2] == 3u) {
      body[0] = 0x13; body[2] = 0;
    } else if (op == 0x11u) {
      lt.key_read_count++;
      uint8_t key = 0;
      if (lt.key_hold > 0) {
        key = lt.key_byte;
        lt.key_hold--;
        lt.key_reads_answered++;
      }
      body[0] = 0x11; body[2] = key;
    } else if (lt_is_echo_op(op)) {
      body[0] = op; body[2] = 1;
    }
    uint16_t crc = lt_crc16_xmodem(body, 6);
    memcpy(lt.resp, body, 6);
    lt.resp[6] = (uint8_t)(crc & 0xFF);
    lt.resp[7] = (uint8_t)(crc >> 8);
    lt.resp_idx = 0;
    if (notify && lemontree_cb_) {
      host_sync();
      enter_callback();
      lemontree_cb_(lemontree_user_, 0, lt.cur_addr, lt.written.data(), (uint32_t)lt.written.size());
      leave_callback();
    }
  } else if (lt.cur_addr >= 0x34u && lt.cur_addr <= 0x37u && !lt.has_vfd &&
             lt.raw[0] == 0 && lt.raw[1] == 0 && lt.raw[2] == 0 && lt.raw[3] == 0) {
    lt.has_tm1650 = true;
    uint32_t idx = lt.cur_addr - 0x34u;
    bool notify = lt.cb_all || (lt.tm1650_digits[idx] != lt.written[0]) || (lt.frame_count == 0);
    lt.tm1650_digits[idx] = lt.written[0];
    lt.frame_count++;
    if (notify && lemontree_cb_) {
      host_sync();
      enter_callback();
      lemontree_cb_(lemontree_user_, 0, lt.cur_addr, lt.written.data(), (uint32_t)lt.written.size());
      leave_callback();
    }
  }
  lt.written.clear();
}

void Core::lemontree_levels(uint32_t do_off, uint32_t levels) {
  Lemontree &lt = lemontree_;
  int slot = (do_off == lt.scl_off) ? 0 : 1;
  if (!lt.prev_ok[slot]) {
    if (levels == 0) {
      lt.prev_reg[slot] = 0;
      lt.prev_ok[slot] = 1;
      return;
    }
    lt.prev_reg[slot] = levels;
    lt.prev_ok[slot] = 1;
  } else {
    if (levels == lt.prev_reg[slot]) return;
    lt.prev_reg[slot] = levels;
  }
  lt.events++;
  uint8_t nscl = lt.scl, nsda = lt.sda;
  if (do_off == lt.scl_off) nscl = (levels & lt.scl_mask) ? 1 : 0;
  if (do_off == lt.sda_off) nsda = (levels & lt.sda_mask) ? 1 : 0;
  if (nscl != lt.scl) {
    lt.scl = nscl;
    if (nscl) {
      if (lt.state != GI2C_IDLE && lt.state != GI2C_IGNORE) {
        if (lt.phase == GP_BITS) {
          lt.byte = (uint8_t)((lt.byte << 1) | lt.sda);
          lt.nbits++;
        } else if (lt.phase == GP_MACK) {
          lt.master_ack = (lt.sda == 0);
        }
      }
    } else {
      if (lt.state != GI2C_IDLE && lt.state != GI2C_IGNORE) {
        if (lt.phase == GP_BITS && lt.nbits == 8) {
          if (lt.state == GI2C_ADDR) {
            uint8_t addr = lt.byte >> 1;
            lt.reading = (lt.byte & 1) != 0;
            bool is_tm = (addr == 0x24u || (addr >= 0x34u && addr <= 0x37u));
            if (addr != 0x28u && (lt.reading || !is_tm)) {
              lt.state = GI2C_IGNORE;
            } else {
              lt.cur_addr = addr;
              lt.phase = GP_ACK;
            }
          } else if (lt.state == GI2C_WRITE) {
            lt.written.push_back(lt.byte);
            lt.phase = GP_ACK;
          } else if (lt.state == GI2C_READ) {
            lt.phase = GP_MACK;
          }
        } else if (lt.phase == GP_ACK) {
          lt.nbits = 0;
          lt.byte = 0;
          if (lt.state == GI2C_ADDR) {
            if (lt.reading) {
              lt.state = GI2C_READ;
              lt.out = lt.resp[lt.resp_idx & 7u];
              lt.resp_idx++;
            } else {
              lt.state = GI2C_WRITE;
              lt.written.clear();
            }
          }
          lt.phase = GP_BITS;
        } else if (lt.phase == GP_MACK) {
          lt.nbits = 0;
          lt.byte = 0;
          if (lt.master_ack) {
            lt.out = lt.resp[lt.resp_idx & 7u];
            lt.resp_idx++;
            lt.phase = GP_BITS;
          } else {
            lt.state = GI2C_IGNORE;
          }
        }
      }
    }
  }
  if (nsda != lt.sda) {
    lt.sda = nsda;
    if (lt.scl && lemontree_sda_out() < 0) {
      lemontree_finish_write();
      if (!nsda) {
        lt.state = GI2C_ADDR;
        lt.phase = GP_BITS;
        lt.nbits = 0;
        lt.byte = 0;
      } else {
        lt.state = GI2C_IDLE;
      }
    }
  }
}

// ------------------------------------------------------------------
// Native devices: the SPI flash controller
// ------------------------------------------------------------------
void Core::spi_config(bool on, uint8_t *rom, uint8_t *image, uint32_t rom_size) {
  bool changed = on != spi.on;
  spi.on = on;
  spi.rom = rom;
  spi.image = image;
  spi.rom_size = rom_size;
  if (changed)
    for (uint32_t w : flash_windows_) rebuild_pages(w, (uint64_t)w + 0x01000000);
}

void Core::spi_write_ins(uint8_t cmd) {
  spi.ins = cmd;
  spi.resp_idx = 0;
  spi.resp_len = 0;
  spi.commands++;
  switch (cmd) {
    case 0x9F:   // JEDEC ID, padded to 4 for word reads
      spi.resp[0] = spi.jedec[0]; spi.resp[1] = spi.jedec[1]; spi.resp[2] = spi.jedec[2]; spi.resp[3] = 0;
      spi.resp_len = 4;
      break;
    case 0x05:   // status
      spi.resp[0] = spi.status;
      spi.resp_len = 1;
      break;
    case 0xAB: { // electronic ID, repeated
      uint8_t res = (uint8_t)(spi.jedec[2] - 1);
      spi.resp[0] = spi.resp[1] = spi.resp[2] = spi.resp[3] = res;
      spi.resp_len = 4;
      break;
    }
    case 0x90:   // manufacturer / device ID
      spi.resp[0] = spi.jedec[0]; spi.resp[1] = spi.jedec[2]; spi.resp[2] = spi.jedec[0]; spi.resp[3] = spi.jedec[2];
      spi.resp_len = 4;
      break;
  }
  if (cmd == 0x06 || cmd == 0x04) {
    spi.wel = cmd == 0x06;
    spi.status = spi.wel ? (uint8_t)(spi.status | 0x02) : (uint8_t)(spi.status & ~0x02);
  }
}

uint64_t Core::spi_flash_load(uint32_t pa, uint32_t size) {
  (void)pa;
  uint64_t v = 0;
  for (uint32_t i = 0; i < size; i++) {
    uint8_t b = spi.resp_idx < spi.resp_len ? spi.resp[spi.resp_idx++] : 0;
    v |= (uint64_t)b << (8 * i);
  }
  return v;
}

void Core::spi_flash_store(uint32_t pa, uint32_t size, uint64_t value) {
  if (spi_passthrough() || !spi.rom_size) return;    // (normal mode: a store to the window does nothing)
  uint32_t off = flash_offset(pa);
  uint8_t cmd = spi.ins;
  auto set_wel = [&](bool w) {
    spi.wel = w;
    spi.status = w ? (uint8_t)(spi.status | 0x02) : (uint8_t)(spi.status & ~0x02);
  };
  switch (cmd) {
    case 0x06: case 0x04: set_wel(cmd == 0x06); return;
    case 0x01:                                    // WRSR
      if (spi.wel) { spi.status = (uint8_t)value; set_wel(false); }
      return;
    case 0xC7: case 0x60: case 0xD8: case 0x52: case 0x20: {
      uint32_t start = 0, len = spi.rom_size;
      if (cmd == 0xD8) len = 0x10000;
      else if (cmd == 0x52) len = 0x8000;
      else if (cmd == 0x20) len = 0x1000;
      if (len != spi.rom_size) start = off & ~(len - 1);
      if (start + len > spi.rom_size) len = spi.rom_size - start;
      memset(spi.rom + start, 0xFF, len);
      if (spi.image) memset(spi.image + start, 0xFF, len);
      spi.erases++;
      set_wel(false);
      return;
    }
    case 0x02: case 0x32: case 0xAD:              // page program (quad), AAI: bits only clear
      for (uint32_t i = 0; i < size; i++) {
        uint32_t o = off + i;
        if (o >= spi.rom_size) break;
        uint8_t b = (uint8_t)(value >> (8 * i));
        if (spi.image) spi.image[o] &= b;
        spi.rom[o] = spi.image ? spi.image[o] : (uint8_t)(spi.rom[o] & b);
      }
      spi.programs++;
      if (cmd != 0xAD) set_wel(false);
      return;
  }
}

uint64_t Core::native_dev_load(uint32_t off, uint32_t size) {
  uint64_t v = 0;
  memcpy(&v, dev_buf_ + off, size);
  for (uint32_t i = 0; i < size; i++) {
    uint32_t o = off + i;
    if ((o & 0xFFFFFFF0u) == 0x00090u || (o & 0xFFFFFFF0u) == 0x2E090u) {
      uint8_t b;
      switch (o & 0xF) {
        case 0x8: b = spi.ins; break;
        case 0x9: b = spi.fmt; break;
        case 0xA: b = spi.dum; break;
        case 0xB: b = spi.cfg; break;
        default: continue;
      }
      v = (v & ~(0xFFull << (8 * i))) | ((uint64_t)b << (8 * i));
    }
  }
  return v;
}

void Core::native_dev_store(uint32_t off, uint32_t size, uint64_t value) {
  for (uint32_t i = 0; i < size; i++) {
    uint32_t o = off + i;
    uint8_t b = (uint8_t)(value >> (8 * i));
    if ((o & 0xFFFFFFF0u) == 0x00090u || (o & 0xFFFFFFF0u) == 0x2E090u) {
      switch (o & 0xF) {
        case 0x8: spi_write_ins(b); break;
        case 0x9: spi.fmt = b; break;
        case 0xA: spi.dum = b; break;
        case 0xB: spi.cfg = b; break;
      }
    }
  }
  memcpy(dev_buf_ + off, &value, size);
}

// ------------------------------------------------------------------
// Hooks
// ------------------------------------------------------------------
int Core::hook_add(int type, void *cb, void *user, uint64_t begin, uint64_t end, uint64_t *id) {
  Hook h{};
  h.id = next_hook_id_++;
  h.type = type;
  h.cb = cb;
  h.user = user;
  h.begin = begin;
  h.end = end;
  hooks_.push_back(h);
  *id = h.id;
  rebuild_hook_pages();
  return ERR_OK;
}

int Core::hook_del(uint64_t id) {
  for (auto &h : hooks_)
    if (h.id == id) h.dead = true;
  if (!running_ || !in_callback) {
    hooks_.erase(std::remove_if(hooks_.begin(), hooks_.end(), [](const Hook &h) { return h.dead; }), hooks_.end());
  }
  rebuild_hook_pages();
  return ERR_OK;
}

void Core::rebuild_hook_pages() {
  flush_blocks();      // (cached blocks end before hooked instructions: hooks moved)
  memset(code_hook_page_, 0, NPAGES);
  uint8_t *old_mem = new uint8_t[NPAGES];
  memcpy(old_mem, mem_hook_page_, NPAGES);
  memset(mem_hook_page_, 0, NPAGES);
  code_hook_all_ = false;
  for (auto &h : hooks_) {
    if (h.dead) continue;
    if (h.type & HOOK_CODE) {
      if (h.begin > h.end) {
        code_hook_all_ = true;
      } else {
        for (uint64_t p = h.begin >> 12; p <= (h.end >> 12) && p < NPAGES; p++) code_hook_page_[p] |= 1;
      }
    }
    uint8_t bits = (h.type & HOOK_MEM_READ ? 1 : 0) | (h.type & HOOK_MEM_WRITE ? 2 : 0) | (h.type & HOOK_MEM_FETCH ? 4 : 0);
    if (bits) {
      if (h.begin > h.end) {
        for (uint32_t p = 0; p < NPAGES; p++) mem_hook_page_[p] |= bits;
      } else {
        for (uint64_t p = h.begin >> 12; p <= (h.end >> 12) && p < NPAGES; p++) mem_hook_page_[p] |= bits;
      }
    }
  }
  if (code_hook_all_) memset(code_hook_page_, 1, NPAGES);
  for (uint32_t b : breakpoints) code_hook_page_[b >> 12] |= 2;
  // pages whose memory hooks changed get their fast pointers again
  for (uint32_t p = 0; p < NPAGES; p++)
    if (old_mem[p] != mem_hook_page_[p]) rebuild_pages((uint64_t)p << 12, ((uint64_t)p + 1) << 12);
  delete[] old_mem;
}

// The code hooks for the instruction at address; true if it must not run now (a
// hook stopped the emulation or moved the PC).
bool Core::code_hooks(uint32_t address, uint32_t size) {
  if (code_hook_page_[address >> 12] & 2) {
    if (check_breakpoint(address)) return true;
  }
  if (!(code_hook_page_[address >> 12] & 1)) return false;
  uint32_t pc0 = pc;
  bool m0 = m16;
  pc_written = false;
  for (size_t i = 0; i < hooks_.size(); i++) {
    Hook &h = hooks_[i];
    if (h.dead || !(h.type & HOOK_CODE)) continue;
    if (h.begin <= h.end && (address < h.begin || address > h.end)) continue;
    host_sync();
    enter_callback();
    ((CodeHookCb)h.cb)(h.user, address, size, m0 ? 1u : 0u);
    leave_callback();
    if (stop_request_) return true;
    if (pc_written) {
      pc_written = false;
      if (pc != pc0 || m16 != m0) return true;
    }
  }
  return false;
}

bool Core::code_hook_at(uint32_t address) const {
  uint8_t f = code_hook_page_[address >> 12];
  if (!f) return false;
  if ((f & 2) && std::find(breakpoints.begin(), breakpoints.end(), address) != breakpoints.end()) return true;
  if (f & 1) {
    if (code_hook_all_) return true;
    for (const Hook &h : hooks_)
      if (!h.dead && (h.type & HOOK_CODE) && (h.begin > h.end || (address >= h.begin && address <= h.end)))
        return true;
  }
  return false;
}

bool Core::check_breakpoint(uint32_t address) {
  if (step_over_bp_once) return false;
  if (std::find(breakpoints.begin(), breakpoints.end(), address) != breakpoints.end()) {
    stop_reason_ = STOP_BREAKPOINT;
    return true;
  }
  return false;
}

// ------------------------------------------------------------------
// Registers
// ------------------------------------------------------------------
int Core::reg_read(int id, uint64_t *value) {
  if (id >= REG_GPR0 && id < REG_GPR0 + 32) { *value = gpr[id - REG_GPR0]; return ERR_OK; }
  switch (id) {
    case REG_PC: *value = pc; return ERR_OK;          // (Unicorn: always even)
    case REG_HI: *value = hi; return ERR_OK;
    case REG_LO: *value = lo; return ERR_OK;
    case REG_CP0_STATUS: *value = status; return ERR_OK;
    case REG_CP0_CONFIG3: *value = cp0[16][3]; return ERR_OK;
    case REG_CP0_USERLOCAL: *value = cp0[4][2]; return ERR_OK;
    case REG_FIR: *value = fir; return ERR_OK;
    case REG_FCSR: *value = fcsr; return ERR_OK;
  }
  if (id >= REG_F0 && id < REG_F0 + 32) { *value = fpr[id - REG_F0]; return ERR_OK; }
  if (id >= REG_CP0_BASE && id < REG_CP0_BASE + 256) {
    int rd = (id - REG_CP0_BASE) >> 3, sel = (id - REG_CP0_BASE) & 7;
    // (a plain read: no timer side effect for Count / Cause)
    switch (rd * 8 + sel) {
      case 9 * 8: *value = count_now(); return ERR_OK;
      case 13 * 8: *value = cause_value(); return ERR_OK;
    }
    *value = cp0_read(rd, sel);
    return ERR_OK;
  }
  *value = 0;
  return ERR_OK;   // (Unicorn returns 0 for registers it does not model)
}

int Core::reg_write(int id, uint64_t value) {
  uint32_t v = (uint32_t)value;
  if (id >= REG_GPR0 && id < REG_GPR0 + 32) {
    if (id != REG_GPR0) gpr[id - REG_GPR0] = v;
    return ERR_OK;
  }
  switch (id) {
    case REG_PC:
      if (in_callback && ds_active) return ERR_OK;   // (Unicorn ignores a hook's PC write in a delay slot)
      pc = v & ~1u;
      m16 = v & 1;
      ds_active = false;
      pc_written = true;
      invalidate_fetch();
      poke_events();
      return ERR_OK;
    case REG_HI: hi = v; return ERR_OK;
    case REG_LO: lo = v; return ERR_OK;
    case REG_CP0_STATUS: status = v; poke_events(); return ERR_OK;   // (raw: the host's own value)
    case REG_CP0_CONFIG3: return ERR_OK;
    case REG_CP0_USERLOCAL: cp0[4][2] = v; return ERR_OK;
    case REG_FIR: return ERR_OK;
    case REG_FCSR: fcsr = v; return ERR_OK;
  }
  if (id >= REG_F0 && id < REG_F0 + 32) { fpr[id - REG_F0] = value; return ERR_OK; }
  if (id >= REG_CP0_BASE && id < REG_CP0_BASE + 256) {
    int rd = (id - REG_CP0_BASE) >> 3, sel = (id - REG_CP0_BASE) & 7;
    switch (rd * 8 + sel) {      // raw stores of the state the host shadows
      case 12 * 8: status = v; break;
      case 13 * 8: cause = v; break;
      case 14 * 8: epc = v; break;
      case 15 * 8 + 1: ebase = v; break;
      case 11 * 8: compare = v; break;
      case 9 * 8: count_base = v; count_icount = icount; break;
      case 30 * 8: error_epc = v; break;
      case 8 * 8: badvaddr = v; break;
      default: cp0[rd][sel] = v; break;
    }
    poke_events();
    return ERR_OK;
  }
  return ERR_OK;
}

// ------------------------------------------------------------------
// CP0, the timer, interrupts
// ------------------------------------------------------------------
void Core::set_count_ratio(uint64_t num, uint64_t den) {
  if (!den) return;
  count_base = count_now();
  count_icount = icount;
  if (!num) {   // a frozen Count (raw Unicorn reads 0: the lockstep tools)
    cnum = 0;
    cden = 1;
    timer_check_at = ~0ull;
    poke_events();
    return;
  }
  uint64_t a = num, b = den;
  while (b) { uint64_t t = a % b; a = b; b = t; }
  cnum = num / a;
  cden = den / a;
  timer_check_at = 0;
  poke_events();
}

uint32_t Core::count_now() const {
  return count_at(icount);
}

void Core::timer_update() {
  if (!timer_enabled) {
    timer_check_at = ~0ull;   // (the anchor stays: a Compare passed meanwhile fires when switched on)
    return;
  }
  uint32_t now = count_now();
  if (timer_armed && !ti) {
    uint32_t d_cmp = compare - timer_anchor;
    if (d_cmp && d_cmp <= (uint32_t)(now - timer_anchor)) ti = true;
  }
  timer_anchor = now;
  if (ti || !timer_armed || !cnum) {
    timer_check_at = ~0ull;
  } else {
    uint64_t d = (uint32_t)(compare - now);
    if (!d) d = 1ull << 32;
    uint64_t k = (d * cden + cnum - 1) / cnum;
    timer_check_at = icount + (k ? k : 1);
  }
}

void Core::set_timer_enabled(bool on) {
  timer_enabled = on;
  if (!on) ti = false;
  timer_check_at = 0;
  poke_events();
}

void Core::write_count(uint32_t value) {
  timer_update();
  count_base = value;
  count_icount = icount;
  timer_anchor = value;
  count_observed = value;
  count_observed_valid = true;
  timer_check_at = 0;
  poke_events();
}

void Core::write_compare(uint32_t value) {
  uint32_t now = count_now();
  timer_update();
  compare = value;
  ti = false;
  timer_armed = true;
  // late-Compare rule (simulator._write_compare): the crossing is checked from
  // the Count the guest last read, if recent
  if (count_observed_valid && (uint32_t)(now - count_observed) <= 0x40000000u) timer_anchor = count_observed;
  count_observed_valid = false;
  timer_update();
  poke_events();
}

void Core::set_ic(uint32_t status_off, uint32_t enable_off, uint32_t ic_base) {
  ic_status_off_ = status_off;
  ic_enable_off_ = enable_off;
  ic_base_ = ic_base;
  poke_events();
}

void Core::ic_set_line(uint32_t line, bool on) {
  uint32_t st_off = ic_status_off_ + 4u * (line >> 5);
  uint32_t b = 1u << (line & 31u);
  if (on) {
    if (line < 64u) ic_lines_ |= (1ull << line);
    else if (line < 128u) ic_lines_hi_ |= (1ull << (line - 64u));
    if (dev_buf_ && st_off + 4u <= dev_size_) {
      uint32_t cur;
      memcpy(&cur, dev_buf_ + st_off, 4);
      cur |= b;
      memcpy(dev_buf_ + st_off, &cur, 4);
    }
  } else {
    if (line < 64u) ic_lines_ &= ~(1ull << line);
    else if (line < 128u) ic_lines_hi_ &= ~(1ull << (line - 64u));
    if (dev_buf_ && st_off + 4u <= dev_size_) {
      uint32_t cur;
      memcpy(&cur, dev_buf_ + st_off, 4);
      cur &= ~b;
      memcpy(dev_buf_ + st_off, &cur, 4);
    }
  }
  poke_events();
}

void Core::ic_set_line_enabled(uint32_t line, bool on) {
  for (int p = 0; p < 2; p++) {
    Core *c = (p == 0) ? this : peer_core_;
    if (!c || !c->dev_buf_) continue;
    bool on_here = false;
    if (on) {
      uint32_t en_off = c->ic_enable_off_ + 4u * (line >> 5);
      if (en_off + 4u <= c->dev_size_) {
        uint32_t enables;
        memcpy(&enables, c->dev_buf_ + en_off, 4);
        on_here = ((enables >> (line & 31u)) & 1u) != 0;
      }
    }
    bool cur_on = (line < 64u) ? (((c->ic_lines_ >> line) & 1ull) != 0)
                               : (line < 128u && (((c->ic_lines_hi_ >> (line - 64u)) & 1ull) != 0));
    if (on_here || cur_on) c->ic_set_line(line, on_here);
  }
}

bool Core::vpo_rule_store(uint32_t off, uint32_t size, uint64_t value) {
  uint32_t base = off & ~3u;
  if (base + 4u > dev_size_) return true;
  uint32_t old_word;
  memcpy(&old_word, dev_buf_ + base, 4);
  uint32_t shift = (off & 3u) * 8u;
  uint32_t mask = (size >= 4 ? 0xFFFFFFFFu : ((1u << (size * 8u)) - 1u)) << shift;
  uint32_t written = ((uint32_t)value << shift) & mask;
  uint32_t word = (old_word & ~mask) | written;
  for (uint32_t k = 0; k < mmio_rule_count_; k++) {
    const MmioRule &r = mmio_rules_[k];
    if ((r.flags & RULE_VPO_WRITE) && r.offset == base) {
      uint32_t field_mask = (r.and_mask & 1u ? (1u << 18) : 0u) | (r.and_mask & 2u ? (1u << 19) : 0u);
      uint32_t status = ((old_word >> 8) & 0x3Fu) & ~((written >> 8) & 0x3Fu);
      uint32_t landed = (word & ~0x3F00u & ~field_mask) | (status << 8) | (old_word & field_mask);
      memcpy(dev_buf_ + base, &landed, 4);
      ic_set_line_enabled(r.req_mask, (status & landed & 0x3Fu) != 0);
      return true;
    }
    if ((r.flags & RULE_VPO_M36F_WRITE) && (base == 0x6288u || base == 0x6488u)) {
      uint32_t status = (old_word & 0x1FFu) & ~(written & 0x1FFu);
      uint32_t landed = (word & ~0x1FFu) | status;
      memcpy(dev_buf_ + base, &landed, 4);
      uint32_t w0 = 0, w1 = 0;
      if (0x648Cu <= dev_size_) {
        memcpy(&w0, dev_buf_ + 0x6288u, 4);
        memcpy(&w1, dev_buf_ + 0x6488u, 4);
      }
      bool active = (((w0 & (w0 >> 16)) | (w1 & (w1 >> 16))) & 0x1FFu) != 0;
      ic_set_line_enabled(r.req_mask, active);
      return true;
    }
    if ((r.flags & RULE_VE_STATUS_WRITE) && r.offset == base) {
      uint32_t landed = old_word & ~written;
      memcpy(dev_buf_ + base, &landed, 4);
      if (!landed) ic_set_line_enabled(r.req_mask, false);
      return true;
    }
    if ((r.flags & RULE_GE3602_WRITE) && (base == r.offset || base == r.offset + 8u)) {
      if (base == r.offset + 8u) {
        if ((off & 3u) == 0 && size == 4u) {
          uint32_t landed = old_word & ~(uint32_t)value;
          memcpy(dev_buf_ + base, &landed, 4);
        } else {
          memcpy(dev_buf_ + off, &value, size);
        }
        return true;
      }
      if ((off & 3u) != 0 || size != 4u || (uint32_t)value != 2u) {
        memcpy(dev_buf_ + off, &value, size);
        return true;
      }
      if (ge_.render) {
        if (!ge_.ram || r.offset + 0x14u > dev_size_) return false;
        uint32_t hi = 0, lo = 0;
        memcpy(&hi, dev_buf_ + r.offset + 0x0Cu, 4);
        memcpy(&lo, dev_buf_ + r.offset + 0x10u, 4);
        uint32_t addr = ((hi & 0xFu) << 24) | (lo & 0xFFFFFFu);
        uint32_t m = lo >> 24;
        uint64_t cmds = 0;
        if (ali_gfx::ge_m3602_run_cpp(ge_.ram, ge_.ram_size, &addr, &m, &cmds) != 0) {
          ge_.m3602_cmds += cmds;
          uint32_t nhi = (hi & ~0xFu) | ((addr >> 24) & 0xFu);
          uint32_t nlo = (addr & 0xFFFFFFu) | (m << 24);
          memcpy(dev_buf_ + r.offset + 0x0Cu, &nhi, 4);
          memcpy(dev_buf_ + r.offset + 0x10u, &nlo, 4);
          return false;
        }
        ge_.m3602_cmds += cmds;
      }
      ge_.ops++;
      uint32_t st = 0, z = 0;
      if (r.offset + 0x0Cu <= dev_size_) {
        memcpy(&st, dev_buf_ + r.offset + 8u, 4);
        st |= 2u;
        memcpy(dev_buf_ + r.offset + 8u, &st, 4);
        memcpy(dev_buf_ + r.offset + 4u, &z, 4);
      }
      memcpy(dev_buf_ + off, &value, size);
      return true;
    }
    if ((r.flags & RULE_OSD_PAL_WRITE) && (off == 0x41ACu || off == 0x41C8u)) {
      if (size == 4u) {
        uint32_t w = (uint32_t)value;
        osd_pal_[off == 0x41C8u ? 1 : 0][w >> 24] = 0x80000000u | (w & 0xFFFFFFu);
      }
      memcpy(dev_buf_ + off, &value, size);
      return true;
    }
    if ((r.flags & RULE_SDRAM_CMD) && off == r.offset) {
      uint64_t landed = value & ~3ull;
      memcpy(dev_buf_ + off, &landed, size);
      return true;
    }
    if ((r.flags & RULE_TRNG_WRITE) && off == r.offset) {
      if (value & 1ull) {
        trng_state_ = trng_state_ * 6364136223846793005ull + 1442695040888963407ull;
        uint64_t out = trng_state_ ^ (trng_state_ >> 17);
        if (r.offset + 16u <= dev_size_) memcpy(dev_buf_ + r.offset + 8u, &out, 8);
        uint64_t landed = value & ~1ull;
        memcpy(dev_buf_ + off, &landed, size);
      } else {
        memcpy(dev_buf_ + off, &value, size);
      }
      return true;
    }
  }
  memcpy(dev_buf_ + off, &value, size);
  return true;
}

void Core::scb_sync_irq(int idx) {
  ScbI2c &s = scb_[idx];
  if (s.ic_line != 0xFFu) {
    bool active = ((s.flags & s.ier) != 0) || ((s.isr1 & s.ier1) != 0);
    if (active != s.irq_active) {
      s.irq_active = active;
      ic_set_line(s.ic_line, active);
    }
  }
}

uint8_t Core::scb_load_byte(int idx, uint32_t o, uint32_t abs_off) {
  ScbI2c &s = scb_[idx];
  if (o == 0x00u) return s.control;
  if (o == 0x01u) return s.status | (((s.ier || s.ier1) && s.rx_head == s.rx_tail) ? 0x01u : 0x00u);
  if (o == 0x02u) return s.ier;
  if (o == 0x03u) return s.flags;
  if (o == 0x0Cu) {
    uint16_t avail = s.rx_tail - s.rx_head;
    return (uint8_t)(0x80u | (avail > 0x1Fu ? 0x1Fu : avail));
  }
  if (o == 0x10u) {
    if (s.rx_head < s.rx_tail) return s.rx[s.rx_head++ & 0xFFu];
    return 0xFFu;
  }
  if (o == 0x14u) return 0u;
  if (o == 0x20u) return s.ier1;
  if (o == 0x21u) return s.isr1;
  return (dev_buf_ && abs_off < dev_size_) ? dev_buf_[abs_off] : 0u;
}

uint64_t Core::scb_load(uint32_t off, uint32_t size) {
  int idx = scb_slot(off);
  if (idx < 0) {
    uint64_t v = 0;
    if (dev_buf_ && off + size <= dev_size_) memcpy(&v, dev_buf_ + off, size);
    return v;
  }
  uint32_t base = off & 0xFFFF00u;
  uint64_t out = 0;
  for (uint32_t i = 0; i < size; i++) {
    uint8_t b = scb_load_byte(idx, (off - base) + i, off + i);
    if (dev_buf_ && off + i < dev_size_) dev_buf_[off + i] = b;
    out |= (uint64_t)b << (8 * i);
  }
  return out;
}

void Core::scb_store(uint32_t off, uint32_t size, uint64_t value) {
  if (dev_buf_ && off + size <= dev_size_) memcpy(dev_buf_ + off, &value, size);
  int idx = scb_slot(off);
  if (idx < 0) return;
  ScbI2c &s = scb_[idx];
  uint32_t base = off & 0xFFFF00u;
  for (uint32_t i = 0; i < size; i++) {
    uint8_t b = (uint8_t)(value >> (8 * i));
    uint32_t o = (off - base) + i;
    if (o == 0x00u) {
      s.control = b & ~0x01u;
      if (b & 0x01u) {
        if (dev_cb_) {
          if (ALI_UNLIKELY(prof_dev_ != nullptr)) (*prof_dev_)[cur_pc_ | (m16 ? 1u : 0u)]++;
          if (!gpio_dev_drains_) host_sync();
          enter_callback();
          dev_cb_(dev_user_, 1, base, 1, b);
          leave_callback();
        }
      }
    } else if (o == 0x01u) {
      s.status = (b == 0u) ? 0u : (s.status & ~b);
    } else if (o == 0x02u) {
      s.ier = b;
      scb_sync_irq(idx);
    } else if (o == 0x03u) {
      s.flags &= ~b;
      scb_sync_irq(idx);
    } else if (o == 0x04u) {
      s.slave = b;
    } else if (o == 0x05u) {
      s.sub[0] = b;
    } else if (o == 0x0Cu) {
      s.length = b & 0x1Fu;
      if (!(b & 0x80u)) {
        s.tx_len = 0;
        s.rx_head = s.rx_tail = 0;
      }
    } else if (o == 0x10u) {
      if (s.tx_len < 256u) s.tx[s.tx_len++] = b;
    } else if (o == 0x20u) {
      s.ier1 = b;
      scb_sync_irq(idx);
    } else if (o == 0x21u) {
      s.isr1 &= ~b;
      scb_sync_irq(idx);
    } else if (o == 0x23u) {
      s.length_hi = b;
    } else if (o == 0x24u) {
      s.sub_extra = b & 3u;
    } else if (o >= 0x25u && o <= 0x27u) {
      s.sub[o - 0x24u] = b;
    }
  }
}

bool Core::ge_store(uint32_t off, uint32_t size, uint64_t value) {
  uint32_t roff = off & 0xFFFu;
  if (roff == 0x004u) {
    uint32_t cmd = (uint32_t)value;
    uint32_t done = (cmd == 1u) ? 4u : (cmd == 2u) ? 1u : (cmd == 3u) ? 2u : 0u;
    if (done) {
      if (ge_.render) {
        uint32_t base = off & ~0xFFFu;
        if (!ge_.ram || base + 0x100u > dev_size_) return false;
        uint32_t live_regs[64];
        memcpy(live_regs, dev_buf_ + base, 256);
        if (cmd == 1u) {
          if (ali_gfx::ge_m36f_exec_one(ge_.ram, ge_.ram_size, ge_.phys_mask, live_regs, &ge_.primitives) != 0)
            return false;
        } else {
          uint32_t o = (cmd == 2u) ? 0x10u : 0x18u;
          uint32_t start = live_regs[o >> 2] & 0x1FFFFFFFu;
          uint32_t end = live_regs[(o >> 2) + 1u] & 0x1FFFFFFFu;
          if (start <= end && end < start + 0x400000u && (uint64_t)end + 4ull <= ge_.ram_size) {
            if ((start & 3u) != 0) return false;
            uint32_t n_words = ((end + 4u) - start) >> 2;
            const uint32_t *words = (const uint32_t *)(ge_.ram + start);
            uint32_t reached = ali_gfx::ge_m36f_run_list_cpp(
                ge_.ram, ge_.ram_size, ge_.phys_mask, words, n_words, ge_.regs, live_regs, &ge_.primitives);
            if (reached < n_words) {
              ge_.resume_valid = true;
              ge_.resume_idx = reached;
              return false;
            }
          }
        }
      }
      ge_.ops++;
      ge_.status |= done;
      ic_set_line(ge_.ic_line, true);
    }
  } else if (roff == 0x008u) {
    ge_.status &= ~(uint32_t)value;
    if (!ge_.status) ic_set_line(ge_.ic_line, false);
  }
  memcpy(dev_buf_ + off, &value, size);
  icount += host_access_cost;
  return true;
}

bool Core::ic_ip3() const {
  if (!dev_buf_) return false;
  if (ic_lines_) {
    uint64_t en = 0;
    if (ic_enable_off_ + 8 <= dev_size_) memcpy(&en, dev_buf_ + ic_enable_off_, 8);
    if (ic_lines_ & en) return true;
  }
  if (ic_lines_hi_) {
    uint64_t en = 0;
    if (ic_enable_off_ + 16 <= dev_size_) memcpy(&en, dev_buf_ + ic_enable_off_ + 8, 8);
    if (ic_lines_hi_ & en) return true;
  }
  if (doorbell_off_ >= 0 && (uint32_t)doorbell_off_ < dev_size_ && ic_base_ + 0xF < dev_size_) {
    uint32_t ring = (uint32_t)dev_buf_[doorbell_off_] << doorbell_shift_;
    if (ring & dev_buf_[ic_base_ + 0xF] & 0xC0) return true;
  }
  return false;
}

uint32_t Core::cause_value() const {
  uint32_t v = cause;
  if (ti) v |= 0x40008000u;
  if (uart_ip3 || ic_ip3()) v |= 0x800u;
  return v;
}

bool Core::irq_deliverable() const {
  uint32_t s = status;
  if ((s & 7) != 1) return false;
  if (ti && (s & 0x8000)) return true;
  if (cause & s & 0x300) return true;
  if ((s & 0x800) && ic_ip3()) return true;
  return false;
}

uint32_t Core::enter_interrupt(uint32_t epc_value) {
  slow_++;            // (no loop pass runs across an interrupt)
  epc = epc_value;
  cause &= ~0x8000007Cu;
  status |= 2;
  bool bev = status & 0x00400000u, iv = cause & 0x00800000u;
  if (ti && (status & 0x8000)) timer_irqs++;
  if ((status & 0x800) && !uart_ip3 && ic_ip3()) ic_irqs++;
  return (bev ? 0xBFC00200u : (ebase & 0xFFFFF000u)) + (iv ? 0x200u : 0x180u);
}

uint32_t Core::cp0_read(int rd, int sel) {
  switch (rd * 8 + sel) {
    case 8 * 8: return badvaddr;
    case 9 * 8: {
      uint32_t v = count_now();
      uint32_t d_cmp = compare - timer_anchor;
      if (timer_enabled && timer_armed && !ti && timer_check_at != 0 && d_cmp != 0 &&
          (uint32_t)(v - timer_anchor) < d_cmp) {
        timer_anchor = v;
      } else {
        timer_update();
      }
      count_observed = v;
      count_observed_valid = true;
      return v;
    }
    case 11 * 8: return compare;
    case 12 * 8: return status;
    case 13 * 8: timer_update(); return cause_value();
    case 14 * 8: return epc;
    case 15 * 8 + 1: return ebase;
    case 17 * 8: return lladdr >> 4;
    case 30 * 8: return error_epc;
  }
  return cp0[rd & 31][sel & 7];
}

void Core::cp0_write(int rd, int sel, uint32_t v) {
  switch (rd * 8 + sel) {
    case 0 * 8: cp0[0][0] = (cp0[0][0] & 0x80000000u) | (v & 0xF); return;      // Index
    case 2 * 8: case 3 * 8: cp0[rd][0] = v & 0x03FFFFFF; return;                // EntryLo0/1
    case 4 * 8: cp0[4][0] = v & 0xFF800000u; return;                            // Context
    case 5 * 8: cp0[5][0] = v & 0x1FFFE000u; return;                            // PageMask
    case 6 * 8: cp0[6][0] = v & 0xF; cp0[1][0] = 0xF; return;                   // Wired
    case 7 * 8: cp0[7][0] = v & 0xF; return;                                    // HWREna
    case 9 * 8: write_count(v); return;
    case 10 * 8: cp0[10][0] = v & 0xFFFFE0FFu; return;                          // EntryHi
    case 11 * 8: write_compare(v); return;
    case 12 * 8: status = (status & ~0x3678FF1Fu) | (v & 0x3678FF1Fu); poke_events(); return;
    case 12 * 8 + 1: cp0[12][1] = 0xE0000000u | (v & 0x3E0); return;           // IntCtl
    case 12 * 8 + 2: cp0[12][2] = v & 0xF3C0; return;
    case 12 * 8 + 3: cp0[12][3] = v; return;
    case 13 * 8: cause = (cause & ~0x08C00300u) | (v & 0x08C00300u); poke_events(); return;
    case 14 * 8: epc = v; return;
    case 15 * 8 + 1: ebase = 0x80000000u | (v & 0x3FFFF000u) | (ebase & 0x3FFu); return;
    case 16 * 8: cp0[16][0] = (cp0[16][0] & ~7u) | (v & 7u); return;           // Config0.K0
    case 18 * 8: cp0[18][0] = v & 0xFFFFFFF8u; return;
    case 19 * 8: cp0[19][0] = (v & 0x40FF0FF8u); return;
    case 23 * 8: cp0[23][0] = (cp0[23][0] & ~0x53308120u) | (v & 0x53308120u); return;
    case 24 * 8: cp0[24][0] = v; return;
    case 25 * 8: cp0[25][0] = v & 0x7FF; return;
    case 26 * 8: cp0[26][0] = v & 0x30000000u; return;
    case 28 * 8: cp0[28][0] = v & 0xFFFFFCF6u; return;
    case 28 * 8 + 1: case 29 * 8: case 29 * 8 + 1: case 31 * 8: cp0[rd][sel] = v; return;
    case 30 * 8: error_epc = v; return;
  }
  // read-only / unmodelled: ignored
}

void Core::eret() {
  if (status & 4) {
    pc = error_epc & ~1u;
    m16 = error_epc & 1;
    status &= ~4u;
  } else {
    pc = epc & ~1u;
    m16 = epc & 1;
    status &= ~2u;
  }
  llbit = false;
  lladdr = 1;
  bool uart_done = uart_ip3;
  uart_ip3 = false;
  if (uart_done && event_cb) {
    enter_callback();
    host_sync();
    event_cb(event_user, EVT_UART_ERET, icount, 0);
    leave_callback();
  }
  poke_events();
}

// ------------------------------------------------------------------
// Execution control
// ------------------------------------------------------------------
void Core::schedule() {
  uint64_t n = limit_;
  if (timer_armed && timer_enabled && !ti && timer_check_at < n) n = timer_check_at;
  if (uart_pending_ && !uart_delivered_ && uart_at_ > icount && uart_at_ < n) n = uart_at_;
  if (deadline_ms_ && wall_check_at_ < n) n = wall_check_at_;
  if (irqs_enabled && ds_active) {
    // an interrupt that waits for the end of a delay slot
    if ((irq_deliverable() || (uart_pending_ && !uart_delivered_ && icount >= uart_at_)) && icount + 1 < n)
      n = icount + 1;
  }
  next_event_ = n;
}

// A Status write (MTC0 Status, DI, EI) run inside a block, `now` the
// instruction count after it.  The single-instruction path poked the events
// after one, so events() ran at the next boundary; here that happens (by a
// poke, which ends the block after the write) only when events() would do
// more than reschedule: a stop, a due deadline / timer check, or an
// interrupt to deliver.  Otherwise its remaining effects are applied directly,
// so the run is the same instruction for instruction.
void Core::status_events(uint64_t now) {
  bool act = stop_request_ || now >= limit_ || (deadline_ms_ && now >= wall_check_at_) ||
             (timer_armed && timer_enabled && !ti && now >= timer_check_at);
  if (!act && irqs_enabled && !ds_active)
    act = (uart_pending_ && !uart_delivered_ && now >= uart_at_ &&
           (uart_force_ || ((status & 1) && !(status & 2)))) || irq_deliverable();
  if (act) {
    poke_events();
    return;
  }
  dev_callback_dirty_ = false;
  uint64_t save = icount;
  icount = now;
  schedule();
  icount = save;
}

bool Core::events() {
  // A callback below (including one reached through host_sync) can dirty this
  // again. Callback exit also marks it, so nested runs cannot lose outer writes.
  dev_callback_dirty_ = false;
  if (stop_request_) {
    stop_request_ = false;
    stop_reason_ = STOP_REQUEST;
    return true;
  }
  if (icount >= limit_) {
    stop_reason_ = STOP_COUNT;
    return true;
  }
  if (deadline_ms_ && icount >= wall_check_at_) {
    if (now_ms() >= deadline_ms_) {
      stop_reason_ = STOP_TIMEOUT;
      return true;
    }
    wall_check_at_ = icount + 200000;
  }
  if (timer_armed && timer_enabled && !ti && icount >= timer_check_at) timer_update();
  if (irqs_enabled && !ds_active) {
    if (uart_pending_ && !uart_delivered_ && icount >= uart_at_ &&
        (uart_force_ || ((status & 1) && !(status & 2)))) {
      // the UART receive interrupt (simulator._enter_uart_irq): IC status / enable bit 16
      uart_delivered_ = true;
      uart_pending_ = false;
      uart_irqs++;
      if (dev_buf_) {
        dev_buf_[ic_status_off_ + 2] |= 1;
        dev_buf_[ic_enable_off_ + 2] |= 1;
      }
      uart_ip3 = true;
      status |= 0x800;
      uint32_t epc_v = pc | (m16 ? 1 : 0);
      uint32_t vec = enter_interrupt(epc_v);
      pc = vec; m16 = false;
      invalidate_fetch();
      if (event_cb) {
        enter_callback();
        host_sync();
        event_cb(event_user, EVT_UART_IRQ, epc_v, vec);
        leave_callback();
      }
    } else if (irq_deliverable()) {
      uint32_t vec = enter_interrupt(pc | (m16 ? 1 : 0));
      pc = vec; m16 = false;
      invalidate_fetch();
    }
  }
  schedule();
  return false;
}

int Core::emu_start(uint64_t begin, uint64_t until, uint64_t timeout_us, uint64_t count) {
  uint32_t b = (uint32_t)begin;
  if ((b & ~1u) != pc || ((b & 1) != 0) != m16) ds_active = false;   // a fresh start
  pc = b & ~1u;
  m16 = b & 1;
  until_ = until;
  uint64_t start_exec = executed;
  (void)start_exec;
  bool skip = idle_skip;
  idle_skip = false;      // (Unicorn has no idle skipping)
  limit_ = count ? icount + count : ~0ull;
  deadline_ms_ = timeout_us ? now_ms() + (timeout_us + 999) / 1000 : 0;
  wall_check_at_ = icount;
  int r = run_loop();
  host_sync();
  idle_skip = skip;
  deadline_ms_ = 0;
  until_ = ~0ull;
  (void)r;
  return stop_reason_ == STOP_ERROR ? err_ : ERR_OK;
}

int Core::run(uint64_t icount_limit) {
  until_ = ~0ull;
  limit_ = icount_limit;
  deadline_ms_ = 0;
  int r2 = run_loop();
  host_sync();
  return r2;
}

}  // namespace ali
