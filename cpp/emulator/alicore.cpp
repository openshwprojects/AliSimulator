// AliSimulator C++ core: memory map, hooks, CP0, interrupts, the run loop.
// The instructions themselves are in alicore_exec.cpp.
#include "alicore.h"

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
  for (auto &r : regions_)
    if (r.owned) free(r.ptr);
  delete[] vr_;
  delete[] vw_;
  delete[] vx_;
  delete[] pregion_;
  delete[] code_hook_page_;
  delete[] mem_hook_page_;
  delete[] devflags_;
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
               !(devflags_[pa - dev_phys_] & (DF_READ | DF_NATIVE)) && !(mem_hook_page_[pa >> 12] & 1);
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
  if (devflags_[off] & DF_READ) {
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
  if (overlaps(ic_status_off_, 8) || overlaps(ic_enable_off_, 8) ||
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
    gpio_log_[2 * gpio_n_] = do_off;
    gpio_log_[2 * gpio_n_ + 1] = (do_val & dir_val) | ~dir_val;
    if (++gpio_n_ == GPIO_LOG_MAX) flush_gpio();
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

bool Core::ic_ip3() const {
  if (!dev_buf_) return false;
  if (ic_lines_) {
    uint64_t en = 0;
    if (ic_enable_off_ + 8 <= dev_size_) memcpy(&en, dev_buf_ + ic_enable_off_, 8);
    if (ic_lines_ & en) return true;
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
      timer_update();
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
