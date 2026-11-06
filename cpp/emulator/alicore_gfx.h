// AliSimulator C++ graphics & GMA rendering kernels (GE_M36F, GE_M3602, GMA capture).
// Bit-for-bit faithful to src/ge_m36f.py, src/ge_m3602.py, src/gma_capture.py, and
// tests/screen_regression.py. Any unsupported feature or out-of-bounds edge case
// returns a fallback status so the Python model records the exact same diagnostics.
#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <vector>

namespace ali_gfx {

static inline int ge_bpp(uint32_t fmt) {
  switch (fmt) {
    case 0x00: case 0x01: case 0x10: case 0x13: return 32;
    case 0x02: case 0x03: case 0x04: case 0x05: case 0x06: case 0x07: case 0x0E: case 0x11: return 16;
    case 0x0B: case 0x0C: case 0x1D: return 8;
    case 0x0A: return 4;
    case 0x08: return 2;
    case 0x09: case 0x1C: return 1;
    default: return 0;
  }
}

static inline bool is_clut_fmt(uint32_t fmt) {
  return fmt == 0x08 || fmt == 0x09 || fmt == 0x0A || fmt == 0x0B || fmt == 0x0C || fmt == 0x0E;
}

static inline bool is_alpha_fmt(uint32_t fmt) {
  return fmt == 0x1C || fmt == 0x1D;
}

static inline bool is_index_fmt(uint32_t fmt) {
  return is_clut_fmt(fmt) || is_alpha_fmt(fmt);
}

static inline bool is_packed_fmt(uint32_t fmt) {
  switch (fmt) {
    case 0x00: case 0x01: case 0x02: case 0x03: case 0x04:
    case 0x05: case 0x06: case 0x10: case 0x13:
      return true;
    default:
      return false;
  }
}

static inline bool is_ycbcr_fmt(uint32_t fmt) {
  return fmt == 0x10 || fmt == 0x13;
}

static inline void packed_widths(uint32_t fmt, int &wa, int &w1, int &w2, int &w3) {
  switch (fmt) {
    case 0x00: case 0x10: wa = 0; w1 = 8; w2 = 8; w3 = 8; break;
    case 0x01: case 0x13: wa = 8; w1 = 8; w2 = 8; w3 = 8; break;
    case 0x02: wa = 0; w1 = 4; w2 = 4; w3 = 4; break;
    case 0x03: wa = 4; w1 = 4; w2 = 4; w3 = 4; break;
    case 0x04: wa = 0; w1 = 5; w2 = 5; w3 = 5; break;
    case 0x05: wa = 1; w1 = 5; w2 = 5; w3 = 5; break;
    case 0x06: wa = 0; w1 = 5; w2 = 6; w3 = 5; break;
    default: wa = w1 = w2 = w3 = 0; break;
  }
}

static inline int packed_used_bits(uint32_t fmt) {
  int wa, w1, w2, w3;
  packed_widths(fmt, wa, w1, w2, w3);
  return wa + w1 + w2 + w3;
}

static inline bool same_raw(uint32_t fmt, uint32_t src_pf, uint32_t dst_pf, bool clut_en, bool index_domain) {
  if (is_packed_fmt(fmt) && !is_ycbcr_fmt(fmt)) {
    if ((src_pf ^ dst_pf) & 0x00860000u) return false;
    int wa, w1, w2, w3;
    packed_widths(fmt, wa, w1, w2, w3);
    return !wa || (!((src_pf | dst_pf) & 0x01000000u) && !((src_pf ^ dst_pf) & 0x02000000u));
  }
  return index_domain && is_index_fmt(fmt) && !clut_en && !((src_pf ^ dst_pf) & 0x00800000u);
}

static inline float expand_chan(uint32_t c, int bits, bool zero_pad) {
  if (bits == 8) return (float)c;
  if (bits == 0) return 0.0f;
  if (zero_pad && bits > 1) return (float)(c << (8 - bits));
  uint32_t out = (bits >= 4) ? ((c << (8 - bits)) | (c >> std::max(0, 2 * bits - 8)))
                             : (c * (255u / ((1u << bits) - 1u)));
  return (float)out;
}

static inline void ycbcr_to_rgb_px(float y_in, float cb_in, float cr_in, int bt709, float &r_out, float &g_out, float &b_out) {
  float y = y_in - 16.0f;
  float cb = cb_in - 128.0f;
  float cr = cr_in - 128.0f;
  float r, g, b;
  if (bt709) {
    float yk = 1.164f * y;
    r = yk + 1.793f * cr;
    g = (yk - 0.213f * cb) - 0.533f * cr;
    b = yk + 2.112f * cb;
  } else {
    float yk = 1.164f * y;
    r = yk + 1.596f * cr;
    g = (yk - 0.392f * cb) - 0.813f * cr;
    b = yk + 2.017f * cb;
  }
  r_out = std::min(std::max(r, 0.0f), 255.0f);
  g_out = std::min(std::max(g, 0.0f), 255.0f);
  b_out = std::min(std::max(b, 0.0f), 255.0f);
}

static inline void rgb_to_ycbcr_px(float r, float g, float b, int bt709, float &y_out, float &cb_out, float &cr_out) {
  if (bt709) {
    y_out = ((16.0f + 0.183f * r) + 0.614f * g) + 0.062f * b;
    cb_out = ((128.0f - 0.101f * r) - 0.339f * g) + 0.439f * b;
    cr_out = ((128.0f + 0.439f * r) - 0.399f * g) - 0.040f * b;
  } else {
    y_out = ((16.0f + 0.257f * r) + 0.504f * g) + 0.098f * b;
    cb_out = ((128.0f - 0.148f * r) - 0.291f * g) + 0.439f * b;
    cr_out = ((128.0f + 0.439f * r) - 0.368f * g) - 0.071f * b;
  }
}

static inline void decode_packed_one(uint32_t v, uint32_t fmt, uint32_t pfreg, float *out4) {
  uint32_t order = (pfreg >> 17) & 3;
  int wa, w1, w2, w3;
  packed_widths(fmt, wa, w1, w2, w3);
  int widths[4];
  if (order == 2 || order == 3) {
    widths[0] = w1; widths[1] = w2; widths[2] = w3; widths[3] = wa;
  } else {
    widths[0] = wa; widths[1] = w1; widths[2] = w2; widths[3] = w3;
  }
  int sh = widths[0] + widths[1] + widths[2] + widths[3];
  uint32_t chans[4];
  for (int i = 0; i < 4; i++) {
    int wd = widths[i];
    sh -= wd;
    chans[i] = wd ? ((v >> sh) & ((1u << wd) - 1u)) : 0u;
  }
  uint32_t c1, c2, c3, a;
  int aw;
  if (order == 2 || order == 3) {
    c1 = chans[0]; c2 = chans[1]; c3 = chans[2]; a = chans[3];
    aw = widths[3];
  } else {
    a = chans[0]; c1 = chans[1]; c2 = chans[2]; c3 = chans[3];
    aw = widths[0];
  }
  bool zp = ((pfreg >> 19) & 1) != 0;
  float e1 = expand_chan(c1, w1, zp);
  float e2 = expand_chan(c2, w2, zp);
  float e3 = expand_chan(c3, w3, zp);
  if (order == 1 || order == 3) std::swap(e1, e3);
  float av;
  if (aw == 0) {
    av = 255.0f;
  } else {
    av = expand_chan(a, aw, false);
    if (((pfreg >> 24) & 1) && aw == 8) av = std::min(av * 2.0f, 255.0f);
    if ((pfreg >> 25) & 1) av = 255.0f - av;
  }
  out4[0] = av;
  if (is_ycbcr_fmt(fmt)) {
    ycbcr_to_rgb_px(e1, e2, e3, 0, out4[1], out4[2], out4[3]);
  } else {
    out4[1] = e1; out4[2] = e2; out4[3] = e3;
  }
}

static inline bool decode_colour_one(uint32_t val, uint32_t fmt, float *out4) {
  if (is_packed_fmt(fmt)) {
    decode_packed_one(val, fmt, 0, out4);
    return true;
  }
  if (is_clut_fmt(fmt)) {
    if (fmt == 0x0E) {
      float g = (float)(val & 0xFFu);
      out4[0] = (float)(val >> 8);
      out4[1] = out4[2] = out4[3] = g;
    } else if (fmt == 0x0B) {
      float g = (float)(val & 0xFu);
      out4[0] = (float)((val >> 4) * 17u);
      out4[1] = out4[2] = out4[3] = g;
    } else {
      float g = (float)val;
      out4[0] = 255.0f;
      out4[1] = out4[2] = out4[3] = g;
    }
    return true;
  }
  if (fmt == 0x1D) {
    out4[0] = (float)val;
    out4[1] = out4[2] = out4[3] = 255.0f;
    return true;
  }
  if (fmt == 0x1C) {
    out4[0] = (float)val * 255.0f;
    out4[1] = out4[2] = out4[3] = 255.0f;
    return true;
  }
  return false;
}

static inline uint32_t round_u8(float x) {
  float v = std::min(std::max(x + 0.5f, 0.0f), 255.0f);
  return (uint32_t)v;
}

static inline bool encode_one(const float *px, uint32_t fmt, uint32_t pfreg, uint32_t &out_val) {
  uint32_t a = round_u8(px[0]);
  uint32_t r = round_u8(px[1]);
  uint32_t g = round_u8(px[2]);
  uint32_t b = round_u8(px[3]);
  uint32_t order = (pfreg >> 17) & 3;
  if (is_packed_fmt(fmt)) {
    if (is_ycbcr_fmt(fmt)) {
      float y, cb, cr;
      rgb_to_ycbcr_px(px[1], px[2], px[3], 0, y, cb, cr);
      r = round_u8(y);
      g = round_u8(cb);
      b = round_u8(cr);
    }
    if ((pfreg >> 25) & 1) a = 255u - a;
    if ((pfreg >> 24) & 1) a >>= 1;
    if (order == 1 || order == 3) std::swap(r, b);
    if (order == 0 || order == 1) {
      switch (fmt) {
        case 0x05: out_val = ((a >> 7) << 15) | ((r >> 3) << 10) | ((g >> 3) << 5) | (b >> 3); return true;
        case 0x06: out_val = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3); return true;
        case 0x01: case 0x13: out_val = (a << 24) | (r << 16) | (g << 8) | b; return true;
        case 0x00: case 0x10: out_val = (r << 16) | (g << 8) | b; return true;
        case 0x03: out_val = ((a >> 4) << 12) | ((r >> 4) << 8) | ((g >> 4) << 4) | (b >> 4); return true;
      }
    }
    int wa, w1, w2, w3;
    packed_widths(fmt, wa, w1, w2, w3);
    uint32_t c0 = wa ? (a >> (8 - wa)) : 0u;
    uint32_t c1 = r >> (8 - w1);
    uint32_t c2 = g >> (8 - w2);
    uint32_t c3 = b >> (8 - w3);
    int seq_w[4];
    uint32_t seq_c[4];
    if (order == 2 || order == 3) {
      seq_c[0] = c1; seq_w[0] = w1;
      seq_c[1] = c2; seq_w[1] = w2;
      seq_c[2] = c3; seq_w[2] = w3;
      seq_c[3] = c0; seq_w[3] = wa;
    } else {
      seq_c[0] = c0; seq_w[0] = wa;
      seq_c[1] = c1; seq_w[1] = w1;
      seq_c[2] = c2; seq_w[2] = w2;
      seq_c[3] = c3; seq_w[3] = w3;
    }
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
      int wd = seq_w[i];
      if (wd) v = (v << wd) | (seq_c[i] & ((1u << wd) - 1u));
    }
    out_val = v;
    return true;
  }
  if (fmt == 0x1D) { out_val = a; return true; }
  if (fmt == 0x1C) { out_val = (a >= 128u) ? 1u : 0u; return true; }
  return false;
}

static inline bool encode_fill_one(uint32_t val, uint32_t col_fmt, uint32_t dst_fmt, uint32_t dst_pf, uint32_t &out_val) {
  float c[4];
  if (!decode_colour_one(val, col_fmt, c)) return false;
  return encode_one(c, dst_fmt, dst_pf, out_val);
}

static inline uint16_t bswap16_val(uint16_t v) {
  return (uint16_t)((v >> 8) | (v << 8));
}

static inline uint32_t bswap32_val(uint32_t v) {
  return ((v >> 24) & 0xFFu) | ((v >> 8) & 0xFF00u) | ((v << 8) & 0xFF0000u) | ((v << 24) & 0xFF000000u);
}

static inline bool ge_addr(const uint32_t *r, uint32_t off, uint32_t phys_mask, uint32_t &out) {
  uint32_t v = r[off >> 2];
  uint32_t sel = v >> 28;
  if (sel) {
    uint32_t idx = (0xBCu + 4u * sel) >> 2;
    if (idx >= 64u) return false;
    v = r[idx];
  }
  out = v & phys_mask;
  return true;
}

struct GeScratch {
  std::vector<uint32_t> raw_a;
  std::vector<uint32_t> raw_b;
  std::vector<uint32_t> raw_c;
  std::vector<uint32_t> rle_buf;
  std::vector<float> ptn_f;
  std::vector<float> src_f;
  std::vector<float> out_f;
  std::vector<float> malpha;
  std::vector<uint8_t> wmask;
  std::vector<uint8_t> pmask;
};

static thread_local GeScratch g_scratch;

static bool read_rle_surface(const uint8_t *ram, uint32_t ram_size, uint32_t addr, uint32_t pfreg,
                             uint32_t x, uint32_t y, uint32_t w, uint32_t h, std::vector<uint32_t> &out) {
  uint32_t fmt = (pfreg >> 12) & 0x1F;
  int bpp = ge_bpp(fmt);
  if (!bpp) return false;
  uint32_t pitch = (pfreg & 0xFFF) ? (pfreg & 0xFFF) : w;
  if (x + w > pitch) return false;
  uint32_t bp = std::max(1, bpp / 8);
  uint64_t total64 = (uint64_t)(y + h) * pitch;
  if (total64 > 16 * 1024 * 1024) return false;
  uint32_t total = (uint32_t)total64;
  auto &buf = g_scratch.rle_buf;
  buf.assign(total, 0u);
  uint32_t i = 0, a = addr;
  uint64_t end64 = std::min<uint64_t>(ram_size, (uint64_t)addr + (uint64_t)total * (bp + 1) + 16);
  uint32_t end = (uint32_t)end64;
  bool big = ((pfreg >> 23) & 1) != 0;
  while (i < total && a < end) {
    uint8_t c = ram[a++];
    uint32_t n = c & 0x7Fu;
    if (c & 0x80u) {
      if ((uint64_t)a + (uint64_t)n * bp > ram_size) return false;
      uint32_t k = std::min(n, total - i);
      for (uint32_t m = 0; m < k; m++) {
        const uint8_t *p = ram + a + m * bp;
        uint32_t v = 0;
        if (bp == 1) v = p[0];
        else if (bp == 2) v = big ? ((uint32_t)p[0] << 8 | p[1]) : ((uint32_t)p[1] << 8 | p[0]);
        else v = big ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3])
                     : ((uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]);
        buf[i + m] = v;
      }
      a += n * bp;
      i += k;
    } else {
      if ((uint64_t)a + bp > ram_size) return false;
      const uint8_t *p = ram + a;
      uint32_t v = 0;
      if (bp == 1) v = p[0];
      else if (bp == 2) v = big ? ((uint32_t)p[0] << 8 | p[1]) : ((uint32_t)p[1] << 8 | p[0]);
      else v = big ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3])
                   : ((uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]);
      a += bp;
      uint32_t k = std::min(n, total - i);
      for (uint32_t m = 0; m < k; m++) buf[i + m] = v;
      i += k;
    }
  }
  out.resize((size_t)w * h);
  for (uint32_t r = 0; r < h; r++) {
    memcpy(&out[(size_t)r * w], &buf[(size_t)(y + r) * pitch + x], w * sizeof(uint32_t));
  }
  return true;
}

static bool read_raw_surface(const uint8_t *ram, uint32_t ram_size, uint32_t addr, uint32_t pfreg,
                             uint32_t x, uint32_t y, uint32_t w, uint32_t h, bool rle,
                             std::vector<uint32_t> &out) {
  if (rle) return read_rle_surface(ram, ram_size, addr, pfreg, x, y, w, h, out);
  uint32_t fmt = (pfreg >> 12) & 0x1F;
  int bpp = ge_bpp(fmt);
  if (!bpp) return false;
  uint32_t pitch = pfreg & 0xFFF;
  out.resize((size_t)w * h);
  if (bpp >= 8) {
    uint32_t bp = (uint32_t)(bpp / 8);
    uint64_t stride = (uint64_t)pitch * bp;
    uint64_t start = (uint64_t)addr + (uint64_t)y * stride + (uint64_t)x * bp;
    uint64_t end = start + (uint64_t)(h - 1) * stride + (uint64_t)w * bp;
    if (end > ram_size) return false;
    bool big = ((pfreg >> 23) & 1) != 0;
    for (uint32_t j = 0; j < h; j++) {
      const uint8_t *row = ram + start + (uint64_t)j * stride;
      uint32_t *dst = &out[(size_t)j * w];
      if (bp == 1) {
        for (uint32_t i = 0; i < w; i++) dst[i] = row[i];
      } else if (bp == 2) {
        if (!big) {
          for (uint32_t i = 0; i < w; i++) {
            uint16_t v;
            memcpy(&v, row + 2 * i, 2);
            dst[i] = v;
          }
        } else {
          for (uint32_t i = 0; i < w; i++) {
            uint16_t v;
            memcpy(&v, row + 2 * i, 2);
            dst[i] = bswap16_val(v);
          }
        }
      } else {
        if (!big) {
          memcpy(dst, row, w * 4);
        } else {
          for (uint32_t i = 0; i < w; i++) {
            uint32_t v;
            memcpy(&v, row + 4 * i, 4);
            dst[i] = bswap32_val(v);
          }
        }
      }
    }
    return true;
  }
  // sub-byte formats (1, 2, 4 bpp)
  bool msb = ((pfreg >> 22) & 1) != 0;
  uint32_t pm = (1u << bpp) - 1u;
  for (uint32_t j = 0; j < h; j++) {
    uint32_t *dst = &out[(size_t)j * w];
    uint64_t row_bit = (uint64_t)(y + j) * pitch;
    for (uint32_t i = 0; i < w; i++) {
      uint64_t bit = (row_bit + (x + i)) * (uint32_t)bpp;
      uint64_t byte_off = (uint64_t)addr + (bit >> 3);
      if (byte_off < ram_size) {
        uint32_t sh = msb ? (uint32_t)(8 - bpp - (bit & 7)) : (uint32_t)(bit & 7);
        dst[i] = (ram[byte_off] >> sh) & pm;
      } else {
        dst[i] = 0;
      }
    }
  }
  return true;
}

static void write_raw_surface(uint8_t *ram, uint32_t ram_size, uint32_t addr, uint32_t pfreg,
                              uint32_t x, uint32_t y, uint32_t w, uint32_t h,
                              const uint32_t *vals, const uint8_t *mask) {
  uint32_t fmt = (pfreg >> 12) & 0x1F;
  int bpp = ge_bpp(fmt);
  if (!bpp) return;
  uint32_t pitch = pfreg & 0xFFF;
  if (bpp >= 8) {
    uint32_t bp = (uint32_t)(bpp / 8);
    uint64_t stride = (uint64_t)pitch * bp;
    bool big = bp > 1 && ((pfreg >> 23) & 1) != 0;
    for (uint32_t j = 0; j < h; j++) {
      uint64_t a = (uint64_t)addr + (uint64_t)(y + j) * stride + (uint64_t)x * bp;
      if (a + (uint64_t)w * bp > ram_size) continue;
      uint8_t *row = ram + a;
      const uint32_t *vrow = vals + (size_t)j * w;
      const uint8_t *mrow = mask ? (mask + (size_t)j * w) : nullptr;
      if (bp == 1) {
        if (!mrow) {
          for (uint32_t i = 0; i < w; i++) row[i] = (uint8_t)vrow[i];
        } else {
          for (uint32_t i = 0; i < w; i++) if (mrow[i]) row[i] = (uint8_t)vrow[i];
        }
      } else if (bp == 2) {
        if (!big) {
          if (!mrow) {
            for (uint32_t i = 0; i < w; i++) { uint16_t v = (uint16_t)vrow[i]; memcpy(row + 2 * i, &v, 2); }
          } else {
            for (uint32_t i = 0; i < w; i++) if (mrow[i]) { uint16_t v = (uint16_t)vrow[i]; memcpy(row + 2 * i, &v, 2); }
          }
        } else {
          if (!mrow) {
            for (uint32_t i = 0; i < w; i++) { uint16_t v = bswap16_val((uint16_t)vrow[i]); memcpy(row + 2 * i, &v, 2); }
          } else {
            for (uint32_t i = 0; i < w; i++) if (mrow[i]) { uint16_t v = bswap16_val((uint16_t)vrow[i]); memcpy(row + 2 * i, &v, 2); }
          }
        }
      } else {
        if (!big) {
          if (!mrow) {
            memcpy(row, vrow, w * 4);
          } else {
            for (uint32_t i = 0; i < w; i++) if (mrow[i]) memcpy(row + 4 * i, &vrow[i], 4);
          }
        } else {
          if (!mrow) {
            for (uint32_t i = 0; i < w; i++) { uint32_t v = bswap32_val(vrow[i]); memcpy(row + 4 * i, &v, 4); }
          } else {
            for (uint32_t i = 0; i < w; i++) if (mrow[i]) { uint32_t v = bswap32_val(vrow[i]); memcpy(row + 4 * i, &v, 4); }
          }
        }
      }
    }
    return;
  }
  // sub-byte write: two passes (AND then OR) to match np.bitwise_and.at + np.bitwise_or.at even if rows overlap
  bool msb = ((pfreg >> 22) & 1) != 0;
  uint32_t pm = (1u << bpp) - 1u;
  for (uint32_t j = 0; j < h; j++) {
    uint64_t row_bit = (uint64_t)(y + j) * pitch;
    const uint8_t *mrow = mask ? (mask + (size_t)j * w) : nullptr;
    for (uint32_t i = 0; i < w; i++) {
      if (mrow && !mrow[i]) continue;
      uint64_t bit = (row_bit + (x + i)) * (uint32_t)bpp;
      uint64_t byte_off = (uint64_t)addr + (bit >> 3);
      if (byte_off < ram_size) {
        uint32_t sh = msb ? (uint32_t)(8 - bpp - (bit & 7)) : (uint32_t)(bit & 7);
        ram[byte_off] &= (uint8_t)~(pm << sh);
      }
    }
  }
  for (uint32_t j = 0; j < h; j++) {
    uint64_t row_bit = (uint64_t)(y + j) * pitch;
    const uint32_t *vrow = vals + (size_t)j * w;
    const uint8_t *mrow = mask ? (mask + (size_t)j * w) : nullptr;
    for (uint32_t i = 0; i < w; i++) {
      if (mrow && !mrow[i]) continue;
      uint64_t bit = (row_bit + (x + i)) * (uint32_t)bpp;
      uint64_t byte_off = (uint64_t)addr + (bit >> 3);
      if (byte_off < ram_size) {
        uint32_t sh = msb ? (uint32_t)(8 - bpp - (bit & 7)) : (uint32_t)(bit & 7);
        ram[byte_off] |= (uint8_t)((vrow[i] & pm) << sh);
      }
    }
  }
}

static void write_const_surface(uint8_t *ram, uint32_t ram_size, uint32_t addr, uint32_t pfreg,
                                uint32_t x, uint32_t y, uint32_t w, uint32_t h,
                                uint32_t val, const uint8_t *mask) {
  uint32_t fmt = (pfreg >> 12) & 0x1F;
  int bpp = ge_bpp(fmt);
  if (!bpp) return;
  uint32_t pitch = pfreg & 0xFFF;
  if (bpp >= 8) {
    uint32_t bp = (uint32_t)(bpp / 8);
    uint64_t stride = (uint64_t)pitch * bp;
    bool big = bp > 1 && ((pfreg >> 23) & 1) != 0;
    uint16_t v16 = big ? bswap16_val((uint16_t)val) : (uint16_t)val;
    uint32_t v32 = big ? bswap32_val(val) : val;
    uint8_t v8 = (uint8_t)val;
    for (uint32_t j = 0; j < h; j++) {
      uint64_t a = (uint64_t)addr + (uint64_t)(y + j) * stride + (uint64_t)x * bp;
      if (a + (uint64_t)w * bp > ram_size) continue;
      uint8_t *row = ram + a;
      const uint8_t *mrow = mask ? (mask + (size_t)j * w) : nullptr;
      if (bp == 1) {
        if (!mrow) memset(row, v8, w);
        else for (uint32_t i = 0; i < w; i++) if (mrow[i]) row[i] = v8;
      } else if (bp == 2) {
        if (!mrow) {
          for (uint32_t i = 0; i < w; i++) memcpy(row + 2 * i, &v16, 2);
        } else {
          for (uint32_t i = 0; i < w; i++) if (mrow[i]) memcpy(row + 2 * i, &v16, 2);
        }
      } else {
        if (!mrow) {
          for (uint32_t i = 0; i < w; i++) memcpy(row + 4 * i, &v32, 4);
        } else {
          for (uint32_t i = 0; i < w; i++) if (mrow[i]) memcpy(row + 4 * i, &v32, 4);
        }
      }
    }
    return;
  }
  auto &tmp = g_scratch.raw_c;
  tmp.assign((size_t)w * h, val);
  write_raw_surface(ram, ram_size, addr, pfreg, x, y, w, h, tmp.data(), mask);
}

static bool decode_surface(const uint32_t *raw, size_t count, uint32_t fmt, uint32_t pfreg,
                           const float *clut, uint32_t clut_n, std::vector<float> &out) {
  out.resize(count * 4);
  float *dst = out.data();
  if (is_packed_fmt(fmt)) {
    for (size_t i = 0; i < count; i++) {
      decode_packed_one(raw[i], fmt, pfreg, dst + 4 * i);
    }
    return true;
  }
  if (is_clut_fmt(fmt)) {
    for (size_t i = 0; i < count; i++) {
      uint32_t v = raw[i];
      uint32_t idx;
      float alpha = -1.0f;
      if (fmt == 0x0E) {
        idx = v & 0xFFu;
        alpha = (float)(v >> 8);
      } else if (fmt == 0x0B) {
        idx = v & 0xFu;
        alpha = (float)((v >> 4) * 17u);
      } else {
        idx = v;
      }
      float *p = dst + 4 * i;
      if (!clut) {
        float g = (float)idx;
        p[0] = 255.0f; p[1] = g; p[2] = g; p[3] = g;
      } else {
        uint32_t ci = std::min(idx, clut_n - 1u);
        const float *c = clut + 4 * ci;
        p[0] = c[0]; p[1] = c[1]; p[2] = c[2]; p[3] = c[3];
      }
      if (alpha >= 0.0f) p[0] = alpha;
    }
    return true;
  }
  if (fmt == 0x1D) {
    for (size_t i = 0; i < count; i++) {
      float *p = dst + 4 * i;
      p[0] = (float)raw[i]; p[1] = 255.0f; p[2] = 255.0f; p[3] = 255.0f;
    }
    return true;
  }
  if (fmt == 0x1C) {
    for (size_t i = 0; i < count; i++) {
      float *p = dst + 4 * i;
      p[0] = (float)raw[i] * 255.0f; p[1] = 255.0f; p[2] = 255.0f; p[3] = 255.0f;
    }
    return true;
  }
  return false;
}

static bool encode_surface(const float *px, size_t count, uint32_t fmt, uint32_t pfreg, std::vector<uint32_t> &out) {
  out.resize(count);
  uint32_t *dst = out.data();
  for (size_t i = 0; i < count; i++) {
    if (!encode_one(px + 4 * i, fmt, pfreg, dst[i])) return false;
  }
  return true;
}

static bool load_clut(const uint8_t *ram, uint32_t ram_size, uint32_t phys_mask, const uint32_t *r,
                      uint32_t n, float *pal_out, uint32_t &pal_n) {
  uint32_t addr = r[0x78 >> 2] & phys_mask & ~7u;
  uint32_t ctl = r[0x74 >> 2];
  n = std::max(2u, n);
  if ((uint64_t)addr + 4ull * n > ram_size) return false;
  uint32_t pfreg = ((ctl >> 24) & 3u) << 17;
  for (uint32_t i = 0; i < n; i++) {
    uint32_t v;
    memcpy(&v, ram + addr + 4 * i, 4);
    decode_packed_one(v, 0x01, pfreg, pal_out + 4 * i);
  }
  pal_n = n;
  return true;
}

static void expand_2x(std::vector<uint32_t> &raw, uint32_t fw, uint32_t fh, uint32_t w, uint32_t h,
                      uint32_t sx, uint32_t sy) {
  if (!sx && !sy) return;
  auto &tmp = g_scratch.raw_c;
  tmp.resize((size_t)w * h);
  for (uint32_t j = 0; j < h; j++) {
    uint32_t sj = sy ? (j >> 1) : j;
    const uint32_t *srow = &raw[(size_t)sj * fw];
    uint32_t *drow = &tmp[(size_t)j * w];
    for (uint32_t i = 0; i < w; i++) {
      drow[i] = srow[sx ? (i >> 1) : i];
    }
  }
  raw.swap(tmp);
}

// Execute one GE_M36F primitive on `ram`. Returns 0 on success (incrementing *prims_io),
// or -1 to fall back to the Python implementation (for unsupported features or edge cases).
static int ge_m36f_exec_one(uint8_t *ram, uint32_t ram_size, uint32_t phys_mask,
                            const uint32_t *r, uint64_t *prims_io) {
  uint32_t m = r[0x30 >> 2];
  uint32_t src_mode = m & 7u;
  uint32_t ptn_type = (m >> 3) & 7u;
  uint32_t msk_mode = (m >> 6) & 3u;
  uint32_t prim = (m >> 8) & 7u;
  uint32_t api = (m >> 11) & 0x1Fu;
  bool clut_en = ((m >> 18) & 1u) != 0;
  bool cc_en = ((m >> 19) & 1u) != 0;
  bool ckey_en = ((m >> 20) & 1u) != 0;
  uint32_t rop = (m >> 21) & 7u;
  bool clip_en = ((m >> 28) & 1u) != 0;
  bool bmask_en = ((m >> 29) & 1u) != 0;

  uint32_t dst_pf = r[0x38 >> 2];
  uint32_t dst_fmt = (dst_pf >> 12) & 0x1Fu;
  uint32_t dst = 0;
  if (!ge_addr(r, 0x34, phys_mask, dst)) return -1;
  uint32_t dxy = r[0x3C >> 2];
  uint32_t dx = dxy & 0xFFFu, dy = (dxy >> 16) & 0xFFFu;
  uint32_t dwh = r[0x40 >> 2];
  uint32_t w = dwh & 0xFFFu, h = (dwh >> 16) & 0xFFFu;
  if (api == 9u || api == 11u) w = h = 1u;

  if (w == 0 || h == 0 || dst == 0) {
    (*prims_io)++;
    return 0;
  }
  if ((uint64_t)w * h > 4096ull * 2048ull) {
    return -1;
  }
  if (!ge_bpp(dst_fmt)) return -1;

  size_t npix = (size_t)w * h;
  const uint8_t *wmask_ptr = nullptr;
  if (clip_en) {
    uint32_t c0 = r[0x7C >> 2], c1 = r[0x80 >> 2];
    uint32_t cx0 = c0 & 0xFFFu, cy0 = (c0 >> 16) & 0xFFFu;
    uint32_t cx1 = c1 & 0xFFFu, cy1 = (c1 >> 16) & 0xFFFu;
    bool outside = ((c0 >> 31) & 1u) != 0;
    auto &wm = g_scratch.wmask;
    wm.resize(npix);
    for (uint32_t j = 0; j < h; j++) {
      uint32_t yy = dy + j;
      bool y_in = (yy >= cy0 && yy <= cy1);
      uint8_t *row = &wm[(size_t)j * w];
      for (uint32_t i = 0; i < w; i++) {
        uint32_t xx = dx + i;
        bool in = y_in && (xx >= cx0 && xx <= cx1);
        row[i] = (uint8_t)(outside ? !in : in);
      }
    }
    wmask_ptr = wm.data();
  }

  uint32_t src_pf = r[0x48 >> 2];
  uint32_t ptn_pf = r[0x54 >> 2];
  uint32_t ptn_fmt = (ptn_pf >> 12) & 0x1Fu;
  bool index_domain = is_index_fmt(dst_fmt);
  uint32_t col_fmt = r[0x9C >> 2] & 0x1Fu;

  bool plain = !(ckey_en || bmask_en || msk_mode || cc_en) && (((r[0x84 >> 2] >> 20) & 3u) != 3u);
  if (plain && rop == 1u && ptn_type == 1u && ptn_fmt == dst_fmt && !((m >> 16) & 1u) &&
      !((ptn_pf >> 28) & 3u) && same_raw(ptn_fmt, ptn_pf, dst_pf, clut_en, index_domain)) {
    uint32_t p_addr = 0;
    if (!ge_addr(r, 0x50, phys_mask, p_addr)) return -1;
    uint32_t pxy = r[0x58 >> 2];
    auto &raw = g_scratch.raw_a;
    if (!read_raw_surface(ram, ram_size, p_addr, ptn_pf, pxy & 0xFFFu, (pxy >> 16) & 0xFFFu, w, h, false, raw))
      return -1;
    int used = packed_used_bits(ptn_fmt);
    if (is_packed_fmt(ptn_fmt) && used < ge_bpp(ptn_fmt)) {
      uint32_t mask = (1u << used) - 1u;
      for (size_t i = 0; i < npix; i++) raw[i] &= mask;
    }
    write_raw_surface(ram, ram_size, dst, dst_pf, dx, dy, w, h, raw.data(), wmask_ptr);
    (*prims_io)++;
    return 0;
  }
  if (plain && rop == 0u && (src_mode == 1u || src_mode == 2u) && ptn_type == 0u && prim == 0u) {
    uint32_t s_pf = (src_pf & 0xFFFu) ? src_pf : dst_pf;
    uint32_t s_fmt = (s_pf >> 12) & 0x1Fu;
    if (s_fmt == dst_fmt && same_raw(s_fmt, s_pf, dst_pf, clut_en, index_domain)) {
      uint32_t s_addr = 0;
      if (!ge_addr(r, 0x44, phys_mask, s_addr)) return -1;
      if (!s_addr) s_addr = dst;
      uint32_t sxy = r[0x4C >> 2];
      if (sxy == 0x0FFF0FFFu) sxy = dxy;
      auto &raw = g_scratch.raw_a;
      if (!read_raw_surface(ram, ram_size, s_addr, s_pf, sxy & 0xFFFu, (sxy >> 16) & 0xFFFu, w, h, false, raw))
        return -1;
      int used = packed_used_bits(s_fmt);
      if (is_packed_fmt(s_fmt) && used < ge_bpp(s_fmt)) {
        uint32_t mask = (1u << used) - 1u;
        for (size_t i = 0; i < npix; i++) raw[i] &= mask;
      }
      write_raw_surface(ram, ram_size, dst, dst_pf, dx, dy, w, h, raw.data(), wmask_ptr);
      (*prims_io)++;
      return 0;
    }
  }
  if (plain && rop == 1u && ptn_type == 0u && (prim == 3u || prim == 4u) && api != 1u && api != 2u && !index_domain) {
    uint32_t enc = 0;
    if (!encode_fill_one(prim == 3u ? r[0x90 >> 2] : r[0x98 >> 2], col_fmt, dst_fmt, dst_pf, enc))
      return -1;
    write_const_surface(ram, ram_size, dst, dst_pf, dx, dy, w, h, enc, wmask_ptr);
    (*prims_io)++;
    return 0;
  }
  if (plain && ptn_type == 2u && !index_domain && ge_bpp(ptn_fmt) == 1) {
    bool fill_back = (api == 6u) || (((ptn_pf >> 27) & 1u) != 0);
    uint32_t fg = r[0x94 >> 2], bg = r[0x90 >> 2];
    if (rop == 1u) {
      uint32_t p_addr = 0;
      if (!ge_addr(r, 0x50, phys_mask, p_addr)) return -1;
      uint32_t pxy = r[0x58 >> 2];
      uint32_t sx = (ptn_pf >> 28) & 1u, sy = (ptn_pf >> 29) & 1u;
      uint32_t fw = (w + sx) >> sx, fh = (h + sy) >> sy;
      auto &raw = g_scratch.raw_a;
      if (!read_raw_surface(ram, ram_size, p_addr, ptn_pf, pxy & 0xFFFu, (pxy >> 16) & 0xFFFu, fw, fh, false, raw))
        return -1;
      expand_2x(raw, fw, fh, w, h, sx, sy);
      uint32_t fg_enc = 0;
      if (!encode_fill_one(fg, col_fmt, dst_fmt, dst_pf, fg_enc)) return -1;
      if (fill_back) {
        uint32_t bg_enc = 0;
        if (!encode_fill_one(bg, col_fmt, dst_fmt, dst_pf, bg_enc)) return -1;
        for (size_t i = 0; i < npix; i++) raw[i] = raw[i] ? fg_enc : bg_enc;
        write_raw_surface(ram, ram_size, dst, dst_pf, dx, dy, w, h, raw.data(), wmask_ptr);
      } else {
        auto &pm = g_scratch.pmask;
        pm.resize(npix);
        for (size_t i = 0; i < npix; i++) pm[i] = (uint8_t)(raw[i] != 0 && (!wmask_ptr || wmask_ptr[i]));
        write_const_surface(ram, ram_size, dst, dst_pf, dx, dy, w, h, fg_enc, pm.data());
      }
      (*prims_io)++;
      return 0;
    }
    if (rop == 2u) {
      uint32_t ac = r[0x84 >> 2];
      uint32_t s_pf = (src_pf & 0xFFFu) ? src_pf : dst_pf;
      uint32_t sxy = r[0x4C >> 2];
      uint32_t s_addr = 0;
      if (!ge_addr(r, 0x44, phys_mask, s_addr)) return -1;
      if (!s_addr) s_addr = dst;
      bool same_dst = (src_mode == 0u) || ((src_mode == 1u || src_mode == 2u) && s_addr == dst &&
                                           (sxy == dxy || sxy == 0x0FFF0FFFu) && s_pf == dst_pf);
      if (same_dst && (ac & 0x100FFFu) == 0xFFu && (((ac >> 20) & 3u) == 0u) &&
          same_raw(dst_fmt, dst_pf, dst_pf, clut_en, index_domain) &&
          packed_used_bits(dst_fmt) == ge_bpp(dst_fmt)) {
        float fgc[4], bgc[4] = {0, 0, 0, 0};
        if (!decode_colour_one(fg, col_fmt, fgc)) return -1;
        if (fill_back && !decode_colour_one(bg, col_fmt, bgc)) return -1;
        if (fgc[0] == 255.0f && (!fill_back || bgc[0] == 0.0f || bgc[0] == 255.0f)) {
          uint32_t p_addr = 0;
          if (!ge_addr(r, 0x50, phys_mask, p_addr)) return -1;
          uint32_t pxy = r[0x58 >> 2];
          uint32_t sx = (ptn_pf >> 28) & 1u, sy = (ptn_pf >> 29) & 1u;
          uint32_t fw = (w + sx) >> sx, fh = (h + sy) >> sy;
          auto &raw = g_scratch.raw_a;
          if (!read_raw_surface(ram, ram_size, p_addr, ptn_pf, pxy & 0xFFFu, (pxy >> 16) & 0xFFFu, fw, fh, false, raw))
            return -1;
          expand_2x(raw, fw, fh, w, h, sx, sy);
          uint32_t fg_enc = 0;
          if (!encode_fill_one(fg, col_fmt, dst_fmt, dst_pf, fg_enc)) return -1;
          if (fill_back && bgc[0] == 255.0f) {
            uint32_t bg_enc = 0;
            if (!encode_fill_one(bg, col_fmt, dst_fmt, dst_pf, bg_enc)) return -1;
            for (size_t i = 0; i < npix; i++) raw[i] = raw[i] ? fg_enc : bg_enc;
            write_raw_surface(ram, ram_size, dst, dst_pf, dx, dy, w, h, raw.data(), wmask_ptr);
          } else {
            auto &pm = g_scratch.pmask;
            pm.resize(npix);
            for (size_t i = 0; i < npix; i++) pm[i] = (uint8_t)(raw[i] != 0 && (!wmask_ptr || wmask_ptr[i]));
            write_const_surface(ram, ram_size, dst, dst_pf, dx, dy, w, h, fg_enc, pm.data());
          }
          (*prims_io)++;
          return 0;
        }
      }
    }
  }

  // General path in C++
  bool ptn_present = false, ptn_is_raw = false;
  bool ptn_raw_valid = false;
  auto &ptn_raw = g_scratch.raw_a;
  auto &ptn_f = g_scratch.ptn_f;
  bool has_pmask = false;
  auto &pmask = g_scratch.pmask;

  if (ptn_type == 1u) {
    uint32_t p_addr = 0;
    if (!ge_addr(r, 0x50, phys_mask, p_addr)) return -1;
    uint32_t pxy = r[0x58 >> 2];
    uint32_t px = pxy & 0xFFFu, py = (pxy >> 16) & 0xFFFu;
    uint32_t pwh = r[0x5C >> 2];
    uint32_t pw = pwh & 0xFFFu, ph = (pwh >> 16) & 0xFFFu;
    if ((pw != w || ph != h) && pw && ph && api == 13u) return -1;
    uint32_t sx = (ptn_pf >> 28) & 1u, sy = (ptn_pf >> 29) & 1u;
    uint32_t fw = (w + sx) >> sx, fh = (h + sy) >> sy;
    if (!read_raw_surface(ram, ram_size, p_addr, ptn_pf, px, py, fw, fh, ((m >> 16) & 1u) != 0, ptn_raw))
      return -1;
    expand_2x(ptn_raw, fw, fh, w, h, sx, sy);
    ptn_raw_valid = true;
    ptn_present = true;
    if (index_domain && is_index_fmt(ptn_fmt) && !clut_en) {
      ptn_is_raw = true;
    } else {
      float clut_buf[256 * 4];
      uint32_t clut_n = 0;
      const float *clut_ptr = nullptr;
      if (clut_en && is_clut_fmt(ptn_fmt)) {
        uint32_t n_entries = 1u << std::min(8, ge_bpp(ptn_fmt));
        if (load_clut(ram, ram_size, phys_mask, r, n_entries, clut_buf, clut_n))
          clut_ptr = clut_buf;
      }
      if (!decode_surface(ptn_raw.data(), npix, ptn_fmt, ptn_pf, clut_ptr, clut_n, ptn_f))
        return -1;
      if (cc_en && clut_ptr) {
        int bt709 = (int)(r[0x74 >> 2] & 1u);
        for (size_t i = 0; i < npix; i++) {
          float *p = &ptn_f[4 * i];
          ycbcr_to_rgb_px(p[1], p[2], p[3], bt709, p[1], p[2], p[3]);
        }
      }
      ptn_is_raw = false;
    }
  } else if (ptn_type == 2u) {
    uint32_t p_addr = 0;
    if (!ge_addr(r, 0x50, phys_mask, p_addr)) return -1;
    uint32_t pxy = r[0x58 >> 2];
    uint32_t px = pxy & 0xFFFu, py = (pxy >> 16) & 0xFFFu;
    uint32_t sx = (ptn_pf >> 28) & 1u, sy = (ptn_pf >> 29) & 1u;
    uint32_t fw = (w + sx) >> sx, fh = (h + sy) >> sy;
    if (!read_raw_surface(ram, ram_size, p_addr, ptn_pf, px, py, fw, fh, false, ptn_raw))
      return -1;
    expand_2x(ptn_raw, fw, fh, w, h, sx, sy);
    bool fill_back = (api == 6u) || (((ptn_pf >> 27) & 1u) != 0);
    int bits = ge_bpp(ptn_fmt);
    if (!bits) bits = 1;
    float scale = (ptn_fmt == 0x1Du) ? 1.0f : ((ptn_fmt == 0x1Cu || ptn_fmt == 0x09u) ? 255.0f : (255.0f / (float)((1 << bits) - 1)));
    uint32_t fg = r[0x94 >> 2], bg = r[0x90 >> 2];
    ptn_present = true;
    if (index_domain) {
      ptn_is_raw = true;
      if (!fill_back) {
        has_pmask = true;
        pmask.resize(npix);
      }
      for (size_t i = 0; i < npix; i++) {
        float a = (float)ptn_raw[i] * scale;
        bool on = (a >= 128.0f);
        ptn_raw[i] = on ? fg : bg;
        if (!fill_back) pmask[i] = (uint8_t)on;
      }
    } else {
      float fgc[4], bgc[4];
      if (!decode_colour_one(fg, col_fmt, fgc) || !decode_colour_one(bg, col_fmt, bgc))
        return -1;
      ptn_is_raw = false;
      ptn_f.resize(npix * 4);
      bool need_pm = !fill_back && rop != 2u && rop != 4u;
      if (need_pm) {
        has_pmask = true;
        pmask.resize(npix);
      }
      for (size_t i = 0; i < npix; i++) {
        float a = (float)ptn_raw[i] * scale;
        float t = a / 255.0f;
        float *p = &ptn_f[4 * i];
        if (fill_back) {
          float inv = 1.0f - t;
          p[0] = fgc[0] * t + bgc[0] * inv;
          p[1] = fgc[1] * t + bgc[1] * inv;
          p[2] = fgc[2] * t + bgc[2] * inv;
          p[3] = fgc[3] * t + bgc[3] * inv;
        } else {
          p[0] = fgc[0] * t;
          p[1] = fgc[1];
          p[2] = fgc[2];
          p[3] = fgc[3];
          if (need_pm) pmask[i] = (uint8_t)(a >= 128.0f);
        }
      }
    }
  } else if (prim) {
    uint32_t back = r[0x90 >> 2], draw = r[0x98 >> 2];
    bool is_frame = (prim == 1u || prim == 2u || api == 1u || api == 2u);
    ptn_present = true;
    if (index_domain) {
      ptn_is_raw = true;
      ptn_raw.resize(npix);
      if (prim == 3u) {
        std::fill(ptn_raw.begin(), ptn_raw.end(), back);
      } else if (prim == 4u || prim == 0u) {
        std::fill(ptn_raw.begin(), ptn_raw.end(), draw);
      } else if (prim == 1u) {
        std::fill(ptn_raw.begin(), ptn_raw.end(), draw);
        has_pmask = true;
        pmask.resize(npix);
        for (uint32_t j = 0; j < h; j++)
          for (uint32_t i = 0; i < w; i++)
            pmask[(size_t)j * w + i] = (uint8_t)(j == 0 || j == h - 1 || i == 0 || i == w - 1);
      } else {
        for (uint32_t j = 0; j < h; j++)
          for (uint32_t i = 0; i < w; i++)
            ptn_raw[(size_t)j * w + i] = (j == 0 || j == h - 1 || i == 0 || i == w - 1) ? draw : back;
      }
    } else {
      float bc[4], dc[4];
      if (!decode_colour_one(back, col_fmt, bc) || !decode_colour_one(draw, col_fmt, dc))
        return -1;
      ptn_is_raw = false;
      ptn_f.resize(npix * 4);
      if (prim == 1u) {
        has_pmask = true;
        pmask.resize(npix);
      }
      for (uint32_t j = 0; j < h; j++) {
        for (uint32_t i = 0; i < w; i++) {
          bool border = is_frame && (j == 0 || j == h - 1 || i == 0 || i == w - 1);
          if (prim == 1u) pmask[(size_t)j * w + i] = (uint8_t)border;
          const float *c = (prim == 3u || (prim == 2u && !border)) ? bc : dc;
          float *p = &ptn_f[4 * ((size_t)j * w + i)];
          p[0] = c[0]; p[1] = c[1]; p[2] = c[2]; p[3] = c[3];
        }
      }
    }
  }

  // SRC (background)
  bool src_present = false, src_is_raw = false;
  auto &src_raw = g_scratch.raw_b;
  auto &src_f = g_scratch.src_f;
  if (src_mode == 1u || src_mode == 2u || ((rop == 0u || rop == 2u || rop == 3u || rop == 4u) && src_mode == 0u && !ptn_present)) {
    uint32_t s_addr = 0;
    if (!ge_addr(r, 0x44, phys_mask, s_addr)) return -1;
    if (!s_addr) s_addr = dst;
    uint32_t sxy = r[0x4C >> 2];
    if (sxy == 0x0FFF0FFFu) sxy = dxy;
    uint32_t sx_ = sxy & 0xFFFu, sy_ = (sxy >> 16) & 0xFFFu;
    uint32_t s_pf = (src_pf & 0xFFFu) ? src_pf : dst_pf;
    uint32_t s_fmt = (s_pf >> 12) & 0x1Fu;
    if (!read_raw_surface(ram, ram_size, s_addr, s_pf, sx_, sy_, w, h, false, src_raw))
      return -1;
    src_present = true;
    if (index_domain && is_index_fmt(s_fmt)) {
      src_is_raw = true;
    } else {
      float clut_buf[256 * 4];
      uint32_t clut_n = 0;
      const float *clut_ptr = nullptr;
      if (clut_en && is_clut_fmt(s_fmt) && ptn_type != 1u) {
        if (load_clut(ram, ram_size, phys_mask, r, 256u, clut_buf, clut_n))
          clut_ptr = clut_buf;
      }
      if (!decode_surface(src_raw.data(), npix, s_fmt, s_pf, clut_ptr, clut_n, src_f))
        return -1;
      src_is_raw = false;
    }
  } else if (src_mode == 3u || src_mode == 4u) {
    uint32_t back = r[0x90 >> 2];
    src_present = true;
    if (index_domain) {
      src_is_raw = true;
      src_raw.assign(npix, back);
    } else {
      float bc[4];
      if (!decode_colour_one(back, col_fmt, bc)) return -1;
      src_is_raw = false;
      src_f.resize(npix * 4);
      for (size_t i = 0; i < npix; i++) {
        float *p = &src_f[4 * i];
        p[0] = bc[0]; p[1] = bc[1]; p[2] = bc[2]; p[3] = bc[3];
      }
    }
  }

  bool need_dst = (rop == 2u || rop == 3u || rop == 4u || ckey_en || bmask_en);
  if (!src_present && need_dst) {
    if (!read_raw_surface(ram, ram_size, dst, dst_pf, dx, dy, w, h, false, src_raw))
      return -1;
    src_present = true;
    if (index_domain) {
      src_is_raw = true;
    } else {
      if (!decode_surface(src_raw.data(), npix, dst_fmt, dst_pf, nullptr, 0, src_f))
        return -1;
      src_is_raw = false;
    }
  }

  // MSK
  bool has_malpha = false;
  auto &malpha = g_scratch.malpha;
  if (msk_mode) {
    uint32_t m_addr = 0;
    if (!ge_addr(r, 0x60, phys_mask, m_addr)) return -1;
    uint32_t m_pf = r[0x64 >> 2];
    uint32_t m_fmt = (m_pf >> 12) & 0x1Fu;
    uint32_t mxy = r[0x68 >> 2];
    auto &mraw = g_scratch.raw_c;
    if (!read_raw_surface(ram, ram_size, m_addr, m_pf, mxy & 0xFFFu, (mxy >> 16) & 0xFFFu, w, h,
                          ((m >> 17) & 1u) != 0, mraw))
      return -1;
    int mbpp = ge_bpp(m_fmt);
    if (!mbpp) return -1;
    if (m_fmt == 0x1Cu || mbpp == 1) {
      if (!has_pmask) {
        has_pmask = true;
        pmask.resize(npix);
        for (size_t i = 0; i < npix; i++) pmask[i] = (uint8_t)(mraw[i] != 0);
      } else {
        for (size_t i = 0; i < npix; i++) pmask[i] = (uint8_t)(pmask[i] && (mraw[i] != 0));
      }
    } else {
      int bits = std::min(8, mbpp);
      uint32_t mask_bits = (1u << bits) - 1u;
      float denom = (float)mask_bits;
      bool inv = ((m_pf >> 25) & 1u) != 0;
      has_malpha = true;
      malpha.resize(npix);
      for (size_t i = 0; i < npix; i++) {
        float ma = (float)(mraw[i] & mask_bits) / denom;
        if (inv) ma = 1.0f - ma;
        malpha[i] = ma;
      }
      if (rop != 2u && rop != 4u) {
        if (!has_pmask) {
          has_pmask = true;
          pmask.resize(npix);
          for (size_t i = 0; i < npix; i++) pmask[i] = (uint8_t)(malpha[i] >= 0.5f);
        } else {
          for (size_t i = 0; i < npix; i++) pmask[i] = (uint8_t)(pmask[i] && (malpha[i] >= 0.5f));
        }
      }
    }
  }

  // ROP
  bool out_present = false, out_is_raw = false;
  std::vector<uint32_t> *out_raw_ptr = nullptr;
  std::vector<float> *out_f_ptr = nullptr;
  auto &out_f = g_scratch.out_f;
  auto &out_raw_vec = g_scratch.raw_c;

  if (rop == 0u) {
    if (src_present) {
      out_present = true; out_is_raw = src_is_raw;
      out_raw_ptr = &src_raw; out_f_ptr = &src_f;
    } else if (ptn_present) {
      out_present = true; out_is_raw = ptn_is_raw;
      out_raw_ptr = &ptn_raw; out_f_ptr = &ptn_f;
    }
  } else if (rop == 1u) {
    if (ptn_present) {
      out_present = true; out_is_raw = ptn_is_raw;
      out_raw_ptr = &ptn_raw; out_f_ptr = &ptn_f;
    } else if (src_present) {
      out_present = true; out_is_raw = src_is_raw;
      out_raw_ptr = &src_raw; out_f_ptr = &src_f;
    }
  } else if ((rop == 2u || rop == 4u) && !index_domain) {
    if (!ptn_present) {
      if (src_present) {
        out_present = true; out_is_raw = src_is_raw;
        out_raw_ptr = &src_raw; out_f_ptr = &src_f;
      }
    } else {
      if (ptn_is_raw || (src_present && src_is_raw)) return -1;
      uint32_t ac = r[0x84 >> 2];
      uint32_t bmode = (ac >> 8) & 0xFu;
      if (bmode != 0u) return -1;
      float galpha = (float)((double)(ac & 0xFFu) / 255.0);
      bool gsel = ((ac >> 12) & 1u) != 0;
      uint32_t out_mode = (ac >> 20) & 3u;
      if (!src_present) {
        src_f.assign(npix * 4, 0.0f);
      }
      out_f.resize(npix * 4);
      for (size_t i = 0; i < npix; i++) {
        const float *p = &ptn_f[4 * i];
        const float *s = &src_f[4 * i];
        float pa = p[0] / 255.0f;
        pa = gsel ? galpha : (pa * galpha);
        if (has_malpha) pa = pa * malpha[i];
        float sa = s[0] / 255.0f;
        float inv_pa = 1.0f - pa;
        float *res = &out_f[4 * i];
        res[1] = (p[1] * pa) + (s[1] * inv_pa);
        res[2] = (p[2] * pa) + (s[2] * inv_pa);
        res[3] = (p[3] * pa) + (s[3] * inv_pa);
        if (out_mode == 1u) res[0] = s[0];
        else if (out_mode == 2u) res[0] = p[0];
        else res[0] = (pa + (sa * inv_pa)) * 255.0f;
      }
      out_present = true;
      out_is_raw = false;
      out_f_ptr = &out_f;
    }
  } else if (rop == 3u || rop == 4u || (rop == 2u && index_domain)) {
    if (!ptn_present && !src_present) return -1;
    uint32_t op = (r[0x84 >> 2] >> 16) & 0xFu;
    std::vector<uint32_t> a_vec, b_vec;
    const uint32_t *a_ptr = nullptr;
    const uint32_t *b_ptr = nullptr;
    if (index_domain) {
      if (ptn_present && !ptn_is_raw) return -1;
      if (src_present && !src_is_raw) return -1;
      a_ptr = ptn_present ? ptn_raw.data() : src_raw.data();
      b_ptr = src_present ? src_raw.data() : a_ptr;
    } else {
      if (ptn_present) {
        if (ptn_is_raw) a_ptr = ptn_raw.data();
        else {
          if (!encode_surface(ptn_f.data(), npix, dst_fmt, dst_pf, a_vec)) return -1;
          a_ptr = a_vec.data();
        }
      }
      if (src_present) {
        if (src_is_raw) b_ptr = src_raw.data();
        else {
          if (!encode_surface(src_f.data(), npix, dst_fmt, dst_pf, b_vec)) return -1;
          b_ptr = b_vec.data();
        }
      } else {
        b_ptr = a_ptr;
      }
      if (!a_ptr) a_ptr = b_ptr;
    }
    out_raw_vec.resize(npix);
    for (size_t i = 0; i < npix; i++) {
      uint32_t a = a_ptr[i], b = b_ptr[i];
      uint32_t na = ~a, nb = ~b, rv = 0;
      switch (op) {
        case 0: rv = 0u; break;
        case 1: rv = a & b; break;
        case 2: rv = a & nb; break;
        case 3: rv = b; break;
        case 4: rv = na & b; break;
        case 5: rv = a; break;
        case 6: rv = a ^ b; break;
        case 7: rv = a | b; break;
        case 8: rv = ~(a | b); break;
        case 9: rv = a ^ nb; break;
        case 10: rv = na; break;
        case 11: rv = na | b; break;
        case 12: rv = nb; break;
        case 13: rv = a | nb; break;
        case 14: rv = ~(a & b); break;
        case 15: rv = ~0u; break;
      }
      out_raw_vec[i] = rv;
    }
    out_present = true;
    if (index_domain) {
      out_is_raw = true;
      out_raw_ptr = &out_raw_vec;
    } else {
      if (!decode_surface(out_raw_vec.data(), npix, dst_fmt, dst_pf, nullptr, 0, out_f))
        return -1;
      out_is_raw = false;
      out_f_ptr = &out_f;
    }
  }

  if (!out_present) return -1;

  // Colour key
  if (ckey_en && (ptn_present || src_present)) {
    uint32_t lo = r[0x88 >> 2], hi = r[0x8C >> 2];
    uint32_t ck_mode = (r[0x84 >> 2] >> 30) & 3u;
    std::vector<uint32_t> dst_ck_raw;
    std::vector<float> dst_ck_f;
    bool is_idx_key = false;
    bool cfmt_none = false;
    const uint32_t *ck_raw_ptr = nullptr;
    const float *ck_f_ptr = nullptr;

    if (ck_mode == 0u) {
      if (!read_raw_surface(ram, ram_size, dst, dst_pf, dx, dy, w, h, false, dst_ck_raw))
        return -1;
      if (index_domain || is_index_fmt(dst_fmt)) {
        is_idx_key = true;
        ck_raw_ptr = dst_ck_raw.data();
      } else {
        if (!decode_surface(dst_ck_raw.data(), npix, dst_fmt, dst_pf, nullptr, 0, dst_ck_f))
          return -1;
        ck_f_ptr = dst_ck_f.data();
      }
    } else if (ck_mode == 2u && ptn_raw_valid && is_clut_fmt(ptn_fmt)) {
      is_idx_key = true;
      cfmt_none = true;
      ck_raw_ptr = ptn_raw.data();
    } else {
      if (!ptn_present) return -1;
      if (index_domain) {
        is_idx_key = true;
        if (ptn_is_raw) {
          ck_raw_ptr = ptn_raw.data();
        } else {
          if (!encode_surface(ptn_f.data(), npix, dst_fmt, dst_pf, dst_ck_raw)) return -1;
          ck_raw_ptr = dst_ck_raw.data();
        }
      } else {
        if (ptn_is_raw) return -1;
        ck_f_ptr = ptn_f.data();
      }
    }

    if (!has_pmask) {
      has_pmask = true;
      pmask.assign(npix, 1u);
    }
    if (is_idx_key) {
      uint32_t klo = cfmt_none ? (lo & 0xFFu) : lo;
      uint32_t khi = cfmt_none ? (hi & 0xFFu) : hi;
      for (size_t i = 0; i < npix; i++) {
        uint32_t v = ck_raw_ptr[i];
        bool hit = (v >= klo && v <= khi);
        if (hit) pmask[i] = 0;
      }
    } else {
      uint32_t lo_a = (lo >> 24) & 0xFFu, lo_r = (lo >> 16) & 0xFFu, lo_g = (lo >> 8) & 0xFFu, lo_b = lo & 0xFFu;
      uint32_t hi_a = (hi >> 24) & 0xFFu, hi_r = (hi >> 16) & 0xFFu, hi_g = (hi >> 8) & 0xFFu, hi_b = hi & 0xFFu;
      for (size_t i = 0; i < npix; i++) {
        const float *c = &ck_f_ptr[4 * i];
        uint32_t ca = round_u8(c[0]), cr = round_u8(c[1]), cg = round_u8(c[2]), cb = round_u8(c[3]);
        bool hit = (ca >= lo_a && ca <= hi_a) && (cr >= lo_r && cr <= hi_r) &&
                   (cg >= lo_g && cg <= hi_g) && (cb >= lo_b && cb <= hi_b);
        if (hit) pmask[i] = 0;
      }
    }
  }

  if (has_pmask) {
    if (!wmask_ptr) {
      wmask_ptr = pmask.data();
    } else {
      auto &wm = g_scratch.wmask;
      for (size_t i = 0; i < npix; i++) wm[i] = (uint8_t)(wm[i] && pmask[i]);
      wmask_ptr = wm.data();
    }
  }

  const uint32_t *final_vals = nullptr;
  if (index_domain) {
    if (out_is_raw) {
      final_vals = out_raw_ptr->data();
    } else {
      if (!encode_surface(out_f_ptr->data(), npix, dst_fmt, dst_pf, out_raw_vec))
        return -1;
      final_vals = out_raw_vec.data();
    }
  } else {
    if (out_is_raw) {
      if (!decode_surface(out_raw_ptr->data(), npix, dst_fmt, dst_pf, nullptr, 0, out_f))
        return -1;
      out_f_ptr = &out_f;
    }
    uint32_t mode = (r[0x84 >> 2] >> 20) & 3u;
    if (mode == 3u) {
      float a_reg = (float)((dst_pf >> 24) & 0xFFu);
      float *fp = out_f_ptr->data();
      for (size_t i = 0; i < npix; i++) fp[4 * i] = a_reg;
    }
    if (!encode_surface(out_f_ptr->data(), npix, dst_fmt, dst_pf, out_raw_vec))
      return -1;
    final_vals = out_raw_vec.data();
  }

  std::vector<uint32_t> bmask_vec;
  if (bmask_en) {
    uint32_t bm = r[0x70 >> 2];
    if (!read_raw_surface(ram, ram_size, dst, dst_pf, dx, dy, w, h, false, bmask_vec))
      return -1;
    for (size_t i = 0; i < npix; i++) {
      bmask_vec[i] = (final_vals[i] & bm) | (bmask_vec[i] & ~bm);
    }
    final_vals = bmask_vec.data();
  }

  write_raw_surface(ram, ram_size, dst, dst_pf, dx, dy, w, h, final_vals, wmask_ptr);
  (*prims_io)++;
  return 0;
}

// Run a GE_M36F command list in C++. Returns the word index reached (== n_words if completed,
// or the index of the header that needs Python fallback).
static uint32_t ge_m36f_run_list_cpp(uint8_t *ram, uint32_t ram_size, uint32_t phys_mask,
                                     const uint32_t *words, uint32_t n_words,
                                     uint32_t *ge_regs, const uint32_t *live_regs,
                                     uint64_t *prims_io) {
  static const uint8_t GROUP_COUNT[17] = {1, 2, 2, 2, 2, 3, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2};
  static const uint8_t GROUP_REGS[17][3] = {
    {0x30 >> 2, 0, 0},
    {0x34 >> 2, 0x38 >> 2, 0},
    {0x44 >> 2, 0x48 >> 2, 0},
    {0x50 >> 2, 0x54 >> 2, 0},
    {0x60 >> 2, 0x64 >> 2, 0},
    {0x90 >> 2, 0x94 >> 2, 0x98 >> 2},
    {0x9C >> 2, 0, 0},
    {0x88 >> 2, 0x8C >> 2, 0},
    {0x3C >> 2, 0x40 >> 2, 0},
    {0x4C >> 2, 0, 0},
    {0x58 >> 2, 0x5C >> 2, 0},
    {0x68 >> 2, 0x6C >> 2, 0},
    {0x70 >> 2, 0, 0},
    {0x74 >> 2, 0x78 >> 2, 0},
    {0x7C >> 2, 0x80 >> 2, 0},
    {0x84 >> 2, 0, 0},
    {0xA0 >> 2, 0xA4 >> 2, 0},
  };
  if (live_regs) {
    for (uint32_t o = 0xC0; o < 0xD0; o += 4) ge_regs[o >> 2] = live_regs[o >> 2];
  }
  uint32_t i = 0;
  while (i < n_words) {
    uint32_t hdr_idx = i;
    uint32_t h = words[i++];
    uint32_t op = h >> 24;
    if (op == 0x02u || op == 0x82u) {
      uint32_t mask = h & 0xFFFFFFu;
      uint32_t save_regs[64];
      memcpy(save_regs, ge_regs, sizeof(save_regs));
      for (int g = 0; g < 17; g++) {
        if ((mask >> g) & 1u) {
          int cnt = GROUP_COUNT[g];
          for (int k = 0; k < cnt; k++) {
            if (i >= n_words) return n_words;
            ge_regs[GROUP_REGS[g][k]] = words[i++];
          }
        }
      }
      if (ge_m36f_exec_one(ram, ram_size, phys_mask, ge_regs, prims_io) != 0) {
        memcpy(ge_regs, save_regs, sizeof(save_regs));
        return hdr_idx;
      }
    } else if (op == 0x81u) {
      uint32_t reg = (h >> 8) & 0xFFu;
      uint32_t cnt = h & 0xFFu;
      for (uint32_t k = 0; k < cnt; k++) {
        if (i >= n_words) return n_words;
        ge_regs[((reg >> 2) + k) & 63u] = words[i++];
      }
    } else {
      return hdr_idx;
    }
  }
  return n_words;
}

// ------------------------------------------------------------------
// GE_M3602 C++ acceleration (src/ge_m3602.py)
// ------------------------------------------------------------------
static inline int ge_m3602_bpp(uint32_t fmt) {
  switch (fmt) {
    case 0x00: case 0x02: case 0x03: case 0x04: case 0x06: case 0x07: case 0x0C: return 2;
    case 0x05: case 0x15: return 4;
    case 0x0B: case 0x19: return 1;
    default: return 0;
  }
}

// Runs a chain of GE_M3602 commands starting at (*addr_io, *mask_io).
// Returns 0 if finished, or 1 if the command at (*addr_io, *mask_io) needs Python fallback (to record unsupported).
static int ge_m3602_run_cpp(uint8_t *ram, uint32_t ram_size, uint32_t *addr_io, uint32_t *mask_io, uint64_t *cmds_io) {
  static const int SEC_BITS[8] = {7, 0, 1, 3, 4, 2, 6, 5};
  static const int SEC_WORDS[8] = {2, 6, 6, 4, 4, 2, 2, 3};
  uint32_t address = *addr_io;
  uint32_t mask = *mask_io;
  while (*cmds_io < 4096u) {
    uint32_t a = address % ram_size;
    if (a + 40u * 4u > ram_size) return 0;
    uint32_t w[40];
    memcpy(w, ram + a, 40 * 4);

    int sec_off[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
    int idx = 8;
    for (int s = 0; s < 8; s++) {
      int bit = SEC_BITS[s];
      int nw = SEC_WORDS[s];
      if ((mask >> bit) & 1u) {
        sec_off[bit] = idx;
        idx += nw;
      }
    }
    if (sec_off[0] < 0) { *addr_io = address; *mask_io = mask; return 1; }
    uint32_t ctrl = w[1];
    if (((ctrl >> 16) & 7u) != 1u) { *addr_io = address; *mask_io = mask; return 1; }
    const uint32_t *src1 = &w[sec_off[0]];
    uint32_t size = src1[4];
    uint32_t width = (size & 0xFFFFu) + 1u;
    uint32_t height = (size >> 16) + 1u;
    uint32_t dfmt = (w[5] >> 16) & 0x1Fu;
    uint32_t dpitch = w[5] & 0xFFFFu;
    int dbpp = ge_m3602_bpp(dfmt);
    if (!dbpp) { *addr_io = address; *mask_io = mask; return 1; }
    uint32_t dx = w[4] & 0xFFFFu, dy = w[4] >> 16;

    const uint32_t *palette = nullptr;
    uint32_t pal_buf[256];
    if (sec_off[2] >= 0 && ((w[sec_off[2]] >> 18) & 1u)) {
      uint32_t p = w[sec_off[2] + 1] % ram_size;
      if (p + 1024u <= ram_size) {
        memcpy(pal_buf, ram + p, 1024);
        palette = pal_buf;
      }
    }

    uint32_t mode = (ctrl >> 3) & 3u;
    if (sec_off[1] < 0 || (mode != 1u && mode != 2u)) { *addr_io = address; *mask_io = mask; return 1; }
    const uint32_t *src2 = &w[sec_off[1]];

    if (dpitch / (uint32_t)dbpp <= dx) { *addr_io = address; *mask_io = mask; return 1; }
    uint32_t write_w = std::min(width, dpitch / (uint32_t)dbpp - dx);
    if (write_w == 0 || height == 0) { *addr_io = address; *mask_io = mask; return 1; }
    uint32_t dst_a = (w[2] + dy * dpitch + dx * (uint32_t)dbpp) % ram_size;
    if ((uint64_t)dst_a + (uint64_t)(height - 1u) * dpitch + (uint64_t)write_w * dbpp > ram_size) {
      *addr_io = address; *mask_io = mask; return 1;
    }

    bool has_clip = (sec_off[6] >= 0);
    uint32_t cx0 = 0, cy0 = 0, cx1 = 0, cy1 = 0;
    bool clip_in = true;
    if (has_clip) {
      uint32_t c0 = w[sec_off[6]], c1 = w[sec_off[6] + 1];
      cx0 = c0 & 0x7FFFu; cy0 = (c0 >> 16) & 0x7FFFu;
      cx1 = c1 & 0x7FFFu; cy1 = (c1 >> 16) & 0x7FFFu;
      clip_in = (c0 >> 31) != 0;
    }

    if (mode == 2u) {
      uint32_t colour = src2[5];
      uint32_t sfmt = (src2[3] >> 16) & 0x1Fu;
      if (palette && sfmt == 0x0Bu && dbpp == 4) {
        colour = palette[colour & 0xFFu];
      }
      for (uint32_t r = 0; r < height; r++) {
        uint32_t yy = dy + r;
        bool y_inside = (yy >= cy0 && yy <= cy1);
        uint8_t *drow = ram + dst_a + (size_t)r * dpitch;
        for (uint32_t c = 0; c < write_w; c++) {
          if (has_clip) {
            uint32_t xx = dx + c;
            bool in = y_inside && (xx >= cx0 && xx <= cx1);
            if (clip_in ? !in : in) continue;
          }
          if (dbpp == 1) drow[c] = (uint8_t)colour;
          else if (dbpp == 2) { uint16_t v = (uint16_t)colour; memcpy(drow + 2 * c, &v, 2); }
          else { memcpy(drow + 4 * c, &colour, 4); }
        }
      }
    } else {
      uint32_t sfmt = (src2[3] >> 16) & 0x1Fu;
      uint32_t spitch = src2[3] & 0xFFFFu;
      int sbpp = ge_m3602_bpp(sfmt);
      if (!sbpp) { *addr_io = address; *mask_io = mask; return 1; }
      int eff_sbpp = (palette && sfmt == 0x0Bu) ? 4 : sbpp;
      if (eff_sbpp != dbpp) { *addr_io = address; *mask_io = mask; return 1; }
      uint32_t sx = src2[2] & 0xFFFFu, sy = src2[2] >> 16;
      uint32_t sw = (src2[4] & 0xFFFFu) + 1u, sh = (src2[4] >> 16) + 1u;
      uint32_t src_a = (src2[0] + sy * spitch + sx * (uint32_t)sbpp) % ram_size;
      if (sw == 0 || sh == 0 || (uint64_t)src_a + (uint64_t)(sh - 1u) * spitch + (uint64_t)sw * sbpp > ram_size) {
        *addr_io = address; *mask_io = mask; return 1;
      }
      bool has_resize = (sec_off[3] >= 0);
      uint32_t hstep = has_resize ? (w[sec_off[3] + 1] & 0xFFFFu) : 8192u;
      uint32_t vstep = has_resize ? (w[sec_off[3] + 1] >> 16) : 8192u;

      auto &out_buf = g_scratch.raw_a;
      out_buf.resize((size_t)height * write_w);
      for (uint32_t r = 0; r < height; r++) {
        uint32_t sr = has_resize ? std::min((r * vstep) >> 13, sh - 1u) : std::min(r, sh - 1u);
        const uint8_t *srow = ram + src_a + (size_t)sr * spitch;
        uint32_t *orow = &out_buf[(size_t)r * write_w];
        for (uint32_t c = 0; c < write_w; c++) {
          uint32_t sc = has_resize ? std::min((c * hstep) >> 13, sw - 1u) : std::min(c, sw - 1u);
          uint32_t val = 0;
          if (sbpp == 1) val = srow[sc];
          else if (sbpp == 2) { uint16_t v; memcpy(&v, srow + 2 * sc, 2); val = v; }
          else { memcpy(&val, srow + 4 * sc, 4); }
          if (palette && sfmt == 0x0Bu) val = palette[val & 0xFFu];
          orow[c] = val;
        }
      }
      for (uint32_t r = 0; r < height; r++) {
        uint32_t yy = dy + r;
        bool y_inside = (yy >= cy0 && yy <= cy1);
        uint8_t *drow = ram + dst_a + (size_t)r * dpitch;
        const uint32_t *orow = &out_buf[(size_t)r * write_w];
        for (uint32_t c = 0; c < write_w; c++) {
          if (has_clip) {
            uint32_t xx = dx + c;
            bool in = y_inside && (xx >= cx0 && xx <= cx1);
            if (clip_in ? !in : in) continue;
          }
          uint32_t val = orow[c];
          if (dbpp == 1) drow[c] = (uint8_t)val;
          else if (dbpp == 2) { uint16_t v = (uint16_t)val; memcpy(drow + 2 * c, &v, 2); }
          else { memcpy(drow + 4 * c, &val, 4); }
        }
      }
    }

    (*cmds_io)++;
    uint32_t link = w[0];
    if (!link) return 0;
    address = (address & 0x0F000000u) | (link & 0xFFFFFFu);
    mask = link >> 24;
  }
  return 0;
}

// ------------------------------------------------------------------
// GMA capture & screen regression kernels
// ------------------------------------------------------------------
static thread_local uint64_t g_colour_seen[1 << 18];
static thread_local uint32_t g_colour_dirty[65536];

static uint32_t gma_count_colours_cpp(const uint8_t *rgb, uint32_t n_pixels) {
  uint32_t unique_count = 0;
  uint32_t n_dirty = 0;
  uint32_t last_c = 0xFFFFFFFFu;
  bool overflow = false;
  for (uint32_t i = 0; i < n_pixels; i++) {
    const uint8_t *p = rgb + 3 * i;
    uint32_t c = ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
    if (c == last_c) continue;
    last_c = c;
    uint32_t w = c >> 6;
    uint64_t bit = 1ull << (c & 63u);
    uint64_t cur = g_colour_seen[w];
    if (!(cur & bit)) {
      if (!cur) {
        if (n_dirty < 65536u) g_colour_dirty[n_dirty++] = w;
        else overflow = true;
      }
      g_colour_seen[w] = cur | bit;
      unique_count++;
    }
  }
  if (!overflow) {
    for (uint32_t i = 0; i < n_dirty; i++) g_colour_seen[g_colour_dirty[i]] = 0;
  } else {
    memset(g_colour_seen, 0, sizeof(g_colour_seen));
  }
  return unique_count;
}

static uint32_t gma_diff_rgb_cpp(const uint8_t *a, const uint8_t *b, uint32_t n_pixels, uint32_t *max_diff_out) {
  uint32_t diff_pixels = 0;
  uint32_t max_d = 0;
  for (uint32_t i = 0; i < n_pixels; i++) {
    const uint8_t *pa = a + 3 * i;
    const uint8_t *pb = b + 3 * i;
    uint32_t d0 = pa[0] > pb[0] ? (uint32_t)(pa[0] - pb[0]) : (uint32_t)(pb[0] - pa[0]);
    uint32_t d1 = pa[1] > pb[1] ? (uint32_t)(pa[1] - pb[1]) : (uint32_t)(pb[1] - pa[1]);
    uint32_t d2 = pa[2] > pb[2] ? (uint32_t)(pa[2] - pb[2]) : (uint32_t)(pb[2] - pa[2]);
    uint32_t dm = std::max(d0, std::max(d1, d2));
    if (dm) {
      diff_pixels++;
      if (dm > max_d) max_d = dm;
    }
  }
  if (max_diff_out) *max_diff_out = max_d;
  return diff_pixels;
}

static void gma_blend_cpp(float *canvas, uint32_t cw, uint32_t ch,
                          const uint8_t *rgba, uint32_t rw, uint32_t rh,
                          int32_t x, int32_t y) {
  if (x >= (int32_t)cw || y >= (int32_t)ch || x < 0 || y < 0) return;
  uint32_t hh = std::min(rh, ch - (uint32_t)y);
  uint32_t ww = std::min(rw, cw - (uint32_t)x);
  if (hh == 0 || ww == 0) return;
  for (uint32_t j = 0; j < hh; j++) {
    float *drow = canvas + ((size_t)(y + j) * cw + (uint32_t)x) * 3;
    const uint8_t *srow = rgba + (size_t)j * rw * 4;
    for (uint32_t i = 0; i < ww; i++) {
      uint8_t au = srow[4 * i + 3];
      if (au == 0) continue;
      float *d = drow + 3 * i;
      if (au == 255) {
        d[0] = (float)srow[4 * i + 0];
        d[1] = (float)srow[4 * i + 1];
        d[2] = (float)srow[4 * i + 2];
      } else {
        float a = (float)au / 255.0f;
        float inv_a = 1.0f - a;
        d[0] = (d[0] * inv_a) + ((float)srow[4 * i + 0] * a);
        d[1] = (d[1] * inv_a) + ((float)srow[4 * i + 1] * a);
        d[2] = (d[2] * inv_a) + ((float)srow[4 * i + 2] * a);
      }
    }
  }
}

static void gma_scale_u8_cpp(const uint8_t *src, uint32_t sw, uint32_t sh, uint32_t channels,
                             uint8_t *dst, const int32_t *rows, uint32_t dh,
                             const int32_t *cols, uint32_t dw) {
  (void)sh;
  if (channels == 4) {
    const uint32_t *s32 = (const uint32_t *)src;
    uint32_t *d32 = (uint32_t *)dst;
    for (uint32_t j = 0; j < dh; j++) {
      const uint32_t *srow = s32 + (size_t)rows[j] * sw;
      uint32_t *drow = d32 + (size_t)j * dw;
      for (uint32_t i = 0; i < dw; i++) {
        drow[i] = srow[cols[i]];
      }
    }
  } else if (channels == 3) {
    for (uint32_t j = 0; j < dh; j++) {
      const uint8_t *srow = src + (size_t)rows[j] * sw * 3;
      uint8_t *drow = dst + (size_t)j * dw * 3;
      for (uint32_t i = 0; i < dw; i++) {
        const uint8_t *sp = srow + (size_t)cols[i] * 3;
        uint8_t *dp = drow + (size_t)i * 3;
        dp[0] = sp[0]; dp[1] = sp[1]; dp[2] = sp[2];
      }
    }
  }
}

}  // namespace ali_gfx
