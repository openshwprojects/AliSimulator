"""
Unit test (fast): the transport stream the demultiplexer model feeds a locked
channel (transport_stream.py, dmx_m36.py).  Checks the table builders -- the
MPEG-2 CRC-32, the section lengths, the TS packetisation with continuity
counters -- and the demultiplexer register model on a booted-but-not-run
dump.bin: the filter RAM write port (mask / value as the driver's
dmx_set_pid writes them), the united ring (base, length, threshold), the
write pointer the firmware reads, the threshold interrupt on line 7 and its
read-to-clear status, and that the feed stops when the ring is full.  Then a
signal on one frequency (set_signal(frequencies=...)): the demodulator's lock
bits and the stream only while the MxL603 model is tuned there.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import datetime
import struct

import transport_stream as ts
import tuners
from simulator import AliMipsSimulator

ok = True


def check(cond, msg):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    ok &= bool(cond)


print("=== Unit test: transport stream tables and the demultiplexer model ===")
check(ts.crc32_mpeg2(b"123456789") == 0x0376E6E7, "CRC-32/MPEG-2 check value of '123456789' is 0x0376E6E7")
check(ts.mjd(datetime.date(2026, 10, 10)) == 61323, "MJD of 2026-10-10 is 61323")
mux = ts.Mux(clock=datetime.datetime(2026, 10, 10, 12, 34, 56))
for pid in sorted(mux.known_pids()):
    for sec in mux.sections_for(pid):
        length = struct.unpack(">H", sec[1:3])[0] & 0xFFF
        check(len(sec) == 3 + length, f"PID 0x{pid:04X} table 0x{sec[0]:02X}: section_length {length} matches ({len(sec)} bytes)")
        if sec[0] != ts.TID_TDT:
            check(ts.crc32_mpeg2(sec) == 0, f"PID 0x{pid:04X} table 0x{sec[0]:02X}: the CRC-32 checks")
pat = mux.sections_for(ts.PID_PAT)[0]
check(pat[8:12] == b"\x01\x01\xe1\x00", "the PAT lists programme 0x0101 on PMT PID 0x0100")
tdt = mux.sections_for(ts.PID_TDT)[0]
check(tdt[3:8] == bytes([61323 >> 8, 61323 & 0xFF, 0x12, 0x34, 0x56]), "the TDT carries 2026-10-10 12:34:56 as MJD + BCD")
packets, counter = ts.ts_packets(0x0100, b"\x02" * 300, 5)
check(len(packets) == 2 and all(len(p) == 188 for p in packets), "a 300-byte section takes two 188-byte packets")
check(packets[0][:4] == bytes([0x47, 0x41, 0x00, 0x15]) and packets[0][4] == 0 and packets[1][3] == 0x16 and counter == 7,
      "payload_unit_start and pointer_field 0 on the first packet, continuity counters 5, 6")
check(packets[1][-1] == 0xFF, "the last packet is padded with 0xFF")

# the channel database of dump.bin
image = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dumps", "dump.bin"), "rb").read()
rec = ts.channel_by_pmt_pid(image, 0x0321)
check(rec is not None and rec[0] == 0x001A and rec[1] == 0x0322 and rec[2].startswith("Polsat Sport New"),
      f"dump.bin's channel on PMT PID 0x0321 is programme 0x1A \"Polsat Sport News\", video 0x322 ({rec})")
rec = ts.channel_by_pmt_pid(image, 0x06A5)
check(rec is not None and rec[0] == 0x0011 and rec[2].startswith("TVP Opol"), f"PMT PID 0x06A5 is programme 0x11 \"TVP Opole\" ({rec})")
check(ts.channel_by_pmt_pid(image, 0x1234) is None, "an unknown PMT PID has no record")

# the register model, on a loaded dump.bin (nothing is run)
logs = []
sim = AliMipsSimulator(log_handler=lambda m: logs.append(m) if m.startswith("[DMX]") else None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(lambda c: None)
sim.loadFile("dump.bin")
dmx = sim.attach_mux(mux)
check(dmx is not None and dmx.base == 0x22000 and dmx.line == 7, "the M3801 family has DMX0 at 0xB8022000 on line 7")
base = 0xB8000000 + dmx.base
mu = sim.mu


def guest_write(addr, data):
    """A guest store: the model's write hooks, then the memory (the device
    window runs a write hook before the store lands)."""
    for h in sim._mmio_wr.get(addr & 0xFFFFFF, []):
        h(mu, 0, addr, len(data), int.from_bytes(data, 'little'), None)
    mu.mem_write(addr, data)


def guest_read(addr, n):
    for h in sim._mmio_rd.get(addr & 0xFFFFFF, []):
        h(mu, 0, addr, n, 0, None)
    return int.from_bytes(mu.mem_read(addr, n), 'little')


for index, pid in ((3, ts.PID_PAT), (5, 0x0100), (7, ts.PID_SDT)):      # as dmx_set_pid programs a filter
    mu.mem_write(base + 0x64, bytes([0x1F, 0xFF, 0, 0, 0, 0, 0, 0]))
    mu.mem_write(base + 0x60, bytes([index]))
    guest_write(base + 0x62, bytes([2]))
    mu.mem_write(base + 0x64, bytes([pid >> 8, pid & 0xFF, 0, 0, 0, 0, 0, 0]))
    mu.mem_write(base + 0x60, bytes([0x40 | index]))
    guest_write(base + 0x62, bytes([2]))
check(mu.mem_read(base + 0x62, 1)[0] == 2 and guest_read(base + 0x62, 1) == 0,
      "a filter RAM write completes at once: the go bit reads back clear")
guest_write(base + 0x03, bytes([1]))
check(guest_read(base + 0x03, 1) == 0 and any(m.startswith("[DMX] reset") for m in logs), "the reset bit (+03) reads back clear")
check(dmx.filter_pid(5) == 0x0100 and dmx.filter_pid(3) == 0, "the filters' PIDs are read back from mask and value")
mu.mem_write(base + 0x40, bytes([0xA8]))                                 # filters 3, 5, 7 enabled
mu.mem_write(base + 0xB2, bytes([1]))                                    # united ring at physical 0x500000
mu.mem_write(base + 0xB0, bytes([0]))
mu.mem_write(base + 0xC0, (0x03A00000).to_bytes(4, 'little'))      # the whole address, as the Comsat writes it
mu.mem_write(base + 0x140, (4096).to_bytes(2, 'little'))
mu.mem_write(base + 0x142, (0x50).to_bytes(2, 'little'))
mu.mem_write(base + 0x300, (1).to_bytes(4, 'little'))                    # threshold interrupt of channel 0
mu.mem_write(base + 0x00, bytes([0x20]))                                 # enable
check(dmx.enabled() and dmx.united() and dmx.ring_base() == 0x03A00000 and dmx.ring_length() == 4096,
      f"enabled, united ring at 0x{dmx.ring_base():X} of {dmx.ring_length()} packets")
check(set(dmx.enabled_pids()) == {0, 0x100, 0x11}, "the enabled filters are on PIDs 0x0000, 0x0100, 0x0011")
dmx.service()
check(dmx.write_ptr[0] == 3 and guest_read(base + 0x1C0, 2) == 3, "one repetition of each PID: the write pointer reads 3")
first = bytes(mu.mem_read(0xA0000000 + 0x03A00000, 188))
check(first[:5] == bytes([0x47, 0x40, 0x00, 0x10, 0x00]) and first[5:8] == pat[:3], "the ring's first packet carries the PAT")
check(not sim._ic_lines & (1 << 7), "below the threshold no interrupt is raised")
sim._vt_accum += 10
for _ in range(100):
    dmx.service()
    sim._vt_accum += 0.1
check(dmx.write_ptr[0] >= 0x50 and bool(sim._ic_lines & (1 << 7)) and dmx.status == 1,
      f"after 10 s the ring holds {dmx.write_ptr[0]} packets: the threshold interrupt is up on line 7")
check(guest_read(base + 0x310, 4) == 1 and dmx.status == 0 and not sim._ic_lines & (1 << 7),
      "reading the status (+310) returns bit 0 and clears it, dropping the line")
guest_write(base + 0x1C2, dmx.write_ptr[0].to_bytes(2, 'little'))      # the driver consumed everything
sim._vt_accum += 1
written = dmx.packets_written
dmx.service()
check(dmx.packets_written == written + 3, "with the ring consumed the next due repetition goes in (3 packets)")
mu.mem_write(base + 0x140, (8).to_bytes(2, 'little'))                    # a tiny ring: 8 packets
dmx.write_ptr[0] = 5
guest_write(base + 0x1C2, (6).to_bytes(2, 'little'))                     # only 0 packets free (rd - wr - 1)
sim._vt_accum += 1
written = dmx.packets_written
dmx.service()
check(dmx.packets_written == written, "a full ring takes nothing (the firmware is behind)")
check(any("filter 5 value" in m for m in logs) and any("feeding PID 0x0000" in m for m in logs), "the model logs its filters and feeds")

# a signal on one frequency only (set_signal(frequencies=...)): the demodulator reports lock, and
# the stream flows, while the tuner model is tuned there -- a channel search finds that channel only
mu.mem_write(base + 0x140, (4096).to_bytes(2, 'little'))
guest_write(base + 0x1C2, dmx.write_ptr[0].to_bytes(2, 'little'))      # the ring consumed
tuner, demod = sim.set_signal(True, frequencies=[578_000_000])
lock = 0xB803E01D                                                        # get_lock(): bits 5 / 6
tuner.write(bytes([0x0F, 0x22, 0x10, 0x80, 0x11, 0x76]))                 # the MxL603 on 474 MHz (UHF 21)
sim._vt_accum += 1
written = dmx.packets_written
dmx.service()
check(not sim.tuned_to_signal() and guest_read(lock, 1) & 0x60 == 0 and dmx.packets_written == written,
      f"signal on 578 MHz, tuner on {tuners.describe(tuner)}: no lock, no packets")
tuner.write(bytes([0x10, 0x80, 0x11, 0x90]))                             # 578 MHz (UHF 34): 0x9080 / 64
sim._vt_accum += 1
dmx.service()
check(sim.tuned_to_signal() and guest_read(lock, 1) & 0x60 == 0x60 and dmx.packets_written > written,
      f"tuner on {tuners.describe(tuner)}: the demodulator reports lock and the stream flows")
sim.set_signal(True)
tuner.write(bytes([0x10, 0x80, 0x11, 0x76]))
check(sim.tuned_to_signal() and guest_read(lock, 1) & 0x60 == 0x60, "set_signal(True) without frequencies: a signal everywhere again")

# the M3821's driver (the R265 Lite's) writes each PID filter as one entry: +60 = the filter's
# number with the type bits 0, +64 = the PID's two header bytes, no mask
m21 = AliMipsSimulator(log_handler=lambda m: None)
m21.setSPIDump(False)
m21.setUartHandler(lambda c: None)
m21.loadFile("Opticum Blue R265 Lite/T2GEN265_1.1.5-2022-08-01.abs")
d21 = m21.chip.dmx
check(d21 is not None and d21.base == 0x22000 and d21.pid_entries, "the M3821 family has DMX0 at 0xB8022000, with PID entries")
b21 = 0xB8000000 + d21.base
for index, pid in ((0, ts.PID_PAT), (1, ts.PID_SDT)):
    m21.mu.mem_write(b21 + 0x64, bytes([pid >> 8, pid & 0xFF, 0, 0, 0, 0, 0, 0]))
    m21.mu.mem_write(b21 + 0x60, bytes([index]))
    for h in m21._mmio_wr.get((b21 + 0x62) & 0xFFFFFF, []):
        h(m21.mu, 0, b21 + 0x62, 1, 2, None)
check(d21.filter_pid(0) == ts.PID_PAT and d21.filter_pid(1) == ts.PID_SDT,
      "an M3821 filter entry is its PID: filters 0 / 1 on the PAT / SDT")
print(f"\n[{'PASS' if ok else 'FAIL'}] transport stream and demultiplexer model")
sys.exit(0 if ok else 1)
