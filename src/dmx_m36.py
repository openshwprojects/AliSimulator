"""
Model of the ALi M36xx transport-stream demultiplexer (the SDK's "DMX_M36").
The register protocol is reverse-engineered from the SDK's driver objects in
refs/MainCode/ddk/libcore_hd.a (dmx_hal.o, dmx_api.o, dmx_filter.o,
dmx_sec.o, dmx_tasks.o); the base is the firmwares': the Comsat TE 1050 HD
(dump.bin) and the Thomson THT501 program DMX0 at 0xB8022000 and DMX1 at
0xB8024000 (that library's dmx_api_open names 0xB8012000 for its own chip),
with DMX0's interrupt on controller line 7 (OS IRQ 15):

  +00  control: bit 5 enables the demultiplexer (dmx_hal_en_dmx)
  +01/+02  sync byte (0x47) and sync mode (dmx_hal_set_sync); +03  reset
       all (write 1, the driver polls it until it clears)
  +10..+16  filter FIFO status and thresholds
  +40..+45  one enable bit per PID filter, 48 filters (dmx_hal_en_filter)
  +60..+70  the filter RAM's write port: +64/+68 (and +6C/+70 for a control
       word) hold the data, +60 = type | filter (0x00 mask, 0x40 value,
       0x80 CW), +62 = 2 starts the write and reads back 0 when done
       (dmx_hal_set_ram).  A PID filter is 8 bytes of mask and value over
       the start of the TS packet: the driver's dmx_set_pid writes mask
       1F FF 00.. and value = the PID (dmx_filter.o); the section header
       filters of a request (get_section_param.mask_value) are applied in
       software by its section parser (dmx_sec.o).
  +B0/+B2/+C0  the DMA buffer: in "united" mode (+B2 = 1, dmx_hal_set_united_
       buff) one ring of 188-byte packets for every filter, its physical
       base in +C0 (the Comsat's driver writes the whole 0x03A078A0 there;
       the library splits bits 23..26 off into +B0)
  +140/+142  the ring's length and interrupt threshold in packets (channel
       0; +140 + 4 * ch per channel in divided mode)
  +1C0 + 4 * ch  the hardware's write pointer (packets, 13 bits), +1C2 + 4
       * ch the driver's read pointer (dmx_hal_get_write / set_read)
  +300/+304  threshold interrupt enable, one bit per channel; +310/+314 the
       status the ISR reads (dmx_interrupt); +340/+344 overflow enable and
       status

The driver's task (dmx_task) takes the packets between the read and the
write pointer of channel 0 one by one -- sync byte, PID, the filter whose
PID it is -- and runs its section parser on them (parse_sec: adaptation
field, payload_unit_start, pointer field, continuity counter, the software
mask / value over the section header), assembling the sections the
application asked for (dmx_get_section / dmx_async_get_section).

The model keeps the filters the driver programs, and once a multiplex is
attached (transport_stream.Mux, sim.attach_mux) it writes that multiplex's
tables for every enabled PID into the ring between emulation slices -- the
PAT, PMTs and TDT a few times a second, the SDT, NIT and EIT once a
second -- advancing the write pointer, and raises the threshold interrupt
when the ring holds at least `threshold` unread packets.  So a locked
channel (sim.set_signal) can carry a service, and the application's channel
change finds its tables instead of giving up.
"""
import struct

PACKET = 188


class Demux:
    FILTERS = 48
    # how often a PID's tables repeat, in emulation seconds
    PERIODS = {0x0000: 0.1, 0x0014: 0.25, 0x0011: 1.0, 0x0010: 1.0, 0x0012: 1.0}
    PMT_PERIOD = 0.1

    def __init__(self, sim, base=0x22000, line=7):
        self.sim = sim
        self.base = base                    # offset in the device window
        self.line = line
        self.mux = None
        self.adaptive = True                # follow the firmware's PMT PID / programme number
        self._pmt_next = False              # the next filter on a non-standard PID is the PMT's
        self.filters = {}                   # filter -> {'mask': bytes, 'value': bytes}
        self.write_ptr = [0] * self.FILTERS
        self.status = 0                     # threshold interrupt status (48 bits)
        self.next_due = {}                  # PID -> emulation time of the next repetition
        self.packets_written = 0
        self.interrupts = 0
        self.resets = 0
        self.fed_pids = set()
        b = base
        # (a write hook runs before the store lands, so a bit the hardware
        # clears by itself -- the reset, the RAM port's go bit -- is cleared
        # when the driver reads it back, in a read hook)
        sim._mmio_on('w', self._w_control, b + 0x00, b + 0x03)
        sim._mmio_on('r', self._r_control, b + 0x03, b + 0x03)
        sim._mmio_on('w', self._w_ram_port, b + 0x60, b + 0x63)
        sim._mmio_on('r', self._r_ram_port, b + 0x62, b + 0x62)
        sim._mmio_on('w', self._w_buffer, b + 0xB0, b + 0xC3)
        sim._mmio_on('w', self._w_buffer, b + 0x140, b + 0x143)
        sim._mmio_on('r', self._r_pointers, b + 0x1C0, b + 0x1C0 + 4 * self.FILTERS - 1)
        sim._mmio_on('w', self._w_pointers, b + 0x1C0, b + 0x1C0 + 4 * self.FILTERS - 1)
        sim._mmio_on('r', self._r_status, b + 0x310, b + 0x317)

    # -- registers ------------------------------------------------------------

    def _reg(self, off, size=1):
        return int.from_bytes(self.sim.mu.mem_read(0xB8000000 + self.base + off, size), 'little')

    def _set(self, off, value, size=1):
        self.sim.mu.mem_write(0xB8000000 + self.base + off, value.to_bytes(size, 'little'))

    def _w_control(self, uc, access, address, size, value, user_data):
        self.sim._device_access(uc)
        off = (address & 0xFFFFFF) - self.base
        if off <= 3 < off + size and (value >> (8 * (3 - off))) & 1:    # +03 reset
            self.sim._dev_note(uc, 'dmx', address, value)
            # (the pointers stay: the driver's task resets the DMX when the
            # packet at its read pointer has no sync byte, and goes on
            # reading from that pointer afterwards)
            self.status = 0
            self.sim._ic_set_line(self.line, False)
            rd = self.read_ptr()
            slot = bytes(uc.mem_read(0xA0000000 + self.ring_base() + rd * PACKET, 8)) if self.ring_base() else b""
            self.resets += 1
            if self.resets <= 20:
                self.sim.log(f"[DMX] reset (read {rd}, write {self.write_ptr[0]}, slot {rd} starts {slot.hex()}, "
                             f"ring 0x{self.ring_base():07X} x{self.ring_length()})")

    def _w_buffer(self, uc, access, address, size, value, user_data):
        """+B0..+C3 and +140..+143: the ring's configuration, logged as the driver sets it."""
        self.sim._device_access(uc)
        off = (address & 0xFFFFFF) - self.base
        self.sim.log(f"[DMX] +{off:03X} [{size}] = 0x{value:0{2 * size}X}")

    def _r_control(self, uc, access, address, size, value, user_data):
        """+03: the reset bit has cleared by the time the driver reads it back."""
        self.sim._device_access(uc)
        a = 0xB8000000 + self.base + 0x03
        uc.mem_write(a, bytes([uc.mem_read(a, 1)[0] & ~1]))

    def _r_ram_port(self, uc, access, address, size, value, user_data):
        """+62: the go bit has cleared (the write to the filter RAM is done)."""
        self.sim._device_access(uc)
        a = 0xB8000000 + self.base + 0x62
        uc.mem_write(a, bytes([uc.mem_read(a, 1)[0] & ~2]))

    def _w_ram_port(self, uc, access, address, size, value, user_data):
        """+62 = 2: copy +64/+68 (+6C/+70) into the filter named by +60."""
        self.sim._device_access(uc)
        off = (address & 0xFFFFFF) - self.base
        if not (off <= 0x62 < off + size):
            return
        go = (value >> (8 * (0x62 - off))) & 0xFF
        if not go & 2:
            return
        self.sim._dev_note(uc, 'dmx', address, value)
        sel = self._reg(0x60)
        kind, index = sel & 0xC0, sel & 0x3F
        data = bytes(self.sim.mu.mem_read(0xB8000000 + self.base + 0x64, 16 if kind == 0x80 else 8))
        entry = self.filters.setdefault(index, {})
        entry[{0x00: 'mask', 0x40: 'value'}.get(kind, 'cw')] = data
        pid = self.filter_pid(index)
        self.sim.log(f"[DMX] filter {index} {('mask', 'value', 'cw')[kind >> 6 if kind < 0xC0 else 2]} "
                     f"{data.hex()}" + (f" (PID 0x{pid:04X})" if pid is not None else ""))
        if kind == 0x40 and pid is not None and self.mux is not None and self.adaptive:
            import transport_stream
            if pid == transport_stream.PID_PAT:
                self._pmt_next = True           # a channel change: the PMT filter follows the PAT's
            elif pid not in transport_stream.STANDARD_PIDS and self._pmt_next:
                self._pmt_next = False
                self._adapt_to(pid)

    def _adapt_to(self, pid):
        """The first filter on a non-standard PID after the PAT's is the
        firmware asking for its channel's PMT (the PID from its channel
        database; the Comsat programs PAT, PMT, CAT, then the elementary
        streams): move the service's PMT there, with the programme number the
        firmware's section filter (dmx_sec.o's restrict: 16 mask bytes then
        the value bytes, table_id 0x02 and the programme number in bytes
        3..4) waits for when one is found in RAM."""
        import transport_stream
        if pid in transport_stream.STANDARD_PIDS or pid in self.mux.known_pids() or pid >= 0x1FFF:
            return
        record = transport_stream.channel_by_pmt_pid(self.sim.rom_image, pid) if getattr(self.sim, "rom_image", None) is not None else None
        if record:
            program, video, name = record
            service = self.mux.adapt(pid, program, name, video)
            how = f"programme number 0x{program:04X}, \"{name}\", video PID 0x{video:04X} from the dump's channel database"
        else:
            program = self._program_number_wanted()
            service = self.mux.adapt(pid, program)
            how = f"programme number 0x{program:04X} from its section filter" if program else "programme number unknown"
        self.next_due.pop(transport_stream.PID_PAT, None)
        self.sim.log(f"[DMX] the firmware filters PID 0x{pid:04X}: the service's PMT moves there ({how})")

    def _program_number_wanted(self):
        """The programme number (service id) the firmware's section filters
        in RAM wait for.  dmx_sec.o's restrict holds 16 mask bytes then the
        value bytes; a filter on the table id and the id extension (bytes 3
        and 4: the programme number of a PMT, the service id of an EIT) has
        mask FF .. .. FF FF.  Takes a PMT filter's (table 0x02) number, else
        an EIT's (0x4E / 0x4F) service id; None when there is none."""
        try:
            import numpy as np
        except ImportError:
            return None
        ram = np.frombuffer(self.sim.ram_buffer, dtype=np.uint8, count=self.sim.ram_size)
        n = len(ram) - 24
        hits = np.flatnonzero((ram[:n] == 0xFF) & (ram[3:n + 3] == 0xFF) & (ram[4:n + 4] == 0xFF)
                              & (ram[1:n + 1] == 0) & (ram[2:n + 2] == 0))
        found = {}
        for off in hits[:256]:
            tid = int(ram[off + 16])
            if tid not in (0x02, 0x4E, 0x4F) or any(ram[off + 5:off + 16]):
                continue
            ext = (int(ram[off + 19]) << 8) | int(ram[off + 20])
            if ext:
                found[(tid, ext)] = found.get((tid, ext), 0) + 1
        if not found:
            return None
        self.sim.log("[DMX] section filters in RAM: " + ", ".join(
            f"table 0x{t:02X} id 0x{e:04X} x{c}" for (t, e), c in sorted(found.items())))
        for tid in (0x02, 0x4E, 0x4F):
            ids = {e: c for (t, e), c in found.items() if t == tid}
            if ids:
                return max(ids, key=ids.get)
        return None

    def _r_pointers(self, uc, access, address, size, value, user_data):
        """+1C0 + 4 * ch: the write pointer is the model's."""
        self.sim._device_access(uc)
        off = (address & 0xFFFFFF) - self.base - 0x1C0
        ch = off >> 2
        if off & 3 == 0 and ch < self.FILTERS:
            uc.mem_write(address, (self.write_ptr[ch] & 0x1FFF).to_bytes(2, 'little') + uc.mem_read(address + 2, 2)[:max(0, size - 2)])

    def _w_pointers(self, uc, access, address, size, value, user_data):
        self.sim._device_access(uc)

    def _r_status(self, uc, access, address, size, value, user_data):
        """+310/+314: the pending threshold bits; reading them clears them."""
        self.sim._device_access(uc)
        word = ((address & 0xFFFFFF) - self.base - 0x310) >> 2
        bits = (self.status >> (32 * word)) & 0xFFFFFFFF
        uc.mem_write((address & ~3), bits.to_bytes(4, 'little'))
        self.status &= ~(0xFFFFFFFF << (32 * word))
        if not self.status:
            self.sim._ic_set_line(self.line, False)

    # -- state --------------------------------------------------------------

    def enabled(self):
        return bool(self._reg(0x00) & 0x20)

    def united(self):
        return bool(self._reg(0xB2) & 1)

    def ring_base(self):
        """Physical address of the united ring: the Comsat's driver writes
        the whole address to +C0 (0x03A078A0) and 0 to +B0; the SDK library's
        dmx_hal_set_united_buff splits it, bits 23..26 into +B0."""
        return (self._reg(0xC0, 4) & 0x0FFFFFFF) | ((self._reg(0xB0) & 0x0F) << 23)

    def ring_length(self):
        return self._reg(0x140, 2) or 1

    def threshold(self):
        return self._reg(0x142, 2) or 1

    def read_ptr(self, ch=0):
        return self._reg(0x1C2 + 4 * ch, 2) & 0x1FFF

    def filter_enabled(self, index):
        return bool(self._reg(0x40 + (index >> 3)) & (1 << (index & 7)))

    def filter_pid(self, index):
        f = self.filters.get(index)
        if not f or 'mask' not in f or 'value' not in f:
            return None
        m, v = f['mask'], f['value']
        if (m[0] & 0x1F) != 0x1F or m[1] != 0xFF:
            return None
        return ((v[0] & 0x1F) << 8) | v[1]

    def enabled_pids(self):
        out = {}
        for index in self.filters:
            if self.filter_enabled(index):
                pid = self.filter_pid(index)
                if pid is not None:
                    out.setdefault(pid, index)
        return out

    def describe(self):
        pids = self.enabled_pids()
        return (f"DMX {'on' if self.enabled() else 'off'}, {'united' if self.united() else 'divided'} ring "
                f"0x{self.ring_base():07X} x{self.ring_length()} (threshold {self.threshold()}), "
                f"filters on PIDs {' '.join(f'0x{p:04X}' for p in sorted(pids)) or 'none'}, "
                f"write {self.write_ptr[0]} read {self.read_ptr()}, {self.packets_written} packets written, "
                f"{self.interrupts} interrupts")

    # -- the feed ---------------------------------------------------------------

    def service(self):
        """Between emulation slices: put the multiplex's tables for every
        enabled PID that is due into the ring -- while the tuner is on a
        frequency with a signal (sim.tuned_to_signal: the stream comes out of
        the demodulator; a channel search tunes past many without one)."""
        if self.mux is None or not self.enabled() or not self.united() or not self.sim.tuned_to_signal():
            return
        pids = self.enabled_pids()
        if not pids:
            return
        now = self.sim._vtime()
        length, threshold, base = self.ring_length(), self.threshold(), self.ring_base()
        for pid in sorted(pids):
            period = self.PERIODS.get(pid, self.PMT_PERIOD if self.mux.by_pmt_pid(pid) else None)
            if period is None:
                continue
            due = self.next_due.get(pid, 0.0)
            if now < due:
                continue
            self.next_due[pid] = now + period
            packets = self.mux.packets_for(pid)
            if not packets:
                continue
            rd, wr = self.read_ptr(), self.write_ptr[0]
            free = (rd - wr - 1) % length
            if len(packets) > free:
                continue                                    # the ring is full: the firmware is behind
            for pk in packets:
                self.sim.mu.mem_write(0xA0000000 + base + wr * PACKET, pk)
                wr = (wr + 1) % length
            self.write_ptr[0] = wr
            self.packets_written += len(packets)
            if pid not in self.fed_pids:
                self.fed_pids.add(pid)
                self.sim.log(f"[DMX] feeding PID 0x{pid:04X} ({len(packets)} packets per repetition) into the ring")
        pending = (self.write_ptr[0] - self.read_ptr()) % length
        if pending >= threshold and not self.status & 1:
            self.status |= 1
            if self._reg(0x300, 4) & 1:
                self.interrupts += 1
                self.sim._ic_set_line(self.line, True)
