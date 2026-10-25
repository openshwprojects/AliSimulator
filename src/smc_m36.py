"""
Model of the ALi M36xx / M35xx Smart Card controller (SMC, 0xB8018800 / 0xB8018900).
Reverse-engineered from the SDK's smc_m36 driver in Ferguson Ariva 204 V1.3B3
(0x8025bb00..0x80261d60):

  +00  REG_DEV_CTRL   bit 7 enables the controller
  +01  REG_SCR_CTRL   bit 1 warm reset, bit 2 VCC, bit 3 CLK, bits 4..5 RX/TX enable
  +02  REG_FIFO_CTRL  bits 5..7 flush TX/RX FIFOs and set thresholds
  +04  REG_IER0       interrupt enable 0
  +05  REG_IER1       interrupt enable 1
  +06  REG_ISR0       interrupt status 0 (write 1 to clear):
                        bit 2 = FIFO_TRANS, bit 4 = BYTE_RCV, bit 5 = FIFO_RECV, bit 7 = TX_DONE
  +07  REG_ISR1       interrupt status 1 (write 1 to clear):
                        bit 0 = RST_NATR, bit 1 = RST_HIGH, bit 4 = CARD_INSERT,
                        bit 5 = CARD_REMOVE, bit 6 = COUNT_ST
  +08  REG_ICCSR      bit 7 = card inserted (1 = present, 0 = absent)
  +0A  REG_RBR        RX FIFO data byte (read pops one byte)
  +0B  REG_THR        TX FIFO data byte (write pushes one byte)
  +0C  REG_ETU0       16-bit ETU divisor (default 372 = 0x0174)
  +0E  REG_GTR0       16-bit guard time (default 12)
  +10  REG_CBWTR0     32-bit character waiting time (default 0x3200)
  +14  REG_RFIFO_CNT  low 8 bits of unread RX FIFO byte count
  +16  REG_ETU_CAP    16-bit captured ETU counter (0x0174)
  +28  REG_CLK_CAP    16-bit captured clock counter (0x045C)
  +2A  REG_TFIFO_CNT  16-bit TX FIFO threshold / count
  +2C  REG_RFIFO_HI   bit 0 = bit 8 of unread RX FIFO byte count

When a virtual smart card is inserted (attach_smart_card / set_card), it
answers a warm or cold reset with its ATR (by default Conax CAS7:
3B 24 00 30 42 30 30, historical bytes "0B00"), echoes PPS requests
(FF 10 ...), and answers ISO 7816-3 T=0 APDU commands with procedure byte INS
and status word 90 00.
"""
from collections import deque

CONAX_ATR = bytes.fromhex("3B240030423030")     # TS=0x3B (direct), T0=0x24 (TA1 present, 4 hist bytes: "0B00")


class SmartCard:
    BASE = 0x18800
    LINE = 12                                   # interrupt-controller line 12 (OS IRQ 20)
    CONAX_ATR = CONAX_ATR

    def __init__(self, sim, base=BASE, line=LINE, inserted=False, atr=CONAX_ATR):
        self.sim = sim
        self.base = base
        self.line = line
        self.ca_system_id = 0x0B00
        self.inserted = bool(inserted)
        self.atr = bytes(atr)
        self.rx_fifo = deque()
        self.tx_buf = bytearray()
        self._tx_expected_body = 0
        self._pending_response = b""
        self._atr_armed = True
        self.isr0 = 0
        self.isr1 = 0
        self.resets = 0
        self.apdus = []
        self.pps_exchanges = 0
        b = base
        self._init_regs()
        sim._mmio_on('r', self._r_reg, b + 0x00, b + 0x30)
        sim._mmio_on('w', self._w_reg, b + 0x00, b + 0x30)

    def reset(self):
        """Reset the controller state (on loadFile)."""
        self.inserted = False
        self.atr = CONAX_ATR
        self.ca_system_id = 0x0B00
        self.rx_fifo.clear()
        self.tx_buf.clear()
        self._tx_expected_body = 0
        self._pending_response = b""
        self._atr_armed = True
        self.isr0 = 0
        self.isr1 = 0
        self.resets = 0
        self.apdus.clear()
        self.pps_exchanges = 0
        self._init_regs()

    def _init_regs(self):
        v = self.sim._mmio_view
        b = self.base
        v[b + 0x08] = 0x80 if self.inserted else 0x00
        v[b + 0x0C:b + 0x0E] = (372).to_bytes(2, 'little')
        v[b + 0x0E:b + 0x10] = (12).to_bytes(2, 'little')
        v[b + 0x10:b + 0x14] = (0x3200).to_bytes(4, 'little')
        v[b + 0x16:b + 0x18] = (372).to_bytes(2, 'little')
        v[b + 0x28:b + 0x2A] = (1116).to_bytes(2, 'little')
        self._sync_rx_count()

    def set_card(self, inserted=True, atr=None):
        """Insert or remove the virtual smart card."""
        was = self.inserted
        self.inserted = bool(inserted)
        if atr is not None:
            self.atr = bytes(atr)
        self.rx_fifo.clear()
        self.tx_buf.clear()
        self._tx_expected_body = 0
        self._pending_response = b""
        self._atr_armed = True
        self.sim._mmio_view[self.base + 0x08] = 0x80 if self.inserted else 0x00
        if self.inserted != was:
            self.isr1 |= 0x10 if self.inserted else 0x20
            self.sim._mmio_view[self.base + 0x07] = self.isr1
            self._update_irq()
        self._sync_rx_count()

    def _sync_rx_count(self):
        n = min(len(self.rx_fifo), 0x1FF)
        v = self.sim._mmio_view
        b = self.base
        v[b + 0x14] = n & 0xFF
        v[b + 0x2C] = (v[b + 0x2C] & 0xFE) | ((n >> 8) & 1)

    def _update_irq(self):
        v = self.sim._mmio_view
        b = self.base
        ier0, ier1 = v[b + 0x04], v[b + 0x05]
        enables = int.from_bytes(self.sim.peek(self.sim._ic_en + 4 * (self.line // 32), 4), 'little')
        line_enabled = bool((enables >> (self.line % 32)) & 1)
        active = bool((self.isr0 & ier0) or (self.isr1 & ier1)) and line_enabled
        if active or (self.sim._ic_lines >> self.line) & 1:
            self.sim._ic_set_line(self.line, active)

    def _queue_rx(self, data, is_atr=False):
        self.rx_fifo.extend(data)
        self.isr0 |= 0x34                       # FIFO_RECV | BYTE_RCV | FIFO_TRANS
        if is_atr:
            self.isr1 = (self.isr1 & ~0x01) | 0x42  # COUNT_ST | RST_HIGH, no RST_NATR
        self.sim._mmio_view[self.base + 0x06] = self.isr0
        self.sim._mmio_view[self.base + 0x07] = self.isr1
        self._sync_rx_count()
        self._update_irq()

    def _handle_tx_byte(self, byte):
        self.tx_buf.append(byte)
        self.isr0 |= 0x84                       # TX_DONE | FIFO_TRANS
        self.sim._mmio_view[self.base + 0x06] = self.isr0
        # 1. PPS request: 0xFF, PPS0, [PPS1..3], PCK
        if self.tx_buf[0] == 0xFF:
            if len(self.tx_buf) >= 2:
                pps0 = self.tx_buf[1]
                expected = 3 + ((pps0 >> 4) & 1) + ((pps0 >> 5) & 1) + ((pps0 >> 6) & 1)
                if len(self.tx_buf) >= expected:
                    pps = bytes(self.tx_buf[:expected])
                    self.tx_buf.clear()
                    self.pps_exchanges += 1
                    self._queue_rx(pps)
            return
        # 2. Waiting for T=0 command body bytes after sending procedure byte INS
        if self._tx_expected_body > 0:
            self._tx_expected_body -= 1
            if self._tx_expected_body == 0:
                self.apdus.append(bytes(self.tx_buf))
                self.tx_buf.clear()
                resp, self._pending_response = self._pending_response, b""
                self._queue_rx(resp)
            return
        # 3. 5-byte ISO 7816-3 T=0 APDU header: CLA INS P1 P2 P3
        if len(self.tx_buf) == 5:
            cla, ins, p1, p2, p3 = self.tx_buf
            # Outgoing data commands (e.g. Conax CASS commands DD 26 / DD 82 / DD 84 / DD C2 with P3 > 0)
            # vs incoming data commands (e.g. GET RESPONSE 00 C0 00 00 Le or P3 == 0)
            if p3 == 0:
                self.apdus.append(bytes(self.tx_buf))
                self.tx_buf.clear()
                self._queue_rx(bytes([ins, 0x90, 0x00]))
            elif ins in (0xC0, 0xB0, 0xB2, 0xCA):
                # Read/Get Response: send INS procedure byte + P3 payload bytes + 90 00
                self.apdus.append(bytes(self.tx_buf))
                self.tx_buf.clear()
                payload = (b"\x0B\x00" * ((p3 + 1) // 2))[:p3]
                self._queue_rx(bytes([ins]) + payload + b"\x90\x00")
            else:
                # Write/Command with P3 incoming bytes from host: acknowledge with INS, then 98 08 (Conax DD 26) or 90 00 after P3 bytes
                self._tx_expected_body = p3
                self._pending_response = b"\x98\x08" if (cla == 0xDD and ins == 0x26) else b"\x90\x00"
                self._queue_rx(bytes([ins]))

    def _r_reg(self, uc, access, address, size, value, user_data):
        self.sim._device_access(uc)
        for i in range(size):
            a = address + i
            off = (a & 0xFFFFFF) - self.base
            abs_off = a & 0xFFFFFF
            if off == 0x06:
                self.sim._mmio_view[abs_off] = self.isr0
            elif off == 0x07:
                self.sim._mmio_view[abs_off] = self.isr1
            elif off == 0x08:
                self.sim._mmio_view[abs_off] = 0x80 if self.inserted else 0x00
            elif off == 0x0A:
                rp = self.sim._dev_replay_of(uc, 'smc_rx', a)
                if rp is not None:
                    self.sim._mmio_view[abs_off] = rp[2]
                elif self.rx_fifo:
                    b = self.rx_fifo.popleft()
                    self.sim._mmio_view[abs_off] = b
                    self.sim._dev_note(uc, 'smc_rx', a, b)
                    self._sync_rx_count()
                else:
                    self.sim._mmio_view[abs_off] = 0x00
            elif off in (0x14, 0x2C):
                self._sync_rx_count()

    def _w_reg(self, uc, access, address, size, value, user_data):
        self.sim._device_access(uc)
        base_addr = address & ~3
        shift = (address & 3) * 8
        mask = ((1 << (size * 8)) - 1) << shift
        word = int.from_bytes(uc.mem_read(base_addr, 4), 'little')
        merged = (word & ~mask) | ((value << shift) & mask)
        for i in range(size):
            a = address + i
            off = (a & 0xFFFFFF) - self.base
            b = (value >> (8 * i)) & 0xFF
            if off == 0x01:
                # Card activation (bits 4..5 RX/TX enable) or warm reset (bit 1) triggers ATR when armed
                if self.inserted and ((b & 0x02) or (self._atr_armed and (b & 0x30))):
                    self._atr_armed = False
                    self.resets += 1
                    self.rx_fifo.clear()
                    self.tx_buf.clear()
                    self._tx_expected_body = 0
                    self._queue_rx(self.atr, is_atr=True)
            elif off == 0x02:
                if b & 0xE0:
                    self.rx_fifo.clear()
                    self.tx_buf.clear()
                    self._tx_expected_body = 0
                    self._atr_armed = True
                    self._sync_rx_count()
            elif off == 0x06:
                self.isr0 &= ~b & 0xFF
                merged = (merged & ~(0xFF << ((a & 3) * 8))) | (self.isr0 << ((a & 3) * 8))
                self._update_irq()
            elif off == 0x07:
                self.isr1 &= ~b & 0xFF
                merged = (merged & ~(0xFF << ((a & 3) * 8))) | (self.isr1 << ((a & 3) * 8))
                self._update_irq()
            elif off == 0x0B:
                if self.sim._dev_replay_of(uc, 'smc_tx', a, b) is None:
                    self.sim._dev_note(uc, 'smc_tx', a, b)
                    if self.inserted:
                        self._handle_tx_byte(b)
        return (merged & mask) >> shift
