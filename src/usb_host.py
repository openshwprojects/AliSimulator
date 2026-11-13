"""
The ALi USB 2.0 host controller (the SDK's hc_s3602 / hcd_s3602 driver): the
port -- a device can be plugged in and out, the controller reports the
connection and the device's speed, raises its interrupt and completes a bus
reset -- endpoint 0's control transfers to a built-in USB device, an IN
transfer on endpoint B received into RAM by DMA (an interrupt endpoint's
report, or a bulk transfer of several packets), an OUT on endpoint A sent from
RAM by DMA, and endpoint C's and D's polling of an interrupt IN endpoint.  Four
devices: a mass-storage stick (its descriptors; given a disk image, the
bulk-only transport with the SCSI commands to read it -- without one its bulk
endpoints answer NAK, so a mass-storage driver waits at its first command), a
keyboard (HID boot protocol: GET_REPORT, the interrupt endpoint, keys typed
with .type()), a mouse (HID boot protocol: moved, clicked and its wheel turned
in emulated time) and a hub (its ports' power, reset and status; devices
plugged into them, other hubs too -- tokens are routed through the tree by
address, and to a device that is not high speed behind a high-speed hub only
as split transfers through that hub's transaction translator).  Data toggles
are kept per device endpoint and per controller endpoint (A, B and D): a
packet sent with the other one is dropped, as on the bus.

Register meanings, from the SDK's accessor functions (hc_s3602_reg.o in
refs/MainCode/ddk/libcore_v40b.a), its interrupt handlers (hcd_s3602_h2c_int
and the proc_ctrl_* states in hcd_s3602_proc.o) and the S3811 firmwares'
driver (dump.bin, dump_maciej.bin; traced here):
  +0x10  port: bit 0 over-current, bit 1 device connected, bit 2 (revision 0:
         cleared and set after the PHY set-up and before a bus reset), bit 5
         drive a bus reset (issue_reset_to_device writes 0x20; the controller
         ends it), bit 6 suspend, bit 7 resume
  +0x11  endpoint 0: bits 0..1 the token's PID (set_ep0_token_pid: 0 SETUP,
         1 OUT, 2 IN), bit 4 FIFO reset (init_ep_fifo writes 0x10 then 0),
         bit 5 send the token (ep_force_token_sending); read: bit 7 the FIFO
         is empty (get_ep_fifo_empty_status), bit 2 all empty
  +0x12  endpoint 0's FIFO port (rw_ep_fifo_port): a SETUP / OUT packet's
         bytes in, an IN packet's bytes out
  +0x13 / +0x16 / +0x19 / +0x22  endpoints A / B / C / D: bits 6..7 transfer
         type (0x80 bulk, 0xC0 interrupt), bits 2..5 the device's endpoint
  +0x14 / +0x17 / +0x1A / +0x23  their FIFOs: bit 4 reset, bit 0 pulsed =
         data toggle reset; read: bit 7 empty.  +0x1B / +0x24 endpoint C's /
         D's FIFO port
  +0x1C  device address (the old mode)
  +0x1D  why the last token failed (hcd_s3602_upt_parse_error): 0x80 stall,
         0x40 PID error, 0x20 no response, 0x10 unexpected, 0x08 data
         toggle, 0x04 UTMI, 0x02 CRC
  +0x1E  interrupt enable 1        +0x1F  interrupt enable 2
  +0x20  interrupt flags 1: bit 0 connection changed (the handler re-reads
         +0x10 bit 1), bit 1 bus reset done (it then reads the speed); read
         to clear
  +0x21  interrupt flags 2: bit 7 / 3 endpoint 0's token done / failed (the
         control state machine's next step), bits 6 / 2 endpoint A, 5 / 1 B,
         4 / 0 C; read to clear
  +0x2B  bit 5: endpoint C polls its endpoint every +0xA2 ms, bit 3: endpoint
         D every 2^(+0xA3 - 1) microframes (en_int_interval_ctrl)
  +0x2C  16 bits: the size of endpoint B's last packet
  +0x2E  interrupt enable 3 (en_host_int_flag3_all: 0x77)
  +0x2F  interrupt flags 3: bit 4 / 0 endpoint D's packet came / its token
         failed (hcd_s3602_h2c_int: epD_finish_ok, ep_err_finish); read to clear
  +0x30  bits 4..6: endpoint B's packet size, 8 << n, set with bit 7
  +0x31  bits 0..2: endpoint C's packet size, 8 << n; bits 4..6 endpoint D's
  +0x32  bits 5..6 the device's speed (hcd_ioctrl_get_speed): 0x00 high,
         0x20 full, 0x40 low; bit 2 the controller sends the IN tokens
         (dma_host_in_token), bit 3 the DMA transfer runs (en_dma_transfer):
         the controller clears both when the transfer ends
  +0x38  24 bits: the bytes a DMA receive transfer takes (set_dma_rx_cnt)
  +0x40  32 bits: the receive buffer's physical address; +0x44 its index
  +0x48  24 bits: the bytes received (read_dma_rx_count)
  +0x13 / +0x14  endpoint A (OUT): its device endpoint; FIFO reset (bit 4),
         toggle reset (bit 0 pulsed)
  +0x50 / +0x54 / +0x58 / +0x5C  DMA transmit: the buffer's physical address,
         its index, the bytes to send, the bytes left; started by the +0x60
         bit 0 strobe and +0x32 bit 3, done at flags 2 bit 6 and +0x63 = 0x03
  +0x82 / +0x83  endpoint A's device address << 1 | split, and its translator
  +0x60  bit 5 / 4: the DMA receiver's state set up / its transfer started
         (strobes: they read back 0)
  +0x63  the interface's interrupt status: the handler serves flags 1/2 when
         bits 0 and 3 are both set, a finished DMA receive when 0 and 2 are;
         read to clear
  +0x68  0x80 | size code << 4: DMA receive (enable_dma_auto_rx)
  +0x80 / +0x84 / +0x86 / +0x88  endpoint 0's / B's / C's / D's device
         address << 1 (the new mode, which the firmwares switch on with +0x8F
         = 0x80); bit 0: the device is reached through a high-speed hub's
         transaction translator (set_ep_device_address's last argument)
  +0x81 / +0x85 / +0x87 / +0x89  that translator (set_ssplit_ctrl_info): bits
         0..2 the hub's address, 3..5 its port, bit 6 the device is low speed;
         +0x89 bit 7 reads 1 while endpoint D's split transaction is under way
  +0x90  set_plug_status: with bit 1 set the controller does not split
  +0xA2  endpoint C's polling interval (ms)   +0xA3  endpoint D's (2^(n - 1)
         microframes; 0 stops it)   +0xA8  NAK retry period (1)
  +0xF0 / +0xF4  the PHY's settings (32-bit; per chip revision), +0xF2 its
         reset (7, 2 ms, 0)
The S3811 (dump_maciej's application) attaches it at 0xB8032000 on
interrupt-controller line 29 (hcdi_s3602_open: OS IRQ 0x25 = line 29 + 8).
A token reaches the device only when the address it carries (+0x80 in the new
mode, +0x1C before) is the device's own; SET_ADDRESS takes effect after its
status stage.

Endpoint B's IN (the SDK's hcd_s3602_bulkin_start), as a real S3811
(revision 1) does it with a low-speed keyboard -- measured with test code run
from the box's RAM:
  - it starts when +0x32 bits 2 and 3 are set after the +0x60 strobes: the
    first token at once, and while the device answers NAK one more per
    frame (1 ms; +0xA8 = 1 -- 2..15 mean that many per frame, 0 one after
    the other, 0x10 and above never again);
  - a packet: its bytes in RAM at +0x40's address about 0.1 ms after the
    token, +0x48 = their number, +0x2C the same, flags 2 bit 5, +0x63 = 0x05,
    +0x17 reads 0x86 until the next FIFO reset, +0x32 bits 2 / 3 cleared;
  - nobody answers (no such address or endpoint): +0x1D = 0x20 and flags 1
    bit 5 after one token, flags 2 bit 1 and +0x63 = 0x09 after a second;
  - the data toggle lasts from one transfer to the next; bit 0 of +0x17
    pulsed puts it back to DATA0; a packet with the other toggle is
    acknowledged and dropped (+0x1D bit 3) and the IN goes on;
  - only the FIFO reset (+0x17 bit 4) ends a pending IN: clearing +0x32's
    bits, +0x68 or the +0x60 strobe does not.
Endpoint C (hcd_s3602_IntInC_start) sends nothing at all to a low-speed
device there -- no data, and no error for an address nobody has -- so the
model's endpoint C polls only full- and high-speed devices (a hub's status
endpoint is what the SDK uses it for; on that box it stayed silent for a
high-speed hub too, which the model does not copy).
Endpoint D (hcd_s3602_IntInD_start) does poll, on the same box: with +0xA3 =
7 a token every 8 ms (+0x89 bit 7 high for about 1 ms each time behind a
hub), the first within a few ms; a hub's status endpoint answered every
change of a port (a byte, flags 3 bit 4 with +0x63 = 0x09), a low-speed
keyboard behind a hub its report; an endpoint a low-speed device behind a
hub does not have failed each time with +0x1D = 0x10 and flags 1 bit 4 (a
high-speed hub's own missing endpoint: 0x20 and bit 5), without flags 3, and
the polling went on.  The SDK (epD_finish_ok) stops the
polling (+0xA3 = 0, +0x2B bit 3 cleared) when the flag comes, empties the
FIFO and starts it again; the data toggle lasts through that, bit 0 of +0x23
pulsed puts it back to DATA0, and a packet with the other toggle is
acknowledged and dropped (+0x1D = 0x08; a hub sent its change again, a
mouse's movement would be lost).

Behind a real seven-port high-speed hub (two Terminus 1a40:0101 chips) the
same box showed: high-speed devices answer at their address as they are; the
low-speed keyboard on the hub's port 4 answers control transfers with +0x80 =
address << 1 | 1 and +0x81 = 0x61 (low speed, port 4, hub 1), and endpoint B's
IN with the same in +0x84 / +0x85 -- pending while it has nothing to report,
its reports arriving when keys are pressed; an endpoint the keyboard does not
have comes back as a stall 0.24 ms after the IN's start (the translator's
answer after three tries nobody answered), not as "no response"; with +0x90 =
2 or 3 the keyboard gets no answer at all.

Opt-in: sim.attach_usb_host() installs it (nothing changes for a firmware
until then); usb.attach(speed[, device]) / usb.detach() plug a device in and
out (the stick unless a device is given).  usb.setups lists every SETUP
packet the device received.
"""

import ctypes

SPEED_BITS = {"high": 0x00, "full": 0x20, "low": 0x40}
RESET_TIME_S = 0.010                      # a bus reset lasts 10 ms (SE0, USB 2.0 7.1.7.5)
TOKEN_TIME_S = 0.0002                     # a control token with its handshake
IN_TIME_S = 0.0001                        # endpoint B's IN: a low-speed packet is in RAM after about this long
FRAME_S = 0.001                           # a NAKed IN is sent again in the next frame (+0xA8 = 1)
STALL, NO_RESPONSE, TOGGLE = 0x80, 0x20, 0x08   # +0x1D codes
HALTED = object()                         # VirtualDevice.interrupt_in: the endpoint is halted (it answers STALL)


def _string(text):
    data = text.encode("utf-16-le")
    return bytes([2 + len(data), 0x03]) + data


class VirtualDevice:
    """A USB device's standard requests (chapter 9) over its descriptors."""

    EP0_SIZE = 64

    def __init__(self, device, config, strings):
        self.address = 0
        self.pending_address = None           # SET_ADDRESS, in effect after its status stage
        self.configuration = 0
        self.device = device
        self.config = config
        self.strings = strings
        self.clock = lambda: 0.0              # the emulated time (set by UsbHost.attach)
        self.in_endpoints = set()             # the IN endpoints its configuration has (their numbers)
        self.out_endpoints = set()
        self.interrupt_endpoints = set()      # (IN ones: their packets go to UsbHost.interrupt_packets)
        i = 0
        while i + 1 < len(config) and config[i]:
            if config[i + 1] == 0x05:
                (self.in_endpoints if config[i + 2] & 0x80 else self.out_endpoints).add(config[i + 2] & 0x0F)
                if config[i + 3] & 3 == 3:
                    self.interrupt_endpoints.add(config[i + 2] & 0x0F)
            i += config[i]
        self.in_toggle = {}                   # endpoint -> the toggle (0 DATA0 / 1 DATA1) of its next packet
        self.out_toggle = {}                  # the same for its OUT endpoints

    def class_request(self, rtype, request, value, index, length):
        return None

    def setup(self, packet):
        """A SETUP packet: (data for the IN stage or b'', or None to stall)."""
        rtype, request = packet[0], packet[1]
        value, index = packet[2] | packet[3] << 8, packet[4] | packet[5] << 8
        length = packet[6] | packet[7] << 8
        if rtype == 0x80 and request == 0x06:                                 # GET_DESCRIPTOR
            kind, which = value >> 8, value & 0xFF
            data = {1: self.device, 2: self.config}.get(kind)
            if kind == 3:
                data = self.strings.get(which)
            if kind == 6:
                data = getattr(self, "qualifier", None)
            return None if data is None else data[:length]
        if rtype == 0x00 and request == 0x05:                                 # SET_ADDRESS
            self.pending_address = value & 0x7F
            return b""
        if rtype == 0x00 and request == 0x09:                                 # SET_CONFIGURATION
            self.configuration = value & 0xFF
            self.in_toggle.clear()                                            # every endpoint starts with DATA0
            self.out_toggle.clear()
            return b""
        if rtype == 0x02 and request == 0x01 and value == 0:                  # CLEAR_FEATURE(ENDPOINT_HALT)
            ep = index & 0x0F
            (self.in_toggle if index & 0x80 else self.out_toggle).pop(ep, None)   # its toggle: DATA0
            self.halt_clears = getattr(self, "halt_clears", 0) + 1
            self.halt_cleared(index)
            return b""
        if rtype == 0x80 and request == 0x08:                                 # GET_CONFIGURATION
            return bytes([self.configuration])
        if rtype in (0x80, 0x81, 0x82) and request == 0x00:                   # GET_STATUS
            return b"\x00\x00"
        if rtype in (0x00, 0x01, 0x02) and request in (0x01, 0x03):           # CLEAR / SET_FEATURE
            return b""
        if rtype == 0x01 and request == 0x0B:                                 # SET_INTERFACE
            return b""
        return self.class_request(rtype, request, value, index, length)

    def interrupt_in(self, endpoint):
        """An IN token on interrupt endpoint `endpoint`: its packet, None (NAK)
        or HALTED (STALL)."""
        return None

    def in_transfer(self, endpoint, count, maxp):
        """An IN transfer of `count` bytes at most (packets of `maxp`) from the
        endpoint: its bytes (a short packet, or `count`, ends it), None (NAK)
        or HALTED.  An interrupt endpoint gives one packet."""
        return self.interrupt_in(endpoint)

    def bulk_out(self, endpoint, data):
        """An OUT transfer's data: True (taken), None (NAK) or HALTED."""
        return None

    def halt_cleared(self, endpoint):
        """CLEAR_FEATURE(ENDPOINT_HALT) on an endpoint (bit 7: IN) arrived."""


class VirtualStick(VirtualDevice):
    """A USB 2.0 mass-storage stick (pid.codes test IDs 1209:0001): its
    descriptors, its standard requests, GET MAX LUN and the bulk-only
    transport's reset -- and, given a disk image (bytes; fat_image.build makes
    FAT ones), the bulk-only transport itself: a command block wrapper on its
    bulk OUT endpoint 0x02, the data and the status wrapper on its bulk IN
    endpoint 0x81, with the SCSI commands a host reads a disk with (INQUIRY,
    TEST UNIT READY, REQUEST SENSE, READ CAPACITY(10), READ(10), MODE SENSE(6),
    PREVENT ALLOW MEDIUM REMOVAL); writes are refused (it is write-protected).
    Without an image its bulk endpoints answer NAK to everything (a driver
    waits at its first command).  full_speed=True gives it 64-byte bulk
    packets (a 512-byte sector in eight); unit_attention=True makes its first
    TEST UNIT READY fail with "the medium may have changed" (6/28), as a real
    card reader's did; no_medium=True: a card reader with no card in it;
    lose_after_idle=s: the first command block after s seconds without a
    command is taken (acknowledged) but never answered -- no data, no status
    -- as a real 64 GB stick (090c:2000) did after a minute or more of idling;
    .lost_commands counts them."""

    VID, PID = 0x1209, 0x0001
    MANUFACTURER, PRODUCT, SERIAL = "AliSimulator", "Virtual USB stick", "000000000001"
    EP0_SIZE = 64
    IN_EP, OUT_EP = 1, 2

    def __init__(self, image=None, full_speed=False, unit_attention=False, no_medium=False,
                 vendor="AliSim", product="Virtual stick", revision="1.00", lose_after_idle=None):
        device = bytes([18, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, self.EP0_SIZE,
                        self.VID & 0xFF, self.VID >> 8, self.PID & 0xFF, self.PID >> 8,
                        0x00, 0x01, 1, 2, 3, 1])
        size = 64 if full_speed else 512
        interface = bytes([9, 0x04, 0, 0, 2, 0x08, 0x06, 0x50, 0])          # mass storage, SCSI, bulk-only
        ep_in = bytes([7, 0x05, 0x80 | self.IN_EP, 0x02, size & 0xFF, size >> 8, 0])     # bulk IN
        ep_out = bytes([7, 0x05, self.OUT_EP, 0x02, size & 0xFF, size >> 8, 0])         # bulk OUT
        body = interface + ep_in + ep_out
        total = 9 + len(body)
        config = bytes([9, 0x02, total & 0xFF, total >> 8, 1, 1, 0, 0x80, 50]) + body
        strings = {0: bytes([4, 0x03, 0x09, 0x04]), 1: _string(self.MANUFACTURER),
                   2: _string(self.PRODUCT), 3: _string(self.SERIAL)}
        super().__init__(device, config, strings)
        self.qualifier = bytes([10, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00, self.EP0_SIZE, 1, 0])
        self.image = image
        self.no_medium = no_medium
        self.attention = unit_attention
        self.inquiry_text = (vendor.ljust(8)[:8] + product.ljust(16)[:16] + revision.ljust(4)[:4]).encode("ascii")
        self.sense = (0, 0, 0)
        self.responses = []                   # what the IN endpoint has to give: the data, then the status
        self.commands = []                    # (time, SCSI command block) received
        self.resets = 0
        self.lose_after_idle = lose_after_idle
        self.last_command = None              # when the last command block came
        self.lost_commands = 0

    def class_request(self, rtype, request, value, index, length):
        if rtype == 0xA1 and request == 0xFE:                                 # mass storage GET MAX LUN
            return b"\x00"
        if rtype == 0x21 and request == 0xFF:                                 # Bulk-Only Mass Storage Reset
            self.responses.clear()
            self.resets += 1
            return b""
        return None

    def bulk_out(self, endpoint, data):
        if self.image is None or endpoint != self.OUT_EP:
            return None                                                       # NAK
        if len(data) != 31 or data[:4] != b"USBC":
            return True                                                       # (not a command: ignored)
        tag, length, flags, cb_len = data[4:8], int.from_bytes(data[8:12], "little"), data[12], data[14]
        cb = bytes(data[15:15 + cb_len])
        now = self.clock()
        idle = self.last_command is not None and now - self.last_command >= (self.lose_after_idle or float("inf"))
        self.last_command = now
        if idle:
            self.lost_commands += 1                                           # taken, never answered
            return True
        self.commands.append((round(now, 4), cb))
        status, reply = self._scsi(cb, length)
        reply = reply[:length] if flags & 0x80 else b""
        residue = length - len(reply)
        if flags & 0x80 and length:
            self.responses.append(bytes(reply))
        csw = b"USBS" + tag + residue.to_bytes(4, "little") + bytes([status])
        self.responses.append(csw)
        return True

    def halt_cleared(self, endpoint):
        # a real stick (ffff:5678) ends a command whose bulk IN's halt is cleared between the command
        # block and the data: the data still comes, the status is a stall (and nothing after it)
        if endpoint == 0x80 | self.IN_EP and self.responses and len(self.responses) > 1:
            self.status_stalls = True

    def in_transfer(self, endpoint, count, maxp):
        if endpoint != self.IN_EP:
            return None
        if not self.responses:
            return None                                                       # NAK: nothing to give
        if getattr(self, "status_stalls", False) and len(self.responses) == 1:
            self.status_stalls = False
            self.responses.clear()
            self.stalled_commands = getattr(self, "stalled_commands", 0) + 1
            return HALTED
        item = self.responses[0]
        chunk, rest = item[:count], item[count:]
        if rest:
            self.responses[0] = rest
        else:
            self.responses.pop(0)
        return chunk

    def _fail(self, key, asc, ascq=0):
        self.sense = (key, asc, ascq)
        return 1, b""

    def _scsi(self, cb, length):
        op = cb[0] if cb else 0xFF
        if op == 0x03:                                                        # REQUEST SENSE
            key, asc, ascq = self.sense
            self.sense = (0, 0, 0)
            return 0, bytes([0x70, 0, key, 0, 0, 0, 0, 10, 0, 0, 0, 0, asc, ascq, 0, 0, 0, 0])
        if op == 0x12:                                                        # INQUIRY
            return 0, bytes([0x00, 0x80, 0x04, 0x02, 31, 0, 0, 0]) + self.inquiry_text
        if self.no_medium:
            return self._fail(2, 0x3A)                                        # not ready, no medium
        if self.attention:
            self.attention = False
            return self._fail(6, 0x28)                                        # the medium may have changed
        blocks = len(self.image) // 512
        if op == 0x00:                                                        # TEST UNIT READY
            return 0, b""
        if op == 0x25:                                                        # READ CAPACITY(10)
            return 0, (blocks - 1).to_bytes(4, "big") + (512).to_bytes(4, "big")
        if op == 0x28:                                                        # READ(10)
            lba, count = int.from_bytes(cb[2:6], "big"), int.from_bytes(cb[7:9], "big")
            if lba + count > blocks:
                return self._fail(5, 0x21)                                    # LBA out of range
            return 0, bytes(self.image[lba * 512:(lba + count) * 512])
        if op == 0x1A:                                                        # MODE SENSE(6): write-protected
            return 0, bytes([3, 0, 0x80, 0])
        if op == 0x1E:                                                        # PREVENT ALLOW MEDIUM REMOVAL
            return 0, b""
        return self._fail(5, 0x20)                                            # an invalid command


# the boot keyboard's report descriptor (HID 1.11, appendix B.1)
BOOT_KEYBOARD_REPORT = bytes.fromhex(
    "05 01 09 06 a1 01 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 95 01 75 08 81 01"   # modifiers, reserved
    "95 05 75 01 05 08 19 01 29 05 91 02 95 01 75 03 91 01"                                # LEDs (output)
    "95 06 75 08 15 00 25 65 05 07 19 00 29 65 81 00 c0")                                  # six keys

# characters -> (modifiers, HID usage), US layout
_KEYS = {}
for _i, _c in enumerate("abcdefghijklmnopqrstuvwxyz"):
    _KEYS[_c] = (0, 0x04 + _i)
    _KEYS[_c.upper()] = (0x02, 0x04 + _i)
for _i, (_c, _s) in enumerate(zip("1234567890", "!@#$%^&*()")):
    _KEYS[_c] = (0, 0x1E + _i)
    _KEYS[_s] = (0x02, 0x1E + _i)
for _usage, _c, _s in ((0x2D, "-", "_"), (0x2E, "=", "+"), (0x2F, "[", "{"), (0x30, "]", "}"),
                       (0x31, "\\", "|"), (0x33, ";", ":"), (0x34, "'", '"'), (0x35, "`", "~"),
                       (0x36, ",", "<"), (0x37, ".", ">"), (0x38, "/", "?")):
    _KEYS[_c] = (0, _usage)
    _KEYS[_s] = (0x02, _usage)
_KEYS.update({"\r": (0, 0x28), "\n": (0, 0x28), "\b": (0, 0x2A), "\t": (0, 0x2B), " ": (0, 0x2C)})
_NAMED = {"ENTER": 0x28, "ESC": 0x29, "BS": 0x2A, "TAB": 0x2B, "CAPS": 0x39, "DEL": 0x4C,
          "RIGHT": 0x4F, "LEFT": 0x50, "DOWN": 0x51, "UP": 0x52}


def key_presses(text):
    """`text` as (modifiers, usage) presses: characters, and {UP} {DOWN} {ESC}
    {CAPS} {DEL} {ENTER} {BS} {TAB} or {CTRL-x} (x a letter) for other keys; a
    '{' that starts none of these is the character."""
    out, i = [], 0
    while i < len(text):
        if text[i] == "{" and "}" in text[i:]:
            name = text[i + 1:text.index("}", i)]
            if name.upper() in _NAMED:
                out.append((0, _NAMED[name.upper()]))
                i += len(name) + 2
                continue
            if name.upper().startswith("CTRL-") and len(name) == 6 and name[5].isalpha():
                out.append((0x01, _KEYS[name[5].lower()][1]))
                i += len(name) + 2
                continue
        out.append(_KEYS[text[i]])
        i += 1
    return out


class VirtualKeyboard(VirtualDevice):
    """A USB keyboard (HID boot keyboard, 1209:0002, endpoint 0 of 8 bytes;
    plugged in at any speed -- usb.attach("low", keyboard) as most are): its
    descriptors, the HID class requests (SET_PROTOCOL, SET_IDLE, GET_REPORT,
    ...) and its interrupt endpoint 0x81 (8 bytes, every 10 ms), which answers
    an IN with a report when the keys changed and with NAK otherwise.
    .type(text) presses the keys one after the other in emulated time (each
    held `hold` s, `gap` s apart: 100 ms, a typist's pace -- and slow enough
    for a firmware whose CP0 Count clock runs slower here than on the chip,
    as the demo's, whose 16 ms are 54 ms of emulated time); a report is the
    keys held at that moment.
    get_report: True -- GET_REPORT answers with the keys held; "empty" --
    always with eight zero bytes, as the real low-speed keyboard 1a2c:2d23
    does (its keys come from the interrupt endpoint only); False -- it stalls
    GET_REPORT.  composite=True gives it that keyboard's second interface
    too (HID, its media keys, endpoint 0x82: never anything to report).
    interrupt=False halts its interrupt endpoint (every IN is answered with
    STALL)."""

    VID, PID = 0x1209, 0x0002
    MANUFACTURER, PRODUCT, SERIAL = "AliSimulator", "Virtual USB keyboard", "000000000002"
    EP0_SIZE = 8
    INTERVAL = 10

    def __init__(self, get_report=True, composite=False, interrupt=True):
        device = bytes([18, 0x01, 0x10, 0x01, 0x00, 0x00, 0x00, self.EP0_SIZE,
                        self.VID & 0xFF, self.VID >> 8, self.PID & 0xFF, self.PID >> 8,
                        0x00, 0x01, 1, 2, 3, 1])
        n = len(BOOT_KEYBOARD_REPORT)
        interface = bytes([9, 0x04, 0, 0, 1, 0x03, 0x01, 0x01, 0])          # HID, boot, keyboard
        hid = bytes([9, 0x21, 0x11, 0x01, 0x00, 1, 0x22, n & 0xFF, n >> 8])
        ep_in = bytes([7, 0x05, 0x81, 0x03, 8, 0, self.INTERVAL])           # interrupt IN 8
        body = interface + hid + ep_in
        if composite:                                                       # HID, no boot protocol
            body += (bytes([9, 0x04, 1, 0, 1, 0x03, 0x00, 0x00, 0])
                     + bytes([9, 0x21, 0x11, 0x01, 0x00, 1, 0x22, 50, 0])
                     + bytes([7, 0x05, 0x82, 0x03, 8, 0, self.INTERVAL]))
        total = 9 + len(body)
        config = bytes([9, 0x02, total & 0xFF, total >> 8, 2 if composite else 1, 1, 0, 0xA0, 50]) + body
        strings = {0: bytes([4, 0x03, 0x09, 0x04]), 1: _string(self.MANUFACTURER),
                   2: _string(self.PRODUCT), 3: _string(self.SERIAL)}
        super().__init__(device, config, strings)
        self.hid = hid
        self.get_report = get_report
        self.interrupt = interrupt
        self.protocol = 1                    # report protocol until SET_PROTOCOL(0)
        self.idle = None                     # SET_IDLE's duration (None: never set)
        self.leds = None
        self.schedule = []                   # (time, 8-byte report), in time order
        self.sent = bytes(8)                 # the last report the interrupt endpoint delivered
        self.requests = []                   # the class requests received: (rtype, request, value)

    def type(self, text, hold=0.1, gap=0.1):
        """Press the keys of `text` (see key_presses) from now on, or `gap` s after
        the keys still to come; the time until the last is released."""
        now = self.clock()
        t = max(now, self.schedule[-1][0] + gap if self.schedule else 0.0)
        start = now
        for mods, usage in key_presses(text):
            self.schedule.append((t, bytes([mods, 0, usage, 0, 0, 0, 0, 0])))
            self.schedule.append((t + hold, bytes(8)))
            t += hold + gap
        return t - start

    def report_at(self, t):
        report = bytes(8)
        for when, r in self.schedule:
            if when > t:
                break
            report = r
        return report

    def class_request(self, rtype, request, value, index, length):
        if rtype & 0x60 == 0x20 or (rtype == 0x81 and request == 0x06):
            self.requests.append((rtype, request, value))
        if rtype == 0x81 and request == 0x06:                                 # GET_DESCRIPTOR (interface)
            data = {0x21: self.hid, 0x22: BOOT_KEYBOARD_REPORT}.get(value >> 8)
            return None if data is None else data[:length]
        if rtype == 0x21 and request == 0x0B:                                 # SET_PROTOCOL
            self.protocol = value & 1
            return b""
        if rtype == 0xA1 and request == 0x03:                                 # GET_PROTOCOL
            return bytes([self.protocol])
        if rtype == 0x21 and request == 0x0A:                                 # SET_IDLE
            self.idle = value >> 8
            return b""
        if rtype == 0xA1 and request == 0x02:                                 # GET_IDLE
            return bytes([self.idle or 0])
        if rtype == 0xA1 and request == 0x01:                                 # GET_REPORT
            if not self.get_report or value >> 8 != 1:
                return None
            if self.get_report == "empty":
                return bytes(8)[:length]
            return self.report_at(self.clock())[:length]
        if rtype == 0x21 and request == 0x09:                                 # SET_REPORT (LEDs)
            return b""
        return None

    def interrupt_in(self, endpoint):
        if endpoint != 1:
            return None
        if not self.interrupt:
            return HALTED
        report = self.report_at(self.clock())
        if report == self.sent:
            return None                                                       # nothing new: NAK
        self.sent = report
        return report


# a boot mouse's report descriptor in its report protocol (the A4Tech 09da:c10a's, read on a real box:
# report 1 -- eight buttons, X, Y, the wheel, a pan, each a signed byte; report 4 vendor-defined)
A4TECH_MOUSE_REPORT = bytes.fromhex(
    "05 01 09 02 a1 01 09 01 a1 00 85 01 05 09 19 01 29 08 15 00 25 01 75 01 95 08 81 02 05 01 09 30"
    "09 31 09 38 09 b8 15 81 25 7f 75 08 95 04 81 06 c0 c0 06 a0 ff 09 a5 a1 01 85 04 09 a6 15 80 25"
    "7f 75 08 95 05 81 02 c0")


class VirtualMouse(VirtualDevice):
    """A USB mouse (HID boot mouse, 1209:0004, endpoint 0 of 8 bytes; low speed
    as most are): its descriptors, the HID class requests, its interrupt
    endpoint 0x81 (8 bytes, every 10 ms) -- a report when something changed
    (boot protocol: the buttons, the X and Y movement since the last report,
    at most 127 each, the wheel), NAK otherwise.  GET_REPORT answers what the
    real A4Tech mouse answered: the tail of its report descriptor.
    .move(dx, dy, over) moves it in emulated time (a step every 10 ms),
    .press(buttons) / .release(buttons) / .click(button, hold) the buttons
    (1 left, 2 right, 4 middle), .wheel(n); several presses and releases
    between two polls each make a report of their own."""

    VID, PID = 0x1209, 0x0004
    MANUFACTURER, PRODUCT, SERIAL = "AliSimulator", "Virtual USB mouse", "000000000004"
    EP0_SIZE = 8
    INTERVAL = 10

    def __init__(self):
        device = bytes([18, 0x01, 0x10, 0x01, 0x00, 0x00, 0x00, self.EP0_SIZE,
                        self.VID & 0xFF, self.VID >> 8, self.PID & 0xFF, self.PID >> 8,
                        0x00, 0x01, 1, 2, 3, 1])
        n = len(A4TECH_MOUSE_REPORT)
        interface = bytes([9, 0x04, 0, 0, 1, 0x03, 0x01, 0x02, 0])          # HID, boot, mouse
        hid = bytes([9, 0x21, 0x10, 0x01, 0x00, 1, 0x22, n & 0xFF, n >> 8])
        ep_in = bytes([7, 0x05, 0x81, 0x03, 8, 0, self.INTERVAL])
        body = interface + hid + ep_in
        total = 9 + len(body)
        config = bytes([9, 0x02, total & 0xFF, total >> 8, 1, 1, 0, 0xA0, 50]) + body
        strings = {0: bytes([4, 0x03, 0x09, 0x04]), 1: _string(self.MANUFACTURER),
                   2: _string(self.PRODUCT), 3: _string(self.SERIAL)}
        super().__init__(device, config, strings)
        self.hid = hid
        self.protocol = 1
        self.idle = None
        self.schedule = []                    # (time, kind, a, b) in time order
        self.buttons = 0                      # as the last report told
        self.pressed = 0                      # as the schedule has them now
        self.states = []                      # button states still to report, one report each
        self.pending = [0, 0, 0]              # movement and wheel not reported yet
        self.reports = []                     # (time, report) delivered
        self.requests = []

    def _at(self, delay=0.0):
        now = self.clock()
        return max(now + delay, self.schedule[-1][0] if self.schedule else 0.0)

    def move(self, dx, dy, over=0.2, delay=0.0):
        """Move by (dx, dy) counts, spread over `over` s from now (or after what is scheduled)."""
        t = self._at(delay)
        steps = max(1, int(over / 0.01))
        done_x = done_y = 0
        for i in range(1, steps + 1):
            sx, sy = dx * i // steps - done_x, dy * i // steps - done_y
            done_x, done_y = done_x + sx, done_y + sy
            self.schedule.append((t + i * 0.01, "move", sx, sy))
        return t + steps * 0.01 - self.clock()

    def press(self, buttons, delay=0.0):
        self.schedule.append((self._at(delay), "press", buttons, 0))

    def release(self, buttons, delay=0.0):
        self.schedule.append((self._at(delay), "release", buttons, 0))

    def click(self, button=1, hold=0.15, delay=0.0):
        self.press(button, delay)
        self.release(button, hold)

    def wheel(self, n, delay=0.0):
        self.schedule.append((self._at(delay), "wheel", n, 0))

    def _due(self):
        now = self.clock()
        while self.schedule and self.schedule[0][0] <= now:
            _t, kind, a, b = self.schedule.pop(0)
            if kind == "move":
                self.pending[0] += a
                self.pending[1] += b
            elif kind == "wheel":
                self.pending[2] += a
            else:
                self.pressed = self.pressed | a if kind == "press" else self.pressed & ~a
                self.states.append(self.pressed)

    def class_request(self, rtype, request, value, index, length):
        if rtype & 0x60 == 0x20 or (rtype == 0x81 and request == 0x06):
            self.requests.append((rtype, request, value))
        if rtype == 0x81 and request == 0x06:                                 # GET_DESCRIPTOR (interface)
            data = {0x21: self.hid, 0x22: A4TECH_MOUSE_REPORT}.get(value >> 8)
            return None if data is None else data[:length]
        if rtype == 0x21 and request == 0x0B:                                 # SET_PROTOCOL
            self.protocol = value & 1
            return b""
        if rtype == 0xA1 and request == 0x03:                                 # GET_PROTOCOL
            return bytes([self.protocol])
        if rtype == 0x21 and request == 0x0A:                                 # SET_IDLE
            self.idle = value >> 8
            return b""
        if rtype == 0xA1 and request == 0x01:                                 # GET_REPORT: nonsense
            return A4TECH_MOUSE_REPORT[-8:][:length]
        return None

    def interrupt_in(self, endpoint):
        if endpoint != 1:
            return None
        self._due()
        if self.states:
            self.buttons = self.states.pop(0)
        elif not any(self.pending):
            return None                                                       # nothing new: NAK
        clamp = lambda v: max(-127, min(127, v))                              # noqa: E731
        dx, dy, w = (clamp(v) for v in self.pending)
        self.pending = [self.pending[0] - dx, self.pending[1] - dy, self.pending[2] - w]
        report = bytes([self.buttons, dx & 0xFF, dy & 0xFF, w & 0xFF])
        self.reports.append((round(self.clock(), 4), report))
        return report


class _HubPort:
    def __init__(self):
        self.device = None
        self.speed = "full"                   # the plugged-in device's: "low", "full" or "high"
        self.powered = False
        self.enabled = False
        self.change = 0                       # wPortChange: bit 0 connection, 1 enable, 4 reset
        self.reset_until = None               # a port reset under way ends then


class VirtualHub(VirtualDevice):
    """A USB hub (1209:0003, endpoint 0 of 64 bytes): its descriptors, the hub
    class requests -- the hub descriptor, a port's power / reset / enable
    features and change bits, GET_STATUS of a port -- and its status-change
    endpoint 0x81.  Plugged in at high speed (usb.attach("high", hub)) it is
    a USB 2.0 hub with one transaction translator, as the Terminus 1a40:0101
    tried on a real box: devices that are not high speed behind it are
    reached with split transfers (the controller's +0x80 bit 0 and +0x81).
    .plug(port, device, speed) / .unplug(port) put a device on a port --
    another hub too.  A port reports its device once it is powered, the
    low-speed bit at once and the high-speed bit after its reset, which the
    hub ends by itself (12 ms) with the device at address 0."""

    VID, PID = 0x1209, 0x0003
    MANUFACTURER, PRODUCT = "AliSimulator", "Virtual USB hub"
    EP0_SIZE = 64
    RESET_S = 0.012

    def __init__(self, ports=4):
        device = bytes([18, 0x01, 0x00, 0x02, 0x09, 0x00, 0x01, self.EP0_SIZE,
                        self.VID & 0xFF, self.VID >> 8, self.PID & 0xFF, self.PID >> 8,
                        0x11, 0x01, 1, 2, 0, 1])
        interface = bytes([9, 0x04, 0, 0, 1, 0x09, 0x00, 0x00, 0])          # hub
        ep_in = bytes([7, 0x05, 0x81, 0x03, 1, 0, 12])                       # status change, interrupt IN
        body = interface + ep_in
        total = 9 + len(body)
        config = bytes([9, 0x02, total & 0xFF, total >> 8, 1, 1, 0, 0xE0, 50]) + body
        strings = {0: bytes([4, 0x03, 0x09, 0x04]), 1: _string(self.MANUFACTURER), 2: _string(self.PRODUCT)}
        super().__init__(device, config, strings)
        self.qualifier = bytes([10, 0x06, 0x00, 0x02, 0x09, 0x00, 0x00, self.EP0_SIZE, 1, 0])
        self.hub_descriptor = bytes([9, 0x29, ports, 0x00, 0x00, 0x32, 0x64, 0x00, 0xFF])
        self.ports = {n: _HubPort() for n in range(1, ports + 1)}
        self.features = []                    # (time, "set" / "clear", feature, port) of every port request

    def plug(self, port, device, speed="full"):
        p = self.ports[port]
        p.device, p.speed, p.enabled, p.reset_until = device, speed, False, None
        device.clock = self.clock
        if p.powered:
            p.change |= 0x01

    def unplug(self, port):
        p = self.ports[port]
        p.device, p.enabled, p.reset_until = None, False, None
        if p.powered:
            p.change |= 0x01

    def reset_ports(self):
        """The hub itself was reset (the bus, or the port it is on): its ports are off."""
        for p in self.ports.values():
            p.powered, p.enabled, p.change, p.reset_until = False, False, 0, None

    def settle(self, p):
        """A port reset that has run its time ends: the port enabled, its device at address 0."""
        if p.reset_until is not None and self.clock() >= p.reset_until:
            p.reset_until = None
            if p.device is not None and p.powered:
                p.enabled = True
                p.change |= 0x10
                dev = p.device
                dev.address, dev.pending_address, dev.configuration = 0, None, 0
                dev.in_toggle.clear()
                if isinstance(dev, VirtualHub):
                    dev.reset_ports()

    def port_status(self, port):
        p = self.ports[port]
        self.settle(p)
        there = p.device is not None and p.powered
        status = ((0x0001 if there else 0) | (0x0002 if p.enabled else 0)
                  | (0x0010 if p.reset_until is not None else 0) | (0x0100 if p.powered else 0)
                  | (0x0200 if there and p.speed == "low" else 0)
                  | (0x0400 if p.enabled and p.speed == "high" else 0))
        return status, p.change

    def class_request(self, rtype, request, value, index, length):
        if rtype == 0xA0 and request == 0x06 and value >> 8 == 0x29:          # the hub descriptor
            return self.hub_descriptor[:length]
        if rtype == 0xA0 and request == 0x00:                                 # GET_STATUS (hub)
            return bytes(4)[:length]
        if rtype == 0x20 and request in (0x01, 0x03):                         # CLEAR / SET_FEATURE (hub)
            return b""
        port = index & 0xFF
        if port not in self.ports:
            return None
        p = self.ports[port]
        if rtype == 0xA3 and request == 0x00:                                 # GET_STATUS (port)
            status, change = self.port_status(port)
            return bytes([status & 0xFF, status >> 8, change & 0xFF, change >> 8])[:length]
        if rtype == 0x23 and request in (0x01, 0x03):                         # CLEAR / SET_FEATURE (port)
            self.settle(p)
            self.features.append((round(self.clock(), 4), "set" if request == 0x03 else "clear", value, port))
            if request == 0x03:
                if value == 8 and not p.powered:                              # PORT_POWER
                    p.powered = True
                    if p.device is not None:
                        p.change |= 0x01
                elif value == 4 and p.device is not None and p.powered:       # PORT_RESET
                    p.enabled = False
                    p.reset_until = self.clock() + self.RESET_S
            elif value == 1:                                                  # PORT_ENABLE
                p.enabled = False
            elif value == 8:                                                  # PORT_POWER
                p.powered, p.enabled = False, False
            elif 16 <= value <= 20:                                           # C_PORT_CONNECTION .. C_PORT_RESET
                p.change &= ~(1 << (value - 16))
            return b""
        return None

    def interrupt_in(self, endpoint):
        if endpoint != 1:
            return None
        bits = 0
        for n, p in self.ports.items():
            self.settle(p)
            if p.change:
                bits |= 1 << n
        return bytes([bits]) if bits else None


class UsbHost:
    SIZE = 0x100

    def __init__(self, sim, base=0x32000, line=29):
        self.sim = sim
        self.base = base & 0xFFFFFF
        self.line = line
        self.device = VirtualStick()
        self.connected = False
        self.speed = SPEED_BITS["high"]
        self.flags1 = 0
        self.flags2 = 0
        self.intf = 0
        self.reset_done_at = None
        self.token_done_at = None
        self.fifo_out = bytearray()           # bytes the CPU wrote into endpoint 0's FIFO
        self.fifo_in = bytearray()            # bytes of an IN packet for the CPU to read
        self.epc_fifo = bytearray()           # endpoint C's received packet
        self.epc_next = None                  # when endpoint C polls next
        self.epd_fifo = bytearray()           # endpoint D's received packet
        self.epd_next = None                  # when endpoint D polls next
        self.epd_toggle = 0                   # the data toggle endpoint D expects
        self.epd_polls = 0                    # IN tokens endpoint D sent
        self.flags3 = 0                       # interrupt flags 3: bit 4 endpoint D done, bit 0 failed
        self.epb_started = False              # +0x60's start strobe written (start_dma_rx_transfer)
        self.epb_pending = False              # an IN under way on endpoint B
        self.epb_next = 0.0                   # when its next token goes out
        self.epb_toggle = 0                   # the data toggle endpoint B expects (0 DATA0)
        self.epb_silent = 0                   # its tokens in a row nobody answered
        self.epb_full = False                 # a packet arrived since the FIFO's last reset (+0x17 reads 0x86)
        self.in_tokens = 0                    # IN tokens endpoint B sent
        self.toggle_drops = 0                 # packets acknowledged and dropped for their data toggle
        self.epa_started = False              # +0x60's transmit start strobe written (start_dma_tx_transfer)
        self.epa_pending = False              # an OUT under way on endpoint A
        self.epa_next = 0.0
        self.epa_toggle = 0                   # the data toggle endpoint A sends next
        self.epa_silent = 0
        self.bulk_out_log = []                # (vtime, data) endpoint A delivered
        self.bulk_in = []                     # (vtime, bytes) endpoint B received from bulk endpoints
        self.pending_in = b""                 # the rest of a control transfer's IN data
        self.stage = None                     # 'data' / 'status_in' / 'stall' after a SETUP
        self.setups = []                      # (vtime, SETUP packet) the device received
        self.interrupt_packets = []           # (vtime, packet) endpoint C delivered
        self.writes = []                      # (vtime, offset, size, value) of every store, for inspection
        self.events = []                      # (vtime, text)
        sim._mmio_on('r', self._read, self.base, self.base + self.SIZE - 1)
        sim._mmio_on('w', self._write, self.base, self.base + self.SIZE - 1)
        sim.slice_services.append(self._service)

    # ---- the device ----
    def attach(self, speed="high", device=None):
        """Plug `device` (a VirtualDevice; a new VirtualStick by default) in."""
        self.speed = SPEED_BITS[speed]
        self.connected = True
        self.device = device if device is not None else VirtualStick()
        self._set_clock(self.device)
        self._event(f"device attached ({speed} speed)")

    def _set_clock(self, device):
        device.clock = self.sim._vtime
        if isinstance(device, VirtualHub):
            for p in device.ports.values():
                if p.device is not None:
                    self._set_clock(p.device)

    def detach(self):
        self.connected = False
        self._event("device removed")

    def _event(self, text):
        self.flags1 |= 0x01                    # connection changed
        self.intf |= 0x09
        self.events.append((round(self.sim._vtime(), 4), text))
        self._update_line()

    # ---- registers ----
    def _reg(self, off):
        return self.sim._mmio_view[self.base + off]

    def _update_line(self):
        en1, en2, en3 = self._reg(0x1E), self._reg(0x1F), self._reg(0x2E)
        pending = (self.intf & 0x09) == 0x09 and bool((self.flags1 & en1) or (self.flags2 & en2)
                                                       or (self.flags3 & en3))
        self.sim._ic_set_line(self.line, pending)

    # registers whose read pops a FIFO or clears flags: a re-executed read (the
    # Unicorn engine rewinds an access a stop interrupted) gets the same byte
    _READ_SIDE_EFFECTS = (0x12, 0x1B, 0x20, 0x21, 0x24, 0x2F, 0x63)

    def _read(self, uc, access, address, size, value, user_data):
        self.sim._device_access(uc)
        self._service()                           # (a reset or token that ended since the last slice)
        abs_off = address & 0xFFFFFF
        off = abs_off - self.base
        view = self.sim._mmio_view
        guarded = size == 1 and off in self._READ_SIDE_EFFECTS
        if guarded:
            rp = self.sim._dev_replay_of(uc, 'usb', address)
            if rp is not None:
                view[abs_off] = rp[2]
                return
        for i in range(size):
            o = off + i
            if o == 0x10:
                v = view[self.base + 0x10] & ~0x03
                view[abs_off + i] = v | (0x02 if self.connected else 0)
            elif o == 0x11:
                v = view[self.base + 0x11] & ~0x84
                view[abs_off + i] = v | (0x84 if not self.fifo_in else 0)
            elif o == 0x12:
                view[abs_off + i] = self.fifo_in.pop(0) if self.fifo_in else 0
            elif o == 0x17:
                v = view[self.base + 0x17] & ~0x86
                view[abs_off + i] = v | (0x86 if self.epb_full else 0x84)
            elif o == 0x14:
                v = view[self.base + 0x14] & ~0x86
                view[abs_off + i] = v | (0x82 if self.epa_pending else 0x86)
            elif o == 0x60:
                view[abs_off + i] = 0                  # (its bits are strobes)
            elif o == 0x1A:
                v = view[self.base + 0x1A] & ~0x84
                view[abs_off + i] = v | (0x84 if not self.epc_fifo else 0)
            elif o == 0x1B:
                view[abs_off + i] = self.epc_fifo.pop(0) if self.epc_fifo else 0
            elif o == 0x23:
                v = view[self.base + 0x23] & ~0x84
                view[abs_off + i] = v | (0x84 if not self.epd_fifo else 0)
            elif o == 0x24:
                view[abs_off + i] = self.epd_fifo.pop(0) if self.epd_fifo else 0
            elif o == 0x2F:
                view[abs_off + i] = self.flags3
                self.flags3 = 0
            elif o == 0x20:
                view[abs_off + i] = self.flags1
                self.flags1 = 0
            elif o == 0x21:
                view[abs_off + i] = self.flags2
                self.flags2 = 0
            elif o == 0x32:
                view[abs_off + i] = (view[self.base + 0x32] & ~0x60) | (self.speed if self.connected else 0)
            elif o == 0x63:
                view[abs_off + i] = self.intf
                self.intf = 0
        if guarded:
            self.sim._dev_note(uc, 'usb', address, view[abs_off])
        if off <= 0x21 and off + size > 0x20 or off <= 0x2F < off + size or off <= 0x63 < off + size:
            self._update_line()

    def _write(self, uc, access, address, size, value, user_data):
        self.sim._device_access(uc)
        off = (address & 0xFFFFFF) - self.base
        self.writes.append((round(self.sim._vtime(), 6), off, size, value & ((1 << (8 * size)) - 1)))
        for i in range(size):
            o, v = off + i, (value >> (8 * i)) & 0xFF
            if o == 0x10 and v & 0x20 and self.reset_done_at is None:
                self.reset_done_at = self.sim._vtime() + RESET_TIME_S
                self.events.append((round(self.sim._vtime(), 4), "bus reset started"))
            elif o == 0x11:
                if v & 0x10:                      # FIFO reset
                    self.fifo_out.clear()
                    self.fifo_in.clear()
                if v & 0x20 and self.token_done_at is None:
                    self.token_done_at = self.sim._vtime() + TOKEN_TIME_S
                    self.token_pid = v & 0x03
            elif o == 0x12:
                # (a re-executed store -- see _READ_SIDE_EFFECTS -- pushes its byte once)
                if size == 1 and self.sim._dev_replay_of(uc, 'usb_w', address, value) is not None:
                    continue
                self.fifo_out.append(v)
                if size == 1:
                    self.sim._dev_note(uc, 'usb_w', address, value)
            elif o == 0x1A and v & 0x10:          # endpoint C's FIFO reset
                self.epc_fifo.clear()
            elif o == 0x23:
                if v & 0x10:                      # endpoint D's FIFO reset
                    self.epd_fifo.clear()
                if v & 0x01:                      # its data toggle back to DATA0
                    self.epd_toggle = 0
            elif o == 0x17:
                if v & 0x10:                      # endpoint B's FIFO reset: it also ends a pending IN
                    self.epb_pending = False
                    self.epb_full = False
                if v & 0x01:                      # (set_ep_data_toggle's pulse) the toggle back to DATA0
                    self.epb_toggle = 0
            elif o == 0x14:
                if v & 0x10:                      # endpoint A's FIFO reset: it ends an OUT
                    self.epa_pending = False
                if v & 0x01:
                    self.epa_toggle = 0
            elif o == 0x60:
                if v & 0x10:                      # start_dma_rx_transfer
                    self.epb_started = True
                if v & 0x01:                      # start_dma_tx_transfer
                    self.epa_started = True
            elif o == 0x32 and v & 0x0C == 0x0C and self.epb_started and not self.epb_pending:
                self.epb_started = False          # dma_host_in_token + en_dma_transfer: the IN goes out
                self.epb_pending = True
                self.epb_silent = 0
                self.epb_next = self.sim._vtime() + IN_TIME_S
            elif o == 0x32 and v & 0x0C == 0x08 and self.epa_started and not self.epa_pending:
                self.epa_started = False          # en_dma_transfer alone: the OUT goes out
                self.epa_pending = True
                self.epa_silent = 0
                self.epa_next = self.sim._vtime() + IN_TIME_S

    def _route(self, new_mode_reg):
        """What a token carries: (device address, split flag, split info) --
        the new mode's per-endpoint registers (+0x80 / +0x81 endpoint 0, +0x84
        / +0x85 endpoint B, +0x86 / +0x87 endpoint C, +0x88 / +0x89 endpoint
        D), else +0x1C.  With +0x90
        bit 1 set the controller does not split (measured: a low-speed device
        behind a hub then gets no answer)."""
        view, b = self.sim._mmio_view, self.base
        if not view[b + 0x8F] & 0x80:
            return view[b + 0x1C] & 0x7F, 0, 0
        a = view[b + new_mode_reg]
        split = a & 1 if not view[b + 0x90] & 0x02 else 0
        return (a >> 1) & 0x0F, split, view[b + new_mode_reg + 1]

    def _walk(self, device=None, speed=None, translator=None, reachable=True):
        """Every device on the bus: (device, its speed here, the translator it is
        behind -- (hub address, port) for a device that is not high speed under
        a high-speed hub, else None -- and whether tokens reach it: every port
        on the way powered and enabled, every hub configured)."""
        if device is None:
            if not self.connected:
                return
            device = self.device
            speed = {v: k for k, v in SPEED_BITS.items()}[self.speed]
        yield device, speed, translator, reachable
        if not isinstance(device, VirtualHub):
            return
        for n, p in device.ports.items():
            device.settle(p)
            if p.device is None:
                continue
            ok = reachable and p.powered and p.enabled and bool(device.configuration)
            if speed == "high" and p.speed == "high":
                child, tt = "high", None
            else:
                child = "low" if p.speed == "low" else "full"
                tt = (device.address, n) if speed == "high" else translator
                if tt is None and child == "low" and speed != "low":
                    ok = False        # a full-speed hub would need a preamble packet for it
            yield from self._walk(p.device, child, tt, ok)

    def _target(self, new_mode_reg):
        """The device a token at those registers reaches, or None; and the error
        the controller then reports: "no response", or a stall when the token
        went to a hub's translator (which answers for its silent port)."""
        address, split, info = self._route(new_mode_reg)
        hub_there = False
        for dev, speed, tt, ok in self._walk():
            if split and ok and speed == "high" and isinstance(dev, VirtualHub) and dev.address == (info & 7) \
                    and dev.configuration:
                hub_there = True
            if not ok or dev.address != address:
                continue
            if tt is None:
                if not split:
                    return dev, 0
            elif split and (info & 7) == tt[0] and (info >> 3) & 7 == tt[1] and bool(info & 0x40) == (speed == "low"):
                return dev, 0
        return None, (STALL if hub_there else NO_RESPONSE)

    def _token(self, pid):
        """Endpoint 0's token with the device: 0 done, else the +0x1D error code."""
        dev, error = self._target(0x80)
        if dev is None:
            return error
        if pid == 0:                                                    # SETUP
            packet = bytes(self.fifo_out[:8])
            self.fifo_out.clear()
            self.setups.append((round(self.sim._vtime(), 4), packet))
            answer = dev.setup(packet) if len(packet) == 8 else None
            if answer is None:
                self.events.append((round(self.sim._vtime(), 4), f"SETUP {packet.hex(' ')} stalled"))
                self.pending_in = b""
                self.stage = "stall"
                return 0
            self.pending_in = answer if packet[0] & 0x80 else b""
            self.stage = "data" if packet[0] & 0x80 and packet[6] | packet[7] << 8 else "status_in"
            return 0
        if self.stage == "stall":
            return STALL
        if pid == 2:                                                    # IN
            chunk, self.pending_in = self.pending_in[:dev.EP0_SIZE], self.pending_in[dev.EP0_SIZE:]
            self.fifo_in = bytearray(chunk)
            if self.stage == "status_in":                               # the status stage ends the request
                self.stage = None
                if dev.pending_address is not None:
                    dev.address, dev.pending_address = dev.pending_address, None
            return 0
        self.fifo_out.clear()                                           # OUT (data or status)
        return 0

    def _service_epb(self):
        """Endpoint B's pending IN (the module's notes): the token that is due,
        to the device's endpoint (+0x16 bits 2..5) at +0x84's address."""
        now = self.sim._vtime()
        if not self.epb_pending or now < self.epb_next:
            return
        view, b = self.sim._mmio_view, self.base
        ep = (view[b + 0x16] >> 2) & 0x0F
        self.in_tokens += 1
        dev, error = self._target(0x84)
        if dev is not None and not (dev.configuration and ep in dev.in_endpoints):
            dev, error = None, (STALL if self._route(0x84)[1] else NO_RESPONSE)
        if dev is None and error == NO_RESPONSE:
            view[b + 0x1D] = NO_RESPONSE              # nobody answers
            self.flags1 |= 0x20
            self.epb_silent += 1
            if self.epb_silent < 2:
                self.epb_next = now + IN_TIME_S       # (once more)
                return
            self.epb_pending = False
            view[b + 0x32] &= ~0x0C
            self.flags2 |= 0x02                       # endpoint B failed
            self.intf |= 0x09
            self._update_line()
            return
        self.epb_silent = 0
        # (through a hub's translator a silent device or endpoint comes back as a stall: measured,
        #  0.24 ms after the IN's start)
        count = view[b + 0x38] | view[b + 0x39] << 8 | view[b + 0x3A] << 16
        maxp = 8 << ((view[b + 0x30] >> 4) & 7)
        data = dev.in_transfer(ep, count, maxp) if dev is not None else HALTED
        if data is HALTED:                            # STALL (assumed to end the IN as it ends endpoint 0's token)
            view[b + 0x1D] = STALL
            self.epb_pending = False
            view[b + 0x32] &= ~0x0C
            self.flags2 |= 0x02
            self.intf |= 0x09
            self._update_line()
            return
        if data is None:                              # NAK: again in the next frame (+0xA8)
            period = view[b + 0xA8]
            self.epb_next = (float("inf") if period & 0xF0 else
                             now + (IN_TIME_S if not period else FRAME_S / period))
            return
        data = bytes(data[:count])
        packets = len(data) // maxp + 1 if len(data) < count else -(-len(data) // maxp)
        toggle = dev.in_toggle.get(ep, 0)
        if toggle != self.epb_toggle:                 # not the toggle expected: the first packet is
            view[b + 0x1D] |= TOGGLE                  # acknowledged and dropped, the IN goes on
            self.toggle_drops += 1
            dev.in_toggle[ep] = toggle ^ 1
            data, packets = data[maxp:], packets - 1
            if packets <= 0:
                self.epb_next = now + IN_TIME_S
                return
        dev.in_toggle[ep] = dev.in_toggle.get(ep, 0) ^ (packets & 1)
        self.epb_toggle ^= packets & 1
        address = int.from_bytes(bytes(view[b + 0x40:b + 0x44]), "little") & 0x0FFFFFE0
        if data and address + len(data) <= self.sim.ram_size:
            ctypes.memmove(ctypes.addressof(self.sim.ram_buffer) + address, data, len(data))
        for i, v in enumerate(len(data).to_bytes(4, "little")):
            view[b + 0x48 + i] = v
        for i, v in enumerate((0x20).to_bytes(4, "little")):
            view[b + 0x44 + i] = v
        view[b + 0x2C], view[b + 0x2D] = len(data) & 0xFF, len(data) >> 8
        view[b + 0x1D] = 0
        view[b + 0x32] &= ~0x0C
        self.epb_pending = False
        self.epb_full = True
        if ep in dev.interrupt_endpoints:
            self.interrupt_packets.append((round(now, 4), data))
        else:
            self.bulk_in.append((round(now, 4), len(data)))
        self.flags2 |= 0x20                           # endpoint B done
        self.intf |= 0x05
        self._update_line()

    def _service_epa(self):
        """Endpoint A's OUT (the SDK's bulkout_start): the bytes at +0x50 (+0x58 of
        them) to the device's endpoint (+0x13 bits 2..5) at +0x82's address."""
        now = self.sim._vtime()
        if not self.epa_pending or now < self.epa_next:
            return
        view, b = self.sim._mmio_view, self.base
        ep = (view[b + 0x13] >> 2) & 0x0F
        maxp = 8 << (view[b + 0x30] & 7)
        dev, error = self._target(0x82)
        if dev is not None and not (dev.configuration and ep in dev.out_endpoints):
            dev, error = None, (STALL if self._route(0x82)[1] else NO_RESPONSE)
        if dev is None and error == NO_RESPONSE:
            view[b + 0x1D] = NO_RESPONSE
            self.flags1 |= 0x20
            self.epa_silent += 1
            if self.epa_silent < 2:
                self.epa_next = now + IN_TIME_S
                return
            self._epa_end(0x04)                       # endpoint A failed
            return
        self.epa_silent = 0
        length = int.from_bytes(bytes(view[b + 0x58:b + 0x5C]), "little") & 0xFFFFFF
        address = int.from_bytes(bytes(view[b + 0x50:b + 0x54]), "little") & 0x0FFFFFE0
        data = bytes(self.sim.ram_buffer[address:address + length]) if address + length <= self.sim.ram_size else b""
        packets = max(1, -(-len(data) // maxp))
        toggle = dev.out_toggle.get(ep, 0) if dev is not None else 0
        if dev is not None and toggle != self.epa_toggle:
            # the device takes the first packet for one it has had already: acknowledged, thrown away
            self.toggle_drops += 1
            data, packets = data[maxp:], packets - 1
            self.epa_toggle ^= 1
            if packets <= 0:
                self._epa_end(0x40)                   # (the controller thinks it was delivered)
                return
        answer = dev.bulk_out(ep, data) if dev is not None else HALTED
        if answer is HALTED:
            view[b + 0x1D] = STALL
            self._epa_end(0x04)
            return
        if answer is None:                            # NAK: again in the next frame
            self.epa_next = now + FRAME_S
            return
        dev.out_toggle[ep] = dev.out_toggle.get(ep, 0) ^ (packets & 1)
        self.epa_toggle ^= packets & 1
        self.bulk_out_log.append((round(now, 4), bytes(data)))
        for i, v in enumerate((0x20).to_bytes(4, "little")):
            view[b + 0x54 + i] = v
        view[b + 0x5C:b + 0x60] = bytes(4)
        view[b + 0x1D] = 0
        self._epa_end(0x40)                           # endpoint A done

    def _epa_end(self, flag):
        view, b = self.sim._mmio_view, self.base
        self.epa_pending = False
        view[b + 0x32] &= ~0x08
        self.flags2 |= flag
        self.intf |= 0x03 if flag == 0x40 else 0x09   # (the DMA transmit done; an error: flags 2)
        self._update_line()

    def _service_epc(self):
        """Endpoint C: while +0x2B bit 5 is set, an IN token every +0xA2 ms to
        the device's endpoint (+0x19 bits 2..5) until it answers with data --
        but none at all to a low-speed device (the module's notes)."""
        view = self.sim._mmio_view
        b = self.base
        interval = view[b + 0xA2]
        if not (view[b + 0x2B] & 0x20 and interval and view[b + 0x19] & 0xC0 == 0xC0) \
                or self.speed == SPEED_BITS["low"]:
            self.epc_next = None
            return
        now = self.sim._vtime()
        if self.epc_next is None:
            self.epc_next = now + interval / 1000
            return
        if now < self.epc_next or self.epc_fifo or self.flags2 & 0x11:
            return
        self.epc_next = now + interval / 1000
        dev, error = self._target(0x86)
        if dev is None:
            self.flags2 |= 0x01                   # endpoint C failed: no response
            view[b + 0x1D] = error
        else:
            data = dev.interrupt_in((view[b + 0x19] >> 2) & 0x0F)
            if data is None:
                return                            # NAK: polled again at the interval
            if data is HALTED:
                self.flags2 |= 0x01               # endpoint C failed: a stall
                view[b + 0x1D] = STALL
            else:
                data = bytes(data[:8 << (view[b + 0x31] & 7)])
                self.epc_fifo = bytearray(data)
                self.interrupt_packets.append((round(now, 4), data))
                self.flags2 |= 0x10               # endpoint C done
        self.intf |= 0x09
        self._update_line()

    def _service_epd(self):
        """Endpoint D (the module's notes): while +0x2B bit 3 is set and +0xA3
        is not 0, an IN token every 2^(+0xA3 - 1) microframes -- the first one
        within a frame -- to the device's endpoint (+0x22 bits 2..5) at +0x88's
        address, through a translator too, until a packet is in its FIFO
        (flags 3 bit 4).  A failed token sets +0x1D and a flags 1 bit -- 0x10
        through a translator, 0x20 for no response (measured), 0x80 and bit 4
        for a stall without one (assumed) -- and the polling goes on, flags 3
        untouched, as on the box.  A packet with the other data toggle is
        acknowledged and dropped (+0x1D bit 3): the device's report is lost,
        the polling goes on."""
        view, b = self.sim._mmio_view, self.base
        code = view[b + 0xA3]
        if not (view[b + 0x2B] & 0x08 and code and view[b + 0x22] & 0xC0 == 0xC0):
            self.epd_next = None
            return
        now = self.sim._vtime()
        period = (1 << (min(code, 16) - 1)) * 125e-6
        if self.epd_next is None:
            self.epd_next = now + min(period, FRAME_S)
            return
        if now < self.epd_next or self.epd_fifo or self.flags3 & 0x11:
            return
        self.epd_next = now + period
        self.epd_polls += 1
        ep = (view[b + 0x22] >> 2) & 0x0F
        split = self._route(0x88)[1]
        dev, _error = self._target(0x88)
        there = dev is not None and dev.configuration and ep in dev.in_endpoints
        data = dev.interrupt_in(ep) if there else HALTED
        if data is None:
            return                                # NAK: polled again at the interval
        if data is HALTED:
            # failed (the translator's answer, nobody there, the device's stall): +0x1D and flags 1
            # only -- no flags 3, no +0x63 bits -- and the polling goes on (measured)
            code = 0x10 if split else (STALL if there else NO_RESPONSE)
            view[b + 0x1D] = code
            self.flags1 |= 0x20 if code == NO_RESPONSE else 0x10
            return
        toggle = dev.in_toggle.get(ep, 0)
        dev.in_toggle[ep] = toggle ^ 1            # (acknowledged either way)
        if toggle != self.epd_toggle:
            view[b + 0x1D] |= TOGGLE
            self.toggle_drops += 1
            return
        self.epd_toggle ^= 1
        data = bytes(data[:8 << ((view[b + 0x31] >> 4) & 7)])
        self.epd_fifo = bytearray(data)
        self.interrupt_packets.append((round(now, 4), data))
        self.flags3 |= 0x10                       # endpoint D done
        self.intf |= 0x09
        self._update_line()

    def _service(self):
        view = self.sim._mmio_view
        if self.reset_done_at is not None and self.sim._vtime() >= self.reset_done_at:
            self.reset_done_at = None
            view[self.base + 0x10] &= ~0x20       # the controller ends the reset
            if self.connected:
                self.flags1 |= 0x02
                self.intf |= 0x09
                self.device.address = 0           # a reset device answers at address 0,
                self.device.pending_address = None
                self.device.configuration = 0     # is not configured, its endpoints start with DATA0
                self.device.in_toggle.clear()
                if isinstance(self.device, VirtualHub):
                    self.device.reset_ports()     # (a hub's ports are off: nothing behind it is reached)
            self.events.append((round(self.sim._vtime(), 4), "bus reset done"))
            self._update_line()
        if self.token_done_at is not None and self.sim._vtime() >= self.token_done_at:
            self.token_done_at = None
            view[self.base + 0x11] &= ~0x20      # the token went out
            error = self._token(self.token_pid)
            if error:
                self.flags2 |= 0x08               # endpoint 0 failed
                view[self.base + 0x1D] = error
            else:
                self.flags2 |= 0x80               # endpoint 0 done
            self.intf |= 0x09
            self._update_line()
        self._service_epa()
        self._service_epb()
        if self.connected:
            self._service_epc()
            self._service_epd()
