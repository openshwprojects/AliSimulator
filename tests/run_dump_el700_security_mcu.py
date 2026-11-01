#!/usr/bin/env python3
"""
The Echolink EL-700 FTA / Eurosat 3023 2 MB MX29LV160 parallel NOR flash dump
(Moresat's 2007 "SMT01---0.9.6" ALi M3329C platform) runs its bootloader up to
its external `PAN_SMTM51_0` front-panel / anti-clone MCU handshake and RS-232
upgrade fallback -- and no further, because the external 8051 MCU's secret
XTEA key response is not known.

The bootloader configures SDRAM, unpacks its relocated image into 0x80300000,
identifies the 2 MB Macronix MX29LV160 parallel NOR flash (`STO_FLASH_0`) via
AMD autoselect, probes its bit-banged I2C bus (SCL = GPIO 10, SDA = GPIO 9),
and opens both 16550 UARTs: `SCI_16550_0` (`0xB8001300`, 115200 baud) for the
RS-232 upgrade console and `SCI_16550_1` (`0xB8001400`, 9600 baud, IC line 6:
`chips/m3329.py` `Uart16550`) for the `PAN_SMTM51_0` MCU.  Every `UART2` packet
has the form `[cmd, len, payload..., sum & 0xFF]` and awaits a `0x80` link
acknowledge on `UART2` RX.

The bootloader displays `" on "` (`05 05 33 20 6f 6e 20 5a`), reads the
`"CODE"`-wrapped `maincode` chunk at `0x010080` (`"CODE"` + big-endian length
`0x0007EBC9`), and sends four challenge packets (`0d 0a 00 00 92 d0 7c 93 b8
74 f7 d5 80`) carrying the 8-byte challenge from `0x8030EED4`, waiting `3 x
250 ms` per attempt (`osal_delay` fixed 108 ticks/us build) for a `0x11 0x0A`
response with the secret half of the 128-bit XTEA key.  With an ACK-only
stand-in on `UART2` (acknowledging link frames with `0x80` without spoofing the
unknown key), `0x8030D7A8` cleanly aborts decryption without calling
`LzmaDecode` on `maincode`, displays `"upg "` (`05 05 33 75 70 67 20 a9`) on
the front panel, and prints `"\r\n>:"` on `UART1`.
"""
import os
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for, resolve_dump

DUMP = "flash ECHOLINK EL700FTA mx29lv160.bin"
MAINCODE_DATA = 0x10080
EXPECTED_CHALLENGE = bytes.fromhex("92d07c93b874f7d5")
MAX_VTIME_S = 45.0
SLICE_INSTRUCTIONS = 200_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


class Smtm51StandIn:
    """Link-layer stand-in for `PAN_SMTM51_0` on `M3329` `UART2` (`0xB8001400`):
    verifies each `[cmd, len, payload..., checksum]` packet and sends the
    1-byte `0x80` link acknowledge over `UART2` RX without answering `0x0D`
    anti-clone key challenges."""

    def __init__(self, uart2):
        self.uart2 = uart2
        self._buf = bytearray()
        self.frames = []
        self.bad_checksums = 0

    def on_tx_byte(self, byte_val):
        self._buf.append(byte_val)
        if len(self._buf) >= 2:
            need = 2 + self._buf[1] + 1
            if len(self._buf) == need:
                pkt = bytes(self._buf)
                self._buf.clear()
                if (sum(pkt[:-1]) & 0xFF) == pkt[-1]:
                    self.frames.append(pkt)
                    self.uart2.receive(0x80)
                else:
                    self.bad_checksums += 1

    def panel_texts(self):
        return [f[3:-1].decode("latin-1") for f in self.frames
                if len(f) == 8 and f[0] == 0x05 and f[1] == 0x05 and f[2] == 0x33]


print(f"=== Echolink EL-700 FTA ({DUMP}): M3329C bootloader & PAN_SMTM51_0 security handshake ===")
image = open(resolve_dump(DUMP), "rb").read()
uart1 = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(lambda c: uart1.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(DUMP)
mcu = Smtm51StandIn(sim.chip.uart2)
sim.chip.uart2.tx_handler = mcu.on_tx_byte

check(type(sim.chip).__name__ == "M3329" and sim.chip.flash is not None,
      f"runs as M3329 with 8-bit parallel NOR flash attached ({type(sim.chip.flash).__name__})")
check(any(type(d).__name__ == "GpioI2cBus" for d in sim.gpio_devices),
      "the sidecar's gpioI2c bus (SCL 10 / SDA 9) is attached")
check(image[MAINCODE_DATA:MAINCODE_DATA + 4] == b"CODE"
      and struct.unpack_from(">I", image, MAINCODE_DATA + 4)[0] == 0x0007EBC9,
      "maincode chunk at 0x10080 carries Moresat \"CODE\" XTEA wrapper (0x7EBC9 bytes)")

while sim._vtime() < MAX_VTIME_S:
    if ">:" in "".join(uart1) and "upg " in mcu.panel_texts():
        break
    sim.run(max_instructions=sim.instruction_count + SLICE_INSTRUCTIONS,
            max_vtime=min(MAX_VTIME_S, sim._vtime() + 1.0))

uart_text = "".join(uart1)
texts = mcu.panel_texts()
challenges = [f for f in mcu.frames if f[:2] == b"\x0d\x0a"]
print(f"stopped at vtime {sim._vtime():.2f} s ({sim.instruction_count / 1e6:.1f} M instructions), "
      f"{len(mcu.frames)} UART2 frames, panel texts {texts!r}")

check(b"PAN_SMTM51_0" in bytes(sim.peek(0x80300000, 0x24000))
      and len(sim.lzma_decodes) == 0 and not any(sim.peek(0x80000200, 64)),
      f"bootloader unpacks to 0x80300000 (PAN_SMTM51_0 live) and aborts maincode LzmaDecode() cleanly "
      f"(lzma_decodes={len(sim.lzma_decodes)})")
check(sim.chip.uart2.dll == 12 and sim.chip.uart2.lcr == 0x03 and (sim.chip.uart2.ier & 0x01) == 0x01,
      f"SCI_16550_1 (0xB8001400) configured for 9600 8N1 with RX interrupt enabled "
      f"(dll={sim.chip.uart2.dll}, lcr=0x{sim.chip.uart2.lcr:02X}, ier=0x{sim.chip.uart2.ier:02X})")
check(mcu.bad_checksums == 0 and len(mcu.frames) >= 8,
      f"every PAN_SMTM51_0 UART2 frame carries a valid checksum ({len(mcu.frames)} frames, {mcu.bad_checksums} bad)")
check(" on " in texts and "upg " in texts and texts.index(" on ") < texts.index("upg "),
      f"front panel transitions from ' on ' to 'upg ' ({texts})")
check(len(challenges) == 4 and all(f[2:4] == b"\x00\x00" and f[4:12] == EXPECTED_CHALLENGE for f in challenges),
      f"bootloader sends 4 XTEA-key challenge requests carrying {EXPECTED_CHALLENGE.hex()} (got {len(challenges)})")
check(">:" in uart_text,
      f"without the MCU's secret key reply, enters RS-232 recovery prompt '>:' on UART1 ({uart_text!r})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Echolink EL-700 FTA bootloader completes PAN_SMTM51_0 handshake & RS-232 recovery fallback")
