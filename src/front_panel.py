"""
Front panels of the firmware dumps: which LED-driver chip sits on which
bit-banged GPIO pins, and what its key-matrix positions do (found by pressing
them in the simulator).  tv_gui.py and the run scripts get a dump's panel
decoder from make_panel(); the decoders (tm1650_decoder.py, tm1628_decoder.py)
follow the firmware's GPIO writes and answer its key reads.

  * TM1650 (I2C: SCL, SDA): Opticum STB HD N2 (dump_maciej.bin) and Globo STB
    HD N3 -- SCL = GPIO 31, SDA = GPIO 9; the panel driver reacts to the key
    matrix positions KI1/DIG4 (up) and KI2/DIG4 (down).  The Ferguson Ariva
    T650i's FD650K is TM1650-compatible on the same pins, with its own digit
    order and segment wiring and eight keys on DIG1 / DIG2 of KI4..KI7 (the
    T750i's and T760i's the same, on other pins).  The Opticum Blue R265 Lite
    (M3822P, the M3821 family) has an HD2015 -- TM1650-compatible too -- on
    SCL = GPIO 57, SDA = GPIO 58 (bank 0xB80000D4 bits 25 / 26); its firmware
    writes " ON " at boot.
    The 2005 M3329 board's chip sits on SCL = GPIO 15, SDA = GPIO 16; its
    driver acts on a key held for several polls.
  * TM1628-class (3-wire: CLK, DIO, STB): Cabletech URZ0083Q (PCB
    6390-M3801) and the Strong SRT 8115 (MC6422-M3801) -- CLK = GPIO 31, DIO =
    GPIO 9, STB = GPIO 11; their digits in RAM 0, 2, 4, 6 with their own
    segment wiring (" ON " at boot, "noCH" without channels); the
    Cabletech's panel driver reacts to KS9/K1 (down), KS9/K2 (up) and
    KS10/K1 (power -> standby, "oFF "), the Strong's to the same three with
    up and down swapped.  The Cabletech URZ0195 has a
    uPD16312-class chip on the same bus with STB = GPIO 14, its digits in
    grids 4, 2, 3, 1 with their own segment wiring (" ON ", "----", then the
    channel number "0004"); its firmwares' key maps have no panel keys.  The
    Ferguson Ariva 52E's PT6964 sits on CLK = GPIO 65, DIO = GPIO 66, STB =
    GPIO 64 (its segment wiring is not known).
  * Buttons straight on GPIO inputs, no chip and no display (gpio_keys.py):
    the Strong Prima VIII -- GPIO 31 (channel up) and 9 (channel down),
    pulled up, low while pressed.

A dump that matches no entry gets the TM1650 on GPIO 31 / 9 (a board without
one shows a blank display and ignores the keys).
"""
import os

from gpio_keys import GpioKeys
from hc164_decoder import HC164Decoder
from lemontree_decoder import LemontreeDecoder
from tm1628_decoder import TM1628Decoder
from tm1650_decoder import TM1650Decoder

# Opticum Blue R265 Lite (M3822P): an HD2015 -- TM1650-compatible -- on GPIO bank 1 (0xB80000D4),
# SCL = GPIO 57, SDA = GPIO 58; no display is soldered on this box, the chip only scans its three
# buttons, but the firmware still writes " ON " at boot and its application "noCH" (digits in the
# standard layout).  The application drives the bus open-drain (tm1650_decoder.py) and polls the
# keys: KI1/DIG4 and KI7/DIG4 step the home menu's highlight (one down, the other -- presumably
# up -- wrapping round to the same tile of its two-row column), KI2/DIG4 is power (standby,
# "oFF "); the other 25 positions do nothing there.  Both the flash dump (M3822P.bin) and the
# update images (T2GEN265_*.abs) are this board.
_R265_LITE = dict(chip="tm1650", scl=57, sda=58, labels={(1, 4): "▼", (7, 4): "▲", (2, 4): "PWR"})

# The Ferguson Ariva T650i / T750i / T760i panel (an FD650K): eight keys on DIG1 / DIG2 of rows
# KI4..KI7, which their PAN_FD650K driver turns into the panel codes 0xFFFF0001..80 their UIs map
# -- KI4/DIG1 0x02 down, KI4/DIG2 0x40 exit, KI5/DIG1 0x10 left, KI5/DIG2 0x80 menu, KI6/DIG1 0x08
# right, KI6/DIG2 0x04 power, KI7/DIG1 0x01 up, KI7/DIG2 0x20 OK (read off the driver's switch on
# the key byte; on the T750i's wizard right steps the Region value, exit leaves the wizard for its
# channel-editing menu, down moves that menu's highlight)
_FERGUSON_KEYS = {(4, 1): "▼", (4, 2): "EXIT", (5, 1): "◀", (5, 2): "MENU", (6, 1): "▶", (6, 2): "PWR",
                  (7, 1): "▲", (7, 2): "OK"}


def _fd650k(scl, sda):
    return dict(chip="tm1650", scl=scl, sda=sda, digit_order=(2, 3, 1, 0),
                seg_map=(1, 5, 6, 0, 7, 2, 4, 3), labels=_FERGUSON_KEYS)

# (substring of the dump's path, case-insensitive) -> panel spec
PANELS = [
    ("dump_maciej", dict(chip="tm1650", scl=31, sda=9, labels={(1, 4): "▲", (2, 4): "▼"})),
    # the Globo STB HD N3 dump ("Ali_3801_Globo_DVBT_dump SPI 4mb.bin"; the Globo HD-XS2 is another board)
    ("Ali_3801_Globo", dict(chip="tm1650", scl=31, sda=9, labels={(1, 4): "▲", (2, 4): "▼"})),
    # the official Opticum / Globo update for the HD T90, STB HD N2 and N3: the same boards
    ("T90", dict(chip="tm1650", scl=31, sda=9, labels={(1, 4): "▲", (2, 4): "▼"})),
    # keys found on its first-install wizard: KS9/K1 = down, KS9/K2 = up, KS10/K1 = power
    # (standby: the panel shows "oFF "); the other 17 positions do nothing there
    ("URZ0083Q", dict(chip="tm1628", clk=31, dio=9, stb=11, digit_addrs=(0, 2, 4, 6),
                      seg_map=(4, 2, 0, 6, 7, 3, 1, 5),
                      labels={(9, 1): "▼", (9, 2): "▲", (10, 1): "PWR"})),
    # its bootloader prints "stb: 14 clock: 31 data: 9 / nec 16312 attach ok / digit: 4 seg: 16":
    # a uPD16312 / PT6312-class driver with the same 3-wire command set.  Its 4 digits are the
    # low bytes of grids 4, 2, 3, 1 (RAM 6, 2, 4, 0) with their own segment wiring -- read off the
    # 2012 firmware's font table ('0' = 0xEE, '4' = 0x87, '-' = 0x01) and its texts: " ON " at
    # boot, "----" while it tunes, then the channel number ("0004"), "oFF " in standby; the 2013
    # firmware has the same font and digits ("0005").  No panel key can do anything on either: their
    # UIs' key maps (58 entries each) hold remote keys only, not one panel code (and all 40 key
    # bits pressed on the 2012 firmware's live-TV screen changed nothing).
    ("URZ0195", dict(chip="tm1628", clk=31, dio=9, stb=14, digit_addrs=(6, 2, 4, 0),
                     seg_map=(3, 7, 1, 5, 6, 2, 0, 4), labels={})),
    # Cabletech URZ0194S: the URZ0083Q's bootloader build, remote (same wake code) and panel bus,
    # but its digits use the standard segment layout (" ON ", "----", "noCH" come out as is) and
    # its keys differ (found on its wizard): KS7/K1 = left and KS9/K1 = right step the highlighted
    # value, KS8/K1 = menu (its main menu opens), KS8/K2 = down, KS9/K2 = power (standby "oFF ")
    ("urz0194", dict(chip="tm1628", clk=31, dio=9, stb=11, digit_addrs=(0, 2, 4, 6),
                     labels={(7, 1): "◀", (9, 1): "▶", (8, 1): "MENU", (8, 2): "▼", (9, 2): "PWR"})),
    # Strong SRT 8115 (MC6422-M3801): the Cabletech URZ0083Q's panel -- the same 3-wire bus and
    # pins (GPIO 31 clocks, 9 carries the data, 11 strobes), digits in RAM 0, 2, 4, 6 with the same
    # segment wiring (its font table is the URZ0083Q's byte for byte: '0' = 0xDD, '1' = 0x05,
    # '-' = 0x02), RAM 1 and 11 indicator LEDs: " ON " from the bootloader, "----" from the
    # application.  Its panel code reads 5 key bytes, takes the first that is neither 0 nor 0x3F
    # and looks it up in a table of {value, code, byte index} (0x8052EB78): byte 4 = 1 (KS9/K1)
    # up, 2 (KS9/K2) down, 8 (KS10/K1) power -- the URZ0083Q's table has up and down the other
    # way round, as its keys were found by pressing them
    ("srt8115", dict(chip="tm1628", clk=31, dio=9, stb=11, digit_addrs=(0, 2, 4, 6),
                     seg_map=(4, 2, 0, 6, 7, 3, 1, 5),
                     labels={(9, 1): "▲", (9, 2): "▼", (10, 1): "PWR"})),
    # Ferguson Ariva 52E (M3606-class, bootloader "HSJ2"): its drivers are named PAN_PT6964_0, a
    # TM1628-class 3-wire chip, which its bootloader drives on GPIO bank 2 (0xB80000F4) bits 0..2:
    # STB = GPIO 64, CLK = GPIO 65, DIO = GPIO 66 (found from its pin toggles, 2026-10-31).  The
    # bootloader writes RAM 2-3 (0x13 0x03) and 6-7 (0x33 0x03); which segments those are is not
    # known (the application, which has the font, never runs: its main code is decrypted by the
    # board's security IC, see the sidecar), so the digits come out as "?" in the standard layout.
    ("A52E_", dict(chip="tm1628", clk=65, dio=66, stb=64, digit_addrs=(0, 2, 4, 6), labels={})),
    ("A102E_", dict(chip="tm1628", clk=38, dio=40, stb=39, digit_addrs=(0, 2, 4, 6), labels={})),
    # Ferguson Ariva T650i: an FD650K ("PAN_FD650K"), TM1650-compatible, on the usual pins; its
    # digits are registers 0x6C, 0x6E, 0x6A, 0x68 from the left and its segments a..g, DP sit on
    # bits 1, 5, 6, 0, 7, 2, 4, 3 (read off the font table its application builds in RAM:
    # '0' = 0xEF, '1' = 0x60, '8' = 0xF7, '-' = 0x10): " On " from the bootloader, "Strt"
    # when the application starts
    ("T650i", _fd650k(31, 9)),
    # Ferguson Ariva T750i / T760i (the M3821 generation): the T650i's FD650K and digit layout on
    # other pins -- the T750i's on GPIO bank 4 (0xB8000454), SCL = GPIO 128 (bit 0, always an
    # output), SDA = GPIO 129 (bit 1, switched to an input for the chip's answers); the T760i's on
    # bank 3 (0xB8000354), SCL = GPIO 107, SDA = GPIO 110.  Both write " On " from the
    # bootloader, the T750i " on ", "Strt" and "Find" from its application.  All three Fergusons'
    # PAN_FD650K drivers switch on the key byte (key - 0x5C, a jump table: _FERGUSON_KEYS)
    ("T750i", _fd650k(128, 129)),
    ("T760i", _fd650k(107, 110)),
    ("A104_", _fd650k(107, 110)),
    ("A204_", _fd650k(107, 108)),
    ("A154", _fd650k(107, 108)),
    ("A254", _fd650k(107, 108)),
    ("254Combo", _fd650k(107, 108)),
    ("A255", _fd650k(107, 108)),
    ("255combo", _fd650k(107, 108)),
    # GTMedia V9 Super (128 MB M3505 / C3505): FD650_0 ("PAN_FD650_0") on GPIO bank 3, SCL = GPIO 107,
    # SDA = GPIO 110, digits 0x6E, 0x6C, 0x6A, 0x68 from the left and segments a..g, DP on bits
    # 0, 6, 4, 2, 1, 7, 5, 3 (read off its font table at mc+0x7F5A06: '0'=0xD7, '1'=0x50, 'b'=0xB6,
    # 'o'=0x36, 't'=0xA6 -> "boot")
    ("V9Super", dict(chip="tm1650", scl=107, sda=110, digit_order=(3, 2, 1, 0),
                     seg_map=(0, 6, 4, 2, 1, 7, 5, 3), labels=_FERGUSON_KEYS)),
    ("V9_Super", dict(chip="tm1650", scl=107, sda=110, digit_order=(3, 2, 1, 0),
                      seg_map=(0, 6, 4, 2, 1, 7, 5, 3), labels=_FERGUSON_KEYS)),
    # Ferguson Ariva 54 (the C3503D, chips/c3503.py): the same FD650K and layout on GPIO bank 0
    # (0xB8000054), SCL = GPIO 24, SDA = GPIO 23 (" On ", " on ", "nenu" on its external IR/LED
    # eye; the Ariva 53's board_cfg leaves its panel I2C attach pointer NULL -- no display)
    ("A54_", _fd650k(24, 23)),
    ("PICCO_S2", dict(chip="tm1650", scl=24, sda=23, labels={})),
    ("AMIKO_Mira2_wifi", dict(chip="tm1650", scl=24, sda=23, labels={})),
    ("MIRA WIFI 2", dict(chip="tm1650", scl=24, sda=23, labels={})),
    ("MIRA2 WIFI", dict(chip="tm1650", scl=24, sda=23, labels={})),
    ("underline.3in1", dict(chip="tm1650", scl=31, sda=9, labels={})),
    ("underline_3in1", dict(chip="tm1650", scl=31, sda=9, labels={})),
    ("AMIKO_HD8140_", dict(chip="tm1650", scl=31, sda=9, labels={})),
    # Amiko HD8155 (128 MB C3505) and HD8265+ (256 MB C3505): a CH455 ("---led 455 attach OK--"),
    # TM1650-compatible in the standard digit and segment layout (" ON " from the bootloader,
    # " on " from the application), on GPIO bank 3 (0xB8000354) -- SCL = GPIO 107, SDA = GPIO 110
    # on the HD8155; SCL = GPIO 107, SDA = GPIO 108 on the HD8265+
    ("8155", dict(chip="tm1650", scl=107, sda=110, labels={})),
    ("Amiko_Mini_HD265", dict(chip="tm1650", scl=107, sda=110, labels={})),
    ("MINI HD265", dict(chip="tm1650", scl=107, sda=110, labels={})),
    ("mini265", dict(chip="tm1650", scl=107, sda=110, labels={})),
    ("piccollino_S2+T2C", dict(chip="tm1650", scl=107, sda=110, labels={})),
    ("Impluse_H265", dict(chip="tm1650", scl=107, sda=110, labels={})),
    ("Mini_Combo_Extra", dict(chip="tm1650", scl=107, sda=110, labels={})),
    ("MINI COMBO EXTRA", dict(chip="tm1650", scl=107, sda=110, labels={})),
    ("_combo_EXTRA", dict(chip="tm1650", scl=107, sda=110, labels={})),
    ("Piccollino_S2_v.", dict(chip="tm1650", scl=107, sda=110, labels={})),
    ("AMIKO 8265", dict(chip="tm1650", scl=107, sda=108, labels={})),
    ("8265", dict(chip="tm1650", scl=107, sda=108, labels={})),
    ("HD8275_", dict(chip="tm1650", scl=107, sda=108, labels={})),
    ("Amiko_HD8255", dict(chip="tm1650", scl=107, sda=108, labels={})),
    ("HD8140C_SE", dict(chip="tm1650", scl=107, sda=108, labels={})),
    ("HD8142_Twin-C", dict(chip="tm1650", scl=107, sda=108, labels={})),
    ("piccollo_S2+T2C", dict(chip="tm1650", scl=107, sda=108, labels={})),
    # Amiko X-Finder 3 (256 MB M3529F / C3505 handheld meter with built-in TFT LCD): no 4-digit LED
    # display is fitted (the generic M3529F bootloader probes 107/110), while maincode's
    # panel_ch455_task enables CH455 (0x48 = 0x01) and scans the meter's keypad on GPIO 107 / 108
    ("AMIKO_XFinder_III", dict(chip="tm1650", scl=107, sda=108, labels={})),
    # Amiko T58 (4 MB SPI, single-CPU M3821) and Amiko Eco TC-200 (8 MB SPI, dual-CPU M3821A): CH455
    # (PAN_CH455_0) on GPIO bank 4, SCL = GPIO 128, SDA = GPIO 129 (" ON " -> " on ")
    ("AMIKO_T58", dict(chip="tm1650", scl=128, sda=129, labels={})),
    ("AMIKO_ECO_TC-200", dict(chip="tm1650", scl=128, sda=129, labels={})),
    ("AMIKO_Impulse_T2C", dict(chip="tm1650", scl=128, sda=129, labels={})),
    ("AMIKO_Impluse_T2C", dict(chip="tm1650", scl=128, sda=129, labels={})),
    # Amiko HD8260+ (16 MB SPI, 256 MB M3516A / M3503) and Amiko Impulse SAT (8 MB SPI, 128 MB
    # M3510B / M3503): a CH455 ("CH455 panel init OK!") on GPIO bank 4 (0xB8000454), SCL = GPIO 135,
    # SDA = GPIO 134 (" ON " -> " on ")
    ("8260_Edision", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("AMIKO_HD8260", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("8260", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("piccollo_3in1_PLUS_CI", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("14000A00", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("Impulse_SAT", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("AMIKO_HD8150", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("MicroHD SE", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("MicroHD_SE", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("MICRO HD SE", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("STC3220", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("Piccollino_v.", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("AMIKO_MiniComboHD_SE", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("AMIKO_HD8270", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("AMIKO_CHD8270", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("AMIKO_MiniHD_RE", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("AMIKO_MiniHD_SE", dict(chip="tm1650", scl=135, sda=134, labels={})),
    ("AMIKO_XFinder_Plus", dict(chip="tm1650", scl=135, sda=134, labels={})),
    # Opticum HD X4 220 (M3602B "Lemontree"): external front-panel and EuP standby MCU at I2C 0x28
    # on SCL = GPIO 62 (0x0D4 bit 30), SDA = GPIO 171 (legacy third bank 0x0E8 bit 11), speaking
    # 8-byte CRC-16/XMODEM frames (" ON " -> "    " -> " on " -> "tUnE")
    ("OPTICUM_HD_X4", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("Opticum HD X402p-403p", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("Opticum_HD-X402p-403p", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("opticum_x4", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("ALI3602_060", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("ALI3602_globo", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("amstar_yumatu", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("globo_x4", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("globo_x7", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("synaps_galaxy_1.5", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("xwindow_gm", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("synaps_dynavision", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("lemontree_proton", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("iltv_1.5.", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("AMIKO_STHD-8800", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("AMIKO_SHD-7900-8000", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("amiko_220_", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("amiko_300_", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("Opticum_HD_x7", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("Optixum_HD_X7", dict(chip="lemontree", scl=62, sda=171, labels={})),
    ("Edision.vip3", dict(chip="lemontree", scl=103, sda=102, labels={})),
    ("Edision.miniplus.highspeed", dict(chip="lemontree", scl=103, sda=102, labels={})),
    ("AMIKO_SHD-8360", dict(chip="lemontree", scl=103, sda=102, labels={})),
    ("AMIKO_HD8840", dict(chip="lemontree", scl=103, sda=102, labels={})),
    ("AMIKO_HD8300", dict(chip="lemontree", scl=103, sda=102, labels={})),
    ("AMIKO_STHD-8820", dict(chip="lemontree", scl=103, sda=102, labels={})),
    ("amiko_0A010A00", dict(chip="lemontree", scl=103, sda=102, labels={})),
    ("amiko_0A050A00", dict(chip="lemontree", scl=103, sda=102, labels={})),
    ("amiko_0A040A00", dict(chip="lemontree", scl=44, sda=43, labels={})),
    ("AMIKO_HD8200", dict(chip="lemontree", scl=44, sda=43, labels={})),
    # Amiko X-Finder 2 (M3516A / M3503 handheld meter): bootloader drives CH455 (" ON ") on GPIO 135/134,
    # application drives the handheld meter's Lemontree-protocol MCU at I2C 0x28 on the same bus
    ("AMIKO_XFinder2", dict(chip="lemontree", scl=135, sda=134, labels={})),
    ("M3822P", _R265_LITE),
    ("T2GEN265", _R265_LITE),
    # Opticum X110TS and X110p (the C3603): a TM1650-compatible chip on SCL = GPIO 9, SDA = GPIO 8 -- " ON "
    # from the bootloader, "Strt" and the channel number ("OOO1") from the application (with its
    # LNB fault line not pulled up -- the sidecar's gpioPullUps -- it showed "LnbP" instead).  Its
    # panel code maps three DIG4 positions (a {code, key byte} table in its main code): KI1/DIG4
    # down, KI2/DIG4 power, KI3/DIG4 up -- held for two reads, a key steps twice
    ("X110TS", dict(chip="tm1650", scl=9, sda=8, labels={(1, 4): "▼", (2, 4): "PWR", (3, 4): "▲"})),
    ("X110p", dict(chip="tm1650", scl=9, sda=8, labels={(1, 4): "▼", (2, 4): "PWR", (3, 4): "▲"})),
    # Globo HD-XS2 (both builds): on GPIO bank 4, SCL = GPIO 135, SDA = GPIO 134 -- " ON " from the
    # bootloader, " on " from the application; its UI's key map has three panel keys (codes 0xFF04,
    # 0xFF02, 0xFF01): KI1/DIG4 power (standby, "oFF "), KI2/DIG4 up and KI3/DIG4 down -- they move
    # the Reta image's language list; the SmartHD main menu's row of tiles takes neither
    ("HD-XS2", dict(chip="tm1650", scl=135, sda=134, labels={(1, 4): "PWR", (2, 4): "▲", (3, 4): "▼"})),
    ("M3515-COMBO", dict(chip="tm1650", scl=135, sda=134, labels={(1, 4): "PWR", (2, 4): "▲", (3, 4): "▼"})),
    ("140_TWIN", dict(chip="tm1650", scl=135, sda=134, labels={(1, 4): "PWR", (2, 4): "▲", (3, 4): "▼"})),
    # Echosonic Mini ESR-250 (M3510A, the M3503 family): the HD-XS2's pins, SCL = GPIO 135, SDA =
    # GPIO 134 (bank 4 bits 7 / 6 toggle) -- "__-_", "___-", "-ON-" while it starts, then "Strt"
    # from the application.  Its UI's key map holds the raw key bytes as panel
    # codes (0xFF44 ...), two sets of seven: DIG1 of KI1..KI7 -- up, down, OK, menu, right, left,
    # power -- and the same keys on DIG2 / DIG3 positions
    ("ESR-250", dict(chip="tm1650", scl=135, sda=134,
                     labels={(1, 1): "▲", (2, 1): "▼", (3, 1): "OK", (4, 1): "MENU", (5, 1): "▶", (6, 1): "◀",
                             (7, 1): "PWR"})),
    # UNI S60: SCL = GPIO 62, SDA = GPIO 63; the bootloader blanks the digits, the application
    # writes " ON ".  Its panel code (0x801639F4) reads the key byte every 100 ms and looks it up in
    # a table of seven DIG4 positions (0x8044375C), of which its UI's key map takes three: KI1/DIG4
    # up, KI2/DIG4 power, KI3/DIG4 down (their codes 0xFFFF0010 / 40 / 02)
    ("_S60_", dict(chip="tm1650", scl=62, sda=63, labels={(1, 4): "▲", (2, 4): "PWR", (3, 4): "▼"})),
    ("S16_", dict(chip="tm1650", scl=62, sda=63, labels={(1, 4): "▲", (2, 4): "PWR", (3, 4): "▼"})),
    # Strong Prima VIII (MC6501-M3801, the GD25Q32B flash dump): two buttons straight on GPIO 31
    # and 9, polled by its application, which sends them on as the panel keys 0xFFFF0001 / 0002
    # (its CH455 driver, "PAN_CH455_0", sits on a software I2C bus with no pins: GPIO 127)
    ("PRIMA VIII", dict(chip="gpio_keys", keys=(31, 9), labels={31: "CH+", 9: "CH-"})),
    # Comsat TE 1050 HD (dump.bin): the same SDK key task on the same pins -- GPIO 31 sends its
    # virtual key 12 (UP), GPIO 9 its 13 (DOWN)
    ("dump.bin", dict(chip="gpio_keys", keys=(31, 9), labels={31: "UP", 9: "DOWN"})),
    # the M3329 board s15125 (chips/m3329.py): a TM1650-compatible chip on SCL = GPIO 15, SDA =
    # GPIO 16, driven by its "pan bin" chunk's code (unpacked to 0xA01FA000) -- "  --" from the
    # bootloader, then the channel number ("0037"); its panel key map (0x8003E0AC) has the seven
    # DIG4 positions: KI1 down, KI2 up, KI3 OK, KI4 menu, KI5 left, KI6 right, KI7 power
    ("ali3329-s15125", dict(chip="tm1650", scl=15, sda=16,
                            labels={(1, 4): "▼", (2, 4): "▲", (3, 4): "OK", (4, 4): "MENU", (5, 4): "◀",
                                    (6, 4): "▶", (7, 4): "PWR"})),
    # Opticum X80 Premium (M3329C / M3101C, 2 MB SPI): CH455 / TM1650 on SCL = GPIO 30, SDA = GPIO 31
    # (" on " -> "----" -> "OOO1")
    ("x80 premium", dict(chip="tm1650", scl=30, sda=31, labels={})),
    # Opticum 7300 PVR CI2CX (M3329E, 4 MB SPI): PT6312 / uPD16312 8-grid 14-segment VFD
    # (PAN_pt6312_0) on CLK = GPIO 3, DIO = GPIO 2, STB = GPIO 4 ("  BOOT  " -> "   ON   " -> "1PLUS1  ")
    ("7300PVR", dict(chip="tm1628", clk=3, dio=2, stb=4, vfd_14seg=True, labels={})),
    # BigSat DSR 6500 Lux (M3329, 2 MB MX29LV160B parallel NOR): PAN_COMMON_0 74HC164 shift register
    # on CLK = GPIO 16, DATA = GPIO 17 with 4 active-low digit strobes on GPIO 18..21 (" ON " -> "----")
    ("bigsat 6500", dict(chip="hc164", clk=16, data=17, digits=(18, 19, 20, 21), labels={})),
    # Opticum 4000A / Globo 7010A (M3329, 2 MB MX29LV160B parallel NOR): the same PAN_COMMON_0 74HC164
    # shift register on CLK = GPIO 16, DATA = GPIO 17, digits GPIO 18..21 (" ON " -> "1737" / "OOO1")
    ("Opticum4000a", dict(chip="hc164", clk=16, data=17, digits=(18, 19, 20, 21), labels={})),
    # BigSat DSR 7035 Plus (M3329, 2 MB M29W160ET parallel NOR): PAN_COMMON_0 74HC164 shift register
    # on CLK = GPIO 0, DATA = GPIO 1 with 4 active-low digit strobes on GPIO 2, 3, 5, 6 and custom
    # segment wiring (" ON " -> "Strt" -> "noCH")
    ("bigsat 7035", dict(chip="hc164", clk=0, data=1, digits=(2, 3, 5, 6),
                         seg_map=(4, 6, 1, 2, 3, 5, 0, 7), labels={})),
]
DEFAULT = dict(chip="tm1650", scl=31, sda=9, labels={})

# 7-segment geometry of one digit for drawing a display (tv_gui.py's canvas,
# report.py's SVG): bit 0..6 = a (top), b, c, d (bottom), e, f, g (middle) as
# polygons in a 26 x 48 box; bit 7 = DP, a dot at (27, 43).
SEG_POLYS = {
    0: [(3, 0), (19, 0), (17, 3), (5, 3)],
    1: [(20, 1), (23, 4), (23, 18), (20, 21), (18, 18), (18, 4)],
    2: [(20, 23), (23, 26), (23, 40), (20, 43), (18, 40), (18, 26)],
    3: [(3, 44), (19, 44), (17, 41), (5, 41)],
    4: [(0, 23), (3, 26), (3, 40), (0, 43), (-2, 40), (-2, 26)],
    5: [(0, 1), (3, 4), (3, 18), (0, 21), (-2, 18), (-2, 4)],
    6: [(3, 22), (19, 22), (17, 24), (5, 24), (3, 22), (5, 20), (17, 20), (19, 22)],
}


def panel_spec(dump):
    """The panel spec of a dump (file name or path)."""
    try:
        import dump_catalog
        if dump_catalog.has_override(dump):
            sc = dump_catalog.load(dump)
            if sc and sc.get("file"):
                fname = sc["file"].lower()
                for pattern, spec in PANELS:
                    if pattern.lower() in fname:
                        return spec
    except Exception:
        pass
    name = os.path.normpath(dump).lower()
    for pattern, spec in PANELS:
        if pattern.lower() in name:
            return spec
    return DEFAULT


def make_panel(dump, log_handler=None):
    """(decoder, keys, description) for a dump's front panel: the decoder to
    attach with sim.setGpioHandler(decoder.on_gpio_write), its key matrix as
    [(label, code)] for decoder.press_key(code), and a one-line description."""
    spec = panel_spec(dump)
    labels = spec.get("labels", {})
    if spec["chip"] == "gpio_keys":
        dec = GpioKeys(spec["keys"], log_handler=log_handler)
        keys = [(labels.get(pin, f"GPIO {pin}"), GpioKeys.key_code(pin)) for pin in spec["keys"]]
        desc = "buttons on GPIO " + " / ".join(str(pin) for pin in spec["keys"]) + ", no display"
    elif spec["chip"] == "hc164":
        digits = tuple(spec.get("digits", (18, 19, 20, 21)))
        dec = HC164Decoder(clk_gpio=spec["clk"], data_gpio=spec["data"], digit_gpios=digits,
                           seg_map=spec.get("seg_map", HC164Decoder.STANDARD_SEG_MAP),
                           active_low_segments=spec.get("active_low_segments", True),
                           active_low_digits=spec.get("active_low_digits", True),
                           log_handler=log_handler)
        keys = []
        desc = (f"74HC164 shift register on CLK {spec['clk']} / DATA {spec['data']}, "
                f"digits GPIO {'/'.join(str(d) for d in digits)}")
    elif spec["chip"] == "lemontree":
        dec = LemontreeDecoder(scl_gpio=spec["scl"], sda_gpio=spec["sda"], log_handler=log_handler,
                               digit_order=spec.get("digit_order", (0, 1, 2, 3)),
                               seg_map=spec.get("seg_map", LemontreeDecoder.LEMONTREE_SEG_MAP))
        keys = [(label, LemontreeDecoder.key_code(code)) for code, label in sorted(labels.items())]
        desc = f"Lemontree EuP MCU (I2C 0x28) on SCL {spec['scl']} / SDA {spec['sda']}"
    elif spec["chip"] == "tm1628":
        dec = TM1628Decoder(clk_gpio=spec["clk"], dio_gpio=spec["dio"], stb_gpio=spec["stb"],
                            digit_addrs=spec.get("digit_addrs", (0, 2, 4, 6)),
                            seg_map=spec.get("seg_map", TM1628Decoder.STANDARD_SEG_MAP),
                            vfd_14seg=spec.get("vfd_14seg", False),
                            log_handler=log_handler)
        keys = [(labels.get((ks, k), f"{ks}-{k}"), TM1628Decoder.key_code(ks, k))
                for ks in range(1, 11) for k in (1, 2)]
        desc = f"TM1628 on CLK {spec['clk']} / DIO {spec['dio']} / STB {spec['stb']}, keys KS1-10 × K1-2"
    else:
        dec = TM1650Decoder(scl_gpio=spec["scl"], sda_gpio=spec["sda"], log_handler=log_handler,
                            digit_order=spec.get("digit_order", (0, 1, 2, 3)),
                            seg_map=spec.get("seg_map", TM1650Decoder.STANDARD_SEG_MAP))
        keys = [(labels.get((ki, dig), f"{ki}-{dig}"), TM1650Decoder.key_code(ki, dig, pressed=False))
                for ki in range(1, 8) for dig in range(1, 5)]
        desc = f"TM1650 on SCL {spec['scl']} / SDA {spec['sda']}, keys KI1-7 × DIG1-4"
    return dec, keys, desc
