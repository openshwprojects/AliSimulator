"""
Infrared remote control for the simulated receiver.

The ALi M36xx firmware reads its remote through the M6303 IR controller
(IRC, registers at 0xB8018100, interrupt-controller line 19 = OS IRQ 27):
the controller samples the IR receiver output and pushes run-length codes
into a FIFO -- one byte per run, bit 7 = line level, bits 6..0 = duration in
work-clock ticks (8 us: IRCCFG = 0x80 | 3).  Its interrupt service routine
(irc_m6303irc_lsr) drains the FIFO on a FIFO-threshold (ISR bit 0) or
idle-timeout (bit 1) interrupt; on the timeout it schedules generate_code,
which feeds the pulse widths to the NEC decoder (irc_nec_std.c).  The decoded
32-bit code becomes a pan_key that the UI maps to a virtual key through its
key table (g_itou_key_tab in control.c).

This module builds those RLC bytes for an NEC frame and finds the firmware's
own key table in RAM, so a key can be pressed by name ('UP', 'OK', ...).
The simulator side (FIFO, status, interrupt) is AliMipsSimulator.ir_send_nec /
press_key.
"""

TICK_US = 8                 # IRC work clock (IRCCFG = 0x83 in the firmware)

# NEC timings, microseconds
NEC_LEAD_MARK, NEC_LEAD_SPACE = 9000, 4500
NEC_BIT_MARK, NEC_ZERO_SPACE, NEC_ONE_SPACE = 560, 560, 1690

# Virtual keys (OSD_VKEY_t, inc/api/libosd/osd_vkey.h); the first 17 are the
# ones every UI needs.  Aliases map to the same value.
VKEYS = {
    '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
    'LEFT': 10, 'RIGHT': 11, 'UP': 12, 'DOWN': 13, 'ENTER': 14, 'OK': 14,
    'MENU': 15, 'EXIT': 16, 'BACK': 16, 'POWER': 17, 'MUTE': 18, 'PAUSE': 19,
    'TVRADIO': 20, 'RECALL': 21, 'AUDIO': 22, 'AUDIOCH': 23, 'ZOOM': 24, 'HELP': 25,
    'SIGNAL': 26, 'INFO': 27, 'PRO_INFOR': 28, 'DVR_INFOR': 29, 'TIMER': 30, 'LANGUAGE': 31,
    'CH+': 32, 'CH-': 33, 'VOL+': 34, 'VOL-': 35, 'PAGE+': 36, 'PAGE-': 37,
    'FAV+': 38, 'FAV-': 39, 'EPG': 40, 'TEXT': 41, 'SUBTITLE': 42, 'FAV': 43, 'SAT': 44,
    'TVSAT': 45, 'RGBCVBS': 46, 'SLEEP': 47, 'FIND': 48, 'LIST': 49, 'MP': 50,
    'RED': 51, 'GREEN': 52, 'YELLOW': 53, 'BLUE': 54,
}

# A firmware built from another SDK generation numbers its virtual keys
# differently.  When a name's VKEYS value is not in the firmware's key table,
# press_key() tries these instead (found by pressing every code of the
# dump_maciej table on its wizard: 29 opens the "info" help text; 19 is its
# POWER, which puts the box into standby that the simulator cannot wake, so it
# is deliberately not listed).
# The Strong Prima VIII's firmware (Libcore 8.32) numbers its EPG key 42 (its table
# has no 40; 42 opened its EPG grid once), its EXIT is 16 as usual, its 15 does nothing.
VKEY_FALLBACKS = {'INFO': (29,), 'EPG': (42,)}

PAN_KEY_TYPE_REMOTE = 1
PAN_KEY_PRESSED = 1


def _runs(level, us):
    """RLC bytes for one line level held for `us` microseconds (a run longer
    than 127 ticks takes several bytes of the same level)."""
    ticks = max(1, round(us / TICK_US))
    out = []
    while ticks > 0:
        n = min(ticks, 0x7F)
        out.append((0x80 if level else 0) | n)
        ticks -= n
    return out


def nec_rlc(address, command, address_hi=None):
    """IRC FIFO bytes of an NEC frame: leader, address, ~address (or the
    high address byte of extended NEC), command, ~command -- each byte LSB
    first -- and the stop mark.  Marks are level 0 (the receiver output is
    active low), spaces level 1; the idle after the frame ends it through
    the controller's timeout."""
    a2 = (~address & 0xFF) if address_hi is None else address_hi & 0xFF
    data = [address & 0xFF, a2, command & 0xFF, ~command & 0xFF]
    out = _runs(0, NEC_LEAD_MARK) + _runs(1, NEC_LEAD_SPACE)
    for byte in data:
        for bit in range(8):
            out += _runs(0, NEC_BIT_MARK)
            out += _runs(1, NEC_ONE_SPACE if (byte >> bit) & 1 else NEC_ZERO_SPACE)
    out += _runs(0, NEC_BIT_MARK)
    return bytes(out)


def _rev8(b):
    return int(f"{b & 0xFF:08b}"[::-1], 2)


def ir16_to_nec(ir16):
    """(address, command) of a key-table code.  The NEC decoder shifts the
    32 bits in as received (MSB first), so its code is rev8(address) << 24 |
    rev8(~address) << 16 | rev8(command) << 8 | rev8(~command) (NEC sends
    each byte LSB first).  This firmware's key_get_key() passes it on
    unchanged (the SDK sample's reverse_bit_order() is not there) and
    scan_code_to_msg_code() keeps (code >> 16 & 0xFF) << 8 | (code & 0xFF)
    as the 16-bit ir_code the key table holds: the high byte is
    rev8(~address), the low byte rev8(~command)."""
    return (~_rev8(ir16 >> 8)) & 0xFF, (~_rev8(ir16)) & 0xFF


# How a firmware's key table relates to the NEC frame bytes differs between
# SDK generations (found by sending a table's MENU code in every plausible
# form and watching the OSD, 2026-10-06):
#   nec    dump_maciej / Globo (Libcore 8.9 / 8.13): see ir16_to_nec above --
#          standard NEC, address = ~rev8(hi), command = ~rev8(lo)
#   ext00  Strong SRT 8115 (Libcore 8.7j), Strong Prima VIII (Libcore 8.32;
#          the flash dump and the update image "SRT_Prima_VIII_V1.0.6"), both
#          Cabletech URZ0195 firmwares (Libcore 8.1.0 and 8.1c: on the 2013
#          one, which had fallen to the default "nec", OK did nothing and DOWN
#          neither -- 2026-10-14), the Ferguson Ariva T650i, T750i and T760i
#          (the last two, on the default "nec", ignored DOWN on their
#          first-install wizards, whose countdown then started the channel
#          search; under "necfirst" too their DOWN moves the highlight) and the Comsat
#          TE 1050 HD (dump.bin; both Libcore 8.1c): extended NEC whose two
#          address bytes are both rev8(hi) (0x00 on the Strongs' remotes, 0x01
#          on the Cabletech's and the Ferguson's, 0xDF on the Comsat's),
#          command = ~rev8(lo) -- these decoders keep the frame's first address
#          byte as the table code's high byte (the Comsat looked a standard
#          NEC frame of its MENU, 0xFBDD, up as 0x04DD: ~0xFB); also the
#          M3601E firmwares (Libcore 5.0) of the Cabletech URZ0083, the
#          Kruger&Matz KM0183 and the Thomson THT501 (found on their
#          first-install wizards: DOWN moved the highlight only this way)
#   necfirst  the Echosonic ESR-250's 2015 firmware (an M3510A): standard NEC,
#          but its key conversion (0x8009C058) keeps (code >> 24) << 8 |
#          (code & 0xFF) -- the frame's first address byte where the older
#          SDKs keep the second (~address): address = rev8(hi), command =
#          ~rev8(lo).  Under "nec" its frames came out 0xFFxx and under
#          "ext00" (both address bytes the same) not at all.  Also the
#          Cabletech URZ0083Q (Libcore 8.1h) and URZ0194S (8.1j), whose NEC
#          decoder (the URZ0083Q's 0x80245734) checks no complement byte:
#          the MENU search of 2026-10-06 had settled on "address = hi,
#          command = lo", but their MENU, 0x0017, is the same frame both ways
#          (rev8(~0x17) = 0x17), and every other key's code came out wrong --
#          DOWN, 0x0037, as 0x0013 -- so only MENU (and OK, 0x000F) worked
#   cmd    the Ferguson Ariva T50 (Libcore 1.1.6): its table code is the low
#          half of the received code, rev8(command) << 8 | rev8(~command), with
#          no address byte; command = rev8(hi).  Its control task keeps a key
#          only when the code's high half is 0x803F (0x8000AD0C): extended NEC
#          with the address bytes 0x01, 0xFC -- with 0x00 every key was dropped
IR_CODINGS = [("dump_maciej", "nec"), ("Ali_3801_Globo", "nec"), ("T90", "nec"),
              ("srt8115", "ext00"), ("urz0195", "ext00"), ("PRIMA VIII", "ext00"), ("Prima_VIII", "ext00"),
              ("T650i", "ext00"), ("T750i", "ext00"), ("T760i", "ext00"),
              ("dump.bin", "ext00"), ("URZ0083_", "ext00"), ("KM00183", "ext00"), ("THT501", "ext00"),
              ("ESR-250", "necfirst"), ("UNI_S60", "necfirst"), ("URZ0083Q", "necfirst"), ("urz0194", "necfirst"),
              ("ArivaT50", "cmd")]


def coding_for(dump):
    """The IR coding of a dump (file name or path); 'nec' when unknown."""
    import os
    name = os.path.normpath(dump).lower()
    for pattern, coding in IR_CODINGS:
        if pattern.lower() in name:
            return coding
    return "nec"


def frame_from_ir16(ir16, coding="nec"):
    """(address, command, address_hi) of the NEC frame for a key-table code
    under `coding` (address_hi None = standard NEC, the second byte is ~address)."""
    hi, lo = ir16 >> 8, ir16 & 0xFF
    if coding == "ext00":
        return _rev8(hi), (~_rev8(lo)) & 0xFF, _rev8(hi)
    if coding == "necfirst":
        return _rev8(hi), (~_rev8(lo)) & 0xFF, None
    if coding == "cmd":
        return 0x01, _rev8(hi), 0xFC
    address, command = ir16_to_nec(ir16)
    return address, command, None


def find_key_table(ram, min_entries=12):
    """Find the UI's remote key table (struct ir_key_map_t {IR_KEY_INFO
    key_info; UINT32 ui_vkey;}) in a RAM image (numpy uint8 array): runs of
    8-byte entries whose key_info is type REMOTE, state PRESSED, count 0 and
    whose ir_code shares the NEC address byte -- or, in the T50's table
    (coding "cmd"), is a command and its complement, rev8(c) << 8 |
    rev8(~c).  Returns {vkey: ir16} of the longest run (first entry per
    vkey), or {} if none is found."""
    import numpy as np
    rev = np.array([_rev8(b) for b in range(256)], np.int64)
    n = len(ram) // 8 * 8
    best = {}
    for phase in (0, 4):
        w = ram[phase:phase + n - 8].view('<u4')
        k, v = w[0::2].astype(np.int64), w[1::2].astype(np.int64)
        m = min(len(k), len(v))
        k, v = k[:m], v[:m]
        hdr = PAN_KEY_TYPE_REMOTE | (PAN_KEY_PRESSED << 4)
        ok = ((k & 0xFFFF) == hdr) & (v < 0x100)
        pair = ((k >> 16) & 0xFF) == rev[~rev[(k >> 24) & 0xFF] & 0xFF]
        same = ok[1:] & ok[:-1] & (((k[1:] >> 24) == (k[:-1] >> 24)) | (pair[1:] & pair[:-1]))
        s = np.concatenate(([0], same.astype(np.int8), [0]))
        d = np.diff(s)
        for st, en in zip(np.nonzero(d == 1)[0], np.nonzero(d == -1)[0]):
            if en - st + 1 < max(min_entries, len(best)):
                continue
            table = {}
            for i in range(st, en + 1):
                table.setdefault(int(v[i]), int(k[i]) >> 16)
            if len(table) >= min_entries and len(table) > len(best):
                best = table
    return best
