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
    'RED': 51, 'GREEN': 52, 'YELLOW': 53, 'BLUE': 54, 'WHITE': 55,
    'CONAX': 56, 'CAS': 56, 'BMLIST': 57,
    'RECORD': 58, 'STOP': 59, 'TSHIFT': 60, 'PLAY': 61, 'REC_STOP': 62,
    'FB': 63, 'REW': 63, 'PREV': 64, 'FF': 65, 'NEXT': 66, 'STEP': 67,
    'BOOKMARK': 68, 'SLOW': 69, 'REPEAT': 70, 'PVR_INFO': 71, 'DVD_MENU': 72,
    'VFORMAT': 73, 'HDMI': 74, 'ASPECT': 75, 'PIP': 76, 'SWAP': 77, 'MOVE': 78,
    'PIP_LIST': 79, 'TIMESHIFT': 80, 'RECORD_LIST': 81, 'PVR_CFG': 82, 'USB_REMOVE': 83,
    'FILELIST': 84, 'USB': 84, 'DVR_CFG': 85, 'MEDIA': 85,
    'ALBUM': 86, 'GAME': 87, 'NET': 88,
    'F1': 96, 'F2': 97, 'F3': 98, 'F4': 99,
    'YOUTUBE': 101, 'WEATH': 102, 'RSS': 103, 'MAP': 104,
    'STOCK': 105, 'YAHOO': 106, 'MAIL': 107, 'IPTV': 108, 'OPT': 122,
}

# Firmwares built from later SDK generations shift OSD_VKEY_t values after
# EXIT = 16: Libcore 8.x / C3505 inserts two enum values (+2 from POWER = 19
# onward), and M3821 builds (T750i / T760i) insert a third before CH+ (+3 from
# TIMER / CH+ = 35 onward).  When a name's VKEYS value is not in the firmware's
# key table, press_key() tries these fallbacks in order.
VKEY_FALLBACKS = {
    'POWER': (19,), 'MUTE': (20,), 'PAUSE': (21,), 'TVRADIO': (22,), 'RECALL': (23,),
    'AUDIO': (24,), 'AUDIOCH': (25,), 'ZOOM': (26,), 'HELP': (27,),
    'SIGNAL': (28,), 'INFO': (29, 30), 'PRO_INFOR': (30, 31), 'DVR_INFOR': (31, 32),
    'TIMER': (32, 33), 'LANGUAGE': (33, 34),
    'CH+': (34, 35), 'CH-': (35, 36), 'VOL+': (36, 37), 'VOL-': (37, 38),
    'PAGE+': (38, 39), 'PAGE-': (39, 40), 'FAV+': (40, 41), 'FAV-': (41, 42),
    'EPG': (42, 43), 'TEXT': (43, 44), 'SUBTITLE': (44, 45), 'FAV': (45, 46),
    'SAT': (46, 47), 'TVSAT': (47, 48), 'RGBCVBS': (48, 49), 'SLEEP': (49, 50),
    'FIND': (50, 51), 'LIST': (51, 52), 'MP': (52, 53),
    'RED': (53, 54), 'GREEN': (54, 55), 'YELLOW': (55, 56), 'BLUE': (56, 57), 'WHITE': (57, 58),
    'CONAX': (58, 59), 'CAS': (58, 59), 'BMLIST': (59, 60),
    'RECORD': (60, 61), 'STOP': (61, 62), 'TSHIFT': (62, 63), 'PLAY': (63, 64), 'REC_STOP': (64, 65),
    'FB': (65, 66), 'REW': (65, 66), 'PREV': (66, 67), 'FF': (67, 68), 'NEXT': (68, 69),
    'STEP': (69, 70), 'BOOKMARK': (70, 71), 'SLOW': (71, 72), 'REPEAT': (72, 73),
    'PVR_INFO': (73, 74), 'DVD_MENU': (74, 75), 'VFORMAT': (75, 76), 'HDMI': (76, 77),
    'ASPECT': (77, 78), 'PIP': (78, 79), 'SWAP': (79, 80), 'MOVE': (80, 81),
    'PIP_LIST': (81, 82), 'TIMESHIFT': (82, 83), 'RECORD_LIST': (83, 84),
    'PVR_CFG': (84, 85), 'USB_REMOVE': (85, 86),
    'FILELIST': (86, 87), 'USB': (86, 87), 'DVR_CFG': (87, 88), 'MEDIA': (87, 88),
}

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
              ("T650i", "ext00"), ("T750i", "ext00"), ("T760i", "ext00"), ("A104_", "ext00"),
              ("A204_", "ext00"), ("A154", "ext00"), ("A254", "ext00"), ("254Combo", "ext00"), ("A54_", "ext00"),
              ("dump.bin", "ext00"), ("URZ0083_", "ext00"), ("KM00183", "ext00"), ("THT501", "ext00"),
              ("ESR-250", "necfirst"), ("_S60_", "necfirst"), ("S16_", "necfirst"), ("Software_S50", "necfirst"),
              ("ALI3606_", "necfirst"), ("OPTIMUSS_underline", "necfirst"), ("miniplus_highspeed", "necfirst"),
              ("X110p_M3606_MCAS", "necfirst"), ("_x110p_1.2", "necfirst"), ("X110p_special", "necfirst"),
              ("URZ0083Q", "necfirst"), ("urz0194", "necfirst"), ("ArivaT50", "cmd")]


def coding_for(dump):
    """The IR coding of a dump (file name or path); 'nec' when unknown."""
    import os
    try:
        import dump_catalog
        if dump_catalog.has_override(dump):
            overridden = dump_catalog.ir_coding(dump)
            if overridden:
                return overridden
    except Exception:
        pass
    name = os.path.normpath(dump).lower()
    for pattern, coding in IR_CODINGS:
        if pattern.lower() in name:
            return coding
    try:
        import dump_catalog
        return dump_catalog.ir_coding(dump) or "nec"
    except Exception:
        return "nec"


def frame_from_ir16(ir16, coding="nec"):
    """(address, command, address_hi) of the NEC frame for a key-table code
    under `coding` (address_hi None = standard NEC, the second byte is ~address)."""
    hi, lo = ir16 >> 8, ir16 & 0xFF
    if coding == "ext00":
        return _rev8(hi), (~_rev8(lo)) & 0xFF, _rev8(hi)
    if coding == "necfirst":
        # Opticum X110p 1.0.11C (table 0x02xx) checks (code & 0xFFFF0000) == 0x02370000 in key_get_key (0x8001C360)
        return _rev8(hi), (~_rev8(lo)) & 0xFF, (0xEC if hi == 0x02 else None)
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
    rev8(~c).  Some M3602 tables (URZ0083/URZ0086 v1.0.x, KM00183/KM00186)
    interleave a few entries of a second remote address inside the main
    table, so each contiguous run of valid entries is also filtered by its
    dominant address byte.  Returns {vkey: ir16} of the longest run (first
    entry per vkey), or {} if none is found."""
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
        # Also check contiguous `ok` runs where a few secondary-remote entries
        # split the main remote's address-byte run: keep entries matching the
        # run's dominant high byte.
        s_ok = np.concatenate(([0], ok.astype(np.int8), [0]))
        d_ok = np.diff(s_ok)
        for st, en in zip(np.nonzero(d_ok == 1)[0], np.nonzero(d_ok == -1)[0]):
            if en - st < max(min_entries, len(best)):
                continue
            hi = (k[st:en] >> 24) & 0xFF
            dom = int(np.bincount(hi).argmax())
            table = {}
            for i in range(st, en):
                if ((int(k[i]) >> 24) & 0xFF) == dom:
                    table.setdefault(int(v[i]), int(k[i]) >> 16)
            if len(table) >= min_entries and len(table) > len(best):
                best = table
    if best:
        # Ferguson firmwares (Ariva 104/204/154/254, T750i, T760i) fill unused
        # key-table slots with a dummy 0x40FF or 0x80FF placeholder at the old
        # unshifted vkey numbers (32=CH+, 33=CH-, 51=RED, 52=GREEN, ...); strip
        # any 0x..FF code that repeats >= 3 times for non-digit keys (vkey > 9).
        import collections
        ff_counts = collections.Counter(code for code in best.values() if (code & 0xFF) == 0xFF)
        dummy = {code for code, n in ff_counts.items() if n >= 3}
        if dummy:
            best = {vk: code for vk, code in best.items() if not (code in dummy and vk > 9)}
    return best
