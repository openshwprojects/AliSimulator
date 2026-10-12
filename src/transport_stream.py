"""
A transport stream for the demultiplexer model: the DVB tables a receiver
needs to complete a channel change, as TS packets.

With a tuner model and the demodulator reporting lock (sim.set_signal), the
firmware finds a carrier but no data: no programme tables (PAT, PMT), so no
service to play or to find in a channel search.  This module builds the tables of
a small multiplex (Mux) -- PAT, PMT per service, SDT with the service names,
NIT, TDT with the clock -- as MPEG-2 private sections and packs them into
188-byte TS packets with continuity counters, so the demultiplexer model
(dmx_m36.py) can feed them to the firmware's section filters.  Everything is
plain ISO 13818-1 / ETSI EN 300 468 syntax: long-form sections with a
CRC-32 (the MPEG-2 polynomial, no reflection), one section per packet run,
a pointer field of 0 on the first packet and 0xFF padding on the last.
"""
import datetime
import re
import struct

TS_PACKET = 188
PID_PAT, PID_CAT, PID_NIT, PID_SDT, PID_EIT, PID_TDT = 0x0000, 0x0001, 0x0010, 0x0011, 0x0012, 0x0014
TID_PAT, TID_CAT, TID_PMT, TID_NIT, TID_SDT, TID_EIT_PF, TID_TDT, TID_TOT = 0x00, 0x01, 0x02, 0x40, 0x42, 0x4E, 0x70, 0x73
STANDARD_PIDS = {PID_PAT, PID_CAT, PID_NIT, PID_SDT, PID_EIT, PID_TDT}

_CRC_TABLE = []
for _i in range(256):
    _c = _i << 24
    for _ in range(8):
        _c = ((_c << 1) ^ 0x04C11DB7) if _c & 0x80000000 else (_c << 1)
    _CRC_TABLE.append(_c & 0xFFFFFFFF)


def crc32_mpeg2(data):
    """The CRC-32 of MPEG-2 sections (polynomial 0x04C11DB7, init 0xFFFFFFFF, no reflection, no final XOR)."""
    crc = 0xFFFFFFFF
    for b in data:
        crc = ((crc << 8) ^ _CRC_TABLE[((crc >> 24) ^ b) & 0xFF]) & 0xFFFFFFFF
    return crc


def section(table_id, id_extension, body, version=0, section_number=0, last_section_number=0, current_next=1):
    """A long-form section: table_id, section_syntax_indicator = 1, length,
    id extension (transport_stream_id / program_number / service_id ...),
    version, section numbers, `body`, CRC-32."""
    length = 5 + len(body) + 4                      # after section_length: ext(2) ver(1) sec(1) last(1) body crc(4)
    head = struct.pack(">BHHBBB", table_id, 0xB000 | length, id_extension & 0xFFFF,
                       0xC0 | ((version & 0x1F) << 1) | (current_next & 1), section_number, last_section_number)
    data = head + body
    return data + struct.pack(">I", crc32_mpeg2(data))


def descriptor(tag, payload):
    return bytes([tag, len(payload)]) + payload


def dvb_string(text):
    """A DVB text string in the default (Latin) character table."""
    return text.encode("latin-1", "replace")


def mjd(date):
    """The Modified Julian Date of a date (ETSI EN 300 468 annex C)."""
    y, m, d = date.year, date.month, date.day
    l = 1 if m in (1, 2) else 0
    return 14956 + d + int((y - 1900 - l) * 365.25) + int((m + 1 + l * 12) * 30.6001)


def bcd(n):
    return ((n // 10) << 4) | (n % 10)


def utc_time(when):
    """The 5-byte UTC_time field: MJD (2 bytes) and hh:mm:ss in BCD."""
    return struct.pack(">H", mjd(when)) + bytes([bcd(when.hour), bcd(when.minute), bcd(when.second)])


def pat(ts_id, programs, version=0):
    """programs: {program_number: PMT PID}; program 0 would be the NIT PID."""
    body = b"".join(struct.pack(">HH", num, 0xE000 | pid) for num, pid in sorted(programs.items()))
    return section(TID_PAT, ts_id, body, version)


def cat(version=0):
    """The conditional access table, with no descriptors (free-to-air)."""
    return section(TID_CAT, 0xFFFF, b"", version)


def pmt(program_number, pcr_pid, streams, version=0, program_descriptors=b""):
    """streams: [(stream_type, elementary PID, descriptors bytes)]."""
    body = struct.pack(">HH", 0xE000 | pcr_pid, 0xF000 | len(program_descriptors)) + program_descriptors
    for stream_type, pid, descs in streams:
        body += struct.pack(">BHH", stream_type, 0xE000 | pid, 0xF000 | len(descs)) + descs
    return section(TID_PMT, program_number, body, version)


def sdt(ts_id, onid, services, version=0):
    """services: [(service_id, name, provider, service_type)] -- service_type 1 = digital TV, 2 = radio."""
    body = struct.pack(">HB", onid, 0xFF)
    for service_id, name, provider, service_type in services:
        prov, nm = dvb_string(provider), dvb_string(name)
        desc = descriptor(0x48, bytes([service_type, len(prov)]) + prov + bytes([len(nm)]) + nm)
        # EIT schedule / present-following flags clear, running_status 4 (running), free_CA_mode 0
        body += struct.pack(">HBH", service_id, 0xFC, 0x8000 | len(desc)) + desc
    return section(TID_SDT, ts_id, body, version)


def nit(network_id, network_name, transports, version=0):
    """transports: [(ts_id, onid, descriptors bytes)]."""
    nd = descriptor(0x40, dvb_string(network_name))
    loop = b"".join(struct.pack(">HHH", ts_id, onid, 0xF000 | len(descs)) + descs for ts_id, onid, descs in transports)
    body = struct.pack(">H", 0xF000 | len(nd)) + nd + struct.pack(">H", 0xF000 | len(loop)) + loop
    return section(TID_NIT, network_id, body, version)


def tdt(when):
    """The time and date table: a short section (no CRC) with the UTC time."""
    return struct.pack(">BH", TID_TDT, 0x7000 | 5) + utc_time(when)


def eit_present_following(service_id, ts_id, onid, now, next_, version=0):
    """now / next_: (event_id, start datetime, duration seconds, title, text) or None."""
    out = []
    for section_number, ev in enumerate((now, next_)):
        if ev is None:
            continue
        event_id, start, seconds, title, text = ev
        name, txt = dvb_string(title), dvb_string(text)
        sed = descriptor(0x4D, b"pol" + bytes([len(name)]) + name + bytes([len(txt)]) + txt)
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        body = struct.pack(">HHBB", ts_id, onid, 1, TID_EIT_PF)     # transport_stream_id, original_network_id,
        #                                                             segment_last_section_number, last_table_id
        body += struct.pack(">H", event_id) + utc_time(start) + bytes([bcd(h), bcd(m), bcd(s)])
        body += struct.pack(">H", (4 << 13) | len(sed)) + sed         # running_status 4, free_CA 0, loop length
        out.append(section(TID_EIT_PF, service_id, body, version, section_number, 1))
    return out


def ts_packets(pid, payload, counter=0):
    """188-byte TS packets carrying one section (or several back to back):
    payload_unit_start on the first with pointer_field 0, 0xFF padding on the
    last.  Returns (packets, next continuity counter)."""
    data = b"\x00" + payload                            # pointer_field
    packets = []
    first = True
    while data:
        chunk, data = data[:184], data[184:]
        header = struct.pack(">BHB", 0x47, (0x4000 if first else 0) | (pid & 0x1FFF), 0x10 | (counter & 0x0F))
        packets.append(header + chunk + b"\xFF" * (184 - len(chunk)))
        counter = (counter + 1) & 0x0F
        first = False
    return packets, counter


def channel_records(image):
    """The channel records of an ALi flash image's databases (the "userdb" and
    "defaultdb" chunks; lib_db's P_NODE, db_node_c.h): [(pmt_pid, programme
    number, video PID, name)], found by their two bit-field words -- video_pid
    in bits 6..18 and pcr_pid in 19..31 of the first, prog_number in bits 0..15
    and pmt_pid in 16..28 of the second -- followed within 160 bytes by the
    UTF-16 service name.  A record counts when its PCR PID is its video PID
    or its PMT PID and the flag bits are plausible."""
    try:
        from chips.base import chunk_chain
    except ImportError:
        return []
    out, seen = [], set()
    image = bytes(image)
    for offset, name, _version in chunk_chain(image):
        if name not in ("userdb", "defaultdb"):
            continue
        length = struct.unpack_from(">I", image, offset + 4)[0]
        db = image[offset + 0x80:offset + 0x80 + length]
        for i in range(0, len(db) - 8):
            w1, w2 = struct.unpack_from("<II", db, i)
            pmt, prog = (w2 >> 16) & 0x1FFF, w2 & 0xFFFF
            video, pcr = (w1 >> 6) & 0x1FFF, w1 >> 19
            if not pmt or not prog or not video or pmt >= 0x1FFF or video >= 0x1FFF or (w1 & 0x0F):
                continue
            if pcr not in (video, pmt, 0x1FFF):
                continue
            # the name: UTF-16 pairs stored without the last character's high
            # byte (the database packs each string one byte short)
            m = re.search(rb"(?:[\x20-\x7e]\x00){2,}[\x20-\x7e]", db[i + 8:i + 256])
            if not m:
                continue
            raw = m.group(0)
            name = (raw + b"\x00").decode("utf-16-le")
            # (a printable name_len byte -- 0x22 for 17 characters -- joins the match: drop it)
            if ord(name[0]) == len(raw) - 1:
                name = name[1:]
            key = (pmt, prog, video)
            if key in seen:
                continue
            seen.add(key)
            out.append((pmt, prog, video, name))
    return out


def channel_by_pmt_pid(image, pmt_pid):
    """(programme number, video PID, name) of the image's channel whose PMT is
    on `pmt_pid`, or None.  With several records (the database keeps old
    versions) the one whose video PID follows the PMT PID wins, then the
    most frequent programme number."""
    records = [r for r in channel_records(image) if r[0] == pmt_pid]
    if not records:
        return None
    records.sort(key=lambda r: (r[2] != pmt_pid + 1, -sum(1 for q in records if q[1] == r[1])))
    pmt, prog, video, name = records[0]
    return prog, video, name


class Service:
    def __init__(self, service_id, pmt_pid, name, video_pid, audio_pid, provider="AliSimulator", service_type=1):
        self.service_id, self.pmt_pid, self.name = service_id, pmt_pid, name
        self.video_pid, self.audio_pid = video_pid, audio_pid
        self.provider, self.service_type = provider, service_type


class Mux:
    """A multiplex: its services and the tables that describe them.  The
    tables are rebuilt on each request (the TDT carries the clock), the
    continuity counter of every PID carries on between requests."""

    def __init__(self, ts_id=0x1001, onid=0x2001, network_id=0x3001, network_name="AliSimulator network",
                 services=None, clock=None):
        self.ts_id, self.onid, self.network_id, self.network_name = ts_id, onid, network_id, network_name
        self.services = list(services) if services else [Service(0x0101, 0x0100, "AliSimulator TV", 0x0101, 0x0102)]
        self.clock = clock                  # a datetime for the TDT, or None for the host's UTC time
        self.counters = {}
        self.versions = {}

    def add(self, service):
        self.services.append(service)

    def by_pmt_pid(self, pid):
        return next((s for s in self.services if s.pmt_pid == pid), None)

    def sections_for(self, pid):
        """The sections carried on a PID (a list of bytes), [] for a PID with none."""
        if pid == PID_PAT:
            return [pat(self.ts_id, {s.service_id: s.pmt_pid for s in self.services})]
        if pid == PID_CAT:
            return [cat()]
        if pid == PID_SDT:
            return [sdt(self.ts_id, self.onid, [(s.service_id, s.name, s.provider, s.service_type) for s in self.services])]
        if pid == PID_NIT:
            return [nit(self.network_id, self.network_name, [(self.ts_id, self.onid, b"")])]
        if pid == PID_TDT:
            return [tdt(self.clock or datetime.datetime.now(datetime.timezone.utc))]
        if pid == PID_EIT:
            now = self.clock or datetime.datetime.now(datetime.timezone.utc)
            start = now.replace(minute=0, second=0, microsecond=0)
            out = []
            for s in self.services:
                out += eit_present_following(s.service_id, self.ts_id, self.onid,
                                             (1, start, 3600, f"{s.name} now", "A programme the simulator made up."),
                                             (2, start + datetime.timedelta(hours=1), 3600, f"{s.name} next", ""))
            return out
        s = self.by_pmt_pid(pid)
        if s is not None:
            return [pmt(s.service_id, s.video_pid, [(0x02, s.video_pid, b""), (0x03, s.audio_pid, descriptor(0x0A, b"pol\x00"))])]
        return []

    def packets_for(self, pid):
        """One repetition of the PID's tables as TS packets ([] for an unknown PID)."""
        out = []
        for sec in self.sections_for(pid):
            pk, self.counters[pid] = ts_packets(pid, sec, self.counters.get(pid, 0))
            out += pk
        return out

    def known_pids(self):
        return STANDARD_PIDS | {s.pmt_pid for s in self.services}

    def adapt(self, pmt_pid, service_id=None, name=None, video_pid=None):
        """Move the first service to the PMT PID (and service id, name, video
        PID) a firmware asks for: it requests the PMT on the PID its channel
        database names and matches the programme number it expects (adaptive
        mode of the demultiplexer model).  Returns the service."""
        s = self.services[0]
        s.pmt_pid = pmt_pid
        if service_id is not None:
            s.service_id = service_id
        if name:
            s.name = name
        if video_pid:
            s.video_pid, s.audio_pid = video_pid, video_pid + 1
        return s
