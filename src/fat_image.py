"""
FAT12 / FAT16 / FAT32 disk images for the emulator's virtual USB stick
(usb_host.VirtualStick): directories and files, long file names (with their
8.3 aliases), a volume label, an MBR with one partition or no partition table
at all, and optionally files stored in clusters that are not one after the
other (a fragmented file: its chain has to be followed through the FAT).

    image = fat_image.build({"README.TXT": b"...", "Docs/A long name.txt": b"...", "Empty/": None},
                            fat=16, size_mb=16, label="ALISIM")

Paths use '/'; a path ending in '/' (with the value None) is an empty
directory; parent directories are made as needed.  The result is a bytearray
of size_mb MiB.
"""

SECTOR = 512
DATE = ((2026 - 1980) << 9) | (11 << 5) | 13           # 2026-11-13
TIME = (12 << 11) | (34 << 5) | (56 // 2)              # 12:34:56
_ALLOWED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()-@^_`{}~")


def _valid_83(name):
    if name in (".", ".."):
        return True
    base, dot, ext = name.rpartition(".") if "." in name else (name, "", "")
    if not dot:
        base, ext = name, ""
    return (1 <= len(base) <= 8 and len(ext) <= 3 and name == name.upper()
            and all(c in _ALLOWED for c in base + ext) and name.count(".") <= 1)


def _short(name, taken):
    """The 11-byte 8.3 name for `name` and whether a long name is needed."""
    if _valid_83(name):
        base, _, ext = name.partition(".")
        short = (base.ljust(8) + ext.ljust(3)).encode("ascii")
        taken.add(short)
        return short, False
    base, _, ext = name.rpartition(".") if "." in name[1:] else (name, "", "")
    clean = lambda s: "".join(c for c in s.upper() if c in _ALLOWED)      # noqa: E731
    base, ext = clean(base) or "FILE", clean(ext)[:3]
    for n in range(1, 1000):
        tail = f"~{n}"
        short = ((base[:8 - len(tail)] + tail).ljust(8) + ext.ljust(3)).encode("ascii")
        if short not in taken:
            taken.add(short)
            return short, True
    raise ValueError("too many similar names")


def _checksum(short):
    s = 0
    for b in short:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


def _entry(short, attr, cluster, size):
    return (short + bytes([attr, 0, 0]) + TIME.to_bytes(2, "little") + DATE.to_bytes(2, "little")
            + DATE.to_bytes(2, "little") + (cluster >> 16).to_bytes(2, "little") + TIME.to_bytes(2, "little")
            + DATE.to_bytes(2, "little") + (cluster & 0xFFFF).to_bytes(2, "little") + size.to_bytes(4, "little"))


def _long_entries(name, short):
    """The long-name entries for `name`, as they lie on the disk (the last part first)."""
    chars = [ord(c) for c in name] + [0]
    while len(chars) % 13:
        chars.append(0xFFFF)
    parts = [chars[i:i + 13] for i in range(0, len(chars), 13)]
    out, s = [], _checksum(short)
    for i in reversed(range(len(parts))):
        p = b"".join(c.to_bytes(2, "little") for c in parts[i])
        seq = (i + 1) | (0x40 if i == len(parts) - 1 else 0)
        out.append(bytes([seq]) + p[0:10] + bytes([0x0F, 0, s]) + p[10:22] + b"\0\0" + p[22:26])
    return out


class _File:
    def __init__(self, data):
        self.data = data
        self.chain = []


class _Dir:
    def __init__(self, name, parent):
        self.name, self.parent = name, parent
        self.children = {}                    # name -> _Dir or _File
        self.cluster = 0


def build(files, fat=16, size_mb=16, label="ALISIM", partition=True, fragmented=(), spc=None):
    """The image (see the module's notes); `fragmented`: paths of files whose clusters are
    allocated with a free cluster after each."""
    root = _Dir("", None)
    for path, data in files.items():
        parts = [p for p in path.split("/") if p]
        d = root
        for p in parts[:-1] if (data is not None or not path.endswith("/")) else parts:
            d = d.children.setdefault(p, _Dir(p, d))
        if data is not None:
            d.children[parts[-1]] = _File(bytes(data))
    total = size_mb * 2048
    start = 2048 if partition else 0
    sectors = total - start
    spc = spc or {12: 1, 16: 4, 32: 1}[fat]
    reserved = 32 if fat == 32 else 1
    root_entries = {12: 224, 16: 512, 32: 0}[fat]
    root_sectors = root_entries * 32 // SECTOR
    fat_size = 1
    for _ in range(20):                       # the FAT's size and the clusters it covers, settled
        clusters = (sectors - reserved - 2 * fat_size - root_sectors) // spc
        need = -(-((clusters + 2) * fat // 8) // SECTOR) if fat != 12 else -(-((clusters + 2) * 3 // 2) // SECTOR)
        if need == fat_size:
            break
        fat_size = need
    kind = 12 if clusters < 4085 else 16 if clusters < 65525 else 32
    if kind != fat:
        raise ValueError(f"{size_mb} MB with {spc} sectors per cluster is FAT{kind}, not FAT{fat}")
    cluster_bytes = spc * SECTOR
    data_start = reserved + 2 * fat_size + root_sectors        # (from the volume's start)
    table = [0] * (clusters + 2)
    table[0], table[1] = {12: 0xFF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[fat], {12: 0xFFF, 16: 0xFFFF, 32: 0x0FFFFFFF}[fat]
    eoc = {12: 0xFFF, 16: 0xFFFF, 32: 0x0FFFFFFF}[fat]
    free = [2]

    def allocate(count, gaps=False):
        chain = []
        for _ in range(max(count, 1)):
            c = free[0]
            if c >= clusters + 2:
                raise ValueError("the image is full")
            chain.append(c)
            free[0] += 2 if gaps else 1
        for a, b in zip(chain, chain[1:]):
            table[a] = b
        table[chain[-1]] = eoc
        return chain

    image = bytearray(total * SECTOR)
    base = start * SECTOR

    def write_chain(chain, data):
        for i, c in enumerate(chain):
            piece = data[i * cluster_bytes:(i + 1) * cluster_bytes]
            at = base + (data_start + (c - 2) * spc) * SECTOR
            image[at:at + len(piece)] = piece

    # every directory's entries need the clusters of what is in it: directories first, then files
    def entries_of(d, taken):
        out = []
        if d.parent is not None:
            out.append(_entry(b".          ", 0x10, d.cluster, 0))
            parent = d.parent.cluster if d.parent.parent is not None else 0
            out.append(_entry(b"..         ", 0x10, parent, 0))
        elif label:
            out.append(label.upper().encode("ascii")[:11].ljust(11) + bytes([0x08]) + bytes(20))
        for name, child in d.children.items():
            short, needs_long = _short(name, taken)
            if needs_long:
                out.extend(_long_entries(name, short))
            if isinstance(child, _Dir):
                out.append(_entry(short, 0x10, child.cluster, 0))
            else:
                out.append(_entry(short, 0x20, child.chain[0] if child.chain else 0, len(child.data)))
        return out

    dirs = []

    def walk(d):
        dirs.append(d)
        for child in d.children.values():
            if isinstance(child, _Dir):
                walk(child)
    walk(root)
    sizes = {}
    for d in dirs:                            # (the entries' count does not depend on the clusters)
        n = (2 if d.parent is not None else (1 if label else 0)) + 1
        taken = set()
        for name in d.children:
            short, needs_long = _short(name, taken)
            n += 1 + (len(_long_entries(name, short)) if needs_long else 0)
        sizes[id(d)] = n
    chains = {}
    for d in dirs:
        if d is root and fat != 32:
            if sizes[id(d)] > root_entries:
                raise ValueError("too many entries in the root directory")
            continue
        chains[id(d)] = allocate(-(-sizes[id(d)] * 32 // cluster_bytes))
        d.cluster = chains[id(d)][0]
    def files_of(d, prefix):
        for name, child in d.children.items():
            if isinstance(child, _Dir):
                files_of(child, prefix + name + "/")
            elif child.data:
                child.chain = allocate(-(-len(child.data) // cluster_bytes), gaps=prefix + name in fragmented)
                write_chain(child.chain, child.data)
    files_of(root, "")
    for d in dirs:
        raw = b"".join(entries_of(d, set()))
        if d is root and fat != 32:
            at = base + (reserved + 2 * fat_size) * SECTOR
            image[at:at + len(raw)] = raw
        else:
            write_chain(chains[id(d)], raw)

    # the FATs
    raw = bytearray(fat_size * SECTOR)
    for c, v in enumerate(table):
        if fat == 32:
            raw[c * 4:c * 4 + 4] = v.to_bytes(4, "little")
        elif fat == 16:
            raw[c * 2:c * 2 + 2] = v.to_bytes(2, "little")
        else:
            at = c * 3 // 2
            if c & 1:
                raw[at] = (raw[at] & 0x0F) | ((v << 4) & 0xF0)
                raw[at + 1] = (v >> 4) & 0xFF
            else:
                raw[at] = v & 0xFF
                raw[at + 1] = (raw[at + 1] & 0xF0) | ((v >> 8) & 0x0F)
    for i in range(2):
        at = base + (reserved + i * fat_size) * SECTOR
        image[at:at + len(raw)] = raw

    # the boot sector
    b = bytearray(SECTOR)
    b[0:3] = bytes([0xEB, 0x58 if fat == 32 else 0x3C, 0x90])
    b[3:11] = b"ALISIM  "
    b[11:13] = SECTOR.to_bytes(2, "little")
    b[13] = spc
    b[14:16] = reserved.to_bytes(2, "little")
    b[16] = 2
    b[17:19] = root_entries.to_bytes(2, "little")
    if sectors < 0x10000 and fat != 32:
        b[19:21] = sectors.to_bytes(2, "little")
    else:
        b[32:36] = sectors.to_bytes(4, "little")
    b[21] = 0xF8
    b[24:26] = (63).to_bytes(2, "little")
    b[26:28] = (255).to_bytes(2, "little")
    b[28:32] = start.to_bytes(4, "little")
    tail = 36
    if fat == 32:
        b[36:40] = fat_size.to_bytes(4, "little")
        b[44:48] = root.cluster.to_bytes(4, "little")
        b[48:50] = (1).to_bytes(2, "little")
        b[50:52] = (6).to_bytes(2, "little")
        tail = 64
    else:
        b[22:24] = fat_size.to_bytes(2, "little")
    b[tail] = 0x80
    b[tail + 2] = 0x29
    b[tail + 3:tail + 7] = (0x20261113).to_bytes(4, "little")
    b[tail + 7:tail + 18] = (label or "NO NAME").upper().encode("ascii")[:11].ljust(11)
    b[tail + 18:tail + 26] = f"FAT{fat}".encode().ljust(8)
    b[510:512] = b"\x55\xAA"
    image[base:base + SECTOR] = b
    if fat == 32:
        info = bytearray(SECTOR)
        info[0:4] = (0x41615252).to_bytes(4, "little")
        info[484:488] = (0x61417272).to_bytes(4, "little")
        info[488:492] = (0xFFFFFFFF).to_bytes(4, "little")
        info[492:496] = (0xFFFFFFFF).to_bytes(4, "little")
        info[508:512] = (0xAA550000).to_bytes(4, "little")
        image[base + SECTOR:base + 2 * SECTOR] = info
        image[base + 6 * SECTOR:base + 7 * SECTOR] = b

    if partition:
        mbr = bytearray(SECTOR)
        e = bytearray(16)
        e[0] = 0x00
        e[1:4] = bytes([0xFE, 0xFF, 0xFF])
        e[4] = {12: 0x01, 16: 0x06, 32: 0x0C}[fat]
        e[5:8] = bytes([0xFE, 0xFF, 0xFF])
        e[8:12] = start.to_bytes(4, "little")
        e[12:16] = sectors.to_bytes(4, "little")
        mbr[446:462] = e
        mbr[510:512] = b"\x55\xAA"
        image[0:SECTOR] = mbr
    return image


def _le(b, at, n):
    return int.from_bytes(b[at:at + n], "little")


class Volume:
    """A minimal FAT reader, to check images -- what build made, and what a
    firmware wrote into one (the v4 demo's disk.c is C): Volume(image, its
    first sector); .next(c) a cluster's FAT entry (None at a chain's end, 0
    free), .chain(c), .read(first cluster), .entries(directory's cluster; 0
    the root): dicts of 'short' (11 bytes), 'long' (or None), 'sum_ok' (the
    long name's checksum matches), 'attr', 'cluster', 'size'; .find(path)."""

    def __init__(self, image, start):
        b = image[start * 512:start * 512 + 512]
        self.image, self.start = image, start
        self.spc, reserved, fats, root_entries = b[13], _le(b, 14, 2), b[16], _le(b, 17, 2)
        total = _le(b, 19, 2) or _le(b, 32, 4)
        fat_size = _le(b, 22, 2) or _le(b, 36, 4)
        self.root_sectors = root_entries * 32 // 512
        self.fat_start = start + reserved
        self.root_start = self.fat_start + fats * fat_size
        self.data_start = self.root_start + self.root_sectors
        self.clusters = (total - (reserved + fats * fat_size + self.root_sectors)) // self.spc
        self.fat = 12 if self.clusters < 4085 else 16 if self.clusters < 65525 else 32
        self.root_cluster = _le(b, 44, 4) if self.fat == 32 else 0

    def next(self, c):
        base = self.fat_start * 512
        if self.fat == 32:
            n = _le(self.image, base + c * 4, 4) & 0x0FFFFFFF
            return None if n >= 0x0FFFFFF8 else n
        if self.fat == 16:
            n = _le(self.image, base + c * 2, 2)
            return None if n >= 0xFFF8 else n
        v = _le(self.image, base + c * 3 // 2, 2)
        n = v >> 4 if c & 1 else v & 0xFFF
        return None if n >= 0xFF8 else n

    def chain(self, c):
        out = []
        while c is not None:
            out.append(c)
            c = self.next(c)
        return out

    def read(self, first, size=None):
        data = bytearray()
        if first == 0 and self.fat != 32:
            at = self.root_start * 512
            return bytes(self.image[at:at + self.root_sectors * 512])
        for c in self.chain(first or self.root_cluster):
            at = (self.data_start + (c - 2) * self.spc) * 512
            data += self.image[at:at + self.spc * 512]
        return bytes(data[:size]) if size is not None else bytes(data)

    def entries(self, first):
        raw, out, parts = self.read(first), [], {}
        for i in range(0, len(raw), 32):
            e = raw[i:i + 32]
            if e[0] == 0:
                break
            if e[0] == 0xE5:
                parts = {}
                continue
            if e[11] == 0x0F:
                name = (e[1:11] + e[14:26] + e[28:32]).decode("utf-16-le").split("\0")[0]
                parts[e[0] & 0x1F] = (name, e[13])
                continue
            short = e[0:11]
            long_name = "".join(parts[k][0] for k in sorted(parts)) if parts else None
            sums = {s for _n, s in parts.values()}
            out.append({"short": short, "long": long_name, "sum_ok": not parts or sums == {_checksum(short)},
                        "attr": e[11], "cluster": _le(e, 26, 2) | (_le(e, 20, 2) << 16 if self.fat == 32 else 0),
                        "size": _le(e, 28, 4)})
            parts = {}
        return out

    def find(self, path):
        cluster = 0
        entry = None
        for part in [p for p in path.split("/") if p]:
            for e in self.entries(cluster):
                short = e["short"].decode("ascii")
                name83 = short[:8].rstrip() + ("." + short[8:].rstrip() if short[8:].strip() else "")
                if part in (e["long"], name83):
                    entry = e
                    cluster = e["cluster"]
                    break
            else:
                return None
        return entry
