"""
Test: src/fat_image.py (FAT12 / FAT16 / FAT32 disk images for the emulator's
virtual USB stick) and usb_host.VirtualStick's bulk-only transport and SCSI
commands -- without the emulator.

  layout    - each type's boot sector, MBR, FAT type by cluster count, root
  files     - every file read back through its FAT chain (a fragmented one
              too), long names with their 8.3 aliases and checksums, a
              directory tree with '.' and '..', the volume label
  7-Zip     - when 7-Zip is installed, it lists the images and extracts the
              files byte for byte (an independent reader)
  stick     - command block -> data -> status: INQUIRY, TEST UNIT READY (unit
              attention, no medium), REQUEST SENSE, READ CAPACITY(10),
              READ(10) (beyond the end: a failure with its sense), an
              unknown command, a command block that is not one, the status
              stalled when its bulk IN's halt is cleared in a command's middle
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))

import fat_image                                          # noqa: E402
from usb_host import HALTED, VirtualStick                 # noqa: E402

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


def le(b, at, n):
    return int.from_bytes(b[at:at + n], "little")


class Volume:
    """A minimal FAT reader for the checks (the demo's own is C, in disk.c)."""

    def __init__(self, image, start):
        b = image[start * 512:start * 512 + 512]
        self.image, self.start = image, start
        self.spc, reserved, fats, root_entries = b[13], le(b, 14, 2), b[16], le(b, 17, 2)
        total = le(b, 19, 2) or le(b, 32, 4)
        fat_size = le(b, 22, 2) or le(b, 36, 4)
        self.root_sectors = root_entries * 32 // 512
        self.fat_start = start + reserved
        self.root_start = self.fat_start + fats * fat_size
        self.data_start = self.root_start + self.root_sectors
        self.clusters = (total - (reserved + fats * fat_size + self.root_sectors)) // self.spc
        self.fat = 12 if self.clusters < 4085 else 16 if self.clusters < 65525 else 32
        self.root_cluster = le(b, 44, 4) if self.fat == 32 else 0

    def next(self, c):
        base = self.fat_start * 512
        if self.fat == 32:
            n = le(self.image, base + c * 4, 4) & 0x0FFFFFFF
            return None if n >= 0x0FFFFFF8 else n
        if self.fat == 16:
            n = le(self.image, base + c * 2, 2)
            return None if n >= 0xFFF8 else n
        v = le(self.image, base + c * 3 // 2, 2)
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
                continue
            if e[11] == 0x0F:
                name = (e[1:11] + e[14:26] + e[28:32]).decode("utf-16-le").split("\0")[0]
                parts[e[0] & 0x1F] = (name, e[13])
                continue
            short = e[0:11]
            long_name = "".join(parts[k][0] for k in sorted(parts)) if parts else None
            sums = {s for _n, s in parts.values()}
            out.append({"short": short, "long": long_name, "sum_ok": not parts or sums == {fat_image._checksum(short)},
                        "attr": e[11], "cluster": le(e, 26, 2) | (le(e, 20, 2) << 16 if self.fat == 32 else 0),
                        "size": le(e, 28, 4)})
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


FILES = {"README.TXT": b"hello\n" * 300, "Docs/A long file name.txt": bytes(range(97, 123)) * 200,
         "Docs/sub/deep.bin": bytes(range(256)) * 9, "Empty/": None, "lower.txt": b"lower\n",
         "MixedCase Name.TXT": b"mixed", "zero.bin": b""}

print("=== FAT images ===")
images = {}
for fat, mb, part in ((12, 2, False), (16, 16, True), (32, 40, True)):
    img = fat_image.build(FILES, fat=fat, size_mb=mb, label="ALISIM", partition=part,
                          fragmented=("Docs/A long file name.txt",))
    images[fat] = img
    start = le(img, 446 + 8, 4) if part else 0
    v = Volume(img, start)
    check(len(img) == mb * 1024 * 1024 and img[510:512] == b"\x55\xaa" and v.fat == fat
          and (not part or img[446 + 4] == {16: 0x06, 32: 0x0C}[fat]) and img[start * 512 + 510:start * 512 + 512] == b"\x55\xaa",
          f"FAT{fat}: {mb} MB, {'an MBR partition from sector ' + str(start) if part else 'no partition table'}, "
          f"{v.clusters} clusters of {v.spc * 512} bytes")
    ok = all(v.read(v.find(p)["cluster"], v.find(p)["size"]) == d for p, d in FILES.items() if d)
    check(ok, f"FAT{fat}: every file reads back through its FAT chain")
    long_entry = v.find("Docs/A long file name.txt")
    chain = v.chain(long_entry["cluster"])
    check(len(chain) > 1 and all(b - a == 2 for a, b in zip(chain, chain[1:])),
          f"FAT{fat}: the fragmented file's {len(chain)} clusters have a free one after each")
    check(long_entry["long"] == "A long file name.txt" and long_entry["short"] == b"ALONGF~1TXT" and long_entry["sum_ok"]
          and v.find("lower.txt")["short"] == b"LOWER~1 TXT",
          f"FAT{fat}: long names, their 8.3 aliases and the aliases' checksums")
    sub = v.entries(v.find("Docs/sub")["cluster"])
    check(sub[0]["short"].startswith(b".  ") and sub[1]["short"].startswith(b".. ")
          and sub[1]["cluster"] == v.find("Docs")["cluster"] and v.find("zero.bin")["cluster"] == 0
          and v.find("Empty")["attr"] == 0x10,
          f"FAT{fat}: '.' and '..' (to the parent's cluster), an empty file without a cluster, an empty directory")
    check(any(e["attr"] == 0x08 and e["short"] == b"ALISIM     " for e in v.entries(0)),
          f"FAT{fat}: the volume label in the root directory")

seven = shutil.which("7z") or (r"C:\Program Files\7-Zip\7z.exe" if os.path.exists(r"C:\Program Files\7-Zip\7z.exe")
                                else None)
if seven:
    with tempfile.TemporaryDirectory() as tmp:
        ok = True
        for fat, img in images.items():
            path = os.path.join(tmp, f"fat{fat}.img")
            with open(path, "wb") as f:
                f.write(img)
            out = os.path.join(tmp, f"x{fat}")
            subprocess.run([seven, "x", "-y", f"-o{out}", path], capture_output=True, check=False)
            for p, d in FILES.items():
                if d is None:
                    ok &= os.path.isdir(os.path.join(out, p))
                    continue
                q = os.path.join(out, p)
                ok &= os.path.exists(q) and open(q, "rb").read() == d
        check(ok, "7-Zip extracts every file of the three images byte for byte")
else:
    print("  (7-Zip not found: the independent reader's check skipped)")

print("=== the virtual stick ===")
stick = VirtualStick(images[16], unit_attention=True, vendor="Generic", product="STORAGE DEVICE", revision="1404")
tag = [0x100]


def command(cb, length, dev=stick):
    tag[0] += 1
    cbw = (b"USBC" + tag[0].to_bytes(4, "little") + length.to_bytes(4, "little") + bytes([0x80 if length else 0, 0, len(cb)])
           + bytes(cb).ljust(16, b"\0"))
    assert dev.bulk_out(2, cbw) is True
    data = dev.in_transfer(1, length, 512) if length else b""
    csw = dev.in_transfer(1, 13, 512)
    return data, csw


def sense(dev=stick):
    data, _csw = command([0x03, 0, 0, 0, 18, 0], 18, dev)
    return data[2] & 15, data[12]


data, csw = command([0x12, 0, 0, 0, 36, 0], 36)
check(data[:2] == b"\x00\x80" and data[8:36] == b"Generic STORAGE DEVICE  1404" and csw[:4] == b"USBS"
      and le(csw, 4, 4) == tag[0] and csw[12] == 0, "INQUIRY: a removable disk, its vendor / product / revision; status good")
_d, csw = command([0, 0, 0, 0, 0, 0], 0)
key, asc = sense()
_d, csw2 = command([0, 0, 0, 0, 0, 0], 0)
check(csw[12] == 1 and (key, asc) == (6, 0x28) and csw2[12] == 0,
      "TEST UNIT READY: first 'the medium may have changed' (6/28 from REQUEST SENSE), then ready")
data, csw = command([0x25] + [0] * 9, 8)
check(int.from_bytes(data[:4], "big") == 32767 and int.from_bytes(data[4:], "big") == 512, "READ CAPACITY(10): 32768 sectors of 512 bytes")
data, csw = command([0x28, 0, 0, 0, 0, 0, 0, 0, 2, 0], 1024)
check(data == bytes(images[16][:1024]) and csw[12] == 0 and le(csw, 8, 4) == 0, "READ(10) of two sectors: the image's bytes")
data, csw = command([0x28, 0, 0, 0, 0x7F, 0xFF, 0, 0, 2, 0], 1024)
check(data == b"" and csw[12] == 1 and le(csw, 8, 4) == 1024 and sense() == (5, 0x21),
      "READ(10) past the end: failed, all 1024 bytes left over, sense 5/21")
_d, csw = command([0x2A] + [0] * 9, 0)
check(csw[12] == 1 and sense() == (5, 0x20), "a command it does not know (WRITE(10)): failed, sense 5/20")
check(stick.bulk_out(2, b"not a command") is True and stick.in_transfer(1, 13, 512) is None,
      "an OUT that is not a command block is taken and ignored (nothing to read)")
reader = VirtualStick(images[12], no_medium=True)
_d, csw = command([0, 0, 0, 0, 0, 0], 0, reader)
check(csw[12] == 1 and sense(reader) == (2, 0x3A), "a card reader without a card: not ready, 2/3A")
tag[0] += 1
cbw = b"USBC" + tag[0].to_bytes(4, "little") + (512).to_bytes(4, "little") + bytes([0x80, 0, 10, 0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0]) + bytes(6)
stick.bulk_out(2, cbw)
stick.halt_cleared(0x81)
data = stick.in_transfer(1, 512, 512)
check(data == bytes(images[16][:512]) and stick.in_transfer(1, 13, 512) is HALTED and stick.in_transfer(1, 13, 512) is None,
      "a CLEAR_FEATURE(ENDPOINT_HALT) on its bulk IN in a command's middle: the data still comes, the status stalls "
      "(as a real stick's)")
plain = VirtualStick()
check(plain.bulk_out(2, cbw) is None and plain.in_transfer(1, 13, 512) is None,
      "without an image its bulk endpoints answer NAK (a driver waits at its first command)")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] all FAT image and virtual stick checks")
