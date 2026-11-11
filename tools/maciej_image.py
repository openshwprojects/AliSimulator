"""Inspect and replace the maincode in maciej_333's Opticum HD N2 dump.

This is deliberately specific to its 4 MiB M3801 flash layout.  It never
changes the bootloader, HDCP chunk, radio background, or databases.  Header
integers and CRCs are big endian, while the LZMA-alone size is little endian.
See refs/BootLoader/inc/api/libchunk/chunk.h and loader3/bootloader.c.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import lzma
from pathlib import Path
import struct

FLASH_SIZE = 0x400000
MAIN_OFFSET = 0x50000
MAIN_SPAN = 0x240000
HEADER_SIZE = 128
SECTOR_SIZE = 0x10000
LOAD_ADDRESS = 0x80000200
NO_CRC = 0x4E435243
MAX_APP_SIZE = 0x800000  # Keeps the application clear of the loader's 10 MiB scratch area.
ORIGINAL_SHA256 = "806044f3b831497a23214256edf67f655418ab74995c0a34bb2b518fd8e24c5e"


def _crc_table() -> tuple[int, ...]:
    result = []
    for index in range(256):
        crc = index << 24
        for _ in range(8):
            crc = ((crc << 1) ^ (0x04C11DB7 if crc & 0x80000000 else 0)) & 0xFFFFFFFF
        result.append(crc)
    return tuple(result)


_CRC_TABLE = _crc_table()


def crc32_mpeg2(data: bytes, initial: int = 0xFFFFFFFF) -> int:
    """ALi MG_Table_Driven_CRC: poly 04C11DB7, no reflection/final xor."""
    crc = initial
    for byte in data:
        crc = ((crc << 8) ^ _CRC_TABLE[(crc >> 24) ^ byte]) & 0xFFFFFFFF
    return crc


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Chunk:
    offset: int
    chunk_id: int
    length: int
    span: int
    crc: int
    name: str
    load_address: int
    entry_address: int

    @property
    def data_end(self) -> int:
        return self.offset + 16 + self.length

    def as_dict(self) -> dict:
        return {
            "offset": self.offset, "id": self.chunk_id, "length": self.length,
            "span": self.span, "crc": self.crc, "name": self.name,
            "load_address": self.load_address, "entry_address": self.entry_address,
        }


def split_flash(image: bytes) -> tuple[bytes, int | None]:
    """Strip and verify the optional dump command's four-byte BE CRC."""
    if len(image) not in (FLASH_SIZE, FLASH_SIZE + 4):
        raise ValueError(f"expected 0x400000 or 0x400004 bytes, got {len(image):#x}")
    flash = image[:FLASH_SIZE]
    trailer = None
    if len(image) == FLASH_SIZE + 4:
        trailer = int.from_bytes(image[-4:], "big")
        if crc32_mpeg2(flash) != trailer:
            raise ValueError("UART dump CRC trailer does not match flash contents")
    return flash, trailer


def parse_chunks(flash: bytes, *, verify_crc: bool = True) -> list[Chunk]:
    chunks = []
    offset = 0
    while offset + HEADER_SIZE <= len(flash):
        chunk_id, length, span, crc = struct.unpack_from(">4I", flash, offset)
        if chunk_id in (0, 0xFFFFFFFF):
            raise ValueError(f"missing chunk header at {offset:#x}")
        if span and (span < HEADER_SIZE or offset + span > len(flash)):
            raise ValueError(f"invalid next-chunk span at {offset:#x}")
        end = offset + length + 16
        if end > len(flash) or (span and end > offset + span):
            raise ValueError(f"chunk data overruns its allocation at {offset:#x}")
        if crc != NO_CRC and verify_crc and crc32_mpeg2(flash[offset + 16:end]) != crc:
            raise ValueError(f"chunk CRC mismatch at {offset:#x}")
        name = flash[offset + 16:offset + 32].split(b"\x00")[0].rstrip(b"\xff").decode("ascii", "replace")
        load, entry = struct.unpack_from(">2I", flash, offset + 120)
        if load in (0, 0xFFFFFFFF):
            load = LOAD_ADDRESS
        if entry in (0, 0xFFFFFFFF):
            entry = load
        chunks.append(Chunk(offset, chunk_id, length, span, crc, name, load, entry))
        if not span:
            return chunks
        offset += span
    raise ValueError("chunk chain does not terminate within flash")


def validate_image(image: bytes) -> tuple[bytes, list[Chunk], int | None]:
    flash, trailer = split_flash(image)
    chunks = parse_chunks(flash)
    expected = [(0, 0x23010010), (0x4FE00, 0x09F60100),
                (MAIN_OFFSET, 0x01FE0101), (0x290000, 0x02FD0100),
                (0x2A0000, 0x03FC0100), (0x2BFF80, 0x04FB0100)]
    if [(c.offset, c.chunk_id) for c in chunks] != expected or chunks[2].span != MAIN_SPAN:
        raise ValueError("image does not have dump_maciej.bin's expected chunk layout")
    return flash, chunks, trailer


def extract_application(image: bytes) -> bytes:
    flash, chunks, _ = validate_image(image)
    chunk = chunks[2]
    stream = flash[chunk.offset + HEADER_SIZE:chunk.data_end]
    if len(stream) < 13 or stream[0] >= 225:
        raise ValueError("invalid LZMA header")
    size = int.from_bytes(stream[5:13], "little")
    if not 0 < size <= MAX_APP_SIZE:
        raise ValueError("invalid or unknown LZMA uncompressed size")
    prop = stream[0]
    # The legacy loader reads the known size and decodes the raw range stream.
    # Reproduce that behavior: liblzma's ALONE wrapper rejects a known-size
    # stream carrying Python's optional end marker, although the ALi decoder
    # stops at the known size and successfully boots that stream.
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{
        "id": lzma.FILTER_LZMA1, "lc": prop % 9,
        "lp": (prop // 9) % 5, "pb": prop // 45,
        "dict_size": int.from_bytes(stream[1:5], "little"),
    }])
    result = decoder.decompress(stream[13:], max_length=size)
    if len(result) != size:
        raise ValueError("LZMA stream is shorter than its declared uncompressed size")
    return result


@dataclass(frozen=True)
class PackageResult:
    flash: bytes
    payload: bytes
    flash_offset: int
    chunk: Chunk
    manifest: dict


def package_image(original: bytes, application: bytes) -> PackageResult:
    """Replace maincode, retaining all bytes beyond the new compressed stream.

    `flash` is a raw 4 MiB simulator/programmer image (no UART CRC trailer).
    `payload` starts at flash_offset and is padded to a 64 KiB sector with
    unchanged source bytes.  Classic bootloader transfer uses header span to
    preserve the remaining original maincode allocation in its RAM buffer.
    """
    flash, chunks, trailer = validate_image(original)
    old = chunks[2]
    if not application or len(application) > MAX_APP_SIZE:
        raise ValueError(f"application must contain 1..{MAX_APP_SIZE:#x} bytes")
    if old.load_address != LOAD_ADDRESS or old.entry_address != LOAD_ADDRESS:
        raise ValueError("this packager expects application load and entry at 0x80000200")
    # Match the stock lc=0, lp=2, pb=2 probabilities: the loader allocates a
    # fixed decoder work buffer which may be too small for Python defaults.
    stream = bytearray(lzma.compress(application, format=lzma.FORMAT_ALONE, filters=[{
        "id": lzma.FILTER_LZMA1, "dict_size": 0x800000, "lc": 0, "lp": 2, "pb": 2,
    }]))
    # This old decoder needs a known size; Python normally writes FFFF... .
    stream[5:13] = len(application).to_bytes(8, "little")
    total = HEADER_SIZE + len(stream)
    if total > old.span:
        raise ValueError(f"compressed maincode ({total:#x} bytes) exceeds {old.span:#x}-byte allocation")
    updated = bytearray(flash)
    updated[MAIN_OFFSET + HEADER_SIZE:MAIN_OFFSET + total] = stream
    struct.pack_into(">I", updated, MAIN_OFFSET + 4, total - 16)
    crc = crc32_mpeg2(updated[MAIN_OFFSET + 16:MAIN_OFFSET + total])
    struct.pack_into(">I", updated, MAIN_OFFSET + 12, crc)
    result = bytes(updated)
    payload_size = (total + SECTOR_SIZE - 1) // SECTOR_SIZE * SECTOR_SIZE
    payload = result[MAIN_OFFSET:MAIN_OFFSET + payload_size]
    new = Chunk(MAIN_OFFSET, old.chunk_id, total - 16, old.span, crc,
                old.name, old.load_address, old.entry_address)
    manifest = {
        "format": "maciej-maincode-v1", "input_sha256": sha256(original),
        "input_uart_crc": trailer, "flash_sha256": sha256(result),
        "flash_size": len(result), "flash_offset": MAIN_OFFSET,
        "payload_size": len(payload), "payload_sha256": sha256(payload),
        "application_size": len(application), "application_sha256": sha256(application),
        "compressed_size": len(stream), "load_address": old.load_address,
        "entry_address": old.entry_address, "chunk": new.as_dict(),
        "preserved_prefix_sha256": sha256(result[:MAIN_OFFSET]),
        "preserved_suffix_sha256": sha256(result[MAIN_OFFSET + MAIN_SPAN:]),
        "lzma": {"lc": 0, "lp": 2, "pb": 2, "dictionary_size": 0x800000},
    }
    return PackageResult(result, payload, MAIN_OFFSET, new, manifest)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="verify dump CRC and chunk CRCs; print layout")
    inspect.add_argument("image", type=Path)
    pack = sub.add_parser("pack", help="replace maincode in a copy of the original dump")
    pack.add_argument("--dump", type=Path, default=Path(__file__).resolve().parents[1] / "dumps/dump_maciej.bin")
    pack.add_argument("--app", type=Path, required=True, help="raw MIPS32 little-endian code linked at 0x80000200")
    pack.add_argument("--output", type=Path, required=True, help="raw 4 MiB output flash image")
    pack.add_argument("--payload", type=Path, help="default: OUTPUT stem + .maincode.bin")
    pack.add_argument("--manifest", type=Path, help="default: OUTPUT stem + .json")
    args = parser.parse_args()
    try:
        if args.command == "inspect":
            image = args.image.read_bytes()
            flash, chunks, trailer = validate_image(image)
            application = extract_application(flash)
            print(json.dumps({"size": len(image), "sha256": sha256(image),
                              "uart_crc": trailer, "application_size": len(application),
                              "chunks": [c.as_dict() for c in chunks]}, indent=2))
            return
        payload_path = args.payload or args.output.with_suffix(".maincode.bin")
        manifest_path = args.manifest or args.output.with_suffix(".json")
        outputs = [args.output, payload_path, manifest_path]
        resolved = [p.resolve() for p in outputs]
        inputs = {args.dump.resolve(), args.app.resolve()}
        if len(set(resolved)) != len(resolved) or any(p in inputs for p in resolved):
            raise ValueError("output files must be distinct and must not overwrite either input")
        packaged = package_image(args.dump.read_bytes(), args.app.read_bytes())
        for path in outputs:
            path.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(packaged.flash)
        payload_path.write_bytes(packaged.payload)
        manifest_path.write_text(json.dumps(packaged.manifest, indent=2) + "\n", encoding="utf-8")
        print(f"Flash: {args.output} ({len(packaged.flash):#x} bytes)")
        print(f"Maincode: {payload_path} ({len(packaged.payload):#x} bytes at {MAIN_OFFSET:#x})")
        print(f"Manifest: {manifest_path}")
    except (ValueError, OSError, lzma.LZMAError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
