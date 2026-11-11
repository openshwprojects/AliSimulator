"""Packaging checks against the real dump; no flash device is opened."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.maciej_image import (
    FLASH_SIZE, HEADER_SIZE, MAIN_OFFSET, MAIN_SPAN, ORIGINAL_SHA256,
    crc32_mpeg2, extract_application, package_image, sha256, validate_image,
)


class MaciejImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = (Path(__file__).resolve().parents[1] / "dumps/dump_maciej.bin").read_bytes()
        cls.flash, cls.chunks, cls.trailer = validate_image(cls.original)
        cls.app1 = b"\x00\x00\x00\x00" * 32 + b"MACIEJ APP v1\0"
        cls.app2 = b"\x00\x00\x00\x00" * 32 + b"MACIEJ APP v2\0"
        cls.first = package_image(cls.flash, cls.app1)

    def test_original_checksum_and_layout(self):
        self.assertEqual(sha256(self.original), ORIGINAL_SHA256)
        self.assertEqual(self.trailer, 0x5FE32852)
        self.assertEqual(crc32_mpeg2(b"123456789"), 0x0376E6E7)
        main = self.chunks[2]
        self.assertEqual((main.offset, main.span, main.length, main.crc),
                         (MAIN_OFFSET, MAIN_SPAN, 0x1AED30, 0x599F97A7))
        self.assertEqual(len(extract_application(self.flash)), 0x6F37C0)

    def test_package_roundtrip_and_preservation(self):
        result = self.first
        self.assertEqual(len(result.flash), FLASH_SIZE)
        self.assertEqual(extract_application(result.flash), self.app1)
        self.assertEqual(result.flash[:MAIN_OFFSET], self.flash[:MAIN_OFFSET])
        self.assertEqual(result.flash[result.chunk.data_end:], self.flash[result.chunk.data_end:])
        self.assertEqual(result.flash_offset, MAIN_OFFSET)
        self.assertEqual(result.payload, result.flash[MAIN_OFFSET:MAIN_OFFSET + len(result.payload)])
        self.assertEqual(len(result.payload) % 0x10000, 0)
        header = result.flash[MAIN_OFFSET:MAIN_OFFSET + HEADER_SIZE]
        self.assertEqual(header[8:12], self.flash[MAIN_OFFSET + 8:MAIN_OFFSET + 12])
        self.assertEqual(header[16:], self.flash[MAIN_OFFSET + 16:MAIN_OFFSET + HEADER_SIZE])
        stream = result.flash[MAIN_OFFSET + HEADER_SIZE:result.chunk.data_end]
        self.assertEqual(stream[0], 0x6C)
        self.assertEqual(int.from_bytes(stream[5:13], "little"), len(self.app1))

    def test_second_update_preserves_bootloader_and_other_chunks(self):
        second = package_image(self.first.flash, self.app2)
        self.assertEqual(extract_application(second.flash), self.app2)
        self.assertEqual(second.flash[:MAIN_OFFSET], self.flash[:MAIN_OFFSET])
        self.assertEqual(second.flash[MAIN_OFFSET + MAIN_SPAN:], self.flash[MAIN_OFFSET + MAIN_SPAN:])

    def test_corrupt_data_is_rejected(self):
        broken = bytearray(self.flash)
        broken[MAIN_OFFSET + HEADER_SIZE + 17] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC mismatch"):
            package_image(bytes(broken), self.app1)
        with self.assertRaisesRegex(ValueError, "CRC trailer"):
            validate_image(self.original[:-1] + bytes([self.original[-1] ^ 1]))

    def test_invalid_inputs_are_rejected(self):
        with self.assertRaises(ValueError):
            package_image(self.flash[:-1], self.app1)
        with self.assertRaises(ValueError):
            package_image(self.flash, b"")
        # Span is excluded from CRC; malformed chains still must be rejected.
        broken = bytearray(self.flash)
        struct.pack_into(">I", broken, MAIN_OFFSET + 8, 0x400000)
        with self.assertRaises(ValueError):
            package_image(bytes(broken), self.app1)


if __name__ == "__main__":
    unittest.main()
