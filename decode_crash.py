"""Decode specific MIPS16 instructions at crash site."""
from mips16_decoder import MIPS16Decoder

instructions = [
    (0x81E87A70, b'\x1f\x22'), # 221F
    (0x81E87A72, b'\x01\x6c'), # 6C01
    (0x81E87A74, b'\x43\x1b'), # 1B43
    (0x81E87A76, b'\x4d\x1d'), # 1D4D
    (0x81E87A78, b'\x00\x65'), # 6500
    (0x81E87A7A, b'\x30\xf0'), # F030
]

print("Decoding crash site instructions:")
for addr, chunk in instructions:
    mnemonic, operands = MIPS16Decoder.decode(chunk)
    # Note: Little endian input to decoder? Decoder expects bytes.
    # The decoder likely handles byte order if it takes bytes.
    print(f"0x{addr:08X}: {chunk.hex()} -> {mnemonic} {operands}")
