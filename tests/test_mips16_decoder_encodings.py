"""
Test: MIPS16e decoder against known encodings.

Covers the encodings that were decoded wrongly before (RRI-A opcode 0x08,
the shift function codes, RRR SUBU, the JR/JALR/JRC/JALRC family, ADDIU8 sign
extension and MOV32R) plus a few 4-byte forms (JAL, JALX, EXTENDed LW) taken
from the firmware.  Ghidra output was the reference for the operands.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from mips16_decoder import MIPS16Decoder

# (bytes as found in memory, address, expected mnemonic, expected operands)
CASES = [
    (b'\x2f\x41', 0, 'addiu', 's1,s1,-0x1'),        # RRI-A: rx=s1 ry=s1 imm4=0xF
    (b'\x41\x42', 0, 'addiu', 'v0,v0,0x1'),         # RRI-A: imm4=1
    (b'\x72\x32', 0, 'srl', 'v0,v1,4'),             # SHIFT f=2
    (b'\x73\x32', 0, 'sra', 'v0,v1,4'),             # SHIFT f=3
    (b'\x8b\xe3', 0, 'subu', 'v0,v1,a0'),           # RRR f=3
    (b'\x00\xe8', 0, 'jr', 's0'),                   # RR funct 0, variant 0
    (b'\x20\xe8', 0, 'jr', 'ra'),                   # variant 1
    (b'\x40\xea', 0, 'jalr', 'v0'),                 # variant 2
    (b'\x80\xe8', 0, 'jrc', 's0'),                  # variant 4
    (b'\xa0\xe8', 0, 'jrc', 'ra'),                  # variant 5
    (b'\xc0\xea', 0, 'jalrc', 'v0'),                # variant 6
    (b'\x3c\x65', 0, 'move', 't9,a0'),              # I8 MOV32R
    (b'\x22\x67', 0, 'move', 's1,v0'),              # I8 MOVR32
    (b'\xff\x4a', 0, 'addiu', 'v0,-0x1'),           # ADDIU8 negative
    (b'\x24\x4c', 0, 'addiu', 'a0,0x24'),           # ADDIU8 positive
    (b'\x01\x6a', 0, 'li', 'v0,0x1'),
    (b'\x03\x2a', 0x81E87110, 'bnez', 'v0,0x81e87118'),
    (b'\x43\x1b\x24\x26', 0x81E87108, 'jal', '0x81e89890'),
    (b'\x43\x1f\xd9\x41', 0x81E88B18, 'jalx', '0x81e90764'),
    (b'\x10\xf1\x00\x9a', 0x81E86860, 'lw', 's0,-0x7f00(v0)'),   # EXTEND + LW
    (b'\x40\xf4\x18\x6e', 0x81E87104, 'li', 'a2,0x458'),         # EXTEND + LI
]


def main():
    print("=== Test: MIPS16 decoder encodings ===")
    fails = 0
    for raw, addr, mnem, ops in CASES:
        got = MIPS16Decoder.decode(raw, addr)
        ok = got == (mnem, ops)
        fails += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {raw.hex(' '):12s} -> {got[0]} {got[1]}"
              + ("" if ok else f"   (expected {mnem} {ops})"))
    if fails:
        print(f"\n\033[91m{fails} of {len(CASES)} encodings decoded wrongly\033[0m")
        sys.exit(1)
    print(f"\n\033[92mAll {len(CASES)} encodings decoded correctly\033[0m")
    sys.exit(0)


if __name__ == "__main__":
    main()
