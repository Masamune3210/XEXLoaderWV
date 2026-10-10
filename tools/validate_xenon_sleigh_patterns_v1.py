#!/usr/bin/env python3
"""Strict corpus test for the four Xenon SLEIGH patterns added in v1.

Matches opcode masks independently of Ghidra. This does NOT compile the
.slaspec or validate its runtime p-code; the actual Ghidra test is separate.
"""
import hashlib
import struct
import sys
from pathlib import Path

BASE = 0x80040000
IMAGE_SIZE = 0x1B0000
TEXT_RVA = 0x21000
TEXT_SIZE = 0x1006C8
ACCEPTED_SHA256 = {
    "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8",
    "1c6113602af25b0762fb10dfb0d7ad5c7fef1c7268826982188979b9bb2e4d85",
}
EXPECTED_COUNTS = {
    "lvx128": 269,
    "lvlx": 127,
    "lvrx": 15,
    "vupkd3d128": 11,
}
BOOKMARKS = {
    0x80144DA0:"lvx128", 0x80143584:"lvx128", 0x80141E6C:"lvx128",
    0x80141B40:"lvlx", 0x8013140C:"lvx128", 0x80131240:"lvx128",
    0x8012D3D0:"lvx128", 0x8012D080:"lvx128", 0x8012CF1C:"lvlx",
    0x800CE9A4:"vupkd3d128", 0x800CD580:"lvlx", 0x800CD3E4:"lvlx",
    0x800CC918:"lvx128", 0x800CC17C:"lvx128", 0x800CBEE0:"lvx128",
    0x800BD030:"lvrx",
}

def decode(word):
    op = word >> 26
    xo = (word >> 1) & 1023
    if op == 4 and ((word >> 3) & 255) in (24, 25) and (word & 3) == 3:
        return "lvx128"
    if op == 31 and (word & 1) == 0:
        if xo == 519:
            return "lvlx"
        if xo == 551:
            return "lvrx"
    if op == 6 and ((word >> 3) & 255) in (254, 255):
        return "vupkd3d128"
    return None

def vector_dest(word):
    return ((word >> 21) & 31) | (((word >> 2) & 3) << 5)

def vector_source(word):
    return ((word >> 11) & 31) | ((word & 3) << 5)

def run(path):
    image = Path(path).read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest not in ACCEPTED_SHA256 or len(image) != IMAGE_SIZE:
        raise ValueError("Not the exact verified/normalized 17559 kernel image: "+digest)
    hits = {k:[] for k in EXPECTED_COUNTS}
    for off in range(TEXT_RVA, TEXT_RVA+TEXT_SIZE, 4):
        word, = struct.unpack_from(">I", image, off)
        name = decode(word)
        if name:
            hits[name].append(BASE+off)
    for mnemonic, expected in EXPECTED_COUNTS.items():
        actual = len(hits[mnemonic])
        print(f"{mnemonic:<13} encodings={actual:4d} expected={expected:4d}")
        if actual != expected:
            raise AssertionError(f"Instruction pattern count drift: {mnemonic}")
    for va, expected in sorted(BOOKMARKS.items()):
        word, = struct.unpack_from(">I", image, va-BASE)
        decoded = decode(word)
        assert decoded == expected, (hex(va), hex(word), decoded, expected)
        if decoded in ("lvx128", "vupkd3d128"):
            assert 0 <= vector_dest(word) <= 127
        if decoded == "vupkd3d128":
            assert 0 <= vector_source(word) <= 127
        print(f"  0x{va:08X}: {word:08X} {decoded}")
    print("PASS: 16/16 bookmarked opcode words recognized; " +
          f"{sum(map(len,hits.values()))} matching encoding words in verified .text.")
    print("NOTE: full opcode semantics / Ghidra SLEIGH compilation are NOT tested.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python validate_xenon_sleigh_patterns_v1.py <verified-kernel.exe>")
    run(sys.argv[1])
