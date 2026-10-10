#!/usr/bin/env python3
"""Check the first 10 implemented VMX128 families against exact 17559 bytes.

This is NOT a Ghidra Sleigh compilation or numeric p-code proof.
It verifies raw instruction encodings and bit-field decoding against the
known instruction/error sites recovered from two Ghidra .gzf archives.
"""
import hashlib
import struct
import sys
from collections import Counter
from pathlib import Path

BASE=0x80040000
TEXT_START=0x21000
TEXT_END=0x1216c8
EXPECTED_SHA={
    "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8",
    "1c6113602af25b0762fb10dfb0d7ad5c7fef1c7268826982188979b9bb2e4d85",
}
EXPECTED_COUNTS={
    "lvx128":269,"lvlx":127,"lvrx":15,"vupkd3d128":11,
    "stvx128":77,"vor128":15,"vmulfp128":135,"vmsum4fp128":84,
    "vpermwi128":16,"vrlimi128":91,
}
CASES={
    0x80144da0:("lvx128",0x10ebe8c3),
    0x80143584:("lvx128",0x11a058c3),
    0x80141e6c:("lvx128",0x1140d8c3),
    0x80141b40:("lvlx",0x7db8540e),
    0x8013140c:("lvx128",0x100048c3),
    0x80131240:("lvx128",0x118048c3),
    0x8012d3d0:("lvx128",0x100018c3),
    0x8012d080:("lvx128",0x100058c3),
    0x8012cf1c:("lvlx",0x7d605c0e),
    0x800ce9a4:("vupkd3d128",0x192467f0),
    0x800cd580:("lvlx",0x7d405c0e),
    0x800cd3e4:("lvlx",0x7c00540e),
    0x800cc918:("lvx128",0x100058c3),
    0x800cc17c:("lvx128",0x112058c3),
    0x800cbee0:("lvx128",0x1005d8c3),
    0x800bd030:("lvrx",0x7dab244e),
    0x80145000:("vpermwi128",0x196e6290),
    0x80144efc:("vpermwi128",0x192e6a90),
    0x80144e90:("vpermwi128",0x19ae6a90),
    0x80141ed8:("vmsum4fp128",0x142c01d0),
    0x80141bc4:("vmsum4fp128",0x17cc01d0),
    0x801314a0:("vmulfp128",0x14290090),
    0x801312d0:("vmulfp128",0x14e75890),
    0x8012d3dc:("vmulfp128",0x15a06890),
    0x8012d088:("stvx128",0x100759c3),
    0x800ce9e0:("vrlimi128",0x180417d0),
    0x800cd594:("vrlimi128",0x180467d0),
    0x800cd3f0:("vrlimi128",0x180467d0),
    0x800bd040:("vor128",0x17806adc),
}

def classify(word):
    op=word>>26
    if op==4:
        selector=(word>>3)&255
        if word&3==3 and selector in (24,25):return "lvx128"
        if word&3==3 and selector in (56,57):return "stvx128"
    if op==31 and not(word&1):
        xo=(word>>1)&1023
        if xo==519:return "lvlx"
        if xo==551:return "lvrx"
    if op==5 and (word>>4)&1:
        return {2:"vmulfp128",7:"vmsum4fp128",11:"vor128"}.get((word>>6)&15)
    if op==6:
        if ((word>>3)&255) in (254,255):return "vupkd3d128"
        if ((word>>9)&3)==1 and ((word>>4)&3)==1:return "vpermwi128"
        if ((word>>8)&7)==7 and ((word>>4)&3)==1:return "vrlimi128"
    return None

def reg_dest(word):
    return (word>>21)&31 | ((word>>2)&3)<<5

def reg_source_b(word):
    return (word>>11)&31 | (word&3)<<5

def reg_source_a(word):
    return (word>>16)&31 | ((word>>5)&1)<<5 | ((word>>10)&1)<<6

def validate(path):
    data=Path(path).read_bytes()
    digest=hashlib.sha256(data).hexdigest()
    assert len(data)==0x1b0000 and digest in EXPECTED_SHA, (len(data),digest)
    counts=Counter()
    for off in range(TEXT_START,TEXT_END,4):
        word,=struct.unpack_from(">I",data,off)
        name=classify(word)
        if name:counts[name]+=1
    for name,expected in EXPECTED_COUNTS.items():
        actual=counts[name]
        print(f"{name:15s} {actual:4d} raw encodings (expected {expected})")
        assert actual==expected, (name,actual,expected)
    assert len(CASES)==29
    for address,(expected,expected_word) in sorted(CASES.items()):
        word,=struct.unpack_from(">I",data,address-BASE)
        found=classify(word)
        assert word==expected_word and found==expected, (hex(address),hex(word),found,expected)
        if expected in ("lvx128","stvx128","vor128","vmulfp128","vmsum4fp128","vpermwi128","vrlimi128","vupkd3d128"):
            assert reg_dest(word) in range(128)
        if expected in ("vor128","vmulfp128","vmsum4fp128"):
            assert reg_source_a(word) in range(128)
        if expected in ("vor128","vmulfp128","vmsum4fp128","vpermwi128","vrlimi128","vupkd3d128"):
            assert reg_source_b(word) in range(128)
        print(f"  0x{address:08X} {word:08X} {expected}")
    print("PASS: 29/29 archived instruction words match the expected decoder families")
    print("This only proves raw masks; run Ghidra SleighCompile and live decoder tests.")

if __name__=="__main__":
    if len(sys.argv)!=2:
        raise SystemExit("Usage: python validate_xenon_sleigh_patterns_v2.py <verified-17559-kernel.exe>")
    validate(sys.argv[1])
