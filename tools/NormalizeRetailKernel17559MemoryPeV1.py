#!/usr/bin/env python3
"""Convert verified retail 17559 kernel *memory-image* PE to a disk-layout PE.

Only rewrites the five COFF PointerToRawData DWORDs whose embedded file offsets
differ from the actual bytes in the firmware-derived full memory image.
Source is never modified. The result imports through Ghidra's regular PE loader.
Alternatively, import the original image with Xbox360RetailKernelMemoryPeLoader.
"""
from pathlib import Path
import argparse
import hashlib
import struct

SOURCE_SHA256 = "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8"
OUTPUT_SHA256 = "1c6113602af25b0762fb10dfb0d7ad5c7fef1c7268826982188979b9bb2e4d85"
PATCHES = {
    ".xedata": (0x20000, 0x1B400),
    ".text": (0x21000, 0x1C400),
    ".data": (0x130000, 0x11CC00),
    "PROTDATA": (0x170000, 0x129A00),
    "CLRDATAA": (0x180000, 0x139600),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    original = args.source.read_bytes()
    actual = hashlib.sha256(original).hexdigest()
    if actual != SOURCE_SHA256 or len(original) != 0x1B0000:
        raise ValueError("Not the exact verified retail 17559 kernel memory image: " + actual)
    data = bytearray(original)
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
        raise ValueError("Invalid embedded PE signature")
    if struct.unpack_from("<H", data, pe_offset+4)[0] != 0x01F2:
        raise ValueError("Unexpected PE machine")
    section_count = struct.unpack_from("<H", data, pe_offset+6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset+20)[0]
    section_table = pe_offset + 24 + optional_size
    changed = set()
    for index in range(section_count):
        entry = section_table + index*40
        name = data[entry:entry+8].split(b"\x00", 1)[0].decode("ascii")
        virtual_size, rva, raw_size, raw_pointer = struct.unpack_from("<IIII", data, entry+8)
        if name in PATCHES:
            expected_rva, expected_raw = PATCHES[name]
            if (rva, raw_pointer) != (expected_rva, expected_raw):
                raise ValueError("Unexpected section mapping for " + name)
            if rva + raw_size > len(original):
                raise ValueError("Section outside memory image: " + name)
            struct.pack_into("<I", data, entry+20, rva)
            changed.add(name)
        elif raw_pointer != rva:
            raise ValueError("Unexpected non-identity section mapping: " + name)
    if changed != set(PATCHES):
        raise ValueError("Missing expected PE sections: " + str(set(PATCHES)-changed))
    resulting_sha = hashlib.sha256(data).hexdigest()
    if resulting_sha != OUTPUT_SHA256:
        raise ValueError("Normalized PE digest unexpectedly changed: " + resulting_sha)
    if args.source.resolve() == args.destination.resolve():
        raise ValueError("Refusing to overwrite original firmware image")
    args.destination.write_bytes(data)
    print("Normalized kernel PE:", args.destination)
    print("SHA256:", resulting_sha)
    print("Changed only ten section-header bytes, no section payload bytes")


if __name__ == "__main__":
    main()
