"""Static generated-SLEIGH CR0 guard and mathematical SF=0 witnesses.

This is NOT a replacement for SleighCompile or the private original-byte emulator.
The Gradle verifier runs this after prepareXenonCommon and before packaging.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
LANG = ROOT / "data" / "languages" / "xenon_ppc_common.sinc"


def classify(value, bits):
    value &= (1 << bits) - 1
    return 2 if value == 0 else (8 if value >> (bits - 1) else 4)


def main():
    text = LANG.read_text(encoding="utf-8")
    matches = re.findall(r"(?ms)^macro cr0flags\\(result \\) \\{\\n.*?^\\}", text)
    assert len(matches) == 1, "Expected exactly one generated cr0flags macro"
    macro = matches[0]
    for token in (
        "local crFullResult:$(REGISTER_SIZE) = zext(result);",
        "local crResult32:4 = crFullResult:4;",
        "setCrBit(cr0, 0, (crResult32 s< 0));",
        "setCrBit(cr0, 1, (crResult32 s> 0));",
        "setCrBit(cr0, 2, (crResult32 == 0));",
        "setCrBit(cr0, 3, (xer_so & 1));",
    ):
        assert token in macro, ("Missing Xenon CR0 operation", token)
    for old in ("(result s< 0)", "(result s> 0)", "(result == 0)"):
        assert old not in macro, ("Stock full-width CR0 operation remains", old)
    # Model-level witnesses: each retains a nonzero high GPR half but
    # has a zero low word, producing GT in full64 and EQ in fixed SF=0.
    witnesses = {
        0x80080CB4: 0x20000000000,
        0x80083AF0: 0x400000000000,
        0x800925E4: 0x800000000,
        0x800A81E8: 0x1000000000,
        0x8010BF8C: 0x100000000000000,
    }
    for site, value in witnesses.items():
        assert (value >> 32) != 0 and (value & 0xFFFFFFFF) == 0, hex(site)
        assert classify(value, 64) == 4, hex(site)
        assert classify(value, 32) == 2, hex(site)
    print("XENON_CR0_SF0_STATIC_OK", len(witnesses), "model witnesses")


if __name__ == "__main__":
    main()
