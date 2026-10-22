#!/usr/bin/env python3
"""Guard Xenon-specific PowerPC Book III 2.02 tlbiel RB,L source generation.

A static preflight only. The normal Gradle verifyXenonSleigh compiles actual
SLEIGH, and the separate Ghidra p-code witness checks installed semantics.
The purpose is to prevent POWER ISA 3.0's RS/RIC/PRS/R interpretation from
overriding the Xbox 360 hypervisor's immediate L selector.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
ISA = ROOT / "data/languages/xenon_ppc_isa.sinc"
INSTRUCTIONS = ROOT / "data/languages/xenon_ppc_instructions.sinc"

# 17559 native HV address 0x000003B4, legacy RB=r3,L=1.
HV_L1 = 0x7C201A24
L0_R3 = 0x7C001A24
L1_R4 = 0x7C202224
INVALID_RESERVED_FIELD = 0x7C401A24


def decode_legacy(word):
    """Decode relevant 2.02 X-form bits, without interpreting ISA 3 fields."""
    return {
        "op": (word >> 26) & 63,
        "l": (word >> 21) & 31,
        "reserved": (word >> 16) & 31,
        "rb": (word >> 11) & 31,
        "xo": (word >> 1) & 1023,
        "rc": word & 1,
    }


class XenonTlbielLegacyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.isa = ISA.read_text(encoding="utf-8")
        cls.instructions = INSTRUCTIONS.read_text(encoding="utf-8")

    def test_exact_native_17559_and_other_field_examples(self):
        self.assertEqual(decode_legacy(HV_L1),
                         dict(op=31, l=1, reserved=0, rb=3, xo=274, rc=0))
        self.assertEqual(decode_legacy(L0_R3),
                         dict(op=31, l=0, reserved=0, rb=3, xo=274, rc=0))
        self.assertEqual(decode_legacy(L1_R4),
                         dict(op=31, l=1, reserved=0, rb=4, xo=274, rc=0))
        self.assertEqual(decode_legacy(INVALID_RESERVED_FIELD)["l"], 2)

    def test_legacy_l1_single_constructor_with_explicit_flag(self):
        constructors = re.findall(r"(?m)^:tlbiel\s+[^\n]+", self.isa)
        self.assertEqual(len(constructors), 1, constructors)
        self.assertRegex(constructors[0],
            r'^:tlbiel RB_OR_ZERO,"1" is \$\(NOTVLE\) & OP=31'
            r' & BITS_21_25=1 & BITS_16_20=0 & RB_OR_ZERO'
            r' & XOP_1_10=274 & BIT_0=0')
        self.assertIn("TLBInvalidateEntryLocal(RB_OR_ZERO,1:1);",
                      self.isa)

    def test_original_l0_has_explicit_page_size_in_shared_userop(self):
        old_forms = re.findall(r"(?m)^:tlbiel\s+[^\n]+", self.instructions)
        self.assertEqual(len(old_forms), 1, old_forms)
        self.assertIn("BITS_21_25=0", old_forms[0])
        self.assertIn("BITS_16_20=0", old_forms[0])
        self.assertIn("TLBInvalidateEntryLocal(RB_OR_ZERO,0:1);",
                      self.instructions)
        self.assertNotIn("TLBInvalidateEntryLocal(RB_OR_ZERO);",
                         self.instructions)

    def test_no_isa3_pid_ric_prs_r_interpretation_survives(self):
        self.assertNotIn(":tlbiel RB_OR_ZERO,RS_OR_ZERO,", self.isa)
        self.assertNotIn("TLBInvalidateEntryLocal(RB_OR_ZERO,RS_OR_ZERO,",
                         self.isa)
        # The original opaque userop declaration remains available.
        self.assertIn("define pcodeop TLBInvalidateEntryLocal;",
                      self.instructions)


if __name__ == "__main__":
    unittest.main()
