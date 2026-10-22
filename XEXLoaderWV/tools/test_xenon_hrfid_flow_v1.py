#!/usr/bin/env python3
"""Fail-closed static guard for the generated Xenon hrfid control flow.

The task-private PyGhidra comparison already compiled and exercised both
variants against original HV17559 bytes 4c000224 802d002c (2026-10-22).
This offline build guard makes future Gradle builds reject regressions to an
opaque hrfid that falls through. Real Sleigh compilation is a separate,
mandatory Gradle build step.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
ISA = ROOT / "data/languages/xenon_ppc_isa.sinc"
COMMON = ROOT / "data/languages/xenon_ppc_common.sinc"
SPEC = ROOT / "data/languages/xenon_64_be.slaspec"
SOURCE_PATTERN = re.compile(
    r"(?m)^:hrfid\s+is\s+\$\(NOTVLE\)\s*&\s*OP=19"
    r"\s*&\s*XOP_1_10=274\s*&\s*BITS_11_25=0"
    r"\s*&\s*BIT_0=0\s*\{([^}]*)\}"
)


class XenonHrfidFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.isa = ISA.read_text(encoding="utf-8")
        cls.common = COMMON.read_text(encoding="utf-8")
        cls.spec = SPEC.read_text(encoding="utf-8")

    def test_single_hrfid_has_opaque_effect_then_explicit_hsrr0_return(self):
        matches = list(SOURCE_PATTERN.finditer(self.isa))
        self.assertEqual(len(matches), 1, "hrfid constructor has drifted")
        tokens = re.sub(r"\s+", "", matches[0].group(1))
        self.assertEqual(tokens, "hrfidOp();return[spr13a];",
                         "Lost HSRR0 control transfer or changed opaque effects")

    def test_hsrr0_hsrr1_unchanged_fullwidth_registers(self):
        self.assertIn('define register offset=0x1000 size=$(REGISTER_SIZE)', self.common)
        self.assertIn("spr130 spr131 spr132", self.common)
        self.assertIn("spr139 spr13a spr13b spr13c", self.common)
        self.assertIn('@define REGISTER_SIZE "8"', self.spec)

    def test_independent_rfid_constructor_retained(self):
        # Generic 'rfid' must continue to return via SRR0/SRR1.
        source = (ROOT / "data/languages/xenon_ppc_instructions.sinc").read_text(
            encoding="utf-8")
        pat = re.compile(r"(?m)^:rfid\s+is\b[^\n]*\n\{(.+?)\}", re.S)
        bodies = pat.findall(source)
        self.assertEqual(len(bodies), 1, "rfid constructor changed")
        normalized = re.sub(r"\s+", "", bodies[0])
        self.assertIn("MSR=returnFromInterrupt(MSR,SRR1);", normalized)
        self.assertIn("return[ra];", normalized)


if __name__ == "__main__":
    unittest.main()
