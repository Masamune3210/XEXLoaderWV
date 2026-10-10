#!/usr/bin/env python3
"""Offline unit checks for the pinned Xenon ISA audit generator."""
import csv
import importlib.util
import tempfile
import unittest
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "audit_xenon_isa_coverage_v1", HERE / "audit_xenon_isa_coverage_v1.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class XenonIsaInventoryTests(unittest.TestCase):
    def setUp(self):
        self.vmx = audit.read_inventory(audit.INVENTORY)
        self.xform = audit.read_inventory(audit.EXTRA_INVENTORY)
        self.rows = self.vmx + self.xform

    def test_inventory_counts_and_no_duplicates(self):
        self.assertEqual(len(self.vmx), 76)
        self.assertEqual(len(self.xform), 8)
        self.assertEqual(len(self.rows), 84)
        self.assertEqual(len({r["mnemonic"] for r in self.rows}), 84)
        self.assertIn("lvlx128", {r["mnemonic"] for r in self.vmx})
        self.assertIn("lvlx", {r["mnemonic"] for r in self.xform})

    def test_masks_and_selector_disjointness(self):
        for i, left in enumerate(self.rows):
            self.assertEqual(left["mask"] & 0xFC000000, 0xFC000000)
            self.assertEqual(left["value"] >> 26, left["primary"])
            for right in self.rows[i + 1:]:
                self.assertNotEqual(
                    (left["value"] ^ right["value"]) &
                    (left["mask"] & right["mask"]), 0,
                    f"{left['mnemonic']} overlaps {right['mnemonic']}")

    def test_current_sleigh_source_statuses(self):
        source = audit.read_sleigh_source(audit.SLEIGH)
        constructors, custom_ops = audit.parse_sleigh(source)
        statuses = Counter(
            constructors.get(row["mnemonic"], "missing") for row in self.rows)
        self.assertEqual(statuses, Counter(
            {"native-pcode": 45, "opaque-userop": 39}))
        self.assertIn("xenonVupkd3d128", custom_ops)
        self.assertNotIn("xenonVmulfp128", custom_ops)
        self.assertEqual(constructors.get("vmulfp128"), "native-pcode")
        self.assertIn("xenonLvsl128", custom_ops)
        self.assertIn("xenonLvsr128", custom_ops)
        self.assertEqual(constructors.get("dcbz128"), "native-pcode")
        for name in ("vand128", "vandc128", "vnor128", "vxor128", "vsel128"):
            self.assertEqual(constructors.get(name), "native-pcode", name)

    def test_opcode4_memory_and_opcode31_xform_selectors(self):
        """Implemented opcode-4/31 families match their SLEIGH selectors.

        Missing families remain valid inventory entries but have no rule.
        For opcode 31 X-forms, Rc=1 is deliberately excluded (hardware
        validity unverified even though Xenia's decoder accepts it).
        """
        import re

        source = audit.read_sleigh_source(audit.SLEIGH)
        constructors, _ = audit.parse_sleigh(source)
        for row in self.rows:
            if row["primary"] not in (4, 31):
                continue
            rules = re.findall(
                r"(?m)^:" + re.escape(row["mnemonic"]) +
                r" [^\n]+ is ([^\n]+)", source)
            if row["mnemonic"] not in constructors:
                # The inventory intentionally includes still-unimplemented
                # instructions such as vsldoi128 and vperm128.
                self.assertFalse(rules, row["mnemonic"])
                continue
            self.assertTrue(rules, row["mnemonic"])
            for fill in (0, 0xFFFFFFFF, 0x55555555, 0xAAAAAAAA):
                word = row["value"] | (fill & (~row["mask"] & 0xFFFFFFFF))
                if row["mnemonic"] == "vsldoi128":
                    # Opcode 4 VX128_5 has a different selector from the
                    # indexed memory instructions tested below.
                    matches = [p for p in rules
                               if f"BITS_4_5={(word >> 4) & 3}" in p]
                    self.assertEqual(len(matches), 1,
                                     (row["mnemonic"], hex(word)))
                elif row["primary"] == 4:
                    selector = (word >> 3) & 255
                    matches = [p for p in rules
                               if f"XOP_3_10={selector}" in p and
                               f"BITS_0_1={word & 3}" in p]
                    self.assertEqual(len(matches), 1,
                                     (row["mnemonic"], hex(word)))
                elif row["mnemonic"] == "dcbz128":
                    self.assertEqual(len(rules), 1)
                    self.assertIn("BITS_21_25=1", rules[0])
                    self.assertIn("XOP_1_10=1014", rules[0])
                elif (word & 1) == 0:
                    matches = [p for p in rules
                               if f"XOP_1_10={(word >> 1) & 1023}" in p and
                               "Rc=0" in p]
                    self.assertEqual(len(matches), 1,
                                     (row["mnemonic"], hex(word)))

    def test_diagnostic_source_syntax_and_gradle_literals(self):
        # Prevent recurrences of Windows-path unicodeescape parsing and
        # Groovy interpolation of SLEIGH's $(NOTVLE) preprocessor macro.
        import ast

        diagnostic = (HERE / "check_xenon_fixture_install_v1.py").read_text(
            encoding="utf-8")
        ast.parse(diagnostic, filename="check_xenon_fixture_install_v1.py")
        gradle = (audit.ROOT / "build.gradle").read_text(
            encoding="utf-8")
        for symbol in ("dcbzOld", "dcbzNew"):
            self.assertIn(
                "String " + symbol + " = ':dcbz A,B is $(NOTVLE)", gradle)

    def test_copied_isa_includes_and_128bit_zero_widths(self):
        # The copied stock ppc_isa.sinc cannot resolve a local vsx.sinc.
        # Resolve it using the same -dPowerPC argument as other stock files.
        gradle = (audit.ROOT / "build.gradle").read_text(encoding="utf-8")
        self.assertIn("""String stockVsxInclude = '@include "vsx.sinc"'""",
                      gradle)
        self.assertIn(
            """String resolvedVsxInclude = '@include "$(PowerPC)/data/languages/vsx.sinc"'""",
            gradle)
        self.assertIn("src = src.replace(stockVsxInclude, resolvedVsxInclude)",
                      gradle)
        sleigh = audit.SLEIGH.read_text(encoding="utf-8")
        self.assertNotIn("0:16", sleigh,
                         "SLEIGH integer constants cannot be 16 bytes wide")
        self.assertIn("zeroVec:16 = zext(0:8);", sleigh)

    def test_embedded_dcbzl_collision_filter_wiring(self):
        # Stock ppc_common includes the embedded dcbzl alias, which has the
        # same opcode selector as Xenon's dcbz128. Only the Xenon variant
        # should use filtered copies of these inherited language files.
        root = audit.ROOT
        gradle = (root / "build.gradle").read_text(encoding="utf-8")
        slaspec = (root / "data/languages/xenon_64_be.slaspec").read_text(
            encoding="utf-8")
        self.assertIn('@include "xenon_ppc_common.sinc"', slaspec)
        self.assertNotIn(
            '@include "$(PowerPC)/data/languages/ppc_common.sinc"', slaspec)
        for fragment in (
            'tasks.register("prepareXenonCommon")',
            'inputs.files(xenonStockCommon, xenonStockEmbedded)',
            'outputs.files(xenonCommon, xenonEmbedded)',
            """String target = ':dcbzl RA_OR_ZERO,B'""",
            """String dcbzlPattern = 'BITS_21_25=1 & B & XOP_1_10=1014 & BIT_0=0'""",
            """'@include "$(PowerPC)/data/languages/ppc_instructions.sinc"'""",
            """'@include "xenon_ppc_embedded.sinc"'""",
            'embedded = embedded.substring(0, comment) + embedded.substring(end)',
            'tasks.named("prepareXenonCommon")',
        ):
            self.assertIn(fragment, gradle)

    def test_remaining_family_complete_selectors(self):
        # All 46 previously missing families have a decoder. Check every
        # pinned sample word against exactly one corresponding new rule.
        import re

        rest = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        former_missing, ops = audit.parse_sleigh(rest)
        self.assertEqual(len(former_missing), 46)
        self.assertEqual(Counter(former_missing.values()), Counter(
            {"native-pcode": 13, "opaque-userop": 33}))
        original, _ = audit.parse_sleigh(
            audit.SLEIGH.read_text(encoding="utf-8"))
        self.assertEqual(set(former_missing) & set(original), set())
        slaspec = (audit.ROOT / "data/languages/xenon_64_be.slaspec").read_text(
            encoding="utf-8")
        self.assertIn('@include "xenon_vector_remaining_v1.sinc"', slaspec)

        for row in self.rows:
            if row["mnemonic"] not in former_missing:
                continue
            rules = re.findall(
                r"(?m)^:" + re.escape(row["mnemonic"]) +
                r" [^\n]+ is ([^\n]+)", rest)
            self.assertTrue(rules, row["mnemonic"])
            for fill in (0, 0xFFFFFFFF, 0x55555555, 0xAAAAAAAA):
                word = row["value"] | (fill & (~row["mask"] & 0xFFFFFFFF))
                checks = {
                    "BITS_6_10": (word >> 6) & 31,
                    "BITS_4_5": (word >> 4) & 3,
                    "XOP_3_10": (word >> 3) & 255,
                    "BIT_9": (word >> 9) & 1,
                }
                matches = []
                for rule in rules:
                    if all(
                        (m is None or int(m.group(1)) == value)
                        for field, value in checks.items()
                        for m in [re.search(
                            r"(?:^| & )" + field + r"=(\d+)(?: & |$)",
                            rule)]
                    ):
                        matches.append(rule)
                self.assertEqual(len(matches), 1,
                                 (row["mnemonic"], hex(word), matches))

    def test_native_byte_shift_and_unsigned_pack_semantics(self):
        # Xenia uses the last vector byte's 0x78 bits for whole-vector
        # byte shifts, and packs unsigned lanes modulo their output width.
        source = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        for name, operator in (("vslo128", "<<"), ("vsro128", ">>")):
            self.assertIn("last:1 = xenonB(0);", source)
            self.assertIn("xenonD = xenonA " + operator + " shift;", source)
        for name, dst_width, count in (
                ("vpkuhum128", 1, 16), ("vpkuwum128", 2, 8)):
            import re
            rules = re.findall(
                r"(?m)^:" + name + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", source)
            self.assertEqual(len(rules), 4)
            for body in rules:
                self.assertEqual(len(re.findall(
                    r"(?m)^    part\d+:" + str(dst_width) + r" = ", body)),
                    count)
                self.assertNotIn("xenonVpk", body)

    def test_fixture_generation(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            audit.write_results(self.rows, audit.SLEIGH, audit.INVENTORY, out)
            image = (out / "xenon_isa_fixture_v1.bin").read_bytes()
            self.assertEqual(len(image), 84 * 4 * 4)
            with (out / "xenon_isa_fixture_v1.tsv").open(
                    encoding="utf-8", newline="") as f:
                entries = list(csv.DictReader(f, delimiter="\t"))
            self.assertEqual(len(entries), 336)
            for row in entries:
                offset = int(row["offset"], 16)
                word = int(row["word_be"], 16)
                self.assertEqual(image[offset:offset + 4],
                                 word.to_bytes(4, "big"))
                hits = [r["mnemonic"] for r in self.rows
                        if (word & r["mask"]) == r["value"]]
                self.assertEqual(hits, [row["expected_mnemonic"]])
            self.assertTrue((out / "xenon_isa_coverage_v1.md").exists())

    def test_xenia_lookup_parser_reconstructs_masks(self):
        sample = "\n".join((
            "  case 4:",
            "    switch ((ExtractBits(code, 21, 27) << 4)|"
            "(ExtractBits(code, 30, 31) << 0)) {",
            "      case 0b00000000011: PPC_DECODER_HIT(lvsl128);",
            "    }",
        ))
        found = audit.parse_xenia_lookup(sample)
        self.assertEqual(found["lvsl128"],
                         (4, 0xFC0007F3, 0x10000003))


if __name__ == "__main__":
    unittest.main()
