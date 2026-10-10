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
        source = audit.SLEIGH.read_text(encoding="utf-8")
        constructors, custom_ops = audit.parse_sleigh(source)
        statuses = Counter(
            constructors.get(row["mnemonic"], "missing") for row in self.rows)
        self.assertEqual(statuses, Counter(
            {"missing": 46, "native-pcode": 31, "opaque-userop": 7}))
        self.assertIn("xenonVupkd3d128", custom_ops)
        self.assertIn("xenonLvsl128", custom_ops)
        self.assertIn("xenonLvsr128", custom_ops)
        self.assertEqual(constructors.get("dcbz128"), "native-pcode")
        for name in ("vand128", "vandc128", "vnor128", "vxor128", "vsel128"):
            self.assertEqual(constructors.get(name), "native-pcode", name)

    def test_opcode4_memory_and_opcode31_xform_selectors(self):
        """All generated words match unique new SLEIGH selectors.

        For opcode 31 X-forms, Rc=1 is deliberately excluded (hardware
        validity unverified even though Xenia's decoder accepts it).
        """
        import re

        source = audit.SLEIGH.read_text(encoding="utf-8")
        for row in self.rows:
            if row["primary"] not in (4, 31):
                continue
            rules = re.findall(
                r"(?m)^:" + re.escape(row["mnemonic"]) +
                r" [^\\n]+ is ([^\\n]+)", source)
            self.assertTrue(rules, row["mnemonic"])
            for fill in (0, 0xFFFFFFFF, 0x55555555, 0xAAAAAAAA):
                word = row["value"] | (fill & (~row["mask"] & 0xFFFFFFFF))
                if row["primary"] == 4:
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
