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
            {"missing": 67, "native-pcode": 12, "opaque-userop": 5}))
        self.assertIn("xenonVupkd3d128", custom_ops)
        for name in ("vand128", "vandc128", "vnor128", "vxor128", "vsel128"):
            self.assertEqual(constructors.get(name), "native-pcode", name)

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
