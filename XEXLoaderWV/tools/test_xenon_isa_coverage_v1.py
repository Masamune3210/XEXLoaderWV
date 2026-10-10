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
            {"native-pcode": 54, "opaque-userop": 32}))
        self.assertIn("xenonVupkd3d128", custom_ops)
        self.assertNotIn("xenonVmulfp128", custom_ops)
        self.assertEqual(constructors.get("vmulfp128"), "native-pcode")
        self.assertNotIn("xenonLvsl128", custom_ops)
        self.assertNotIn("xenonLvsr128", custom_ops)
        self.assertEqual(constructors.get("dcbz128"), "native-pcode")
        for name in ("lvsl128", "lvsr128"):
            self.assertEqual(constructors.get(name), "native-pcode", name)
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
                # A selector absent from the current SLEIGH source is a
                # regression now that all 84 pinned families have constructors.
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
        sleigh = audit.read_sleigh_source(audit.SLEIGH)
        # Only a standalone integer literal like 0:16 is illegal.
        # Sized variables such as part0:16 and wide0:16 are valid SLEIGH.
        invalid_constant = r"(?<![A-Za-z0-9_])0:16\b"
        self.assertNotRegex(sleigh, invalid_constant,
                            "SLEIGH integer constants cannot be 16 bytes wide")
        self.assertRegex("value = 0:16;", invalid_constant)
        self.assertNotRegex("part0:16 = zext(octet0);", invalid_constant)
        self.assertIn("zeroVec:16 = zext(0:8);", sleigh)

    def test_vector_pcode_temporaries_do_not_shadow_ppc_registers(self):
        # r0-r31 are real PowerPC registers in ppc_common.sinc. A local
        # declaration such as r0:4 = ... is a SleighCompile symbol error.
        import re

        source = audit.read_sleigh_source(audit.SLEIGH)
        declarations = re.findall(
            r"(?m)^\s*([A-Za-z_][A-Za-z_0-9]*):\d+\s*=", source)
        reserved = [
            name for name in declarations
            if re.fullmatch(r"(?:r|f)(?:[0-9]|[12][0-9]|3[01])", name)
        ]
        self.assertEqual(reserved, [],
                         "Native vector locals shadow PowerPC registers")
        for lane in range(4):
            self.assertIn(f"xenonResultLane{lane}:4 =", source)

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

    def test_pcode_fields_are_available_as_pattern_operands(self):
        # SleighCompile rejects references to token fields whose constructor
        # pattern fixes their value as FIELD=constant.
        import re

        fields = (
            "BITS_6_10", "BITS_4_5", "BITS_0_1", "XOP_3_10",
            "XOP_1_10", "BIT_9", "A_BITS", "BITS_21_25", "Rc",
        )
        for source_file in (audit.SLEIGH, audit.ADDITIONAL_SLEIGH):
            source = source_file.read_text(encoding="utf-8")
            for match in re.finditer(
                r"(?m)^:([A-Za-z_][A-Za-z_0-9]*) [^\n]+ is ([^\n]+)\n"
                r"\{\n([\s\S]*?)\n\}", source
            ):
                mnemonic, pattern, body = match.groups()
                for field in fields:
                    if not re.search(r"\b" + field + r"\b", body):
                        continue
                    self.assertRegex(
                        pattern, r"\b" + field + r"\b",
                        (source_file.name, mnemonic, field))
                    self.assertNotRegex(
                        pattern, r"\b" + field + r"\s*=",
                        (source_file.name, mnemonic, field))

    def test_vpkd3d128_opaque_shift_and_prior_destination(self):
        # VX128_4 embeds z in instruction bits 6-7. The four fixed
        # constructor alternatives must pass 0..3 to the userop.
        # Xenia's pack permutes the packed VB with the prior VD.
        import re

        source = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        constructors = re.findall(
            r"(?m)^:vpkd3d128 [^\n]+ is ([^\n]+)\n"
            r"\{\n([\s\S]*?)\n\}", source)
        self.assertEqual(len(constructors), 4)
        for offset, (pattern, body) in enumerate(constructors):
            self.assertIn(f"BITS_6_10={24 + offset}", pattern)
            self.assertIn(
                f"xenonVpkd3d128(xenonB, xenonD, A_BITS:4, {offset}:4)",
                body)

    def test_remaining_family_complete_selectors(self):
        # All 46 originally missing families plus two documented aliases
        # have constructors. Check each pinned Xenia selector below.
        # pinned sample word against exactly one corresponding new rule.
        import re

        rest = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        former_missing, ops = audit.parse_sleigh(rest)
        self.assertEqual(len(former_missing), 48)
        self.assertEqual(Counter(former_missing.values()), Counter(
            {"native-pcode": 17, "opaque-userop": 31}))
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

    def test_signed_halfword_unpack_aliases_have_disjoint_patterns(self):
        # VA128=0x60 means A_BITS=0 and the two extended VA bits set.
        # These are signed halfword unpacks, not byte unpacks.
        import re

        source = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        for byte_name, half_name, code in (
                ("vupkhsb128", "vupkhsh128", 0x180007A0),
                ("vupklsb128", "vupklsh128", 0x180007E0)):
            byte_rules = re.findall(
                r"(?m)^:" + byte_name + r" [^\n]+ is ([^\n]+)",
                source)
            half_rules = re.findall(
                r"(?m)^:" + half_name + r" [^\n]+ is ([^\n]+)",
                source)
            self.assertEqual(len(byte_rules), 4)
            self.assertEqual(len(half_rules), 1)
            self.assertIn("A_BITS=0", half_rules[0])
            self.assertIn("xenonB", half_rules[0])
            self.assertNotIn("xenonA", half_rules[0])
            self.assertIn("A_BITS!=0",
                          [p for p in byte_rules
                           if f"BITS_6_10={(code >> 6) & 31}" in p and
                           f"BITS_4_5={(code >> 4) & 3}" in p][0])
            self.assertIn(f":{half_name} xenonD,xenonB", source)
            self.assertNotIn(
                f"define pcodeop xenon{half_name[0].upper()}{half_name[1:]};",
                source)

        corrections = audit.read_inventory(audit.CORRECTION_INVENTORY)
        self.assertEqual(
            [(row["mnemonic"], row["mask"], row["value"])
             for row in corrections],
            [("vupkhsh128", 0xFC1F07F0, 0x180007A0),
             ("vupklsh128", 0xFC1F07F0, 0x180007E0)])
        for row in corrections:
            self.assertNotIn(row["mnemonic"],
                             {item["mnemonic"] for item in self.rows})
            for _, fill in audit.FILLS:
                word = row["value"] | (fill & (~row["mask"] & 0xFFFFFFFF))
                self.assertEqual(word & row["mask"], row["value"])
                self.assertEqual((word >> 16) & 31, 0)
                self.assertEqual(audit.decode_expectation(row["mnemonic"], word),
                                 "decode")
                # The broad Xenia byte masks overlap intentionally.
                overlapping = [
                    item for item in self.rows
                    if (word & item["mask"]) == item["value"]]
                self.assertEqual(len(overlapping), 1)
                self.assertGreater(row["mask"].bit_count(),
                                   overlapping[0]["mask"].bit_count())

    def test_corrected_fixture_keeps_pinned_prefix_and_appends_eight(self):
        import hashlib

        corrections = audit.read_inventory(audit.CORRECTION_INVENTORY)
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            old = folder / "pinned"
            full = folder / "with-corrections"
            audit.write_results(self.rows, audit.SLEIGH,
                                audit.INVENTORY, old)
            audit.write_results(self.rows + corrections, audit.SLEIGH,
                                audit.INVENTORY, full)
            old_bytes = (old / "xenon_isa_fixture_v1.bin").read_bytes()
            new_bytes = (full / "xenon_isa_fixture_v1.bin").read_bytes()
            self.assertEqual(len(old_bytes), 1344)
            self.assertEqual(len(new_bytes), 1376)
            self.assertEqual(new_bytes[:1344], old_bytes)
            with (full / "xenon_isa_fixture_v1.tsv").open(
                    encoding="utf-8", newline="") as handle:
                entries = list(csv.DictReader(handle, delimiter="\t"))
            self.assertEqual(len(entries), 344)
            self.assertEqual(
                [row["expected_mnemonic"] for row in entries[336:]],
                ["vupkhsh128"] * 4 + ["vupklsh128"] * 4)
            self.assertEqual(
                [row["word_be"] for row in entries[336::4]],
                ["180007A0", "180007E0"])
            self.assertEqual(
                Counter(row["decode_expectation"] for row in entries),
                Counter({"decode": 328, "reserved-rc1": 16}))
            report = (full / "xenon_isa_coverage_v1.md").read_text(
                encoding="utf-8")
            self.assertIn(
                "Unpack correction inventory SHA-256: " + chr(96) +
                hashlib.sha256(
                    audit.CORRECTION_INVENTORY.read_bytes()).hexdigest(),
                report)
            self.assertIn("Families: **86**", report)

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

    def test_native_permute_control_byte_masks(self):
        # Pinned Xenia LoadVectorShl produces bytes offset..offset+15,
        # while LoadVectorShr produces 16-offset..31-offset.
        import re

        source = audit.SLEIGH.read_text(encoding="utf-8")
        for name in ("lvsl128", "lvsr128"):
            rules = re.findall(
                r"(?m)^:" + name + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", source)
            self.assertEqual(len(rules), 2)
            for body in rules:
                self.assertEqual(
                    len(re.findall(r"(?m)^    part\d+:16 = ", body)), 16)
                self.assertIn("off:4 = offsetFull(0);", body)
                self.assertNotIn("xenonLv", body)

    def test_gradle_build_regenerates_xenon_fixture(self):
        # A caller should not have to remember a separate manual generator
        # step after changing SLEIGH, its inventories, or generator code.
        gradle = (audit.ROOT / "build.gradle").read_text(encoding="utf-8")
        start = gradle.index('tasks.register("generateXenonIsaFixture", Exec)')
        verify = gradle.index('tasks.register("verifyXenonSleigh", Exec)')
        self.assertLess(start, verify)
        body = gradle[start:verify]
        self.assertIn(
            'commandLine pythonCommand, "tools/audit_xenon_isa_coverage_v1.py"',
            body)
        for filename in (
            "xenon_vector_v1.sinc",
            "xenon_vector_remaining_v1.sinc",
            "xenon_64_be.slaspec",
            "xenia_vmx128_opcode_inventory_20261009.tsv",
            "xenia_xform_vector_opcode_inventory_20261009.tsv",
            "xenon_vmx128_unpack_corrections_20261010.tsv",
        ):
            self.assertIn(filename, body)
        self.assertIn('dependsOn tasks.named("generateXenonIsaFixture")',
                      gradle[verify:])
        # No Gradle outputs declaration: every extension build refreshes
        # manifest and report, even when status categories stay identical.
        self.assertNotIn("outputs.", body)

    def test_java_fixture_manifest_header(self):
        java_path = (audit.ROOT.parent / "ghidra_scripts" /
                     "AuditXenonIsaFixtureV1.java")
        source = java_path.read_text(encoding="utf-8")
        self.assertIn('FIXTURE_TSV = "xenon_isa_fixture_v1.tsv"', source)
        self.assertIn('COVERAGE_TSV = "xenon_isa_coverage_v1.tsv"', source)
        self.assertIn("COVERAGE_TSV.equals(manifest.getName())", source)
        self.assertIn("FIXTURE_HEADER.equals(line)", source)
        self.assertIn('"reserved-rc1".equals(expectation)', source)
        self.assertIn("family.reservedPass++", source)
        self.assertIn("int unresolved = checks - passes - reservedPasses", source)
        expected = ("offset", "word_be", "expected_mnemonic",
                    "sleigh_status", "variant", "decode_expectation")
        self.assertIn('"' + r"\t".join(expected) + '"', source)
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            audit.write_results(self.rows, audit.SLEIGH, audit.INVENTORY, out)
            with (out / "xenon_isa_fixture_v1.tsv").open(
                    encoding="utf-8", newline="") as handle:
                self.assertEqual(tuple(handle.readline().strip().split("\t")),
                                 expected)

    def test_opcode31_rc1_reserved_fixtures_are_preserved(self):
        # Cell Vector/SIMD PEM v2.07c X-form encodings fix bit 31 to 0,
        # whereas Xenia's broad dispatch masks bit 31 out. Keep all four
        # raw fixture variants, including the 16 intentionally rejected
        # Rc=1 samples, to detect accidental decoder overacceptance.
        for row in self.xform:
            self.assertEqual(row["primary"], 31)
            self.assertEqual(row["mask"] & 1, 0)
            for label, fill in audit.FILLS:
                word = row["value"] | (fill & (~row["mask"] & 0xFFFFFFFF))
                result = audit.decode_expectation(row["mnemonic"], word)
                self.assertEqual(result,
                                 "reserved-rc1" if (word & 1) else "decode")
        for row in self.vmx:
            for _, fill in audit.FILLS:
                word = row["value"] | (fill & (~row["mask"] & 0xFFFFFFFF))
                self.assertEqual(
                    audit.decode_expectation(row["mnemonic"], word), "decode")

    def test_native_xenon_permute_rotate_and_dot_shapes(self):
        # Follow pinned Xenia's vector swizzle, blend and dot-product
        # layouts. These checks establish operand and lane propagation,
        # not numerical execution or IEEE exception equivalence.
        import re

        main = audit.SLEIGH.read_text(encoding="utf-8")
        supplement = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        cases = (
            ("vpermwi128", main, 8),
            ("vrlimi128", main, 4),
            ("vperm128", supplement, 2),
            ("vmsum4fp128", main, 4),
            ("vmsum3fp128", supplement, 4),
        )
        for name, source, count in cases:
            pattern = (r"(?m)^:" + name +
                       r" [^\n]+ is ([^\n]+)\n\{\n([\s\S]*?)\n\}")
            bodies = re.findall(pattern, source)
            self.assertEqual(len(bodies), count, name)
            op = "xenon" + name[0].upper() + name[1:]
            self.assertNotIn("define pcodeop " + op + ";", source)
            for _, body in bodies:
                self.assertIn("xenonD = ", body, name)
                self.assertNotIn(op + "(", body, name)

        for i, (_, body) in enumerate(re.findall(
                r"(?m)^:vpermwi128 [^\n]+ is ([^\n]+)\n"
                r"\{\n([\s\S]*?)\n\}", main)):
            self.assertIn(f"permutation:4 = A_BITS:4 | {32*i}:4;",
                          body)
            self.assertEqual(len(re.findall(r"(?m)^    packedWord\d+:16",
                                            body)), 4)

        for i, (_, body) in enumerate(re.findall(
                r"(?m)^:vrlimi128 [^\n]+ is ([^\n]+)\n"
                r"\{\n([\s\S]*?)\n\}", main)):
            if i:
                self.assertIn(
                    f"rotated:16 = (xenonB << {32*i}) | "
                    f"(xenonB >> {128-32*i});", body)
            else:
                self.assertIn("rotated:16 = xenonB;", body)
            self.assertIn("fromOld:16 = xenonD & ~selectMask;", body)
            self.assertEqual(len(re.findall(r"(?m)^    expandedMask\d+:16",
                                            body)), 4)

        for _, body in re.findall(
                r"(?m)^:vperm128 [^\n]+ is ([^\n]+)\n"
                r"\{\n([\s\S]*?)\n\}", supplement):
            self.assertEqual(len(re.findall(
                r"(?m)^    assembledOctet\d+:16", body)), 16)
            self.assertIn("controlByte15:1 = xenonC(15);", body)
            self.assertIn("byteB15:1 = fromB15(0);", body)

        for name, source, lanes in (
                ("vmsum3fp128", supplement, 3),
                ("vmsum4fp128", main, 4)):
            bodies = re.findall(
                r"(?m)^:" + name + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", source)
            for body in bodies:
                self.assertEqual(len(re.findall(
                    r"(?m)^    product\d+:4 = .* f\* .*;", body)),
                    lanes)
                self.assertEqual(len(re.findall(
                    r"(?m)^    dotLane\d+:16", body)), 4)

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
            self.assertEqual(
                Counter(row["decode_expectation"] for row in entries),
                Counter({"decode": 320, "reserved-rc1": 16}))
            for row in entries:
                word = int(row["word_be"], 16)
                expected_behavior = audit.decode_expectation(
                    row["expected_mnemonic"], word)
                self.assertEqual(row["decode_expectation"], expected_behavior)
                if row["decode_expectation"] == "reserved-rc1":
                    self.assertIn(row["expected_mnemonic"], audit.EXTRA_NAMES)
                    self.assertEqual(word & 1, 1)
            for row in entries:
                offset = int(row["offset"], 16)
                word = int(row["word_be"], 16)
                self.assertEqual(image[offset:offset + 4],
                                 word.to_bytes(4, "big"))
                hits = [r["mnemonic"] for r in self.rows
                        if (word & r["mask"]) == r["value"]]
                self.assertEqual(hits, [row["expected_mnemonic"]])
            self.assertTrue((out / "xenon_isa_coverage_v1.md").exists())
            report = (out / "xenon_isa_coverage_v1.md").read_text(
                encoding="utf-8")
            import hashlib
            source_sha = hashlib.sha256(
                audit.read_sleigh_source(audit.SLEIGH).encode("utf-8")
            ).hexdigest()
            self.assertIn("SLEIGH SHA-256: " + chr(96) + source_sha, report)
            self.assertIn("Inventory SHA-256: " + chr(96) +
                          hashlib.sha256(audit.INVENTORY.read_bytes()).hexdigest(),
                          report)
            self.assertIn("Extra inventory SHA-256: " + chr(96) +
                          hashlib.sha256(
                              audit.EXTRA_INVENTORY.read_bytes()).hexdigest(),
                          report)
            self.assertIn("Language specification SHA-256: " + chr(96) +
                          hashlib.sha256((audit.ROOT / "data/languages/xenon_64_be.slaspec").read_bytes()).hexdigest(),
                          report)
            self.assertIn("Generator SHA-256: " + chr(96) +
                          hashlib.sha256(Path(audit.__file__).read_bytes()).hexdigest(),
                          report)


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
