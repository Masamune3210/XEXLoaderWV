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

    def test_numerical_pack_v3_has_independent_source_register_probes(self):
        # Decoder fixture deliberately uses homogeneous fills. Numerical
        # tests must not treat those samples as independent VA / VB sources.
        source = (audit.ROOT.parent /
                  "ghidra_scripts/AuditXenonNumericalPcode.java").read_text(
                      encoding="utf-8")
        self.assertIn("getDefaultOperandRepresentation(index)", source)
        self.assertIn("currentProgram.getRegister(rendered)", source)
        self.assertIn('rendered.matches("(?:vs|xv)[0-9]{1,3}")', source)
        self.assertIn('requireVectorRegister("vs33")', source)
        self.assertIn('requireVectorRegister("vs34")', source)
        self.assertIn('requireVectorRegister("vs35")', source)
        self.assertIn('emulator.writeMemory(address, syntheticBytes);', source)
        self.assertIn('emulator.readMemory(address, 4)', source)
        self.assertNotIn('currentProgram.getMemory().setBytes(', source)

        rows = {row["mnemonic"]: row for row in self.vmx}
        names = ("vpkshss128", "vpkshus128", "vpkswss128",
                 "vpkswus128", "vpkuhus128", "vpkuwus128")
        for name in names:
            data = rows[name]
            self.assertEqual(data["mask"], 0xfc0003d0)
            original = data["value"] | (0x55555555 & ~data["mask"])
            probe = ((original & 0xfc0003d0) |
                     (1 << 21) | (2 << 16) | (3 << 11))
            self.assertEqual(probe & data["mask"], data["value"], name)
            self.assertEqual(
                ((probe >> 21) & 31, (probe >> 16) & 31,
                 (probe >> 11) & 31), (1, 2, 3), name)
            self.assertNotEqual((probe >> 16) & 31, (probe >> 11) & 31)
            self.assertNotEqual((probe >> 21) & 31, (probe >> 16) & 31)
            self.assertNotEqual((probe >> 21) & 31, (probe >> 11) & 31)

    def test_native_d3d_unpack_numeric_probe_oracles(self):
        # 96 emulator-private numerical probes must retain the exact
        # vupkd3d128 selector, dest/source separation, and independently
        # specified packed-bit results before Ghidra runtime execution.
        import re

        source = (audit.ROOT.parent /
                  "ghidra_scripts/AuditXenonNumericalPcode.java").read_text(
                      encoding="utf-8")
        self.assertIn("emulator.writeMemory(address, bytes);", source)
        self.assertIn("emulator.readMemory(address, 4)", source)
        self.assertIn('vector(bank == 0 ? "vs33" : "xv65")', source)
        self.assertIn('vector("vs35")', source)
        self.assertNotIn("currentProgram.getMemory().setBytes(", source)
        self.assertIn("originalFixtureMatches(address, originalWord)", source)
        self.assertIn("for (int bank = 0; bank < 2; bank++)", source)
        self.assertIn("for (int low = 0; low < 4; low++)", source)
        pattern = re.compile(
            r'new TestCase\("([^"]+)",\s*(\d+),\s*(0x[0-9a-fA-F]+)L,\s*'
            r'((?:0x[0-9a-fA-F]+L|0L)(?:,\s*'
            r'(?:0x[0-9a-fA-F]+L|0L)){3})\)')
        cases = pattern.findall(source)
        self.assertEqual(len(cases), 12)
        self.assertEqual({int(fmt) for _, fmt, _, _ in cases},
                         {0, 1, 2, 4})

        def sign(value, bits):
            return value - (1 << bits) if value & (1 << (bits - 1)) else value

        def component(value, bits):
            if value == -(1 << (bits - 1)):
                return 0x7fc00000
            return (0x40400000 + value) & 0xffffffff

        for label, format_string, packed_string, words_string in cases:
            fmt, packed = int(format_string), int(packed_string, 16)
            expected = [int(x[:-1], 0)
                        for x in re.findall(r'(?:0x[0-9a-fA-F]+|0)L',
                                            words_string)]
            self.assertEqual(len(expected), 4, label)
            if fmt == 0:
                rgba = [(packed >> 16) & 255, (packed >> 8) & 255,
                        packed & 255, (packed >> 24) & 255]
                actual = [0x3f800000 | value for value in rgba]
            elif fmt == 1:
                actual = [
                    component(sign((packed >> 16) & 0xffff, 16), 16),
                    component(sign(packed & 0xffff, 16), 16),
                    0, 0x3f800000]
            elif fmt == 2:
                actual = [
                    component(sign((packed >> shift) & 0x3ff, 10), 10)
                    for shift in (0, 10, 20)]
                actual.append(0x3f800000 | ((packed >> 30) & 3))
            else:
                actual = [
                    component(sign((packed >> shift) & 0xffff, 16), 16)
                    for shift in (48, 32, 16, 0)]
            self.assertEqual(actual, expected, label)

            for bank in (0, 1):
                for low in range(4):
                    word = (0x180007f0 | (1 << 21) | (3 << 11) |
                            ((fmt * 4 + low) << 16) | (bank << 3))
                    self.assertEqual(word & 0xfc0007f0, 0x180007f0)
                    self.assertEqual((word >> 21) & 31, 1)
                    self.assertEqual((word >> 11) & 31, 3)
                    self.assertEqual((word >> 16) & 31, fmt * 4 + low)
                    self.assertEqual((word >> 3) & 1, bank)

    def test_guarded_fused_float_numeric_probe_matrix(self):
        # Native semantics can only be asserted for nonzero integral f32
        # inputs in [-2048, 2048] and exact, nonzero output lanes.
        # Keep the three distinct operand formulas and all four encodings.
        import re
        import struct

        source = (audit.ROOT.parent /
                  "ghidra_scripts/AuditXenonNumericalPcode.java"
                  ).read_text(encoding="utf-8")
        families = re.findall(
            r'new Family\("([^"]+)",\s*(0x[0-9a-fA-F]+)L,\s*(\d+)\)',
            source)
        self.assertEqual(
            families,
            [("vmaddfp128", "0x140000d0", "0"),
             ("vmaddcfp128", "0x14000110", "1"),
             ("vnmsubfp128", "0x14000150", "2")])
        patterns = re.findall(
            r'new Pattern\("([^"]+)",\s*'
            r'new int\[\] \{([^}]*)\},\s*'
            r'new int\[\] \{([^}]*)\},\s*'
            r'new int\[\] \{([^}]*)\}\)',
            source)
        self.assertEqual(len(patterns), 6)

        self.assertIn("emulator.writeMemory(address, op);", source)
        self.assertIn("emulator.readMemory(address, 4)", source)
        self.assertIn("fixtureMatches(address, word)", source)
        self.assertNotIn("currentProgram.getMemory().setBytes(", source)
        self.assertIn('vectorRegister("vs33")', source)
        self.assertIn('vectorRegister("vs35")', source)
        self.assertIn(
            'Register a = vectorRegister(guardedFpSourceAName(variant));',
            source)
        self.assertIn(
            'String[] names = { "vs34", "xv34", "xv66", "xv98" };',
            source)
        self.assertIn("((word >>> 5) & 1) != (variant & 1)", source)
        self.assertIn(
            "((word >>> 10) & 1) != ((variant >>> 1) & 1)",
            source)
        self.assertIn("emulator.readRegister(a)", source)
        self.assertIn("emulator.readRegister(b)", source)

        def bits(value):
            return int.from_bytes(struct.pack(">f", float(value)), "big")

        for _, selector_string, formula_string in families:
            selector, formula = int(selector_string, 16), int(formula_string)
            for variant in range(4):
                word = (selector | (1 << 21) | (2 << 16) |
                        (3 << 11) | ((variant & 1) << 5) |
                        ((variant & 2) << 9))
                self.assertEqual(word & 0xfc0003d0, selector)
                self.assertEqual(((word >> 21) & 31,
                                  (word >> 16) & 31,
                                  (word >> 11) & 31),
                                 (1, 2, 3))
                self.assertEqual((word >> 5) & 1, variant & 1)
                self.assertEqual((word >> 10) & 1, (variant >> 1) & 1)
                # These are genuine VX128 VA register extension bits.
                expected_a = ("vs34", "xv34", "xv66", "xv98")[variant]
                mbh, oe = variant & 1, (variant >> 1) & 1
                definition = (
                    f'xenonA: "{expected_a}" is vrAR=2 & '
                    f'MBH={mbh} & OE={oe} '
                    f'{{ export {expected_a}; }}')
                self.assertIn(
                    definition, audit.SLEIGH.read_text(encoding="utf-8"))
            for label, a_string, b_string, d_string in patterns:
                a, b, d = ([
                    int(x.strip()) for x in values.split(",")]
                    for values in (a_string, b_string, d_string))
                self.assertEqual((len(a), len(b), len(d)), (4, 4, 4),
                                 label)
                for av, bv, dv in zip(a, b, d):
                    self.assertTrue(
                        all(0 < abs(x) <= 2048 for x in (av, bv, dv)),
                        (label, av, bv, dv))
                    value = ((av * bv + dv) if formula == 0
                             else (av * dv + bv) if formula == 1
                             else (dv - av * bv))
                    self.assertTrue(0 < abs(value) < (1 << 24),
                                    (label, formula, value))
                    self.assertEqual(
                        struct.unpack(">f", struct.pack(">I", bits(value)))[0],
                        float(value))

    def test_sleigh_semantics_reject_cpp_style_comments(self):
        # C++ // comments inside Sleigh constructor actions are NOT valid.
        # A single such comment can make the parser reject all subsequent
        # instruction constructors with misleading display/EOF errors.
        import re

        for path in (audit.SLEIGH, audit.ADDITIONAL_SLEIGH):
            source = path.read_text(encoding="utf-8")
            lines = [
                number for number, line in enumerate(source.splitlines(), 1)
                if re.match(r"\s*//", line) or re.search(r";\s*//", line)
            ]
            self.assertFalse(
                lines, f"{path.name}: unsupported // comments at {lines}")

    def test_sleigh_constant_varnodes_fit_eight_bytes(self):
        # Ghidra SleighCompile rejects numeric constants declared :9+
        # even when the destination varnode legitimately has 16 bytes.
        # Inspect code only: '#' lines are SLEIGH comments and may quote
        # unrelated ranges such as bit fields [6:10].
        import re

        numeric = re.compile(
            r"(?<![A-Za-z0-9_])(?:0[xX][0-9a-fA-F]+|[0-9]+):([0-9]+)\b")
        for path in (audit.SLEIGH, audit.ADDITIONAL_SLEIGH):
            errors = [
                (line_number, match.group(0))
                for line_number, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), 1)
                if not line.lstrip().startswith("#")
                for match in numeric.finditer(line)
                if int(match.group(1)) > 8
            ]
            self.assertFalse(
                errors, f"{path.name}: oversized literal varnodes {errors}")

    def test_current_sleigh_source_statuses(self):
        source = audit.read_sleigh_source(audit.SLEIGH)
        constructors, custom_ops = audit.parse_sleigh(source)
        statuses = Counter(
            constructors.get(row["mnemonic"], "missing") for row in self.rows)
        self.assertEqual(statuses, Counter(
            {"native-pcode": 71, "opaque-userop": 13}))
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

    def test_no_duplicate_typed_pcode_temporary_declarations(self):
        # SleighCompile rejects a second NAME:SIZE assignment anywhere in
        # one constructor, even when each declaration is in a different
        # control-flow branch. Reassign a previously declared temp using
        # NAME = ... instead. Check both Xenon SLEIGH source files.
        import re

        for path in (audit.SLEIGH, audit.ADDITIONAL_SLEIGH):
            source = path.read_text(encoding="utf-8")
            constructors = re.findall(
                r"(?m)^:([A-Za-z]\w*) [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", source)
            for name, body in constructors:
                declarations = re.findall(
                    r"(?m)^\s*(?:local\s+)?([A-Za-z_]\w*):\d+\s*=",
                    body)
                unique = set(declarations)
                self.assertEqual(len(declarations), len(unique),
                                 f"{path.name}: {name}: "
                                 f"duplicate typed locals "
                                 f"{[x for x in unique if declarations.count(x)>1]}")

    def test_saturating_conversion_and_rounding_branch_assignment(self):
        # The compiler error at xenon_vector_remaining_v1.sinc:3988
        # was caused by declaring convertedInt0:4 separately in all
        # three branches. Ensure each lane has one typed initializer,
        # with bare assignments along all possible control-flow paths.
        import re

        source = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        for family, alternatives, paths in (
            ("vcfpsxws128", 2, 3),
            ("vcfpuxws128", 2, 3),
            ("vrfiz128", 2, 2),
        ):
            bodies = re.findall(
                r"(?m)^:" + family + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", source)
            self.assertEqual(len(bodies), alternatives)
            prefix = "roundOutput" if family == "vrfiz128" else "convertedInt"
            for body in bodies:
                for lane in range(4):
                    name = f"{prefix}{lane}"
                    self.assertEqual(
                        len(re.findall(
                            r"(?m)^\s*" + name + r":4\s*=\s*0:4;",
                            body)), 1, (family, name))
                    self.assertEqual(
                        len(re.findall(
                            r"(?m)^\s*" + name + r"\s*=", body)),
                        paths, (family, name))
                    self.assertEqual(
                        re.findall(
                            r"(?m)^\s*" + name + r":4\s*=\s*([^\n]+)",
                            body), ["0:4;"], (family, name))

    def test_vscr_sat_is_register_backed_and_wired_to_legacy_transfers(self):
        # SAT is architecturally VSCR[31], the least-significant bit.
        # A saturating pack must set it without clearing an existing SAT.
        # mfvscr/mtvscr must access that *same* register, not disconnected
        # stock opaque CALL_OTHER operations or an independent shadow.
        import re

        slaspec = (audit.ROOT / "data/languages/xenon_64_be.slaspec"
                   ).read_text(encoding="utf-8")
        self.assertIn(
            "define register offset=0x5000 size=4 [ xenonVSCR ];",
            slaspec)
        self.assertLess(
            slaspec.index("define register offset=0x5000"),
            slaspec.index('@include "xenon_altivec_pre207.sinc"'))

        gradle = (audit.ROOT / "build.gradle").read_text(
            encoding="utf-8")
        self.assertIn(
            'legacy.indexOf(":mfvscr vrD")', gradle)
        self.assertIn(
            'legacy.indexOf(":mtvscr vrB")', gradle)
        match = re.search(
            r"String nativeTransfers = '''\n([\s\S]*?)\n'''", gradle)
        self.assertIsNotNone(match)
        transfer = match.group(1)
        self.assertIn(
            ":mfvscr vrD is OP=4", transfer)
        self.assertIn(
            "vscrVector:16 = zext(xenonVSCR);", transfer)
        self.assertIn(
            "vrD = vscrVector;", transfer)
        self.assertIn(
            ":mtvscr vrB is OP=4", transfer)
        self.assertIn(
            "xenonVSCR = vrB(0);", transfer)
        self.assertNotIn(
            "moveFromVectorStatusAndControlRegister()", transfer)
        self.assertNotIn(
            "moveToVectorStatusAndControlRegister(", transfer)

        supplement = audit.ADDITIONAL_SLEIGH.read_text(
            encoding="utf-8")
        self.assertNotIn("xenonSetVscrSatIf", supplement)
        families = (
            ("vpkshss128", 4, "saturatedAny"),
            ("vpkshus128", 4, "saturatedAny"),
            ("vpkswss128", 4, "saturatedAny"),
            ("vpkswus128", 4, "saturatedAny"),
            ("vpkuhus128", 4, "saturatedAny"),
            ("vpkuwus128", 4, "saturatedAny"),
            ("vcfpsxws128", 2, "conversionSaturated"),
            ("vcfpuxws128", 2, "conversionSaturated"),
        )
        for name, count, flag in families:
            bodies = re.findall(
                r"(?m)^:" + name + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", supplement)
            self.assertEqual(len(bodies), count, name)
            for body in bodies:
                self.assertIn(
                    "xenonVSCR = xenonVSCR | zext(" + flag + ");",
                    body)
                self.assertEqual(
                    body.count("xenonVSCR = "), 1, name)

    def test_xenon_vsldoi_excludes_overlapping_generic_madd(self):
        # Real Ghidra 12.1.3 native decode collision: 0x10221830 was
        # incorrectly preferred as scalar maddhd over Xenon vsldoi128.
        # The fix belongs in the isolated generated Xenon PPC ISA, not
        # a modification to Ghidra's installed stock PPC language.
        gradle = (audit.ROOT / "build.gradle").read_text(
            encoding="utf-8")
        slaspec = (audit.ROOT /
                   "data/languages/xenon_64_be.slaspec").read_text(
                       encoding="utf-8")
        self.assertIn('@include "xenon_ppc_isa.sinc"', slaspec)
        self.assertIn('tasks.register("prepareXenonIsa")', gradle)
        self.assertIn("inputs.file(xenonStockIsa)", gradle)
        self.assertIn("outputs.file(xenonLegacyIsa)", gradle)
        self.assertIn('src = src.substring(0, start) + src.substring(end + 2)',
                      gradle)
        self.assertIn('body.contains(expectedSelector)', gradle)
        self.assertIn('body.contains(spec.result)', gradle)
        self.assertIn(
            'Installed Ghidra " + spec.name +',
            gradle)

        spec_section = gradle[
            gradle.index('for (def spec : ['):
            gradle.index('xenonLegacyIsa.setText(', 
                         gradle.index('for (def spec : ['))]
        for name, xo, result in (
                ("maddhd", 48, "D = tmpp(8);"),
                ("maddhdu", 49, "D = tmpp(8);"),
                ("maddld", 51, "D = tmpp:8;")):
            self.assertIn(
                f'name: "{name}",', spec_section)
            self.assertIn(
                f'xo: {xo},', spec_section)
            self.assertIn(
                f'result: "{result}"', spec_section)
            # All these scalar selectors overlap Xenon's native vsldoi128
            # mask, including encodings for its extra VD bank bits.
            self.assertEqual(xo & 0x10, 0x10)
            word = (0x10000010 | (1 << 21) | (2 << 16) |
                    (3 << 11) | (1 << 5) | (xo & 0xf))
            self.assertEqual(word & 0xfc000010, 0x10000010)
            self.assertEqual(word & 0xfc00003f, 0x10000000 | xo)
        self.assertEqual(
            0x10221830 & 0xfc00003f, 0x10000030)
        self.assertEqual(
            0x10221c30 & 0xfc00003f, 0x10000030)

    def test_legacy_lwarx_reservation_bookkeeping_is_xenon_local(self):
        # Real xboxkrnl 17559 (0x80064574/800647bc/80088fbc)
        # executes lwarx immediately before stwcx. in lock loops.
        # The stock BIT_0=0 lwarx body comments out reservation writes,
        # whereas the less-specific PPC ISA constructor does set them.
        gradle = (audit.ROOT / "build.gradle").read_text(
            encoding="utf-8")
        slaspec = (audit.ROOT /
                   "data/languages/xenon_64_be.slaspec").read_text(
                       encoding="utf-8")
        assert '@include "xenon_ppc_common.sinc"' in slaspec
        assert 'xenonStockInstructions' in gradle
        assert 'xenonInstructions' in gradle
        assert 'inputs.files(xenonStockCommon, xenonStockEmbedded, xenonStockInstructions)' in gradle
        assert 'outputs.files(xenonCommon, xenonEmbedded, xenonInstructions)' in gradle
        assert """'@include "xenon_ppc_instructions.sinc"'""" in gradle
        assert "'XOP_1_10=20 & BIT_0=0'" in gradle
        assert "'ea:$(REGISTER_SIZE) = RA_OR_ZERO+B;'" in gradle
        assert "'D = zext(*:4(ea));'" in gradle
        assert "oldReservation" in gradle
        assert "'\\t#RESERVE = 1;\\n\\t#RESERVE_ADDRSS:$(REGISTER_SIZE) = ea;'" in gradle
        assert "'\\tRESERVE = 1;\\n\\tRESERVE_LENGTH = 4;\\n\\tRESERVE_ADDRESS = ea;'" in gradle
        assert "lwarxBody.replace(oldReservation, newReservation)" in gradle
        assert "instructions.substring(lwarxEnd + 2)" in gradle
        assert 'xenonInstructions.setText(' in gradle
        assert "refusing Xenon reservation patch" in gradle
        # No claim that this resolves the separate conditional-store
        # and sync CALLOTHERs; hardware contention remains opaque.

    def test_xenon_stwcx_models_atomic_result_without_forced_write(self):
        # Real 17559 lwarx/stwcx. pairs now establish reservation
        # bookkeeping; a conditional store must model BOTH outcomes,
        # not assign success or write memory merely on RESERVE != 0.
        gradle = (audit.ROOT / "build.gradle").read_text(
            encoding="utf-8")
        start = gradle.index("String xenonStwcx = '''")
        end = gradle.index("'''", start + len("String xenonStwcx = '''"))
        constructor = gradle[start:end]
        for fragment in (
                "define pcodeop xenonAtomicStoreWordConditional;",
                "common = common.replace(stockAtomicUserop,",
                "instructions = instructions.replace(stockStwcx, xenonStwcx)",
                "Installed Ghidra stwcx. constructor changed",
                "if (RESERVE == 0) goto <finishStoreConditional>;",
                "succeeded = xenonAtomicStoreWordConditional(",
                "RESERVE = 0;",
                "RESERVE_LENGTH = 0;",
                "setCrBit(cr0, 0, 0);",
                "setCrBit(cr0, 1, 0);",
                "setCrBit(cr0, 2, succeeded);",
                "setCrBit(cr0, 3, (xer_so & 1));",
        ):
            self.assertIn(fragment, gradle if fragment.startswith(
                ("define pcodeop", "common =", "instructions =", "Installed Ghidra"))
                else constructor)
        self.assertNotIn("*[ram]:4", constructor)
        self.assertNotIn("cr0flags(0:", constructor)
        self.assertNotIn("goto inst_next", constructor)
        # Hardware contention remains in one opaque atomic operation.
        self.assertEqual(
            constructor.count("xenonAtomicStoreWordConditional("), 1)
        self.assertEqual(constructor.count("<finishStoreConditional>"), 2)

    def test_xenon_stdcx_preserves_opaque_atomic_success_result(self):
        # A doubleword conditional store has the same reservation and
        # CR0 completion contract as the verified word conditional store.
        # No unconditional 8-byte memory write is permissible.
        gradle = (audit.ROOT / "build.gradle").read_text(encoding="utf-8")
        start = gradle.index("String xenonStdcx = '''")
        end = gradle.index("'''", start + len("String xenonStdcx = '''"))
        constructor = gradle[start:end]
        for fragment in (
                "define pcodeop xenonAtomicStoreDoubleWordConditional;",
                "common = common.replace(stockDwordAtomicUserop,",
                "instructions = instructions.replace(stockStdcx, xenonStdcx)",
                "Installed Ghidra stdcx. constructor changed",
        ):
            self.assertIn(fragment, gradle)
        for fragment in (
                "XOP_1_10=214 & BIT_0=1",
                "local succeeded:1 = 0;",
                "if (RESERVE == 0) goto <finishDoubleWordConditional>;",
                "succeeded = xenonAtomicStoreDoubleWordConditional(",
                "RESERVE = 0;",
                "RESERVE_LENGTH = 0;",
                "setCrBit(cr0, 0, 0);",
                "setCrBit(cr0, 1, 0);",
                "setCrBit(cr0, 2, succeeded);",
                "setCrBit(cr0, 3, (xer_so & 1));",
        ):
            self.assertIn(fragment, constructor)
        self.assertNotIn("*[ram]:8", constructor)
        self.assertNotIn("cr0flags(0:", constructor)
        self.assertNotIn("goto inst_next", constructor)
        self.assertEqual(
            constructor.count("xenonAtomicStoreDoubleWordConditional("), 1)

    def test_copied_instruction_helpers_use_installed_powerpc_path(self):
        # Generated PPC instructions live outside their stock directory.
        # Relative stock include paths would fail at the first lmw helper.
        gradle = (audit.ROOT / "build.gradle").read_text(
            encoding="utf-8")
        for helper in (
                "lmwInstructions.sinc", "lswInstructions.sinc",
                "mulhwInstructions.sinc", "stmwInstructions.sinc",
                "stswiInstructions.sinc"):
            self.assertIn(f'"{helper}"', gradle)
        for fragment in (
            "new File(xenonStockInstructions.parentFile, helper)",
            'String relativeInclude =',
            'String resolvedInclude =',
            '@include "$(PowerPC)/data/languages/',
            "instructions = instructions.replace(relativeInclude, resolvedInclude)",
            "!stockHelper.isFile()",
        ):
            self.assertIn(fragment, gradle)

    def test_xenon_stswi_partial_store_uses_only_requested_bytes(self):
        # Ghidra 12.1.3 ignores 'sa' in storeRegisterPartial.
        # The Xenon-only macro must write high-order bytes of the low
        # 32-bit GPR word and never clobber trailing destination bytes.
        gradle = (audit.ROOT / "build.gradle").read_text(
            encoding="utf-8")
        start = gradle.index("String xenonPartialStore = '''")
        end = gradle.index("'''", start + len("String xenonPartialStore = '''"))
        macro = gradle[start:end]
        self.assertIn("common = common.replace(stockPartialStore, xenonPartialStore)", gradle)
        self.assertIn("common.indexOf(stockPartialStore)", gradle)
        self.assertIn("local wholeGpr:8 = reg;", macro)
        self.assertIn("local word:4 = wholeGpr:4;", macro)
        self.assertIn("local word:4 = reg;", macro)
        self.assertNotIn("*:4(ea)", macro)
        for fragment in (
                "*:1(ea) = word(3);",
                "if (sa == 1) goto <partialDone>;",
                "*:1(ea) = word(2);",
                "if (sa == 2) goto <partialDone>;",
                "*:1(ea) = word(1);",
                "<partialDone>",
        ):
            self.assertIn(fragment, macro)
        self.assertEqual(macro.count("*:1(ea)"), 3)
        # Numeric oracle independent of machine-word width. For Xenon,
        # STSWI sees only a GPR's low 32 bits, in big-endian byte order.
        for value in (0x1122334455667788, 0xaabbccdd, 0xffffffff00000000):
            word = (value & 0xffffffff).to_bytes(4, "big")
            extracted = [word[0], word[1], word[2]]
            for count in (1, 2, 3):
                self.assertEqual(bytes(extracted[:count]), word[:count])

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
            'inputs.files(xenonStockCommon, xenonStockEmbedded, xenonStockInstructions)',
            'outputs.files(xenonCommon, xenonEmbedded, xenonInstructions)',
            """String target = ':dcbzl RA_OR_ZERO,B'""",
            """String dcbzlPattern = 'BITS_21_25=1 & B & XOP_1_10=1014 & BIT_0=0'""",
            """'@include "xenon_ppc_instructions.sinc"'""",
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
            {"native-pcode": 36, "opaque-userop": 12}))
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

    def test_signed_halfword_unpack_native_lane_mapping(self):
        # Check source halves, signed widening, and destination bit order.
        import re

        source = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        for name, first in (("vupkhsh128", 0), ("vupklsh128", 4)):
            bodies = re.findall(
                r"(?m)^:" + name + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", source)
            self.assertEqual(len(bodies), 1)
            body = bodies[0]
            for i in range(4):
                offset = 14 - 2 * (first + i)
                shift = 96 - 32 * i
                self.assertIn(f"sourceHalf{i}:2 = xenonB({offset});", body)
                self.assertIn(f"signedWord{i}:4 = sext(sourceHalf{i});", body)
                term = f"placedWord{i}:16 = zext(signedWord{i})"
                self.assertIn(term + (f" << {shift}" if shift else "") + ";",
                              body)
            self.assertIn("xenonD = placedWord0 | placedWord1 | "
                          "placedWord2 | placedWord3;", body)

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

    def test_critical_section_helper_metadata_script_preserves_pdata(self):
        # Verified kernel 17559 uses a distinct .pdata function at 800890AC.
        # Apply the inferred wait-helper name, not a body merge or a new
        # Ghidra function. Existing return and ABI datatypes stay untouched.
        src = (audit.ROOT.parent / "ghidra_scripts" /
               "ApplyXboxKrnl17559CriticalSectionWaitMetadataV1.java"
               ).read_text(encoding="utf-8")
        self.assertIn(
            "public class ApplyXboxKrnl17559CriticalSectionWaitMetadataV1",
            src)
        self.assertIn(
            'private static final String WAIT_NAME = "RtlpWaitForCriticalSection";',
            src)
        self.assertIn("0x800890F7L", src)
        self.assertIn("0x800890F8", src)
        self.assertIn("0x80088FF8L", src)
        self.assertIn("0x80073120", src)
        self.assertIn("0x800890DCL", src)
        self.assertIn("0x800890E0L", src)
        self.assertIn("ReferenceIterator refs =", src)
        self.assertIn('helper.setName(WAIT_NAME, SourceType.USER_DEFINED);', src)
        self.assertIn('p.setName(PARAM_NAME, SourceType.USER_DEFINED);', src)
        self.assertIn("helper.setRepeatableComment(existing +", src)
        self.assertNotIn("createFunction(", src)
        self.assertNotIn("removeFunction(", src)
        self.assertNotIn("setReturnType(", src)
        self.assertNotIn("setBody(", src)
        self.assertNotIn("setBytes(", src)
        self.assertNotIn("clearListing(", src)

    def test_reanalysis_metadata_audit_preserves_verified_pdata(self):
        src = (audit.ROOT.parent / "ghidra_scripts" /
               "AuditAnnotateXboxKrnl17559ReanalysisV1.java"
               ).read_text(encoding="utf-8")
        for required in (
            "public class AuditAnnotateXboxKrnl17559ReanalysisV1",
            'getExecutableSHA256()',
            'getExecutableFormat()',
            'getBookmarksIterator()',
            'getFunctions(true)',
            'getRepeatableComment()',
            'findSpan(spans, at)',
            'foundInside == 0',
            'recognizedSharedEntry(at, s)',
            'other nested entries needing review',
            'spans.size() == 3188',
            'getFunctionAt(addr)',
            'f.setRepeatableComment(',
        ):
            self.assertIn(required, src)
        for disallowed in (
            "setNoReturn(", "setReturnType(", "setCallingConvention(",
            "setBody(", "removeFunction(", "createFunction(",
            "clearListing(", "setBytes(", "removeBookmark(",
            "setDataType(", "setName(", "setPrimary(",
        ):
            self.assertNotIn(disallowed, src)
        self.assertIn('APPLY_SAFE_METADATA = true', src)
        self.assertIn('already++', src)
        self.assertIn('No functions created/merged', src)

    def test_xenon_shared_helper_metadata_is_evidence_guarded(self):
        src = (audit.ROOT.parent / "ghidra_scripts" /
               "ApplyXboxKrnl17559SharedRegisterHelpersV1.java"
               ).read_text(encoding="utf-8")
        for expected in (
                'public class ApplyXboxKrnl17559SharedRegisterHelpersV1',
                '0x8010CB90L', '0x8010CBE0L',
                '0x8010D240L', '0x8010D28CL',
                '0x800644ECL', '0x8010CBB8L',
                '0x8006476CL', '0x8010CBC4L',
                '0x80064760L', '0x8010CC08L',
                '0x80064964L', '0x8010CC14L',
                'completeFamily(SAVE_GPR, "std", "gpr")',
                'completeFamily(REST_GPR, "ld", "gpr")',
                'nameExistingEntries(SAVE_GPR, "__savegprlr_"',
                'nameExistingEntries(REST_GPR, "__restgprlr_"',
                'FunctionUpdateType.CUSTOM_STORAGE',
                'params[k] = new ParameterImpl(names[k], t, reg',
                'Undefined8DataType.dataType',
                'new ParameterImpl("poolAddress"',
                'f.updateFunction(null, null',
                'APPLY_ALLOCATOR_PROTOTYPES = true',
        ):
            self.assertIn(expected, src)
        for forbidden in (
                'removeFunction(', 'createFunction(', 'setBody(',
                'setReturnType(', 'setCallingConvention(',
                'clearListing(', 'setBytes(', 'setNoReturn(',
        ):
            self.assertNotIn(forbidden, src)

    def test_committed_ghidra_java_audits_keep_compile_contracts(self):
        # The Ghidra GUI compiles scripts separately from buildExtension.
        # A checked TaskMonitor exception once broke the helper script
        # even though the SLEIGH extension built correctly.
        root = audit.ROOT.parent / "ghidra_scripts"
        for name in (
                "AuditXboxKrnl17559AtomicPcodeV1",
                "AuditXboxKrnl17559AtomicPcodeV2",
                "AuditXboxKrnl17559CriticalSectionHelperV1",
                "AuditXenonNumericalPcode",
                "AuditXenonStswiPartialStoresV1",
        ):
            source = (root / (name + ".java")).read_text(encoding="utf-8")
            self.assertIn(
                "public class " + name + " extends GhidraScript", source)
        helper = (root /
                  "AuditXboxKrnl17559CriticalSectionHelperV1.java"
                  ).read_text(encoding="utf-8")
        self.assertIn(
            "import ghidra.util.exception.CancelledException;", helper)
        self.assertIn(
            "private void dumpFunction(Function fn) throws CancelledException",
            helper)
        self.assertIn("monitor.checkCancelled();", helper)
        for name in ("AuditXenonNumericalPcode",
                     "AuditXenonStswiPartialStoresV1"):
            source = (root / (name + ".java")).read_text(encoding="utf-8")
            self.assertIn('import ghidra.app.emulator.EmulatorHelper;', source)
            self.assertIn('@SuppressWarnings("removal")', source)
        # The source audit intentionally retains the legacy emulator
        # until its exact private-memory numerical behavior can be
        # replaced and independently verified.

    def test_extension_build_runs_offline_regressions_and_sleigh(self):
        # A clean checkout must exercise the checked-in numerical source
        # assertions automatically rather than rely on remembered scripts.
        gradle = (audit.ROOT / "build.gradle").read_text(
            encoding="utf-8")
        begin = gradle.index(
            'tasks.register("testXenonIsaCoverage", Exec)')
        sleigh = gradle.index('tasks.register("verifyXenonSleigh", Exec)')
        diagnostics = gradle.index(
            'tasks.register("diagnoseXenonSleigh", Exec)')
        self.assertLess(begin, sleigh)
        suite = gradle[begin:sleigh]
        verifier = gradle[sleigh:diagnostics]
        self.assertIn(
            'commandLine pythonCommand, "tools/test_xenon_isa_coverage_v1.py"',
            suite)
        self.assertIn('dependsOn tasks.named("generateXenonIsaFixture")',
                      suite)
        self.assertIn('tasks.named("testXenonIsaCoverage")', verifier)
        self.assertIn('tasks.named("prepareXenonCommon")', verifier)
        self.assertIn(
            'tasks.matching { it.name in ["build", "buildExtension", "assemble"] }',
            gradle)
        self.assertIn('dependsOn tasks.named("verifyXenonSleigh")',
                      gradle)

    def test_java_fixture_manifest_header(self):
        # Numerical checks share one script and the existing 344-word fixture.
        source = (audit.ROOT.parent / "ghidra_scripts" /
                  "AuditXenonNumericalPcode.java").read_text(
                      encoding="utf-8")
        self.assertIn("public class AuditXenonNumericalPcode", source)
        self.assertIn('offset\\tword_be\\texpected_mnemonic\\t', source)
        self.assertIn('line.split("\\t", -1)', source)
        self.assertIn('"decode".equals(columns[5])', source)
        self.assertIn("originalFixtureMatches(address, originalWord)", source)
        self.assertIn("fixtureWordMatches(address, fixtureWords.get(address))",
                      source)
        expected = ("offset", "word_be", "expected_mnemonic",
                    "sleigh_status", "variant", "decode_expectation")
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            audit.write_results(self.rows, audit.SLEIGH, audit.INVENTORY, out)
            with (out / "xenon_isa_fixture_v1.tsv").open(
                    encoding="utf-8", newline="") as handle:
                self.assertEqual(tuple(handle.readline().strip().split("\t")),
                                 expected)

    def test_native_shuffle_numeric_selectors_and_oracles(self):
        # Four extended-VA banks and independent VC register selectors.
        # Run the fixed scalar oracle over the complete 128 shift matrix.
        script = (audit.ROOT.parent / "ghidra_scripts" /
                  "AuditXenonNumericalPcode.java").read_text(
                      encoding="utf-8")
        remaining = audit.ADDITIONAL_SLEIGH.read_text(
            encoding="utf-8")
        registers = audit.SLEIGH.read_text(encoding="utf-8")

        self.assertEqual(remaining.count(":vsldoi128 xenonD,"), 2)
        self.assertEqual(remaining.count(":vperm128 xenonD,"), 2)
        self.assertIn("private void runShuffles(File manifest, Address base)",
                      script)
        self.assertIn("runShuffles(manifest, base);", script)
        self.assertIn("runDotProducts(manifest, base);", script)
        self.assertIn("runWholeVectorShifts(manifest, base);", script)
        self.assertIn("runLaneShifts(manifest, base);", script)
        self.assertIn("runLogicalOps(manifest, base);", script)
        self.assertIn("runWordMerges(manifest, base);", script)
        self.assertIn("runWordPermutations(manifest, base);", script)
        self.assertIn("XENON WORD PERMUTATION NATIVE NUMERICAL P-CODE AUDIT", script)
        self.assertIn("XENON WORD MERGE NATIVE NUMERICAL P-CODE AUDIT", script)
        self.assertIn("XENON VECTOR BITWISE NATIVE NUMERICAL P-CODE AUDIT", script)
        self.assertIn("XENON PER-LANE WORD SHIFT NATIVE NUMERICAL P-CODE AUDIT", script)
        self.assertIn("XENON WHOLE-VECTOR SHIFT NATIVE NUMERICAL P-CODE AUDIT", script)
        self.assertIn("XENON FP DOT PRODUCT NATIVE NUMERICAL P-CODE AUDIT", script)
        self.assertIn("import ghidra.app.emulator.DefaultEmulator;", script)
        self.assertIn('pattern == 0 && selector == 0;', script)
        self.assertIn("((DefaultEmulator) emulator.getEmulator())", script)
        self.assertIn(".disassemble(1)", script)
        self.assertIn("emulatorDecoded=[", script)
        self.assertIn("alternativeDestRegisters=", script)
        self.assertIn('recordSuite("SHUFFLE", passed, failed, problems);',
                      script)
        self.assertIn("emulator.writeMemory(address, opcode);", script)
        self.assertIn("emulator.readMemory(address, 4)", script)
        self.assertIn('vectorRegister("vs36")', script)
        self.assertIn('vectorRegister(guardedFpSourceAName(variant))',
                      script)
        self.assertIn("!fixtureMatches(address, original)", script)
        self.assertNotIn("currentProgram.getMemory().setBytes(", script)
        self.assertIn("int start = pattern == 0 ?", script)

        va_names = ("vs34", "xv34", "xv66", "xv98")
        for variant, va in enumerate(va_names):
            mbh, oe = variant & 1, (variant >> 1) & 1
            definition = (f'xenonA: "{va}" is vrAR=2 & '
                          f'MBH={mbh} & OE={oe} {{ export {va}; }}')
            self.assertIn(definition, registers)

            for shift in range(16):
                word = (0x10000010 | (1 << 21) | (2 << 16) |
                        (3 << 11) | (shift << 6) |
                        (mbh << 5) | (oe << 10))
                self.assertEqual(word & 0xfc000010, 0x10000010)
                self.assertEqual((word >> 6) & 15, shift)
                self.assertEqual((word >> 5) & 1, mbh)
                self.assertEqual((word >> 10) & 1, oe)
            word = (0x14000000 | (1 << 21) | (2 << 16) |
                    (3 << 11) | (4 << 6) |
                    (mbh << 5) | (oe << 10))
            self.assertEqual(word & 0xfc000210, 0x14000000)
            self.assertEqual((word >> 6) & 7, 4)
            self.assertEqual((word >> 9) & 1, 0)
            self.assertIn(
                f'xenonC: "vs36" is BITS_6_10={4 + (oe << 4)}',
                remaining)

        mask = (1 << 128) - 1
        for input_variant in (0, 1):
            aa = bytes((0x10 + i if input_variant == 0 else 0x80 + 7*i)
                       & 255 for i in range(16))
            bb = bytes((0xa0 - i if input_variant == 0 else 0x05 + 11*i)
                       & 255 for i in range(16))
            a_bits, b_bits = int.from_bytes(aa, "big"), int.from_bytes(
                bb, "big")
            for shift in range(16):
                expected = int.from_bytes(aa[shift:] + bb[:shift],
                                          "big")
                actual = ((a_bits << (shift * 8)) |
                          (b_bits >> (128 - shift * 8))) & mask
                self.assertEqual(actual, expected)

        # Control values select by bit4 (A/B) and low nibble (octet).
        a = bytes(range(16))
        b = bytes(range(0x80, 0x90))
        controls = [
            bytes(range(16)),
            bytes(0x10 | i for i in range(16)),
            bytes(0x20 | ((i & 1) << 4) | (15-i) for i in range(16)),
            bytes(0xf0 | (15-i) for i in range(16)),
            bytes(0x80 | (0x10 if i % 3 == 0 else 0) |
                  ((i * 7 + 3) & 15) for i in range(16)),
            bytes(0x40 | ((i & 1) << 4) for i in range(16)),
            bytes([0x6f] * 16),
            bytes([0x9f] * 16),
        ]
        self.assertEqual(len(controls), 8)
        for c in controls:
            expected = bytes((b if v & 16 else a)[v & 15] for v in c)
            self.assertEqual(len(expected), 16)
            # High selector bits [5..7] must not modify the chosen byte.
            augmented = bytes(v ^ 0xe0 for v in c)
            self.assertEqual(
                bytes((b if v & 16 else a)[v & 15] for v in augmented),
                expected)

    def test_native_dot_product_numeric_matrix(self):
        # Two independent SLEIGH sources implement exact binary32 dot
        # reductions, with a different number of products.
        import re
        import struct

        script = (audit.ROOT.parent / "ghidra_scripts" /
                  "AuditXenonNumericalPcode.java").read_text(
                      encoding="utf-8")
        expected_ops = (
            ("vmsum3fp128", "0x14000190", 3),
            ("vmsum4fp128", "0x140001d0", 4),
        )
        operations = re.findall(
            r'new DotOperation\("([^"]+)",\s*(0x[0-9a-fA-F]+)L,\s*(\d+)\)',
            script)
        self.assertEqual(
            operations,
            [(name, opcode, str(count)) for name, opcode, count
             in expected_ops])
        self.assertIn("runDotProducts(manifest, base);", script)
        self.assertIn('recordSuite("DOT", passed, failed, problems)', script)
        self.assertIn("emulator.writeMemory(address, opcode);", script)
        self.assertIn("emulator.readMemory(address, 4)", script)
        self.assertIn("fixtureMatches(address, originalWord)", script)
        self.assertIn("emulator.readRegister(a)", script)
        self.assertIn("emulator.readRegister(b)", script)
        self.assertIn(
            "Register a = vectorRegister(guardedFpSourceAName(variant));",
            script)
        self.assertIn("for (int i = 3; i >= 4 - operation.products; i--)",
                      script)
        self.assertNotIn("currentProgram.getMemory().setBytes(", script)

        patterns = re.findall(
            r'new Pattern\("([^"]+)",\s*'
            r'new int\[\] \{([^}]*)\},\s*'
            r'new int\[\] \{([^}]*)\},\s*'
            r'new int\[\] \{([^}]*)\}\)',
            script)
        self.assertEqual(len(patterns), 6)
        count = 0
        for name, opcode_string, products in expected_ops:
            opcode = int(opcode_string, 16)
            code = (audit.SLEIGH if name == "vmsum4fp128"
                    else audit.ADDITIONAL_SLEIGH).read_text(
                        encoding="utf-8")
            self.assertEqual(
                len(re.findall(r"(?m)^:" + name + r" ", code)), 4)
            for variant in range(4):
                mbh, oe = variant & 1, variant >> 1
                word = (opcode | (1 << 21) | (2 << 16) |
                        (3 << 11) | (mbh << 5) | (oe << 10))
                self.assertEqual(word & 0xfc0003d0, opcode)
                self.assertEqual((word >> 5) & 1, mbh)
                self.assertEqual((word >> 10) & 1, oe)
                self.assertEqual(
                    ((word >> 21) & 31, (word >> 16) & 31,
                     (word >> 11) & 31), (1, 2, 3))
                for _, a_string, b_string, _ in patterns:
                    a = [int(v) for v in a_string.split(",")]
                    b = [int(v) for v in b_string.split(",")]
                    self.assertEqual(len(a), 4)
                    self.assertEqual(len(b), 4)
                    self.assertTrue(all(0 < abs(v) <= 2048
                                        for v in a + b))
                    dot = sum(a[i] * b[i] for i in range(4-products, 4))
                    self.assertTrue(0 < abs(dot) < (1 << 24))
                    bits = int.from_bytes(
                        struct.pack(">f", float(dot)), "big")
                    result = bits.to_bytes(4, "big") * 4
                    self.assertEqual(len(result), 16)
                    self.assertEqual(
                        struct.unpack(">f", result[:4])[0], float(dot))
                    count += 1
        self.assertEqual(count, 48)

    def test_native_whole_vector_shift_numeric_matrix(self):
        # Exact 128-bit native shifts. Only control bits 3..6 matter;
        # bit 7 and low three bits must be ignored.
        import re

        script = (audit.ROOT.parent / "ghidra_scripts" /
                  "AuditXenonNumericalPcode.java").read_text(
                      encoding="utf-8")
        source = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        operations = (
            ("vslo128", 0x14000390, "<<"),
            ("vsro128", 0x140003d0, ">>"),
        )
        self.assertIn("runWholeVectorShifts(manifest, base);", script)
        self.assertIn(
            'recordSuite("WHOLE-SHIFT", passed, failed, problems)',
            script)
        self.assertIn('if ((encoded & 0x78) != (count * 8))', script)
        self.assertIn('bytesB[15] = (byte) ((count << 3)', script)
        self.assertIn('(pattern == 0 ? 0x05 : 0x87)', script)
        self.assertIn('!fixtureMatches(address, originalWord)', script)
        self.assertIn('emulator.writeMemory(address, opcode);', script)
        self.assertIn('emulator.readMemory(address, 4)', script)
        self.assertIn('emulator.readRegister(aReg)', script)
        self.assertIn('emulator.readRegister(bReg)', script)
        self.assertNotIn('currentProgram.getMemory().setBytes(', script)

        selectors = re.findall(
            r'new WholeVectorShift\("([^"]+)",\s*(0x[0-9a-fA-F]+)L,'
            r'\s*(true|false)\)', script)
        self.assertEqual(
            selectors,
            [("vslo128", "0x14000390", "true"),
             ("vsro128", "0x140003d0", "false")])
        total = 0
        mask128 = (1 << 128) - 1
        for name, selector, direction in operations:
            self.assertEqual(
                len(re.findall(r"(?m)^:" + name + r" ", source)), 4)
            bodies = re.findall(
                r"(?m)^:" + name + r" [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", source)
            for body in bodies:
                self.assertIn("last:1 = xenonB(0);", body)
                self.assertIn("shift:4 = zext(last & 0x78);", body)
                self.assertIn("xenonD = xenonA " + direction +
                              " shift;", body)

            for variant in range(4):
                mbh, oe = variant & 1, variant >> 1
                word = (selector | (1 << 21) | (2 << 16) |
                        (3 << 11) | (mbh << 5) | (oe << 10))
                self.assertEqual(word & 0xfc0003d0, selector)
                self.assertEqual((word >> 5) & 1, mbh)
                self.assertEqual((word >> 10) & 1, oe)
                for pattern in range(2):
                    if pattern == 0:
                        aa = bytes((0x10 + i) & 255 for i in range(16))
                        bb = bytearray((0xa0 - i) & 255
                                       for i in range(16))
                    else:
                        aa = bytes((0x80 + i * 7) & 255 for i in range(16))
                        bb = bytearray((0x05 + i * 11) & 255
                                       for i in range(16))
                    a = int.from_bytes(aa, "big")
                    for count in range(16):
                        control = (count << 3) | (
                            0x05 if pattern == 0 else 0x87)
                        bb[-1] = control
                        self.assertEqual(control & 0x78, count * 8)
                        self.assertNotEqual(control & 7, 0)
                        if pattern:
                            self.assertEqual(control & 0x80, 0x80)
                        self.assertEqual(len(bb), 16)
                        b = int.from_bytes(bb, "big")
                        shift = b & 0x78
                        self.assertEqual(shift, count * 8)
                        result = ((a << shift) & mask128
                                  if direction == "<<" else a >> shift)
                        self.assertTrue(0 <= result <= mask128)
                        # Compare bytewise oracles independent of BigInteger.
                        nbytes = count
                        expected = (aa[nbytes:] +
                                    bytes(nbytes) if direction == "<<"
                                    else bytes(nbytes) + aa[:16-nbytes])
                        self.assertEqual(
                            result.to_bytes(16, "big"), expected)
                        total += 1
        self.assertEqual(total, 256)

    def test_native_word_lane_shift_numerical_matrix(self):
        # Confirm each of the four independent 32-bit lanes obeys its own
        # low-five-bit control, including signed right-shift and rotation.
        import re

        script = (audit.ROOT.parent / "ghidra_scripts" /
                  "AuditXenonNumericalPcode.java").read_text(
                      encoding="utf-8")
        sleigh = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        operations = (
            ("vrlw128", 0x18000050, 0, "<<"),
            ("vslw128", 0x180000d0, 1, "<<"),
            ("vsraw128", 0x18000150, 2, "s>>"),
            ("vsrw128", 0x180001d0, 3, ">>"),
        )
        self.assertIn("runLaneShifts(manifest, base);", script)
        self.assertIn(
            'recordSuite("LANE-SHIFT", passed, failed, problems)', script)
        self.assertIn('if (!expected.equals(result) || !inputA.equals(afterA) ||',
                      script)
        self.assertIn('!inputB.equals(afterB))', script)
        self.assertIn('!fixtureMatches(address, originalWord)', script)
        self.assertIn('emulator.writeMemory(address, opcode);', script)
        self.assertIn('emulator.readMemory(address, 4)', script)
        self.assertNotIn('currentProgram.getMemory().setBytes(', script)
        declared = re.findall(
            r'new LaneShift\("([^"]+)",\s*(0x[0-9a-fA-F]+)L,\s*(\d+)\)',
            script)
        self.assertEqual(declared, [
            (name, f"0x{selector:08x}", str(op)) for
            name, selector, op, _ in operations])

        src_match = re.search(
            r'private static final int\[\]\[\] LANE_SHIFT_SOURCES = '
            r'\{([\s\S]*?)\n    \};', script)
        ctl_match = re.search(
            r'private static final int\[\]\[\] LANE_SHIFT_COUNTS = '
            r'\{([\s\S]*?)\n    \};', script)
        self.assertIsNotNone(src_match)
        self.assertIsNotNone(ctl_match)
        read_arrays = lambda match: [
            [int(v.strip(), 0) & 0xffffffff
             for v in row.split(",") if v.strip()]
            for row in re.findall(r'\{([^}]+)\}', match.group(1))]
        inputs = read_arrays(src_match)
        controls = read_arrays(ctl_match)
        self.assertEqual(len(inputs), 2)
        self.assertEqual(len(controls), 10)
        self.assertTrue(all(len(row) == 4 for row in inputs + controls))
        self.assertEqual(
            sorted(value for row in controls[:8] for value in row),
            list(range(32)))
        self.assertTrue(
            all(any(value & ~31 for value in row) for row in controls[8:]))

        count = 0
        mask = 0xffffffff
        for name, selector, operation, op_text in operations:
            rules = re.findall(
                r'(?m)^:' + name + r' [^\n]+ is [^\n]+', sleigh)
            self.assertEqual(len(rules), 4, name)
            for lane in range(4):
                self.assertIn(
                    f"xenonInputALane{lane}:4 = xenonA({lane * 4});",
                    sleigh)
                self.assertIn(
                    f"xenonInputBLane{lane}:4 = xenonB({lane * 4});",
                    sleigh)
                self.assertIn(f"sh{lane}:4 = xenonInputBLane{lane} & 31;",
                              sleigh)
                if operation == 0:
                    self.assertIn(
                        f"xenonResultLane{lane}:4 = "
                        f"(xenonInputALane{lane} << sh{lane}) |",
                        sleigh)
                    self.assertIn(
                        f"(xenonInputALane{lane} >> back{lane});", sleigh)
                    self.assertIn(
                        f"back{lane}:4 = (32 - sh{lane}) & 31;", sleigh)
                else:
                    self.assertIn(
                        f"xenonResultLane{lane}:4 = "
                        f"xenonInputALane{lane} {op_text} sh{lane};",
                        sleigh)
            for variant in range(4):
                mbh, oe = variant & 1, variant >> 1
                word = (selector | (1 << 21) | (2 << 16) |
                        (3 << 11) | (mbh << 5) | (oe << 10))
                self.assertEqual(word & 0xfc0003d0, selector)
                self.assertEqual((word >> 5) & 1, mbh)
                self.assertEqual((word >> 10) & 1, oe)
                for row_a in inputs:
                    for row_b in controls:
                        actual = []
                        for a, b in zip(row_a, row_b):
                            sh = b & 31
                            if operation == 0:
                                value = ((a << sh) |
                                         (a >> ((32 - sh) & 31))) & mask
                            elif operation == 1:
                                value = (a << sh) & mask
                            elif operation == 2:
                                signed = a if a < (1 << 31) else a - (1 << 32)
                                value = (signed >> sh) & mask
                            else:
                                value = a >> sh
                            actual.append(value)
                        expected_bytes = b"".join(
                            value.to_bytes(4, "big")
                            for value in reversed(actual))
                        self.assertEqual(len(expected_bytes), 16)
                        count += 1
        self.assertEqual(count, 320)

    def test_native_vector_logical_numerical_matrix(self):
        # Verify the independent A/B operands and old-D-as-mask in vsel,
        # including complementary, sparse, dense and high-bit patterns.
        import re

        script = (audit.ROOT.parent / "ghidra_scripts" /
                  "AuditXenonNumericalPcode.java").read_text(
                      encoding="utf-8")
        sleigh = audit.SLEIGH.read_text(encoding="utf-8")
        operations = (
            ("vand128", 0x14000210, 0, "xenonD = xenonA & xenonB;"),
            ("vandc128", 0x14000250, 1, "xenonD = xenonA & ~xenonB;"),
            ("vnor128", 0x14000290, 2, "xenonD = ~(xenonA | xenonB);"),
            ("vor128", 0x140002d0, 3, "xenonD = xenonA | xenonB;"),
            ("vxor128", 0x14000310, 4, "xenonD = xenonA ^ xenonB;"),
            ("vsel128", 0x14000350, 5,
             "xenonD = (xenonA & ~xenonD) | (xenonB & xenonD);"),
        )
        declared = re.findall(
            r'new LogicalOp\("([^"]+)",\s*(0x[0-9a-fA-F]+)L,\s*(\d+)\)',
            script)
        self.assertEqual(
            declared,
            [(name, f"0x{opcode:08x}", str(kind))
             for name, opcode, kind, _ in operations])

        patterns = re.findall(
            r'new LogicalPattern\("([^"]+)",\s*'
            r'"([0-9a-f]{32})",\s*"([0-9a-f]{32})",\s*'
            r'"([0-9a-f]{32})"\)', script)
        self.assertEqual(len(patterns), 12)
        self.assertEqual(len({p[0] for p in patterns}), 12)
        self.assertIn("runLogicalOps(manifest, base);", script)
        self.assertIn('recordSuite("LOGIC", passed, failed, problems)',
                      script)
        self.assertIn("emulator.writeRegister(destination, pattern.mask);",
                      script)
        self.assertIn("emulator.readRegister(destination).and(MASK128)",
                      script)
        self.assertIn("!pattern.a.equals(afterA)", script)
        self.assertIn("!pattern.b.equals(afterB)", script)
        self.assertIn("!fixtureMatches(address, originalWord)", script)
        self.assertIn("emulator.writeMemory(address, opcode);", script)
        self.assertIn("emulator.readMemory(address, 4)", script)
        self.assertNotIn("currentProgram.getMemory().setBytes(", script)

        mask128 = (1 << 128) - 1
        cases = 0
        for name, opcode, kind, semantics in operations:
            constructors = re.findall(
                r"(?m)^:" + name + r" [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", sleigh)
            self.assertEqual(len(constructors), 4, name)
            self.assertTrue(all(semantics in body for body in constructors))
            for variant in range(4):
                word = (opcode | (1 << 21) | (2 << 16) |
                        (3 << 11) | ((variant & 1) << 5) |
                        ((variant >> 1) << 10))
                self.assertEqual(word & 0xfc0003d0, opcode)
                self.assertEqual((word >> 5) & 1, variant & 1)
                self.assertEqual((word >> 10) & 1, variant >> 1)
                for _, text_a, text_b, text_mask in patterns:
                    a, b, old_d = (int(text_a, 16),
                                   int(text_b, 16),
                                   int(text_mask, 16))
                    if kind == 0:
                        result = a & b
                    elif kind == 1:
                        result = a & (~b & mask128)
                    elif kind == 2:
                        result = ~(a | b) & mask128
                    elif kind == 3:
                        result = a | b
                    elif kind == 4:
                        result = a ^ b
                    else:
                        result = (a & (~old_d & mask128)) | (b & old_d)
                    self.assertEqual(len(result.to_bytes(16, "big")), 16)
                    self.assertTrue(0 <= result <= mask128)
                    if kind == 5:
                        # Bitwise independent truth table, checking old D.
                        for bit in range(128):
                            expected_bit = (((b if (old_d >> bit) & 1
                                              else a) >> bit) & 1)
                            self.assertEqual((result >> bit) & 1,
                                             expected_bit)
                    cases += 1
        self.assertEqual(cases, 288)

    def test_native_word_merges_exact_lane_order(self):
        # Real merge constructors take the high (3,2) or low (1,0)
        # 32-bit word pairs of independent VA/VB, alternating A/B.
        import re

        script = (audit.ROOT.parent / "ghidra_scripts" /
                  "AuditXenonNumericalPcode.java").read_text(
                      encoding="utf-8")
        source = audit.SLEIGH.read_text(encoding="utf-8")
        operations = (
            ("vmrghw128", 0x18000300, True),
            ("vmrglw128", 0x18000340, False),
        )
        declared = re.findall(
            r'new WordMerge\("([^"]+)",\s*(0x[0-9a-fA-F]+)L,\s*'
            r'(true|false)\)', script)
        self.assertEqual(
            declared,
            [(name, f"0x{opcode:08x}", str(high).lower())
             for name, opcode, high in operations])
        self.assertIn("runWordMerges(manifest, base);", script)
        self.assertIn(
            'recordSuite("WORD-MERGE", passed, failed, problems)', script)
        self.assertIn("BigInteger initialD = expected.xor(MASK128);", script)
        self.assertIn("emulator.writeRegister(destination, initialD);",
                      script)
        self.assertIn("!fixtureMatches(address, originalWord)", script)
        self.assertIn("emulator.writeMemory(address, opcode);", script)
        self.assertIn("emulator.readMemory(address, 4)", script)
        self.assertIn("emulator.readRegister(aReg)", script)
        self.assertIn("emulator.readRegister(bReg)", script)
        self.assertNotIn("currentProgram.getMemory().setBytes(", script)

        patterns = re.findall(
            r'new LogicalPattern\("([^"]+)",\s*'
            r'"([0-9a-f]{32})",\s*"([0-9a-f]{32})",\s*'
            r'"([0-9a-f]{32})"\)', script)
        self.assertEqual(len(patterns), 12)
        mask128 = (1 << 128) - 1
        cases = 0
        for name, opcode, high in operations:
            constructors = re.findall(
                r"(?m)^:" + name + r" [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", source)
            self.assertEqual(len(constructors), 4, name)
            first_offset, second_offset = (12, 8) if high else (4, 0)
            for body in constructors:
                self.assertIn(
                    f"aFirst:4 = xenonA({first_offset});", body)
                self.assertIn(
                    f"bFirst:4 = xenonB({first_offset});", body)
                self.assertIn(
                    f"aSecond:4 = xenonA({second_offset});", body)
                self.assertIn(
                    f"bSecond:4 = xenonB({second_offset});", body)
                self.assertIn(
                    "xenonD = first | second | third | fourth;", body)
            for variant in range(4):
                word = (opcode | (1 << 21) | (2 << 16) |
                        (3 << 11) | ((variant & 1) << 5) |
                        ((variant >> 1) << 10))
                self.assertEqual(word & 0xfc0003d0, opcode)
                self.assertEqual((word >> 5) & 1, variant & 1)
                self.assertEqual((word >> 10) & 1, variant >> 1)
                for _, text_a, text_b, _ in patterns:
                    a, b = int(text_a, 16), int(text_b, 16)
                    words_a = [(a >> (i * 32)) & 0xffffffff
                               for i in range(4)]
                    words_b = [(b >> (i * 32)) & 0xffffffff
                               for i in range(4)]
                    upper = 3 if high else 1
                    expected_words = [
                        words_a[upper], words_b[upper],
                        words_a[upper - 1], words_b[upper - 1],
                    ]
                    result_bytes = b"".join(
                        word.to_bytes(4, "big") for word in expected_words)
                    result = int.from_bytes(result_bytes, "big")
                    self.assertTrue(0 <= result <= mask128)
                    self.assertNotEqual(result ^ mask128, result)
                    self.assertEqual(len(result_bytes), 16)
                    cases += 1
        self.assertEqual(cases, 96)

    def test_native_word_permutation_exhaustive_immediates(self):
        # Each instruction encodes an 8-bit 4-word selector via
        # A_BITS[4:0] and the low 3 bits of BITS_6_10-8.
        import re

        script = (audit.ROOT.parent / "ghidra_scripts" /
                  "AuditXenonNumericalPcode.java").read_text(
                      encoding="utf-8")
        sleigh = audit.SLEIGH.read_text(encoding="utf-8")
        self.assertIn(
            "private void runWordPermutations(File manifest, Address base)",
            script)
        self.assertIn("runWordPermutations(manifest, base);", script)
        self.assertIn('recordSuite("WORD-PERMUTE", passed, failed, problems)',
                      script)
        self.assertIn(
            "private static final long PERMUTE_WORD_MASK = 0xfc000630L;",
            script)
        self.assertIn(
            "private static final long PERMUTE_WORD_SELECTOR = 0x18000210L;",
            script)
        self.assertIn('BigInteger initialD = expected.xor(MASK128);',
                      script)
        self.assertIn("emulator.writeRegister(source, b);", script)
        self.assertIn("emulator.writeRegister(destination, initialD);",
                      script)
        self.assertIn("emulator.readRegister(source).and(MASK128)", script)
        self.assertIn("!fixtureMatches(address, originalWord)", script)
        self.assertIn("emulator.writeMemory(address, opcode);", script)
        self.assertIn("emulator.readMemory(address, 4)", script)
        self.assertNotIn("currentProgram.getMemory().setBytes(", script)
        banks = re.search(
            r'private static final String\[\] PERMUTE_WORD_B_BANKS = '
            r'\{([\s\S]*?)\};', script)
        self.assertIsNotNone(banks)
        names = re.findall(r'"([^"]+)"', banks.group(1))
        self.assertEqual(names, ["vs35", "xv35", "xv67", "xv99"])
        for bank, name in enumerate(names):
            self.assertIn(
                f'xenonB: "{name}" is vrBR=3 & BITS_0_1={bank} '
                f'{{ export {name}; }}', sleigh)

        src = re.search(
            r'private static final BigInteger\[\] PERMUTE_WORD_SOURCES = '
            r'\{([\s\S]*?)\};', script)
        self.assertIsNotNone(src)
        vectors = re.findall(
            r'new BigInteger\("([0-9a-f]{32})", 16\)',
            src.group(1))
        self.assertEqual(len(vectors), 2)
        self.assertNotEqual(vectors[0], vectors[1])

        rules = re.findall(
            r'(?m)^:vpermwi128 [^\n]+\n'
            r'\{\n([\s\S]*?)\n\}', sleigh)
        self.assertEqual(len(rules), 8)
        for extra, body in enumerate(rules):
            self.assertIn(
                f"permutation:4 = A_BITS:4 | {extra * 32}:4;", body)
            for lane in range(4):
                self.assertIn(
                    f"pick{lane}:4 = (permutation >> {2 * lane}) & 3;",
                    body)
                self.assertIn(
                    f"wordShift{lane}:4 = (3 - pick{lane}) * 32;",
                    body)
            self.assertIn(
                "xenonD = packedWord3 | packedWord2 | packedWord1 | packedWord0;",
                body)

        count = 0
        for bank in range(4):
            for imm in range(256):
                word = (0x18000210 | (1 << 21) | (3 << 11) |
                        ((imm & 31) << 16) |
                        ((imm >> 5) << 6) | bank)
                self.assertEqual(word & 0xfc000630, 0x18000210)
                self.assertEqual((word >> 16) & 31, imm & 31)
                self.assertEqual((word >> 6) & 7, imm >> 5)
                self.assertEqual(word & 3, bank)
                self.assertEqual((word >> 2) & 3, 0)
                self.assertEqual((word >> 11) & 31, 3)
                for vector in vectors:
                    source = bytes.fromhex(vector)
                    # Reference uses MSB-indexed byte slices and populates
                    # destination words from MSB to LSB, unlike the Java
                    # BigInteger oracle's LSB-first reconstruction.
                    source_words = [source[i:i+4] for i in (0, 4, 8, 12)]
                    chosen = [
                        source_words[(imm >> (6 - i * 2)) & 3]
                        for i in range(4)]
                    expected = b"".join(chosen)
                    self.assertEqual(len(expected), 16)
                    number = int.from_bytes(expected, "big")
                    reference = sum(
                        ((int.from_bytes(source_words[
                            (imm >> (lane * 2)) & 3], "big"))
                         << (lane * 32))
                        for lane in range(4))
                    self.assertEqual(number, reference)
                    self.assertNotEqual(number ^ ((1 << 128) - 1), number)
                    count += 1
        self.assertEqual(count, 2048)

    def test_unified_numerical_script_is_only_entrypoint(self):
        from pathlib import Path

        root = audit.ROOT.parent / "ghidra_scripts"
        script = (root / "AuditXenonNumericalPcode.java").read_text(
            encoding="utf-8")
        self.assertEqual(script.count("protected void run()"), 1)
        self.assertIn("XENON NUMERICAL P-CODE COMBINED RESULT", script)
        self.assertEqual(script.count("UNRESOLVED / INCORRECT STATES"), 1)
        self.assertIn(
            'println("Unresolved details follow in the combined result below.");',
            script)
        self.assertIn("recordSuite(\"PACK\", passed, failed, problems)", script)
        self.assertIn("recordSuite(\"D3D\", passed, failed, problems)", script)
        self.assertIn("recordSuite(\"GUARDED-FP\", passed, failed, problems)", script)
        self.assertIn("runSaturatingPacks(manifest, base);", script)
        self.assertIn("runGuardedFp(manifest, base);", script)
        self.assertIn("runShuffles(manifest, base);", script)
        self.assertIn("XENON BYTE SHUFFLE NATIVE NUMERICAL P-CODE AUDIT", script)
        self.assertIn("XENON D3D UNPACK NATIVE NUMERICAL P-CODE AUDIT", script)
        self.assertIn("XENON NATIVE PACK NUMERICAL P-CODE AUDIT", script)
        self.assertIn("XENON GUARDED FP NATIVE NUMERICAL P-CODE AUDIT", script)
        self.assertNotIn("currentProgram.getMemory().setBytes(", script)
        # Separate, narrowly scoped STSWI/atomic diagnostic scripts are
        # allowed; require exactly one unified *numerical* entry point.
        self.assertEqual(
            sorted(p.name for p in root.glob("AuditXenonNumericalPcode*.java")),
            ["AuditXenonNumericalPcode.java"])
        self.assertEqual(script.count('askFile('), 0)
        self.assertIn('currentProgram.getExecutablePath()', script)
        self.assertIn('System.getenv("XENON_ISA_FIXTURE_TSV")', script)
        self.assertIn('new File(parent, "xenon_isa_fixture_v1.tsv")', script)
        self.assertNotIn('"C:/Users/Johnny/Downloads/', script)
        self.assertIn("if (!manifest.isFile())", script)
        self.assertIn("manifest.getAbsolutePath()", script)

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

    def test_all_corrected_families_and_pcode_classification(self):
        # Unlike the pinned Xenia subset, the combined inventory includes
        # two signed-halfword aliases omitted from Xenia's decoder.
        corrected = audit.read_inventory(audit.CORRECTION_INVENTORY)
        rows = self.rows + corrected
        statuses, operators = audit.parse_sleigh(
            audit.read_sleigh_source(audit.SLEIGH))
        self.assertEqual(len(rows), 86)
        self.assertEqual(len({row["mnemonic"] for row in rows}), 86)
        self.assertEqual(Counter(statuses[row["mnemonic"]] for row in rows),
                         Counter({"native-pcode": 73, "opaque-userop": 13}))
        self.assertEqual(
            [statuses[row["mnemonic"]] for row in corrected],
            ["native-pcode", "native-pcode"])
        self.assertNotIn("xenonSetVscrSatIf", operators)

    def test_signed_byte_unpacks_widen_eight_correct_lanes(self):
        import re

        sleigh = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        for name, first_byte in (("vupkhsb128", 0), ("vupklsb128", 8)):
            bodies = re.findall(
                r"(?m)^:" + name + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", sleigh)
            self.assertEqual(len(bodies), 4, name)
            for body in bodies:
                for i in range(8):
                    offset = 15 - first_byte - i
                    shift = 112 - 16 * i
                    self.assertIn(
                        f"byteIn{i}:1 = xenonB({offset});", body)
                    self.assertIn(
                        f"extendedHalf{i}:2 = sext(byteIn{i});", body)
                    self.assertIn(
                        f"packedHalf{i}:16 = zext(extendedHalf{i})" +
                        (f" << {shift}" if shift else "") + ";", body)
                self.assertIn("xenonD = " + " | ".join(
                    f"packedHalf{i}" for i in range(8)) + ";", body)
                self.assertNotIn("xenonVupk", body)

    def test_vector_comparisons_mask_and_record_cr6_paths(self):
        import re

        sleigh = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        for name, predicate in (
                ("vcmpeqfp128", "f=="),
                ("vcmpgefp128", "f>="),
                ("vcmpgtfp128", "f>"),
                ("vcmpequw128", "==")):
            bodies = re.findall(
                r"(?m)^:" + name + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", sleigh)
            self.assertEqual(len(bodies), 8, name)
            for i, body in enumerate(bodies):
                for lane in range(4):
                    self.assertIn(
                        f"predicate{lane}:1 = compareA{lane} "
                        f"{predicate} compareB{lane};", body)
                    self.assertIn(
                        f"expandedResult{lane}:4 = 0:4 - "
                        f"zext(predicate{lane});", body)
                has_record = i % 4 in (2, 3)
                self.assertEqual("cr6 =" in body, has_record,
                                 (name, i))
                if has_record:
                    self.assertIn("allTrue:1 =", body)
                    self.assertIn("noneTrue:1 =", body)
                    self.assertIn(
                        "cr6 = (allTrue << 3) | (noneTrue << 1);",
                        body)
        bounds = re.findall(
            r"(?m)^:vcmpbfp128 [^\n]+ is [^\n]+\n"
            r"\{\n([\s\S]*?)\n\}", sleigh)
        self.assertEqual(len(bounds), 8)
        for index, body in enumerate(bounds):
            for lane in range(4):
                self.assertIn(
                    f"bfpNan{lane}:1 = nan(bfpA{lane}) | "
                    f"nan(bfpB{lane});", body)
                self.assertIn(
                    f"highBit{lane}:4 = zext(bfpAbove{lane}) << 31;",
                    body)
                self.assertIn(
                    f"lowerBit{lane}:4 = zext(bfpBelow{lane}) << 30;",
                    body)
                if index % 4 in (2, 3):
                    self.assertIn(
                        f"bfpOut{lane}:1 = bfpAbove{lane} | bfpBelow{lane};",
                        body)
                else:
                    self.assertNotIn(f"bfpOut{lane}:", body)
            self.assertEqual("cr6 =" in body, index % 4 in (2, 3))

    def test_saturating_pack_clamps_and_tracks_vscr_dependency(self):
        import re

        sleigh = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        families = (
            ("vpkshss128", 2, 1, True, -128, 127),
            ("vpkshus128", 2, 1, True, 0, 255),
            ("vpkswss128", 4, 2, True, -32768, 32767),
            ("vpkswus128", 4, 2, True, 0, 65535),
            ("vpkuhus128", 2, 1, False, 0, 255),
            ("vpkuwus128", 4, 2, False, 0, 65535),
        )
        for name, src_bytes, dst_bytes, signed, lo, hi in families:
            bodies = re.findall(
                r"(?m)^:" + name + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", sleigh)
            self.assertEqual(len(bodies), 4, name)
            lane_count = 16 // dst_bytes
            per_source = 16 // src_bytes
            for body in bodies:
                for i in range(lane_count):
                    register = "xenonA" if i < per_source else "xenonB"
                    offset = (per_source - 1 - i % per_source) * src_bytes
                    self.assertIn(
                        f"packInput{i}:{src_bytes} = "
                        f"{register}({offset});", body)
                    self.assertIn(
                        f"clipped{i}:{src_bytes} =", body)
                    self.assertIn(
                        f"packed{i}:{dst_bytes} = clipped{i}(0);",
                        body)
                    self.assertIn(
                        f"widened{i}:16 = zext(packed{i})", body)
                self.assertIn(
                    "xenonD = " + " | ".join(
                        f"widened{i}" for i in range(lane_count)) + ";",
                    body)
                self.assertIn(
                    "xenonVSCR = xenonVSCR | zext(saturatedAny);", body)
                self.assertNotIn("pack_unresolved_saturation", body)
            # Independent scalar golden values for boundary interpretation,
            # not a claim that Ghidra's numerical p-code has executed.
            raw_inputs = [lo - 1, lo, lo + 1, hi - 1, hi, hi + 1]
            input_bits = src_bytes * 8
            for raw in raw_inputs:
                if not signed and raw < 0:
                    continue
                mask = (1 << input_bits) - 1
                encoded = raw & mask
                decoded = (encoded - (1 << input_bits)
                           if signed and encoded & (1 << (input_bits - 1))
                           else encoded)
                clamped = max(lo, min(hi, decoded))
                self.assertTrue(lo <= clamped <= hi)
                if lo <= decoded <= hi:
                    self.assertEqual(clamped, decoded)

    def test_vector_float_rounding_modes_have_no_integer_cast_shortcut(self):
        import re

        sleigh = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        modes = (("vrfim128", "floor", 2),
                 ("vrfin128", "round", 2),
                 ("vrfip128", "ceil", 2),
                 ("vrfiz128", "toward-zero", 2))
        for name, mode, total in modes:
            blocks = re.findall(
                r"(?m)^:" + name + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", sleigh)
            self.assertEqual(len(blocks), total)
            for body in blocks:
                self.assertNotIn("trunc(", body, name)
                self.assertNotIn("int2float(", body, name)
                for i in range(4):
                    input_name = ("sourceFloat" if mode == "round"
                                  else "roundInput")
                    self.assertIn(
                        f"{input_name}{i}:4 = xenonB({i*4});", body)
                    if mode == "toward-zero":
                        # The variable is declared once before either branch.
                        # Repeated sized declarations fail SleighCompile.
                        self.assertIn(
                            f"roundOutput{i}:4 = 0:4;",
                            body)
                        self.assertIn(
                            f"roundOutput{i} = floor(roundInput{i});",
                            body)
                        self.assertIn(
                            f"roundOutput{i} = ceil(roundInput{i});",
                            body)
                        self.assertIn(
                            f"roundNegative{i}:1 = roundInput{i} f< 0:4;",
                            body)
                    elif mode == "round":
                        self.assertIn(
                            f"nearest{i}:4 = round(sourceFloat{i});",
                            body)
                    else:
                        self.assertIn(
                            f"roundOutput{i}:4 = {mode}(roundInput{i});",
                            body)

    def test_scaled_word_float_conversions_preserve_width_and_scale(self):
        import re

        sleigh = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        for name, unsigned in (("vcsxwfp128", False),
                               ("vcuxwfp128", True)):
            bodies = re.findall(
                r"(?m)^:" + name + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", sleigh)
            self.assertEqual(len(bodies), 2)
            for body in bodies:
                self.assertIn(
                    "exponent:4 = (127:4 - A_BITS:4) << 23;", body)
                for i in range(4):
                    self.assertIn(
                        f"integerWord{i}:4 = xenonB({i*4});", body)
                    integer = (f"extendedUnsigned{i}" if unsigned
                               else f"integerWord{i}")
                    if unsigned:
                        self.assertIn(
                            f"extendedUnsigned{i}:8 = "
                            f"zext(integerWord{i});", body)
                    self.assertIn(
                        f"convertedWord{i}:4 = int2float({integer});",
                        body)
                    self.assertIn(
                        f"scaledWord{i}:4 = convertedWord{i} f* "
                        "exponent;", body)

    def test_saturating_float_word_conversion_flags_and_nan_fallback(self):
        import re

        sleigh = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        for name, unsigned, bottom, top in (
                ("vcfpsxws128", False, "0xcf000000", "0x4f000000"),
                ("vcfpuxws128", True, "0", "0x4f800000")):
            blocks = re.findall(
                r"(?m)^:" + name + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", sleigh)
            self.assertEqual(len(blocks), 2)
            for body in blocks:
                self.assertIn(
                    "scalingBits:4 = (127:4 + A_BITS:4) << 23;",
                    body)
                self.assertIn("upperBound:4 = " + top + ":4;", body)
                self.assertIn("lowerBound:4 = " + bottom + ":4;", body)
                self.assertIn(
                    "xenonVSCR = xenonVSCR | zext(conversionSaturated);", body)
                self.assertIn("if (anyNaN) goto <conversion_nan_opaque>;",
                              body)
                self.assertIn("xenonD = unresolvedNaN;", body)
                for i in range(4):
                    self.assertIn(
                        f"sourceFloat{i}:4 = xenonB({i*4});", body)
                    self.assertIn(
                        f"conversionNaN{i}:1 = nan(scaledFloat{i});",
                        body)
                    self.assertIn(f"convertedInt{i}:4 =", body)
                    self.assertIn(f"belowMin{i}:1 =", body)
                    self.assertIn(f"aboveMax{i}:1 =", body)

    def test_float_minmax_exceptional_case_is_not_guessed(self):
        import re

        sleigh = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        for name, predicate in (("vmaxfp128", "f>"),
                                ("vminfp128", "f<")):
            bodies = re.findall(
                r"(?m)^:" + name + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", sleigh)
            self.assertEqual(len(bodies), 4)
            for body in bodies:
                for i in range(4):
                    self.assertIn(
                        f"ambiguous{i}:1 = nan(valueA{i}) | "
                        f"nan(valueB{i}) | ((valueA{i} f== valueB{i})"
                        f" & (valueA{i} != valueB{i}));", body)
                    self.assertIn(
                        f"chooseA{i}:1 = valueA{i} {predicate} valueB{i};",
                        body)
                self.assertIn(
                    "if (anyAmbiguous) goto <xenon_opaque_fp>;", body)
                self.assertIn("xenonD = ambiguousResult;", body)

    def test_sleigh_constructor_label_targets_and_userops(self):
        import re

        sleigh = audit.read_sleigh_source(audit.SLEIGH)
        ops = set(re.findall(
            r"(?m)^define pcodeop\s+(\w+);", sleigh))
        bodies = re.findall(
            r"(?m)^:[A-Za-z]\w* [^\n]+ is [^\n]+\n"
            r"\{\n([\s\S]*?)\n\}", sleigh)
        self.assertGreaterEqual(len(bodies), 269)
        called = set()
        for body in bodies:
            labels = re.findall(
                r"(?m)^<([A-Za-z_]\w*)>$", body)
            self.assertEqual(len(labels), len(set(labels)))
            self.assertEqual(
                set(re.findall(r"goto <([A-Za-z_]\w*)>", body)) -
                set(labels), set())
            for op in ops:
                if op + "(" in body:
                    called.add(op)
        self.assertEqual(ops - called, set(),
                         "Unused opaque userop declarations")

    def test_freshness_checker_expected_family_statuses_match_sleigh(self):
        import ast

        source = audit.read_sleigh_source(audit.SLEIGH)
        statuses, unused = audit.parse_sleigh(source)
        checker = (HERE / "check_xenon_fixture_install_v1.py").read_text(
            encoding="utf-8")
        module = ast.parse(checker)
        assignments = [node for node in module.body
                       if isinstance(node, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == "EXPECTED"
                               for t in node.targets)]
        self.assertEqual(len(assignments), 1)
        expected = ast.literal_eval(assignments[0].value)
        self.assertGreaterEqual(len(expected), 35)
        for name, classification in expected.items():
            self.assertEqual(statuses.get(name), classification, name)
        for name in ("vcfpsxws128", "vcfpuxws128"):
            self.assertEqual(expected[name], "opaque-userop")
        for name in ("vpkshss128", "vpkuwus128"):
            self.assertEqual(expected[name], "native-pcode")
        for name in ("vupkhsh128", "vupklsh128", "vcmpbfp128",
                     "vrfim128", "vrfip128", "vrfiz128"):
            self.assertEqual(expected[name], "native-pcode")

    def test_vupkd3d_d3dcolor_integer_lane_mapping(self):
        # Xenia pinned tests: 0x04010203 maps to RGBA 01,02,03,04;
        # 0x80506070 maps to R/G/B/A 50,60,70,80.
        import re

        source = audit.SLEIGH.read_text(encoding="utf-8")
        bodies = re.findall(
            r"(?m)^:vupkd3d128 [^\n]+ is [^\n]+\n"
            r"\{\n([\s\S]*?)\n\}", source)
        self.assertEqual(len(bodies), 2)
        for body in bodies:
            self.assertIn("unpackType:4 = A_BITS:4 >> 2;", body)
            self.assertIn("if (unpackType == 0:4) goto <unpack_color>;", body)
            self.assertIn("goto <unpack_opaque>;", body)
            self.assertIn("packedColor:4 = xenonB(0);", body)
            for name, shift in (("red", 16), ("green", 8),
                                ("alpha", 24)):
                self.assertIn(
                    f"{name}:4 = (packedColor >> {shift}) & 0xff:4;",
                    body)
            self.assertIn("blue:4 = packedColor & 0xff:4;", body)
            for name, shift in (("R", 96), ("G", 64),
                                ("B", 32), ("A", 0)):
                tail = f" << {shift}" if shift else ""
                self.assertIn(
                    f"encoded{name}:4 = 0x3f800000:4 | " +
                    {"R": "red", "G": "green",
                     "B": "blue", "A": "alpha"}[name] + ";",
                    body)
                self.assertIn(
                    f"lane{name}:16 = zext(encoded{name}){tail};",
                    body)
            self.assertIn("xenonD = laneR | laneG | laneB | laneA;", body)
            self.assertIn(
                "if (unpackType == 1:4) goto <unpack_short2_signed>;", body)
            for statement in (
                "packedShorts:4 = xenonB(0);",
                "rawHigh:2 = packedShorts(2);",
                "rawLow:2 = packedShorts(0);",
                "signedHigh:4 = sext(rawHigh);",
                "signedLow:4 = sext(rawLow);",
                "shortX:4 = 0x40400000:4 + signedHigh;",
                "shortY:4 = 0x40400000:4 + signedLow;",
                "highOverflow:1 = rawHigh == 0x8000:2;",
                "lowOverflow:1 = rawLow == 0x8000:2;",
                "if (highOverflow) goto <short_high_nan>;",
                "if (lowOverflow) goto <short_low_nan>;",
                "shortX = 0x7fc00000:4;",
                "shortY = 0x7fc00000:4;",
                "placeX:16 = zext(shortX) << 96;",
                "placeY:16 = zext(shortY) << 64;",
                "shortOneWord:4 = 0x3f800000:4;",
                "shortOne:16 = zext(shortOneWord);",
                "xenonD = placeX | placeY | shortOne;",
            ):
                self.assertIn(statement, body)

            self.assertIn(
                "unpacked:16 = xenonVupkd3d128(xenonB, A_BITS:4);",
                body)
            self.assertIn("xenonD = unpacked;", body)
        examples = {
            0x04010203: [0x3f800001, 0x3f800002,
                         0x3f800003, 0x3f800004],
            0x80506070: [0x3f800050, 0x3f800060,
                         0x3f800070, 0x3f800080],
            0x00000000: [0x3f800000] * 4,
            0xffffffff: [0x3f8000ff] * 4,
        }
        for argb, expected in examples.items():
            rgb = [(argb >> bits) & 0xff for bits in (16, 8, 0, 24)]
            self.assertEqual([0x3f800000 | value for value in rgb],
                             expected)

        for packed, expected in {
            0x00000000: [0x40400000, 0x40400000, 0, 0x3f800000],
            0x12345678: [0x40401234, 0x40405678, 0, 0x3f800000],
            0x7fff0001: [0x40407fff, 0x40400001, 0, 0x3f800000],
            0x7fff8001: [0x40407fff, 0x403f8001, 0, 0x3f800000],
            0x4000c000: [0x40404000, 0x403fc000, 0, 0x3f800000],
            0x00008000: [0x40400000, 0x7fc00000, 0, 0x3f800000],
            0x80008000: [0x7fc00000, 0x7fc00000, 0, 0x3f800000],
        }.items():
            halves = ((packed >> 16) & 0xffff, packed & 0xffff)
            def unpack_half(value):
                signed = value if value < 0x8000 else value - 0x10000
                return (0x7fc00000 if value == 0x8000 else
                        (0x40400000 + signed) & 0xffffffff)
            self.assertEqual([unpack_half(halves[0]),
                              unpack_half(halves[1]), 0, 0x3f800000],
                             expected)

    def test_vupkd3d_2101010_and_short4_exact_unpacks(self):
        import re

        source = audit.SLEIGH.read_text(encoding="utf-8")
        bodies = re.findall(
            r"(?m)^:vupkd3d128 [^\n]+ is [^\n]+\n"
            r"\{\n([\s\S]*?)\n\}", source)
        self.assertEqual(len(bodies), 2)
        for body in bodies:
            self.assertIn("if (unpackType == 2:4) goto <unpack_2101010>;", body)
            self.assertIn("if (unpackType == 4:4) goto <unpack_short4>;", body)
            self.assertIn("packed210:4 = xenonB(0);", body)
            for letter, shift in (("R", 0), ("G", 10), ("B", 20)):
                extract = (f"(packed210 >> {shift}) & 0x3ff:4"
                           if shift else "packed210 & 0x3ff:4")
                self.assertIn(f"raw{letter}10:4 = {extract};", body)
                self.assertIn(
                    f"signed{letter}10:4 = (raw{letter}10 << 22) s>> 22;",
                    body)
                self.assertIn(
                    f"decoded{letter}10:4 = 0x40400000:4 + signed{letter}10;",
                    body)
                self.assertIn(
                    f"overflow{letter}10:1 = raw{letter}10 == 0x200:4;",
                    body)
                self.assertIn(
                    f"decoded{letter}10 = 0x7fc00000:4;", body)
            self.assertIn(
                "rawAlpha2:4 = (packed210 >> 30) & 3:4;", body)
            self.assertIn(
                "decodedAlpha2:4 = 0x3f800000:4 | rawAlpha2;", body)
            for letter, off in (("X", 6), ("Y", 4),
                                ("Z", 2), ("W", 0)):
                self.assertIn(
                    f"half{letter}:2 = xenonB({off});", body)
                self.assertIn(
                    f"signed{letter}16:4 = sext(half{letter});", body)
                self.assertIn(
                    f"decoded{letter}16:4 = 0x40400000:4 + signed{letter}16;",
                    body)
                self.assertIn(
                    f"overflow{letter}16:1 = half{letter} == 0x8000:2;",
                    body)
                self.assertIn(
                    f"decoded{letter}16 = 0x7fc00000:4;", body)
            self.assertIn(
                "xenonD = placeR10 | placeG10 | placeB10 | placeA2;", body)
            self.assertIn(
                "xenonD = placeX16 | placeY16 | placeZ16 | placeW16;", body)

        def signed_component(bits, width):
            sign = 1 << (width - 1)
            if bits == sign:
                return 0x7fc00000
            number = bits - (1 << width) if bits & sign else bits
            return (0x40400000 + number) & 0xffffffff

        def unpack210(word):
            xyz = [signed_component((word >> shift) & 0x3ff, 10)
                   for shift in (0, 10, 20)]
            return xyz + [0x3f800000 | ((word >> 30) & 3)]

        for packed, expected in {
            0x400001ff: [0x404001ff, 0x40400000,
                         0x40400000, 0x3f800001],
            0x40000201: [0x403ffe01, 0x40400000,
                         0x40400000, 0x3f800001],
            0x40000200: [0x7fc00000, 0x40400000,
                         0x40400000, 0x3f800001],
        }.items():
            self.assertEqual(unpack210(packed), expected)

        def unpackshort4(packed):
            return [signed_component((packed >> shift) & 0xffff, 16)
                    for shift in (48, 32, 16, 0)]

        self.assertEqual(unpackshort4(0x7fffffff007ffff8),
                         [0x40407fff, 0x403fffff,
                          0x4040007f, 0x403ffff8])

    def test_vmadd_finite_exact_pcode_paths_preserve_operand_order(self):
        # Native floating-point multiplication followed by addition is NOT
        # generally a fused multiply-add. Verify that the p-code only uses
        # the exact small-integer region and retains its opaque fallback.
        import re
        import struct

        source = audit.ADDITIONAL_SLEIGH.read_text(encoding="utf-8")
        families = {
            "vmaddfp128": ("sourceA{i} f* sourceB{i}",
                           "product{i} f+ sourceD{i}"),
            "vmaddcfp128": ("sourceA{i} f* sourceD{i}",
                            "product{i} f+ sourceB{i}"),
            "vnmsubfp128": ("sourceA{i} f* sourceB{i}",
                            "sourceD{i} f- product{i}"),
        }
        for family, (product, result) in families.items():
            bodies = re.findall(
                r"(?m)^:" + family + r" [^\n]+ is [^\n]+\n"
                r"\{\n([\s\S]*?)\n\}", source)
            self.assertEqual(len(bodies), 4, family)
            for body in bodies:
                self.assertIn("lowerSafe:4 = 0xc5000000:4;", body)
                self.assertIn("upperSafe:4 = 0x45000000:4;", body)
                self.assertIn("goto <fp_opaque>;", body)
                self.assertIn("goto <fp_done>;", body)
                self.assertIn(
                    f"xenonD = shifted0 | shifted1 | shifted2 | shifted3;",
                    body)
                for i in range(4):
                    self.assertIn(
                        f"product{i}:4 = {product.format(i=i)};", body)
                    self.assertIn(
                        f"output{i}:4 = {result.format(i=i)};", body)
                    self.assertIn(
                        f"outputZero{i}:1 = (output{i} & "
                        "0x7fffffff:4) == 0:4;", body)
                    self.assertIn(
                        f"if (outputZero{i}) goto <fp_opaque>;", body)
                    self.assertIn(
                        f"shifted{i}:16 = zext(output{i})" +
                        (f" << {32 * i}" if i else "") + ";", body)
                    for letter, vec in (("A", "xenonA"), ("B", "xenonB"),
                                        ("D", "xenonD")):
                        v = f"source{letter}{i}"
                        self.assertIn(f"{v}:4 = {vec}({i*4});", body)
                        self.assertIn(
                            f"nan{letter}{i}:1 = nan({v});", body)
                        self.assertIn(
                            f"if (nan{letter}{i}) goto <fp_opaque>;", body)
                        self.assertIn(
                            f"if ({v} f< lowerSafe) goto <fp_opaque>;", body)
                        self.assertIn(
                            f"if ({v} f> upperSafe) goto <fp_opaque>;", body)
                        self.assertIn(
                            f"int{letter}{i}:4 = trunc({v});", body)
                        self.assertIn(
                            f"asFloat{letter}{i}:4 = "
                            f"int2float(int{letter}{i});", body)
                        self.assertIn(
                            f"if (integral{letter}{i} == 0:1) "
                            "goto <fp_opaque>;", body)
                self.assertIn(
                    "unresolved:16 = xenon" +
                    {"vmaddfp128": "Vmaddfp128",
                     "vmaddcfp128": "Vmaddcfp128",
                     "vnmsubfp128": "Vnmsubfp128"}[family] +
                    "(xenonA, xenonB, xenonD);", body)

        # Every integer product and final value is exactly representable
        # in binary32 within the guarded range; no fused-vs-unfused
        # rounding discrepancy can exist on these nonzero examples.
        def f32(value):
            return struct.unpack(">f", struct.pack(">f", value))[0]

        values = [-2048, -1024, -129, -31, -3, -1, 1, 7, 23, 127, 1024, 2048]
        for a in values:
            for b in values:
                for d in (-2048, -256, -17, 3, 71, 256, 2048):
                    for name in families:
                        product = a * (d if name == "vmaddcfp128"
                                       else b)
                        self.assertEqual(f32(product), float(product))
                        answer = (a * b + d if name == "vmaddfp128"
                                  else a * d + b if name == "vmaddcfp128"
                                  else d - a * b)
                        if answer != 0:
                            self.assertEqual(f32(answer), float(answer))

    def test_ghidra_numerical_pack_audit_vectors_are_consistent(self):
        # The companion Ghidra Java script actually steps native p-code.
        # Validate its independent boundary-case oracle without Ghidra.
        import re

        script = (audit.ROOT.parent / "ghidra_scripts" /
                  "AuditXenonNumericalPcode.java").read_text(
                      encoding="utf-8")
        self.assertIn("new EmulatorHelper(currentProgram)", script)
        self.assertIn("emulator.step(monitor)", script)
        self.assertIn('emulator.readRegister("xenonVSCR")', script)
        self.assertIn("emulator.readRegister(destination)", script)
        self.assertIn("emulator.dispose();", script)
        cases = re.findall(
            r'new Pack\("(\w+)",\s*(\d+),\s*(\d+),\s*'
            r'(0x[0-9a-fA-F]+L?),\s*(0x[0-9a-fA-F]+L?),\s*'
            r'(0x[0-9a-fA-F]+L?),\s*(0x[0-9a-fA-F]+L?)\s*\)',
            script)
        self.assertEqual(
            {record[0] for record in cases},
            {"vpkshss128", "vpkshus128", "vpkswss128",
             "vpkswus128", "vpkuhus128", "vpkuwus128"})

        for name, in_width, out_width, *values in cases:
            src_bits, dst_bits = int(in_width), int(out_width)
            signed_input = not name.startswith("vpku")
            signed_output = name.endswith("ss128")
            smallest = -(1 << (dst_bits - 1)) if signed_output else 0
            largest = ((1 << (dst_bits - 1)) - 1
                       if signed_output else (1 << dst_bits) - 1)
            source_mask = (1 << src_bits) - 1
            destination_mask = (1 << dst_bits) - 1
            positive, expected_positive, negative, expected_negative = (
                int(text.rstrip("L"), 0) for text in values)
            for encoded, expected in (
                    (positive, expected_positive),
                    (negative, expected_negative)):
                source = encoded & source_mask
                if signed_input and source & (1 << (src_bits - 1)):
                    source -= 1 << src_bits
                answer = max(smallest, min(largest, source))
                self.assertEqual(
                    answer & destination_mask, expected,
                    (name, hex(encoded), hex(expected)))

    def test_distinct_lane_ghidra_saturation_audit(self):
        # The original homogeneous decoder fixture cannot exercise VA/VB
        # independently. Preserve the proven emulator-private override.
        script = (audit.ROOT.parent / "ghidra_scripts" /
                  "AuditXenonNumericalPcode.java").read_text(
                      encoding="utf-8")
        self.assertIn("class AuditXenonNumericalPcode", script)
        self.assertIn('if ("55".equals(columns[4]))', script)
        self.assertIn('requireVectorRegister("vs33")', script)
        self.assertIn('requireVectorRegister("vs34")', script)
        self.assertIn('requireVectorRegister("vs35")', script)
        self.assertIn("emulator.writeMemory(address, syntheticBytes)", script)
        self.assertIn("emulator.writeRegister(va, laneVector(a, pack.inputBits))",
                      script)
        self.assertIn("emulator.writeRegister(vb, laneVector(b, pack.inputBits))",
                      script)
        self.assertIn("output[i] = a[i];", script)
        self.assertIn("output[half + i] = b[i];", script)
        self.assertIn("output[0] = pack.positiveResult;", script)
        self.assertIn("output[1] = pack.negativeResult;", script)
        self.assertIn("output[2 * half - 1] = pack.positiveResult;", script)
        self.assertIn("long initialVSCR = 0x10000L;", script)
        self.assertIn("long expectedVSCR = initialVSCR | (saturating ? 1 : 0);",
                      script)
        self.assertIn("for (boolean saturating : new boolean[] {false, true})",
                      script)
        self.assertIn("emulator.step(monitor)", script)
        self.assertIn("emulator.readRegister(destination)", script)
        self.assertIn("Map<Address, Long> fixtureWords", script)
        self.assertIn("!fixtureWordMatches(address, fixtureWords.get(address))",
                      script)
        self.assertIn("!fixtureWordMatches(patternAddress, fixtureWords.get(patternAddress))",
                      script)

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
