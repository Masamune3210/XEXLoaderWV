## Fixture generation is an automatic Gradle build prerequisite (2026-10-10)

Gradle generateXenonIsaFixture is now an unconditional dependency of verifyXenonSleigh and thus of buildExtension, build and assemble. Builds from inner XEXLoaderWV/ refresh the 336-word big-endian fixture, manifest TSV, coverage TSV and Markdown report under build/xenon-isa-audit/ before SLEIGH compilation. It watches both vector SLEIGH includes, slaspec, both pinned Xenia inventories and generator. No manual Python generator invocation is needed.

Source-only semantic updates need not change the binary opcode fixture, so the Markdown coverage report now includes five SHA-256 fingerprints: combined SLEIGH, slaspec, two inventories and generator source. The checker rejects stale or absent provenance and compares every manifest and coverage TSV row with pinned inventories; lvsl128 and lvsr128 are expected native, not opaque. The Python test suite now has 16 tests. Actual revised Gradle/SLEIGH and Ghidra runtime verification remain pending.

## Constrained-token SLEIGH compilation fix (2026-10-10)

The bulk Xenon language first reached xenon_vector_remaining_v1.sinc:902 and failed because vpkd3d128 referenced BITS_6_10:4 after constraining BITS_6_10=24..27 separately in four constructors. Each now passes its known z shift (0..3) as a constant, and also supplies **prior VD** to the opaque pack userop, as Xenia's blending semantics require. New tests scan token references versus all 267 pattern lists and verify the four pack variants. Local static audit found no other constrained-pattern token reads. There are now 15 Python test methods, not yet run by the user, and the revised SLEIGH is still uncompiled. Coverage remains 47 native / 37 opaque / 0 missing.

## Exact native left/right byte-permutation masks (2026-10-10)

`lvsl128` and `lvsr128` are no longer opaque. Based on Xenia's pinned load-vector-mask implementation and vector tests, they generate the 16-byte sequence `off+i` or `16-off+i` respectively (`i=0..15`, `off=(RA+RB)&15`). Every output octet has a native p-code assembly, no CALL_OTHER. The current **84-family source inventory is 47 native, 37 opaque, 0 missing**, with **12 expected Python tests**, no new build/runtime results yet. The source-only checks verify both 16-octet generators plus each of the 172 new family constructors. Do not infer native p-code guarantees byte-order correctness or that all opaque families are semantically implemented.

## Native VMX128 multiply refinement (2026-10-10)

The earlier `vmulfp128` userop has been replaced with 4×32-bit native floating multiplication and explicitly widened 128-bit lane assembly. Combined pinned-inventory source status is now **45 native, 39 opaque, 0 missing** across all 84 families. Native FP still needs empirical p-code comparison for NaN, subnormal, rounding and exception behavior. Updated tests cover this change. The successful pre-batch Gradle build and last 134/336 runtime report **do not** verify the new supplementary SLEIGH include.

## Complete source-level Xenon VMX128 family coverage batch (2026-10-10)

**Scope, not a claim of full numerical emulation:** All 46 previously unimplemented VMX128 family names now have explicit instruction constructors in the *new* `XEXLoaderWV/data/languages/xenon_vector_remaining_v1.sinc`. The language includes it after `xenon_vector_v1.sinc`. It contains 172 new constructor alternatives covering opcode-4 VX128_5, opcode-5 VX128/VX128_2, opcode-6 VX128/VX128_3/VX128_4/VX128_R. Register operand handling includes `xenonC` for the vperm third vector source. Together with the previously implemented families, pinned-inventory source classification is **44 native-pcode / 40 opaque-userop / 0 missing**, 84 families total.

Native high-level lane operations added: `vsldoi128`, `vaddfp128`, `vsubfp128`, `vrlw128`, `vslw128`, `vsraw128`, `vsrw128`, `vspltw128`, `vspltisw128`, `vslo128`, `vsro128`, `vpkuhum128`, `vpkuwum128`. Explicit 128-bit assembly preserves the destination register size. Mathematical FP lane operations still require numerical verification of rounding, NaN, denormal and console-specific flags.

The other 33 newly added families intentionally use output-producing named opaque pcodeops, **not fake NOPs or made-up arithmetic**. These preserve source/destination dependencies (including prior destination for fused/multiply-add variants) but their exact numerical results remain unsupported. Certain flags (e.g. VSCR saturation / CR6 vector compare) are not fully modeled. Existing seven opaque families are unchanged. The eight opcode-31 X-form families continue restricting Rc=1 cases until hardware validity is known. The separate generated `dcbzl` collision correction remains untested since the last 134/336 runtime report.

Tooling stays in the *inner* Gradle project `XEXLoaderWV/tools/`. The fixture generator and consistency checker now classify the combined vector source. Added regression tests for every remaining family and the new byte-shift/unsigned-pack native operations; **11 Python tests expected**, not yet run. An independent static selector check matched every generated fixture word to one expected family construction with **0 missing/ambiguous rule matches**. SleighCompile and runtime decode are the next actual verification; **no new measured Ghidra decode percentage is claimed**.

## Third Ghidra runtime fixture: 134/336; remaining embedded alias (2026-10-10)

The user successfully ran the newer compiled/installed language: **134 correct/336, 0 byte mismatches, 29 full families, 9 partial, 46 completely missing**. This is +70 correct mnemonics over the previous 64. Unresolved sample counts: 184 missing from 46 source-unimplemented families; 16 opcode-31 X-form `Rc=1` samples excluded pending evidence of hardware validity; 2 partial `dcbz128` cases still decoded `dcbzl`. The audit's `wrong-mnemonic-only=0` excludes wrong aliases within *partial* families and therefore must not be interpreted as zero collisions.

Root cause of the `dcbzl` alias: stock `ppc_common.sinc` includes `ppc_embedded.sinc`, which defines `dcbzl` with `BITS_21_25=1` and `XOP_1_10=1014` for the same opcode as Xenon `dcbz128` when bit 0 is clear. A guarded variant-only `prepareXenonCommon` task now generates local copies of the stock common/embedded include files, redirects the normal instruction include to the installed PowerPC files, and deletes **only** the incompatible `dcbzl` constructor in the generated embedded file. Stock Ghidra remains unchanged. The Xenon `.slaspec` selects the new common include; source-level regression test added. This change has **not** yet been compiled or runtime-tested; expected effect is +2 correct samples but do not assert it until a new Ghidra run.

## Tool location (updated 2026-10-10)

All Xenon ISA Python tools and their pinned TSV inventories have moved from repository-root `tools/` into the **Gradle extension project** at `XEXLoaderWV/tools/` and `XEXLoaderWV/tools/data/`. Run everything from `XEXLoaderWV/` (the directory with `build.gradle`), without changing directories:

```powershell
python -m unittest discover -s tools -p "test_xenon_isa_coverage_v1.py"
python tools/audit_xenon_isa_coverage_v1.py
gradle buildExtension
python tools/check_xenon_fixture_install_v1.py
```

Generated fixtures now live in `XEXLoaderWV/build/xenon-isa-audit/`; the Java Ghidra fixture auditor remains in repository-root `ghidra_scripts/`. Earlier command examples in this document describe **historical layout** and are superseded by these paths.

## Second Ghidra fixture and VX128/X-form memory batch (2026-10-10)

**Observed, installed Xenon SLEIGH (before the changes below):** the user ran a new 336-word Ghidra fixture audit. **64 correct**, **0 unreadable**, **15 families 4/4**, **2 partial** (`lvlx`/`lvrx`, 2/4), and **67 without any correct mnemonic** (64 no-decode-only, 3 wrong-mnemonic-only). The prior audit had 43 correct, 9 fully decoded, 3 partial and 16 wrong-mnemonic-only families. Eliminating POWER 2.07/3.0 definitions stopped the earlier false AltiVec decodes. Remaining wrong aliases in the new report: `dcbz128` as `dcbz/dcbzl`, `lvlxl` as `stvepxl`, `lvrxl` as `stvepx`.

**New code committed, NOT yet built or Ghidra-tested:**

- Xenon-only `prepareXenonIsa` Gradle task generates `xenon_ppc_isa.sinc` from the installed Ghidra source with narrowly modified `dcbz` requiring `BITS_21_25=0` and removal of the two collision-prone `stvepx` / `stvepxl` constructors (and their unused userops). The Xenon .slaspec uses this new generated file; stock A2ALT/Ghidra source files are untouched. Markers are checked and the build aborts on unexpected source layout.
- Twelve opcode-4 VX128_1 load/store families: `lvewx128`, `lvxl128`, `stvxl128`, `stvewx128`, `lvlx128`, `lvlxl128`, `lvrx128`, `lvrxl128`, `stvlx128`, `stvlxl128`, `stvrx128`, `stvrxl128`. Source code models 16-byte alignment, left/right partial access and read-modify-write preservation, no-op/zero semantics at aligned right-edge cases, and individual-word stores, cross-referenced against Xenia's load/store emitters. Semantics are proposed, not runtime-equivalence-proven.
- Two more opcode-4 families `lvsl128`, `lvsr128`: correctly formatted operand/offset dependencies but **opaque userops**, not numerical mask semantics.
- Six opcode-31 vector X-form families `stvlx`, `stvrx`, `lvlxl`, `lvrxl`, `stvlxl`, `stvrxl`, using full 16-byte load/store p-code. These and preexisting `lvlx/lvrx` deliberately require Rc=0, pending legality verification. Two Rc=1 fixture samples per such family remain legitimately unhandled by this decoder.
- `dcbz128` now has its own opcode-31 constructor requiring the Xenia RT=1 selector, and explicit 128-byte cache-line zeroing modeled as eight 16-byte memory writes. Generic `dcbz` is restricted to RT=0 only **for Xenon**.
- Expected pinned 84-family SLEIGH add-on definition count: **31 native, 7 opaque, 46 without add-on constructors**. Source-level checks confirmed all four fixture words each uniquely select expected opcode-4 rules, all Rc=0 opcode-31 samples have one rule, and the Xenia inventories remain nonoverlapping. The 336-word fixture is unchanged; regenerate it because its source-coverage TSV/Markdown status changed.

**Next required verification:** pull; run the six Python unit tests via `python -m unittest discover -s tools -p "test_xenon_isa_coverage_v1.py"`; regenerate fixture via `python tools/audit_xenon_isa_coverage_v1.py`; rebuild `gradle buildExtension` from the `XEXLoaderWV` subdirectory. Compile and packaging of the new SLEIGH code are **not proven** yet. If build succeeds, reinstall/restart Ghidra, import the fixture into a **fresh disposable Program**, run `AuditXenonIsaFixtureV1.java`, and send the full summary/unresolved output. Check 37-site kernel V3 audit afterward. Do not claim full correct numerical p-code from successful disassembly alone.

## Ghidra 12.1.3 fixture runtime results and Xenon-only ISA correction (2026-10-10)

- The user loaded a fresh raw fixture with `PowerPC:BE:64:XENON-32addr`. Second run of `AuditXenonIsaFixtureV1.java` **completed**: 336/336 readable words, 43/336 correct mnemonics; 84 families: 9 complete, 3 partial (`lvx128` 3/4, `lvlx` 2/4, `lvrx` 2/4), 56 without a correct mnemonic and no unexpected decoded alternative, 16 wrong-mnemonic-only. The first script invocation printed a generic error without details; no reliable cause is available.
- Root cause of several *incorrect* alternatives is overlapping **modern Ghidra AltiVec** constructors for ISA 2.07/3.0, beyond Xbox 360 Xenon's instruction era. Examples: `lvsl128` rendered as `vcmpneb`, `lvx128` as `vcmpequd`, `lvlx128` as `vabsdub`, `stvlxl128` as `vpopcntb`. Actual definitions checked in upstream Ghidra `Ghidra/Processors/PowerPC/data/languages/altivec.sinc`. This is a genuine false-decoding risk, not an issue with the raw fixture's bytes.
- Applied **Xenon-only** change: Gradle `prepareXenonLegacyAltivec` creates `xenon_altivec_pre207.sinc` from the installed Ghidra stock source *before* the `altv207_1` declarations. It verifies unique markers and the presence of both later ISA sections before writing; fails the build if Ghidra's upstream source layout changes. `xenon_64_be.slaspec` uses that variant-local include; the installed stock language and its files are untouched. Resulting SLEIGH must be built and runtime-verified, not assumed fixed yet.
- Added source-level native p-code for five opcode-5 logical/select VMX128 families: `vand128`, `vandc128`, `vnor128`, `vxor128`, `vsel128` (Xenia confirms prior VD serves as the selection mask). Exactly 20 new selector constructors across the four combinations of extended VA bits. All 20 new fixtures statically match exactly one new constructor based on their BITS_6_10/BITS_4_5 selectors. **SLEIGH compilation and runtime behavior are pending.**
- Updated expected source coverage: **84 families, 12 native-pcode definitions, 5 opaque-userop definitions, 67 absent**. Counts are source classification only. Xenia's opcode-31 `lvlx`/`lvrx` decoder ignores the Rc bit, whereas our SLEIGH requires `Rc=0`; the current fixture's `ones` and `55` variants set Rc=1. Do **not** widen the SLEIGH encoding merely to satisfy those test vectors without validating whether Rc=1 is legal hardware encoding. Likewise, several remaining opcode-31 aliases (`stvepx`, `dcbzl`) still require separate investigation.
- Next: run `python -m unittest discover -s tools -p "test_xenon_isa_coverage_v1.py"`, `python tools/audit_xenon_isa_coverage_v1.py`; build using `gradle buildExtension` inside `XEXLoaderWV`, confirm the new source generation and SleighCompile both pass; reinstall/restart Ghidra. **Import the fixture into a NEW disposable Program**, because existing wrong disassembly is persisted in older Programs. Run `AuditXenonIsaFixtureV1.java` against the updated program, capture summary and all failed states. Check 37-site kernel V3 audit afterward.

# Xenon instruction-set coverage audit, 2026-10-09

## Scope and source of truth

This audit uses the generated decoder in Xenia at
[xenia-project/xenia @ 95a5c3ee250f80c3b9d139658649d9ffb6db3eec](https://github.com/xenia-project/xenia/blob/95a5c3ee250f80c3b9d139658649d9ffb6db3eec/src/xenia/cpu/ppc/ppc_opcode_lookup_gen.cc)
and compares opcode *family names* against our separate, experimental
PowerPC:BE:64:XENON-32addr SLEIGH add-on.

Two machine-readable snapshots in tools/data are pinned to that revision:
- xenia_vmx128_opcode_inventory_20261009.tsv: all 76 Xenia *128 mnemonics;
- xenia_xform_vector_opcode_inventory_20261009.tsv: eight Xbox-extended
  opcode-31 X-form vector left/right load/store mnemonics without the suffix.

This is a complete inventory of those 84 **selected extension families**,
NOT a complete audit of stock PPC, AltiVec, or every Xenon CPU instruction.
The base language includes Ghidra's installed ppc_common, ppc_isa, ppc_a2,
quicciii, FPRC, and altivec SLEIGH definitions. Its inherited coverage has
not been exhaustively enumerated. A mnemonic absent from our add-on can
still be accepted by stock Ghidra; only the runtime fixture establishes
whether this *installed language* decodes a representative opcode word.

Crucially, opcode-31 lvlx/lvrx and opcode-4 lvlx128/lvrx128 are **different
encodings and different inventory entries**. Do not silently merge them.

## Source-level results

| Primary opcode | Total | Native SLEIGH p-code | Opaque custom userop | No add-on constructor |
|---|---:|---:|---:|---:|
| 4 | 17 | 2 | 0 | 15 |
| 5 | 25 | 1 | 2 | 22 |
| 6 | 33 | 2 | 3 | 28 |
| 31 | 9 | 2 | 0 | 7 |
| **Total** | **84** | **7** | **5** | **72** |

The 76 *128 entries alone have 5 native bodies, 5 opaque userop bodies,
and 66 missing add-on constructors.

Native bodies (not proof of *correct* numerical semantics):
- lvx128, stvx128, vor128, vmrghw128, vmrglw128;
- opcode-31 lvlx and lvrx (not their *128 counterparts).

Opaque/userop bodies: vmulfp128, vmsum4fp128, vpermwi128, vrlimi128,
vupkd3d128. Their source register dependencies are represented but
complete numerical operations are NOT implemented by the custom userops.

The six opcode-31 X-form families not implemented in our add-on are:
stvlx, stvrx, lvlxl, lvrxl, stvlxl, stvrxl. dcbz128 is the seventh
missing opcode-31 extension.

The snapshots contain all known family selectors, 32-bit masks, selector
values, primary opcodes, and source line numbers. The source-level audit
independently found **zero overlapping selector pairs**, and all **336**
representative test words each match exactly one inventory family.
These are static facts about the pinned selectors, not a passing SLEIGH
or Ghidra runtime test.

## Repeatable workflow

From the repository root (one command per line), first exercise the
offline unit checks and then generate the fixtures:

    python -m unittest discover -s tools -p "test_xenon_isa_coverage_v1.py"

    python tools/audit_xenon_isa_coverage_v1.py

Optional source-of-truth cross-check, when a local clone of Xenia is
available:

    python tools/audit_xenon_isa_coverage_v1.py --xenia-lookup C:\path\to\xenia\src\xenia\cpu\ppc\ppc_opcode_lookup_gen.cc

Outputs are untracked working artifacts under build/xenon-isa-audit:

- xenon_isa_coverage_v1.md: family-by-family classification;
- xenon_isa_coverage_v1.tsv: machine-readable implementation status;
- xenon_isa_fixture_v1.bin: 336 big-endian 4-byte instruction words,
  including different fillings of unconstrained selector bits;
- xenon_isa_fixture_v1.tsv: byte offsets, actual expected word, Xenia
  mnemonic, expected source-status classification, and variant.

Import the fixture .bin into Ghidra as a **raw flat binary**, selecting
**PowerPC:BE:64:XENON-32addr**, **big endian**, default compiler. Then
run ghidra_scripts/AuditXenonIsaFixtureV1.java in that disposable Program,
pointing it to the generated fixture TSV. The script verifies the actual
bytes, tries disassembly, checks exact mnemonic family names, and prints
all unresolved/wrong states **at the end**. It does not rewrite bytes,
create signatures, or touch game/kernel Programs.

A negative fixture result is actionable, but consider constructor priority,
register high-bit restrictions, the validity of reserved operand values,
and whether stock Ghidra inherited the instruction. Xenia's opcode lookup
is a decoder reference, not independent architectural certification for
every synthetically filled operand combination.

## Implementation ordering, not instruction-by-instruction whack-a-mole

1. **Opcode 5 logical/vector selection group:** vand128, vandc128,
   vxor128, vnor128, vsel128. Model verified destination/source register
   fields and use native bitwise p-code where correct.
2. **Opcode 4 indexed vector memory group:** the remaining loads and
   stores (including high/low window and LRU variants). Establish
   address alignment, byte order, zero-fill and non-aligned semantics
   before implementing p-code. Do not alias the opcode-31 forms.
3. **Opcode 6 packing, comparison, conversion, shift, and permute
   groups:** establish real operand formats first, then semantics.
4. **Opcode 5 floating-point, packing and fused arithmetic:** use
   Xenia's emitter implementation as the behavioral cross-check.
   Do not label uninterpreted CALL_OTHER as accurate numerical p-code.
5. **Opcode-31 additional forms and dcbz128:** verify cache-line
   behavior and preserve memory side effects, not simply a NOP.

For every batch, add several representative masks/operand configurations
to the fixture, run the actual Ghidra 12.1.3 SLEIGH compiler,
run the fixture verifier, and only then inspect decoded code/function
coverage in retail kernel 17559, XAM, and at least one ordinary game XEX.

## Verification and limitations

- VERIFIED by direct comparison of the pinned Xenia generated decoder:
  76 *128 selectors, eight extra X-form selectors, no two extension
  selectors overlap, and 336 generated selector words are unambiguous.
- VERIFIED by inspection of the currently committed SLEIGH source:
  7 native-body families, 5 explicit-opaque families, 72 without an
  add-on constructor.
- NOT RUN in this environment: Python generator executable, Gradle
  SleighCompile, installed Ghidra's fixture decoder, independent stock
  A2ALT fixture comparison, numeric p-code equivalence tests.
- The preceding 37-site retail-kernel V3 decoder audit remains separate:
  passing it does not prove other Xenon instruction families decode.

## Next step

Run the Python generator, import the fixture, and execute the Java
Ghidra audit. Capture the final unresolved-state block. Implement in
batches from the pinned table, not solely from additional kernel
Bad Instruction bookmarks. Preserve the separate language ID and stock
A2ALT fallback while the variant remains experimental.
