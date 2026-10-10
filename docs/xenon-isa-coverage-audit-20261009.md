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

From the repository root (one command per line):

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
