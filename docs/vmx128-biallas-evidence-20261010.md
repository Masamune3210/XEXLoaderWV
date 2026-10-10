## Implemented decoding correction (2026-10-10)

- **Implemented in the existing `fix/import-thunk-modeling-20261009` branch**: explicit `vupkhsh128` / `vupklsh128` constructors with opcode words `0x180007A0` / `0x180007E0` and `0xFC1F07F0` mask. These match the signed-halfword aliases associated with VA128=0x60. P-code has separate result-producing opaque `xenonVupkhsh128` and `xenonVupklsh128` operations consuming VB and writing VD; no unsupported lane sign-extension arithmetic was invented.
- Both original byte-unpack constructors that formerly overlapped those exact encodings now constrain `A_BITS!=0`, while the new halfword constructors require `A_BITS=0`. All other four original byte-unpack variants remain. Independently verified by static constraint evaluation: all four sample fills for each byte and halfword family match one and only one appropriate constructor; no overlapping applicable patterns.
- A distinct provenance-tagged `tools/data/xenon_vmx128_unpack_corrections_20261010.tsv` records these two **non-Xenia** named families. The original 84 pinned-Xenia family words and first 1,344 fixture bytes remain unchanged. The Gradle generator now appends 8 additional test words, yielding **86 families, 344 words, 1,376 bytes; 328 expected mnemonics and 16 reserved Rc=1 expected rejections**. The manifest format remains six TSV columns. The freshness checker validates the extra inventory SHA, enlarged byte count, exact word/variant rows and opaque classifications. The coverage report describes the corrections separately from the pinned decoder source.
- Python regression tests added for exact encodings, disjoint byte/halfword constraints, original binary prefix preservation, extra 8 sample bytes, fingerprint, classifications, and Gradle input wiring. **21 Python test methods** now exist. Current validation: source-level/inventory/pattern simulation passed, with 0 ambiguities. **Not yet verified:** user-side Python tests, SLEIGH compilation (in particular `A_BITS!=0`), installed language, Ghidra alias decoding, or numerical p-code.
- This section supersedes earlier statements below that these alias opcodes had not yet been implemented. Do not claim the original 336-sample runtime verification proves the new 344-sample fixture; a new fixture Program is required because the binary grew. No Ghidra database labels/signatures are identified from this opcode-only investigation.
# VMX128 original disassembly notes and source independence

Date: 2026-10-10
Branch: `fix/import-thunk-modeling-20261009`

## Original document, provenance, and limitations

- Original: https://biallas.net/doc/vmx128/vmx128.txt , Sven Biallas, **2006/09/01 Revision 1.2**.
- Source was inaccessible directly to the assistant; an identical, independently accessible mirror is `rexglue/rexglue-sdk/docs/ppc/vmx128.txt` (GitHub content SHA `e1bed1a3b9c492008569909d1a9d7759cda9370f`). The *pinned Xenia* copy `xenia-project/xenia/docs/ppc/vmx128.txt` at `95a5c3ee250f80c3b9d139658649d9ffb6db3eec` has the **same SHA and byte content**. Comparing Xenia to this document is NOT two independent numerical confirmations.
- Biallas explicitly describes reconstructing VMX128 instructions from disassemblies, warns of possible errors/missing instructions and unknown semantics. The document is useful for 128-register operand encoding, fixed opcode fields, mnemonic identity, and implied register widths. It is **not** an official ISA specification or a complete instruction-semantics oracle.
- IBM architectural support for the non-contiguous 128-register VMX128 encoding exists separately in US Patent 7,421,566 (`https://patents.google.com/patent/US7421566B2/en`) and Xbox 360 CPU microarchitecture papers. Patents describe proposed/implemented design aspects, not exhaustive machine-code or exceptional-value behavior.

## Corrections and known inventory gap

- Recent **open** Xenia PR [#2331](https://github.com/xenia-project/xenia/pull/2331) by 0dinD supplies a revision 1.3 diff, pointing to original document typos (`stewx128` vs `stvewx128`, operand labels for stores, `vmsub3/4fp128` vs `vmsum3/4fp128`, `vandc128`, `vrlw128`, `vsro128`) and, crucially, **two missing instructions** `vupkhsh128` and `vupklsh128`. Open PR [#2372](https://github.com/xenia-project/xenia/pull/2372) independently reported several of the same documentation typos but refers to #2331 as more complete. Do not silently treat the original 2006 table as corrected.
- [encounter/powerpc-rs `isa.yaml`](https://github.com/encounter/powerpc-rs/blob/4643ee0fd3275e3a89dee709185c37968acca83b/isa.yaml) lists:
  - `vupkhsh128` (signed halfword unpack high): **mask `0xfc1f07f0`, word `0x180007a0`**;
  - `vupklsh128` (signed halfword unpack low): **mask `0xfc1f07f0`, word `0x180007e0`**;
  - existing byte versions `vupkhsb128` word `0x18000380` and `vupklsb128` word `0x180003c0` with that stricter fixed-field mask.
- [hedge-dev/XenonRecomp](https://github.com/hedge-dev/XenonRecomp/blob/ddd128bcca99fe8bfbb99bea583c972351fa6ace/XenonRecomp/recompiler.cpp#L520-L524) and pinned Xenia's `InstrEmit_vupkhsb128` / `InstrEmit_vupklsb128` special-case **`VA128 == 0x60`** to emit signed *halfword* unpack instead of signed byte unpack.
- Our current `xenon_vector_remaining_v1.sinc` has only `:vupkhsb128` and `:vupklsb128` with broad selector masks `0xfc0003d0`, and has **no `:vupkhsh128` / `:vupklsh128` constructors**. Thus `0x180007a0` and `0x180007e0` are potential *misnamed decodes*, not demonstrated complete native/opaque implementations. The 84-family/336-word fixture covers exactly the **pinned Xenia decoder inventory**, NOT every known Xenon opcode family. These two were absent from that inventory because Xenia's decoder normalizes them to the byte mnemonics and its emitter branches on VA. Existing 336 synthetic fills never explicitly test both alias words.

## Concrete next steps before promoting semantics

1. Validate two exact words `0x180007a0`, `0x180007e0` as separate fixture samples and inspect current Ghidra mnemonic and SLEIGH register binding. Independently verify byte variants' reserved operand bits.
2. Split byte and halfword unpack constructors on the full VA encoding (including VA==0x60 special case) **without overlapping SLEIGH patterns**. Keep numerical unpack behavior as opaque until lane ordering and sign extension are demonstrated, rather than copying Xenia's emitter uncritically.
3. Extend the inventory/fixture with two extra named families or explicit alias-case tests while preserving the original 336 pinned-Xenia compatibility fixture, and update Gradle auto-regeneration plus regression tests. Make coverage claims explicitly scoped.
4. For promoted native FP dot/permutation code, verify per-lane and byte-order test vectors independently; this Biallas document specifies encodings, not rounding/fusion/CR6/VSCR semantics.

## Verification

- VERIFIED: same original Biallas content hashes in Xenia pinned revision and RexGlue mirror; Xenia PR #2331 diff and independent powerpc-rs masks/patterns; XenonRecomp source alias handling; absence of the two halfword mnemonics in current Xenon SLEIGH/inventory.
- NOT VERIFIED: execution of those two instructions on Xbox 360 hardware, current Ghidra decode of the precise alias words, uniqueness of a proposed split SLEIGH encoding, or halfword numerical p-code.
- Existing 336-fixture encoding audit remains verified as **320 legal mnemonic matches plus 16 Cell-documented reserved Rc=1 rejections**, and is intentionally not reclassified as a full Xenon ISA audit.
