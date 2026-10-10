# XEX import-thunk modeling (2026-10-09)

## Why this branch exists

XEXLoaderWV processed imports after .pdata-driven disassembly, created labels rather than genuine external thunks, and patched a detached PE byte buffer after memory mapping. For Xbox 360 17559 $flash_xam.xex, Ghidra recorded 443 Bad Instruction bookmarks on import tokens. A targeted repair linked all 443 to xboxkrnl.exe and removed those 443 stale bookmarks. Future imports should not require that repair.

## Changes

- Process import records after mapping sections but before .pdata function discovery.
- Validate type-0 slot/type-1 thunk records, ordinal matches, and mapped address ranges.
- Add external-library symbols/references and genuine Ghidra external thunk functions for recognized native stub layouts.
- Preserve mapped executable bytes; define import-token words as data to block incorrect PPC disassembly.
- Retain unknown data-only imports without guessing signatures, and report unrecognized thunk layouts.

## Status and next steps

Changes are committed to this branch. Build and fresh import in Ghidra 12.1.3 are NOT YET VERIFIED. The existing manually repaired XAM database is untouched.

Build against Ghidra 12.1.3, import the original $flash_xam.xex (SHA256 78b3dbd8ae866f4258f5444205486ea9f8451afaa30f469c875dcf345f828467) into a disposable test program, and confirm 443 real xboxkrnl.exe thunk links and 20 unpaired reference slots before analysis. Check that token words are data, original bytes are intact, and no import-token Bad Instruction bookmarks appear across two analysis passes. Verify a second XEX with a different import layout before merging. A mismatch may require changing the function-entry/data strategy; do not conceal errors with synthetic PPC instructions.

Not in scope: VMX128/Xenon language decoding, compiler-helper ABI fixes, and .pdata packed function-length modeling.

## Fresh-import regression (2026-10-09)

User imported the original 17559 XAM as a second program using this branch's loader and completed auto-analysis. The GZF was inspected offline; original image SHA256 was known from the working file. The current implementation **does not pass the no-recurring-import-errors test**. The GZF contains diagnostic records at 389 of 443 canonical thunk entries: 368 have a parseable "Failed to disassemble ... due to conflicting data" message, 31 have a constructor-failure message (some overlap); five additional malformed/truncated copies are ignored when counting unique addresses. Only 54 thunk entries have no such embedded record. There are 165 non-import constructor-error addresses, versus 335 in the prior analysed archive. The previous import produced constructor errors at all 443 thunk entries, so the change transforms a large part of the error class instead of eliminating it.

Cause to investigate: the branch simultaneously creates a function at a native import-token entry point and declares the same bytes as DWord data. Ghidra auto-analysis tries to disassemble at function entries/branch destinations and records a conflicting-data error. The disassembler expects actual instructions at function entries; declared data alone does not stop it from trying. Earlier branch success claims were premature.

Do **not** fix this by globally disabling "Mark Bad Disassembly", deleting bookmarks after analysis, or patching the original executable bytes. Consider an import-aware disassembly strategy or a clearly documented image-only patch with separately preserved native bytes if acceptable. Before deciding, use a read-only Ghidra audit to verify that all 443 thunk links and both token data declarations survive analysis; embedded GZF diagnostic records may be historical, not live bookmarks. No loader correction or new user-database mutation has been made based solely on this GZF.

Status: implementation present, regression test FAILED, keep branch unmerged.

## Follow-up implementation: mapped-memory runtime relocation veneers

The live read-only audit of the first fresh import confirmed that **all 443 genuine xboxkrnl.exe thunk links were correct**, all 443 original stubs were byte-exact, and both four-byte import tokens were defined as data. However, **339 live Bad Instruction bookmarks remained**: 310 conflicting-data and 29 invalid-instruction errors. The prior GZF-based diagnostic inventory included stale embedded records, so use live bookmarks for regression counts.

Xenia's runtime loader documents that real consoles replace both token words with PowerPC code loading the resolved target address into r11, followed by the native mtctr/bctr pair. Since the external address isn't known at import time, a new configurable loader option (default ON) now writes an **analysis-only unresolved relocation veneer** into the *Ghidra mapped memory*: `3D600000 616B0000 7D6903A6 4E800420` (lis r11,0; ori r11,r11,0; mtctr r11; bctr). Ghidra's native thunk relationship supplies the real external identity. This IS a byte change in the Ghidra database; it does **not** modify the original XEX on disk or the loader's `peImage`. The two original token words are retained in a plate comment at each function entry, and can be recovered from the original file. Disable the loader option to preserve raw imported bytes, at the cost of native-token disassembly errors.

Token words are no longer declared as data when the veneer option is ON, eliminating the known code/data conflict at function entries. The option is applied only to validated canonical 16-byte native import stubs. The prior failures for non-import Xenon instructions are explicitly out of scope.

**Verification status:** this second implementation is committed, but no local Ghidra 12.1.3 extension build, fresh import or repeated auto-analysis has been completed. The previous regression remains reproducible on the earlier first-version build and must not be described as solved until the second build passes.

### Verification

Build/reinstall this branch, import `$flash_xam.xex` under a new test program name, complete auto-analysis twice, and run `AuditXamLoadercheckThunksV2.java` from the Ghidra Script Manager. Expect 443 linked thunks, 443 relocation veneers, no defined data on first two words, and zero live Bad Instruction bookmarks at token +0/+4. Inspect the original-token plate comments and confirm the source XEX SHA256 has not changed. Then test a different XEX with imports. If the veneer body or external linkage is lost, do not merge.
## Design correction: fidelity first

User questioned whether synthetic zero-target PPC veneers could distort decompilation and whether importing/linking the actual xboxkrnl program would be better. This concern is valid: a `lis/ori r11,0; mtctr; bctr` placeholder is not the original XEX or a known runtime-resolved destination, and may mislead control-flow or p-code recovery if Ghidra interprets its instructions instead of the external thunk metadata.

**The analysis-veneer loader option now defaults OFF** (commit f7b9e81). The source XEX and mapped Ghidra memory stay byte-exact by default. Actual Ghidra thunk functions and external references remain the primary import representation. The optional veneer is explicitly labeled EXPERIMENTAL and should not be enabled in the authoritative reverse-engineering database without deliberate validation. With veneers off, invalid-instruction diagnostics at native import tokens may recur, and this does not by itself mean import function linkage is broken.

Recommended direction: import a matching xboxkrnl kernel as its own Program in the same Ghidra project, map the existing `xboxkrnl.exe` external namespace to it, verify ordinals and function names, and propagate reliable function signatures/types. This improves cross-program navigation and call recovery but does not itself rewrite XEX import tokens or eliminate native placeholder disassembly diagnostics. Separate XAM and kernel programs are preferable to merging images into one address space.

Do not merge the experimental veneer approach as a permanent fix to analyzer errors. Preserve known import descriptors and classify their expected instruction-constructor errors instead of substituting ungrounded runtime addresses. A future import-aware Ghidra analyzer is worth investigating, but has not been implemented or verified.
## Xbox 360 retail 17559 kernel acquisition (2026-10-09)

- Recovered genuine CE 1888 from user's Trinity NAND, after validating `CB_A 9231 -> CB_B 9231 -> CD 9231 -> CE 1888`; successfully decrypted using `cb-b-v2` key derivation.
- Successfully decompressed all 36 LZX blocks to the raw 0x120000-byte combined HV+PE kernel image; SHA256 `26f65a4c5c664d308714efacdb55aee833873c87a682cab0c2a4a9a764254c39`.
- Verified the raw 1888 image's SHA1 `95e2a946f4ce4a3d1edb48fc9e4787d0f064a112` **exactly matches** the original-image hash stored in the decrypted *official 17559 CG update*. Thus the extracted base is the exact expected retail starting point.
- The original update `xboxupd.bin` is present in the prior official PIRS extraction as `pirs-extracted/xboxupd.bin` in `17559-system-update-complete-v2.zip`, 507872 bytes, SHA256 `2f85e912775b12f0740dd86ab518d303c7ba6fe837a05cad7d951c433376d537`. CF base=1888, target=17559.
- The CG update expects a target raw HV+kernel image of **0x1F0000 bytes**, SHA1 `f1b66f2aa794f0117a8a2d565c9fec0b601fed83`.
- Standalone `xboxkrnl.1888.recovered_v1.exe` extracted at offset 0x40000 from HV+kernel, 917504 bytes; PE `MZ/PE`, machine 0x01F2, SHA256 `1b24c5acee32590e90c85d7080d68af79a0605f62d14fb27eb0cfb0ce10fb376`.
- The self-contained conversation artifact `xbox360_17559_kernel_reconstruction_inputs_20261009_v1.zip` contains recovered 1888 HV+kernel, official xboxupd.bin, verification/split script and README.
- **Remaining:** apply CF/CG delta with xenon-bltool `xboxupd`, verify output exactly matches CG target SHA1, then import the split 17559 kernel as a separate Ghidra program for external linkage. This patch step has NOT yet been completed or validated.
- No changes to original XAM or NAND; the kernel recovery is an offline, read-only provenance workflow.
## Verified retail 17559 reconstruction and kernel export annotations

- User ran xenon-bltool `xboxupd` against recovered retail 1888 base and official 17559 CF/CG. Signed CF and CG validation succeeded; reconstructed full HV+kernel target SHA1 `f1b66f2aa794f0117a8a2d565c9fec0b601fed83` **exactly matched expected CG target hash**.
- Re-checked user's uploaded final artifacts locally: combined length `0x1F0000`, SHA256 `951ef69619fb0c6940480c245b999a014f9310e1d723f2a4fd6f83a77298f41c`, PE kernel slice offset `0x40000` length `0x1B0000`, SHA256 `e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8`; HV slice length `0x40000`, SHA256 `225d1c6907651126182e8a2ce74d7df59e7970c0086848114de20c35268609f5`. Concatenated HV + kernel equals full image byte-for-byte.
- Verified kernel PE: machine `0x01F2`, preferred image base `0x80040000`, 10 sections; export directory RVA `0x15E00`, 931 ordinal slots (base 1), 921 nonzero RVAs, 10 empty slots; **886 code exports** in `.text` and **35 data exports** outside executable blocks. PE has no named exports (ordinal-only).
- Cross-checked ordinal 207 `NtClose` resolves to VA `0x80089EB0`, and ordinal 409 `XexLoadImage` to VA `0x8007D7C0`, matching independent retail 17559 references.
- Added standalone Ghidra script `ghidra_scripts/AnnotateXboxKrnl17559ExportsV1.java` from 859 `xboxkrnl_replacer` ordinal names in the existing ImportRenamer source. Script verifies base/SHA-256/export header; adds export labels and renames *only* default/placeholder existing function names, never creates functions, edits bytes, changes signatures/types, or renames user-defined functions. Script is NOT YET TESTED inside Ghidra 12.1.3.
- Next: import kernel `.exe` into Ghidra as separate Program with correct PPC language and PE image base `0x80040000`, verify labels and native PowerPC disassembly, run annotation script, then in XAM Symbol Tree > Imports > `xboxkrnl.exe` > Set External Program to that imported Program. This should enable name-based cross-program navigation; confirm behavior and mapping before claiming linkage verified.
- The analysis veneer option stays OFF in XEX loader. No alteration to XAM's original token bytes is required to analyze calls.

## Clean kernel import and `.pdata` audit (2026-10-09)

- Ghidra 12.1.3 imported the verified retail kernel as PE Program `xboxkrnl.exe`, PowerPC `PowerPC:BE:64:A2ALT-32addr`, image base `0x80040000`, executable SHA256 `e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8`. Auto analysis completed: **204560 instructions, 3568 functions, 38540 symbols**. User supplied the resulting `xboxkrnl.exe.gzf` for follow-up.
- Ran `AnnotateXboxKrnl17559ExportsV1.java` successfully: 931 ordinal slots, 10 empty, 886 code and 35 data exports; 627 labels created, 292 default functions renamed, two existing correct names, zero errors, 63 fallback ordinal labels. **534 code exports were within another Ghidra function**; this is a boundary-analysis issue, NOT malformed kernel exports.
- An independent scan of the *verified retail 17559 PE* established that `.pdata` at VA `0x8004FA00..0x80055D9F` comprises **3188 distinct, sorted, non-overlapping 8-byte records**. Each record is big-endian `uint32_t entryVA` followed by `uint32_t unwindPacked`; the established encoded function size is `((unwindPacked >>> 8) & 0x3FFFFF) * 4`.
- Of **886 code exports**, **569 exactly match a .pdata function start**; **317 do not belong to any .pdata range** (potential leaf or assembly entries); **zero are inside a .pdata range**. Thus Ghidra's 534 overlaps reflect overgrown or otherwise conflicting auto-discovered functions, not exports in the middle of known `.pdata` functions. Example: ordinal 5 at `0x800B90C8` matches a `.pdata` start but was flagged as belonging to another function.
- Generated a complete ordinal/VA/classification CSV and standalone runnable Ghidra script `AuditAnnotateXboxKrnl17559PdataV1.java` as conversation files. **Script not yet run inside Ghidra**. It confirms the image SHA256, language, export and `.pdata` layout before any mutations; adds verified `.pdata` range comments; creates exact-range functions only where *no existing function overlaps* and the start is already disassembled; annotates non-`.pdata` export entry points without inventing boundaries. It never shrinks/removes existing functions, changes signatures, or patches bytes.
- The script prints remaining function conflicts at the end. Require user-run results before considering destructive splitting of the 534 occupied exported entry points. The script does not promise to correct them automatically.
- The primary XEX loader branch has restored the `ByteArrayProvider` import in commit `22bccb5` after user encountered two compiler errors. **Rebuild still unconfirmed**. Do not assume new loader behavior has been validated yet.
- Next: run the `.pdata` audit, then import XAM with inherited `Link Existing Project Libraries` enabled and `Load Libraries From Disk` disabled; confirm linking to `xboxkrnl.exe` and audit XAM thunk metadata. Keep native XEX bytes unchanged; defer speculative boundary splitting.


## Early retail 17559 kernel PE analyzer (2026-10-09)

User explicitly requested loader-side prevention of kernel `.pdata` boundary damage, not post-import cleanup. Ghidra's standard PE loader remains unchanged; the **same XEXLoaderWV extension now registers a separate early analysis plug-in**, `Xbox360RetailKernelPdataAnalyzer` at `XEXLoaderWV/src/main/java/xexloaderwv/Xbox360RetailKernelPdataAnalyzer.java`.

- Implements `AbstractAnalyzer` with `AnalyzerType.BYTE_ANALYZER`, `AnalysisPriority.FORMAT_ANALYSIS.after()` and default enablement. Class name ends with `Analyzer` for Ghidra's extension scanner.
- Restricted by **exact verified** retail 17559 `xboxkrnl.exe` executable SHA-256 `e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8`, PE format, image base `0x80040000`, and PowerPC language `PowerPC:BE:64:A2ALT-32addr`. Other kernels/programs do not match.
- Fully validates `.pdata` (3188 sorted, non-overlapping ranges; big-endian packed length `((info >>> 8) & 0x3fffff) * 4`), PE export directory (931 slots, 10 empty, 886 code/35 data, 569 code exports matching `.pdata` starts) and section extents **before any database mutations**. Accepts PE raw-alignment padding in `.pdata` and `.text` sizes.
- Performs flow-restricted disassembly within each known `.pdata` body and creates precise complete function-body address sets **before speculative Ghidra function discovery**. Does not modify memory bytes or function signatures. Existing functions/bodies are never removed or forcibly split, making the operation idempotent/conservative.
- Applies every exported ordinal name through shared `ImportRenamer.Rename("xboxkrnl.exe", ordinal)`, including aliases and unknown-ordinal fallback. Marks the 317 code exports outside `.pdata` as external entrypoints to seed normal Ghidra analysis, without guessing lengths. Data exports receive labels, not function declarations.
- Logs number of created/existing/skipped functions, disassembly failures, labels, leaf entrypoints. Any validation failure aborts with zero changes.
- The normal Ghidra PE import is still used for the kernel; XEXLoaderWV remains responsible for XAM. The extension analyzer is a *separate* registration; it can process PE Programs regardless of which loader imported them.
- **Verification status: source committed, Ghidra 12.1.3 build and fresh-kernel import NOT YET TESTED.** User must rebuild/reinstall extension and restart Ghidra for analyzer registration. Reimport the verified retail PE cleanly and check the initial Auto Analyze options for `Xbox 360 Retail Kernel 17559 Pdata`; confirm expected counts and check new export overlaps without running the old repair scripts. If it doesn't appear or fails, inspect analyzer discovery/build logs.
- Remaining: test actual initialization, compare resulting function counts and export overlap count to 534 from previous import, confirm labels `NtClose`/`XexLoadImage` and Ghidra auto-linking to XAM. No claims of overlap elimination until measured; 317 uncovered entries do not have known lengths.

- Ghidra 12.1.3 rejected the initial analyzer display name `Xbox 360 Retail Kernel 17559 .pdata`: `AnalysisScheduler` forbids periods. Renamed it to `Xbox 360 Retail Kernel 17559 Pdata` without changing any analysis behavior. Requires extension rebuild and Ghidra restart. Analyzer execution has not yet been verified.
