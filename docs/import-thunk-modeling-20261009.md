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


## Initial kernel analyzer run and deferred disassembly follow-up

- User built/installed the analyzer, initial Ghidra 12.1.3 Auto Analyze reported 3103 .pdata functions created, 0 existing, 0 skipped, **85 missing instructions at .pdata entrypoints**, 387 new export labels, and 0 new leaf entrypoints. No validation failure. PDB Universal/MSDIA warnings about missing PDB were unrelated to our kernel analyzer.
- Since Ghidra's PE importer already marked export addresses as external entrypoints, a zero new-leaf count is expected; the analyzer's revised log distinguishes newly marked from previously marked.
- Verified first problematic kernel address `0x80061010` contains legal PPC `7D8802A6` (`mflr r12`). These are pending disassembly issues, not evidence of malformed .pdata ranges. The initial version erroneously **skipped verified function boundary creation whenever early DisassembleCommand didn't define its first instruction**.
- Corrected: always try bounded entry disassembly, but if the entry is still undefined (and not occupied by defined data), create the function with the **exact validated .pdata body anyway**. Ghidra 12.1.3 FunctionManagerDB's createFunction() allows an undefined entrypoint but correctly rejects defined data. This reserves boundaries before later normal instruction/function analysis; no instruction/data patching, no forced conflicts, no guessed signatures. Entries occupied by defined data remain unchanged and are logged explicitly.
- Added diagnostic counts for `pending disassembly`, `entry data conflicts`, and `leaf entrypoints already marked`; truncated diagnostics list contains status from DisassembleCommand where available. The script reports failure only if it actually had to skip function creation, not merely for a pending instruction.
- **Unverified:** user still needs to rebuild/install/restart and reimport the verified kernel cleanly to confirm that all 3188 function bodies are reserved and to inspect whether any of the 85 entries remain undecoded after complete Auto Analyze. Do not claim the underlying disassembler issue is solved until tested.


## Verified boundary reservation, pending early instruction decode (2026-10-09)

- User's clean import with the revised early kernel analyzer now reports **all 3188** `.pdata` function bodies created, **zero existing, zero skipped, zero defined-data conflicts**. The initial `FORMAT_ANALYSIS` pass still has **85 pending entrypoint instructions**; this is NOT a failure to reserve boundaries.
- Export annotations: 351 new labels. Of **301 unique** exported executable entrypoints not covered by `.pdata` (317 ordinal entries including duplicate destinations), all 301 were **already** registered as entrypoints by Ghidra's PE loader, hence 0 newly added. Distinguish unique addresses from ordinal counts.
- The sample pending addresses are consecutive records near the start of `.pdata`: `0x80061010`, `0x800610e8`, `0x80061440`, etc. Their original bytes are valid PowerPC instructions (for example `7D8802A6` is `mflr r12`); Ghidra's early DisassembleCommand returned the generic message `Disassembler requires a start which is an undefined code unit`. That status alone does **not** distinguish existing defined data, an instruction collision, unsupported context, or delayed decoding.
- Added **read-only** `ghidra_scripts/AuditXboxKrnl17559AutoAnalysisV1.java` to inspect the **already imported, fully analyzed** kernel without rerunning the extension or changing database contents. It counts exact/missing/changed `.pdata` function bodies, entrypoint instruction definitions, defined data containing undecoded starts, instructions containing starts, and exports that are absent or inside a different function. Prints actionable diagnostics at bottom. SHA256/language/image-base gated.
- **Next**: user runs this script *once on the existing kernel Program after full auto-analysis*. If the initial 85 pending entries decoded later, no further intervention is necessary. If not, use the classification (defined-data containment vs undefined vs instruction overlap) to make a *source* correction to the analyzer. Do not blindly clear data or change existing functions based on the generic early disassembler warning.
- Ghidra PDB Universal/MSDIA warnings are unrelated: the kernel embeds PDB identity metadata, but no matching PDB was found. No additional PDB support was added.


## Post-analysis audit regression: early .pdata definitions not surviving (2026-10-10)

- User ran read-only `AuditXboxKrnl17559AutoAnalysisV1.java` after a kernel Auto Analyze with early `.pdata` analyzer logging `created=3188, existing=0, skipped=0, pending disassembly=85`.
- **Audit result sharply contradicts early-stage success:** `.pdata` bodies exact **12/3188**, missing function **2930**, changed body **246**. Entry instruction absent **607** (1 defined data, 0 middle-of-instruction, **606 truly undefined**). Kernel exports remain 886 code / 35 data / 10 empty, but just **297** code exports are at function starts; **536** are inside other functions and **53** have no function. The prior plain PE analysis also had 534 overlaps. **DO NOT claim the current analyzer fixes function boundaries.** No XAM import test yet.
- Source inspection of Ghidra 12.1.3: `EntryPointAnalyzer` at `BLOCK_ANALYSIS` uses its own disassembly/flow and `CreateFunctionCmd.fixupFunctionBody` for certain entries, while `ClearFlowAndRepairCmd.repairFunctions` can remove non-start functions or replace function bodies. Both are possible mechanisms; **causation not yet demonstrated**. `FunctionManagerDB.getFunctionAt` returns a primary-symbol function and does not merely hide functions due to missing code, so missing entries deserve investigation.
- Investigated original verified `xboxkrnl.17559.verified_v1.exe`: first failing entry `0x80061010` contains `7D8802A6` (standard `mflr r12`). In the first 200 post-analysis undecoded entries, **193** share this opcode, but **3098/3188** verified `.pdata` starts also share that opcode. Thus this instruction alone **cannot explain** the decode failures. Errors cluster heavily from `0x80061010` to `0x80065BE8`. Do not label these 607 as missing instructions specific to unsupported Xenon opcodes without further proof.
- **Next**: inspect the fresh post-analyzer kernel Program database/exported `.gzf`, especially two examples `0x80061010` (missing/undefined), `0x80065C60` (present/changed), `0x80065DF8` (missing), and examine analyzer/transaction logs. Determine whether function removal is caused by flow repair, late clear-code operations, analyzer cancellation, or import-instance mismatch before introducing destructive automatic function splitting or a second finalizer. Use Ghidra analyzer plugin to address cause, not manual repair script.
- Preserve original import and metadata exactness; existing extension's early verifier/labeling works, but its full-range function definitions are **not durable** through normal auto-analysis.


## Clarification from complete Ghidra application log (2026-10-09 19:44 CDT)

**Correction to preceding "post-analysis audit regression" hypothesis:** The 3188-created analyzer log and the 12-exact post-analysis audit were from **two different kernel imports**, NOT demonstrably from the same auto-analysis session. Do not present the 2930 missing/246 changed audit counts as proof that Ghidra deleted our analyzer-created boundaries.

- **First import**, analyzed around **19:24:44–19:25:17**: the analyzer explicitly logged `created=3188, skipped=0, pending disassembly=85`. The corresponding Auto Analysis timing table **does include** `Xbox 360 Retail Kernel 17559 Pdata 2.090 secs`. Several `ClearFlowAndRepairCmd` warnings are recorded, including function removals/body changes, but their actual effect on this imported program's 3188 final ranges was **not audited**.
- At **19:25:45**, Ghidra application log records `/System Firmware/xboxkrnl.exe: file deleted`; Ghidra then restarted after an extension change.
- **Second import** at **19:35:42**, analyzed **19:35:59–19:36:34**: the Auto Analysis timing table **does not include** `Xbox 360 Retail Kernel 17559 Pdata`, and its analysis messages do not show this analyzer's success/validation line. This strongly indicates the analyzer was **not run or not enabled** for the second import; root cause (disabled option, changed extension registration, etc.) is unknown.
- The read-only `AuditXboxKrnl17559AutoAnalysisV1.java` ran at **19:37:18**, after the **second** import, and reported 12 exact/2930 missing/246 changed; these numbers are consistent with generic PE analysis without our analyzer. Do **not** infer destruction of the earlier 3188 functions based on this audit.
- **Next test**: Fresh import/reanalysis with **Xbox 360 Retail Kernel 17559 Pdata explicitly checked** in initial Auto Analyze dialog, then confirm it appears in end-of-analysis timing report and run read-only audit on that **same program without deleting/replacing it**. Compare results only when both logs are from the same import instance. Record possible `ClearFlowAndRepairCmd` impacts if audit still shows differences.
- No new analyzer behavior changes were necessary from the audit because it did not measure a qualifying analyzer-enabled import. Prior tentative claim of proven analyzer regression has been superseded by this stronger chronology evidence.
