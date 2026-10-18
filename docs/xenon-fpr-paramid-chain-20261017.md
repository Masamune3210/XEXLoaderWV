# Xenon FPR context-saver Parameter ID investigation (2026-10-17)

## Scope and current state
- Program: retail 17559 `xboxkrnl.exe`, SHA-256 `e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8`; Xenon `PowerPC:BE:64:XENON-32addr`.
- Problem: 13 phantom `undefined8` formal parameters in register storage `f1:8` through `f13:8` propagate through a call chain originating at the floating-point context saver `0x80075a38`.
- Audited 2,377 functions containing all 13 phantom FPR parameters; 2,357 lacked native FP instructions. Prior graph audit reached the saver through the wrapper `0x800759f8` and through dispatch to `NtClose` (`0x80089eb0`).
- Separate read-only rollback verification proved the production program remains at its original metadata baseline (14-argument ANALYSIS signatures and custom storage in saver and wrapper); do not assume the earlier sandbox changes reached production.

## Verified disposable-sandbox experiment
`ghidra_scripts/ProbeXenonFprParamIdSandbox_20261017_v1.java`:
1. Refused any program whose domain-file name did not contain `FPR_SANDBOX`; checked exact executable SHA, language, signatures, register storage, and context-saver native fingerprint.
2. Removed 13 incorrect saver formal arguments while retaining the genuine `int` in `r3:4` and unchanged return metadata; set saver signature source to `USER_DEFINED`.
3. Before scoped Parameter ID, the wrapper decompiled its saver call as a call with only the genuine last input (previously `param_14`).
4. `DecompilerParameterIdCmd` scoped to `0x800759f8` succeeded, recovering an ANALYSIS-source wrapper signature with one `int` parameter, no phantom FPR parameters, and default (noncustom) storage.

This isolates a call-graph/parameter-recovery problem, not an established Xenon ISA decode or global calling-convention defect. Do not globally remove all f1–f13 arguments; real FP parameters may exist elsewhere. Do not hand-edit the 2,377 affected functions.

## Completed follow-up experiment (v2)
`ghidra_scripts/ProbeXenonFprParamIdChainSandbox_20261017_v2.java`:
- Requires a **fresh disposable pre-v1** `FPR_SANDBOX` program, not the production database and not a sandbox already mutated by v1.
- Re-checks native bytes and exact baseline signatures before any mutation.
- Discovers a reverse call-reference path from wrapper `0x800759f8` to `NtClose` `0x80089eb0`; prints actual function addresses/names along that path.
- Corrects *only* the context-saver formal boundary, then runs Parameter ID on wrapper and each successive ancestor, one function at a time.
- Prints pre/post signatures and phantom counts at each hop, full-program before/after census, and verifies that existing USER_DEFINED function signatures were not altered.
- Preserves USER_DEFINED ancestor signatures rather than forcing changes.
- If no call path is available, aborts without mutation.

## v2 measured result (2026-10-17)
- Ghidra log: `ProbeXenonFprParamIdChainSandbox_20261017_v2.java` completed in disposable sandbox.
- Six callers found between wrapper 0x800759f8 and NtClose 0x80089eb0:
  1. `0x800778a8` FUN_800778a8: phantom FPR 13 -> 0; one `int` in `r3:4`.
  2. `0x80077b38` FUN_80077b38: phantom FPR 13 -> 0; one `int` in `r3:4`.
  3. `0x800755d0` KiDispatchDpcsAndPendingThreadObserved: phantom FPR 13 -> 0; re-inferred `uint ...(void)`, preserving existing return.
  4. `0x80075504` KiDispatchPendingInterruptLevelsObserved: Parameter ID returns true but **still has all 13** phantom FPR parameters, plus previously known `ulonglong requestedIrql` and `ulonglong pendingLevelsWord`. No correction justified yet.
  5. `0x8007018c` KfReleaseSpinLock: retains 13 phantom FPRs, but is `USER_DEFINED` and was intentionally not reanalyzed; non-FPR parameters are `uint * spinLock`, `ulonglong previousIrql`.
  6. `0x80089eb0` NtClose: Parameter ID returns true but still has 13 phantom FPRs.
- Saver 0x80075a38 and wrapper 0x800759f8 also went 13 -> 0 as in v1.
- Census (this sandbox database): functions with any phantom FPRs 2386 -> 2381; functions with all 13 2381 -> 2376; individual slots 31010 -> 30945 (65 removed).
- Existing `USER_DEFINED` signatures: 289 checked, **0 changed**.
- Result: partial propagation proved; cannot infer that every affected function can be repaired from a single saver boundary. Analyze 0x80075504 native FP instructions, all callees and calls before further mutations.

## Next experiment (prepared; not yet run)
- `ghidra_scripts/AuditXenonFprBoundary_20261017_v3.java` is read-only. Prefer running it on the **same post-v2 FPR_SANDBOX** while still available.
- It records signatures, native FP instruction counts, direct/unresolved call targets, inbound call references, and decompilations for `0x80075504`, `0x8007018c` and `0x80089eb0`, and dumps full C to a uniquely named text report.
- Upload the generated report along with the Ghidra script console output. Determine whether other contaminated callees or actual machine-state use explain why the 0x80075504 parameters survive; analyze `USER_DEFINED` KfReleaseSpinLock separately before deciding how to protect/clean it.
- Do **not** run another broad repair on the production database.

## Decision after v2
- If phantoms disappear through the chain, design an architecture-generic recognizer for context-state saver routines and a narrowly scoped analysis repair sequence. Treat runtime register saves as legitimate.
- If propagation stalls at a specific ancestor, inspect its other calls, explicit signature source and dataflow rather than changing Xenon's global ABI.
- Keep production signatures, unresolved parameter/storage types, and protected USER_DEFINED metadata unchanged until targeted sandbox validation supports a production-safe update.

## Verification
- v1 disposable-sandbox test: **PASS**, including scoped Parameter ID.
- v2 chain test: **PARTIAL PASS** (5 functions corrected, next ANALYSIS caller unchanged; 289 pre-existing USER_DEFINED signatures preserved).
- v3 read-only boundary audit: **NOT RUN** (script committed).
- Production mutation: **NONE** from these experiments.
- Extension rebuild: **NOT REQUIRED** for the present experiment.

## Required continuation policy (user instruction, 2026-10-17)
**Extension-first fix:** Once the root cause of the 13 ghost FPR arguments is established, inspect and fix the underlying `XEXLoaderWV` / Xenon processor extension's analysis, calling-convention, p-code, or parameter-modeling behavior **if an extension-side fix is technically possible**. Do not treat a one-off Ghidra database script as the final solution when the defect can be fixed at source. Validate any extension fix in a fresh sandbox against the kernel and preserved/known legitimate floating-point behavior. If root cause is actually Ghidra core or a database artifact, document why an extension fix is not appropriate and retain a minimal safe repair path.

**No manual metadata assumption:** The user has **not** manually applied function signatures, renames, types, labels or declarations quoted in conversation; they reasonably assumed that previously provided scripts applied them. Never state that metadata is in production without logs proving a script applied it. All **future applicable Ghidra scripts** must carry and, where safe, **apply** all verified relevant discoveries (with dependencies in order), not merely print metadata for manual entry. When a script is deliberately read-only, label it `READ_ONLY` and pair it with a separate guarded, runnable metadata applier; an audit alone never counts as metadata application. Preserve existing valid types and user-defined metadata; never overwrite unsupported signatures, infer changes beyond evidence, or globally strip FPR parameters.

**Verified in disposable sandbox only, still outstanding in production**:
- `0x80075a38`: `undefined __stdcall FUN_80075a38(int param_1)`; genuine arg at `r3:4`; 13 FPR ghosts removed in sandbox.
- `0x800759f8`: `undefined __stdcall FUN_800759f8(int param_1)`; recovered by scoped Parameter ID.
- `0x800778a8`: `undefined __stdcall FUN_800778a8(int param_1)`; recovered by scoped Parameter ID.
- `0x80077b38`: `undefined __stdcall FUN_80077b38(int param_1)`; recovered by scoped Parameter ID.
- `0x800755d0`: `uint __stdcall KiDispatchDpcsAndPendingThreadObserved(void)`; preserved existing return type.
- `0x80075504`: remains unresolved with 13 FPR ghosts; `ulonglong requestedIrql` and `ulonglong pendingLevelsWord` are retained known fields. Do not blindly replace signature.
- `0x8007018c`: `KfReleaseSpinLock` is `USER_DEFINED` with two known general-purpose parameters and 13 FPR ghosts. Do not overwrite intact metadata or edit signature without independent validation.
- `0x80089eb0`: `NtClose` still carries 13 ghosts. Do not rewrite until upstream defects are addressed.

**Current scripts:** v1/v2 were sandbox-mutating proof-of-concept only; v3 boundary audit is intentionally READ_ONLY. None of these proves the five cleaned signatures exist in production. Before treating this task as resolved, supply and run a guarded metadata-application script (or an extension repair plus a guarded metadata synchronization script) that applies **every verified discovery** and reports before/after results, including any additional metadata learned during later investigation.

## v3 boundary audit result and v4 experiment (2026-10-17)
- Received v3 read-only output from **post-v2** `xboxkrnl.exe.FPR_SANDBOX`. Native FP instructions: context saver 0x80075a38 has 33; wrapper 0x800759f8, dispatcher 0x800755d0, IRQL dispatch 0x80075504, KfReleaseSpinLock 0x8007018c, and NtClose 0x80089eb0 each have zero.
- At `0x80075504`, the direct calls are `0x800755d0` (now zero phantom FPR parameters) and `0x80078118` KiDeliverCurrentThreadKernelApcsObserved (still 13 phantom FPR arguments).
- `0x80078118` calls `KfReleaseSpinLock` `0x8007018c`; `0x8007018c` calls `0x80075504`. Thus `IRQL -> APC -> release -> IRQL` is a cyclic dependency. `KfReleaseSpinLock` has 302 distinct callers, causing wide contamination.
- NtClose 0x80089eb0 also calls phantom-contaminated `0x8008bd90`, `0x80089df0`, and `KfReleaseSpinLock`; fixing only one cycle may not clear NtClose.
- `xenon_64_32.cspec` in testing legitimately declares float input-register entries f1-f13. Do **not** remove them globally. The likely extension fix should recognize native floating-point context-saving/exception routines and keep those implicit register values from being inferred as formal function arguments. This is a hypothesis to test; no extension defect is claimed conclusively yet.
- Prepared and committed `ghidra_scripts/ProbeXenonFprApcCycleMetadataSandbox_20261017_v4.java`. Run on disposable FPR_SANDBOX, ideally the existing **post-v2** copy.
  - It checks exact SHA/language and saver's native fingerprint.
  - It **applies or verifies** the five earlier experimentally recovered signatures at 0x80075a38, 0x800759f8, 0x800778a8, 0x80077b38, and 0x800755d0, preserving existing returns, GP carriers, and user-defined metadata.
  - It verifies `0x80075504` has the earlier identified `requestedIrql`/`pendingLevelsWord` at r3/r4.
  - It requires that the full three-node call cycle is present.
  - **Sandbox experiment only:** removes exactly the 13 FPR ghost formals from the existing `USER_DEFINED` KfReleaseSpinLock signature (after checking native zero-FP, known call, and both GP parameters), preserving known `spinLock:uint *` and `previousIrql:ulonglong` and the return type. Runs scoped Parameter ID three passes on APC, IRQL and NtClose, emits call/metadata logs and full decompiled C to a report.
  - Other USER_DEFINED signatures are snapshotted and verified unchanged.
  - Do not transfer these experimental cycle corrections to production. Await output and cross-check for independent parameter sources and genuine FP calls.
- Extension source inspection: `XEXLoaderWV/data/languages/xenon_64_32.cspec` contains standard floating-point argument pentries and cannot safely be stripped. Inspect the extension's loader or analyzer pipeline for an automated, conservative context-saver recognition mechanism after validating v4.

## v4 cycle probe VERIFIED and v5 source isolation (2026-10-17)
- v4 ran on post-v2 `xboxkrnl.exe.FPR_SANDBOX`. Already verified metadata for `0x80075a38`, `0x800759f8`, `0x800778a8`, `0x80077b38`, and `0x800755d0` survived unchanged.
- Direct calls established `IRQL dispatcher 0x80075504 -> APC delivery 0x80078118 -> KfReleaseSpinLock 0x8007018c -> IRQL dispatcher 0x80075504`.
- Removing only the 13 phantom FPR formal parameters from `USER_DEFINED` KfReleaseSpinLock in sandbox, preserving `uint * spinLock`, `ulonglong previousIrql`, return type and explicit storage, allowed scoped Parameter ID to recover `KiDeliverCurrentThreadKernelApcsObserved(void)` and `KiDispatchPendingInterruptLevelsObserved(ulonglong requestedIrql, ulonglong pendingLevelsWord)` **on first pass**. Subsequent two passes stable; all 289 unrelated user-defined signatures unchanged.
- `NtClose` remains contaminated after three Parameter ID passes because it additionally calls `FUN_8008bd90@8008bd90` and `FUN_80089df0@80089df0`, each carrying 13 phantom FPR arguments; `KfReleaseSpinLock` path is now clean. No NtClose metadata patch justified yet.
- `ghidra_scripts/ProbeXenonFprNtCloseSourcesSandbox_20261017_v5.java` committed on `testing`. Run on **post-v4 FPR_SANDBOX**. It verifies or applies all eight sandbox-supported function contracts (five earlier, plus KfReleaseSpinLock, APC delivery, and IRQL dispatch), and audits the two remaining NtClose callees and contaminated descendants up to three calls deep without rewriting their unverified signatures. All operations are SHA/language and sandbox-domain guarded. It writes a uniquely named report with full decompilation for focal functions and adjacency logs for contaminated call trees.
- Extension diagnosis: standard f1-f13 float argument registers in `xenon_64_32.cspec` must remain. The defect manifests as false parameter inference from native context-saving flows and mutually recursive stale signatures, including USER_DEFINED signatures from earlier targeted metadata work. An extension-side conservative early context-saver signature model plus a safe metadata repair/propagation analyzer may be appropriate, but require v5 validation to isolate other roots. Do not apply a blanket ABI change.
- Production program remains untouched by the FPR sandbox experiments; no metadata application there is verified.

## v5 audit result and v6 object-close test (2026-10-17)
- v5 ran in the existing post-v4 disposable `FPR_SANDBOX`. Previously corrected eight functions were already clean; no additional function signatures were changed. Other 289 protected `USER_DEFINED` signatures remained unchanged.
- `NtClose@0x80089eb0` remains at 13 phantom FPR parameters because of two distinct paths:
  - `NtClose -> FUN_8008bd90@0x8008bd90 -> KeGetCurrentProcessType@0x80071a68` (`USER_DEFINED`, byte return, 13 phantom FPRs) `-> KeBugCheckEx@0x800716e8` (13 phantom FPRs). Bugcheck calls contaminated `HalSendSMCMessage@0x80067f48` and `DumpWriteDump@0x800b9580`.
  - `NtClose -> FUN_80089df0@0x80089df0 -> FUN_80089d40@0x80089d40`. The leaf `FUN_80089d40` has no native FP instructions and its direct callees `KfReleaseSpinLock` and `ObDereferenceObject` are already clean. Both `FUN_80089d40` and `FUN_80089df0` are `ANALYSIS` signatures with 13 phantom FPRs and two preserved GP parameters (`longlong@r3:8`, `ulonglong@r4:8`). `FUN_80089df0` has a `bctrl` indirect call, unlike the leaf.
- **v5 report-only finding**: `KeGetCurrentProcessType` contains a protected byte return type and user-defined signature. Do not erase its phantom FPR formals yet without confirming behavior and preserving its return. Do not globally remove arguments from `KeBugCheckEx` where real GP parameters exist.
- Committed `ghidra_scripts/ProbeXenonFprObjectCloseSandbox_20261017_v6.java` to `testing`. Run on **post-v5 disposable FPR_SANDBOX**, not production.
  - Carries the complete eight-verified-signature application/check procedure from v5, including the v4 APC/IRQL cycle corrections.
  - Checks `FUN_80089d40` native FP count, known GP arg types/storage, return type, lack of unresolved calls, and zero contaminated direct callees. If guards pass, run ordinary scoped Parameter ID on the leaf; if recovered as two-GP-parameter function, run scoped Parameter ID on its caller `FUN_80089df0` and then re-test `NtClose`. Do not manually force any of these provisional signatures.
  - Separately audits `KeGetCurrentProcessType` and `KeBugCheckEx` with full decompilation but **does not change them**.
  - Captures each outcome and verifies unrelated USER_DEFINED signatures remain unchanged. Report filename prefix is `XenonFprObjectCloseSandbox_20261017_v6_`.
- An extension-source fix remains the target after the recursive sources and their propagation are characterized; retain legitimate float ABI entries in `xenon_64_32.cspec`. Existing database metadata is not repaired by rebuilding the processor extension alone. Supply a guarded production synchronization script before closing.

## v6 object-close experiment: PASS, new ten-function metadata baseline (2026-10-17)
- v6 ran successfully on post-v5 disposable `FPR_SANDBOX`. Verified all eight previously recovered function contracts were present.
- `FUN_80089d40@0x80089d40`: 13 phantom FPR formals -> 0 by scoped Parameter ID; `undefined __stdcall FUN_80089d40(longlong param_1, ulonglong param_2)`. Return remains `undefined`, GP carriers remain `r3:8`/`r4:8`, source `ANALYSIS`, noncustom storage.
- `FUN_80089df0@0x80089df0`: same result, `undefined __stdcall FUN_80089df0(longlong param_1, ulonglong param_2)`. Its existing `bctrl` indirect call did not block recovery after the leaf was corrected.
- `NtClose@0x80089eb0` still retained all 13 phantom FPRs after scoped Parameter ID, because `FUN_8008bd90@0x8008bd90` remains contaminated.
- Remaining dependency: `NtClose -> FUN_8008bd90 -> KeGetCurrentProcessType@0x80071a68 -> KeBugCheckEx@0x800716e8`. `KeGetCurrentProcessType` has `USER_DEFINED` signature with 13 FPR ghost args, 0 native FP instructions, and a `byte` return stored at `r3:1`. `KeBugCheckEx` also carries 13 FPR ghosts but has legitimate GP arguments and complex callees; do not remove those blindly.
- All 289 unrelated `USER_DEFINED` signatures unchanged.
- **Metadata accountability**: now **ten** verified recovered signatures on the disposable sandbox: the original five context-saver/DPC chain functions, the spinlock/APC/IRQL cycle trio, and `FUN_80089d40`/`FUN_80089df0`. None has been proved applied to production.
- Committed `ghidra_scripts/ProbeXenonFprProcessBoundarySandbox_20261017_v7.java` to `testing`. Run against the **post-v6 FPR_SANDBOX**. It verifies/applies all ten established signatures, then **experimentally** removes only the 13 FPR ghosts from `USER_DEFINED` `KeGetCurrentProcessType`, retaining the exact existing `byte` return and `r3:1` return storage. It runs scoped Parameter ID on `FUN_8008bd90`, and on `NtClose` only if `NtClose` has no other contaminated direct callees. It preserves the `KeBugCheckEx` signature, all its GP parameters, and all unrelated USER_DEFINED signatures. The new process-type correction is **unverified** until v7 output.
- Report is uniquely named `XenonFprProcessBoundarySandbox_20261017_v7_*.txt`. Upload report after v7 run.
- **Extension-first goal unchanged**: investigate the extension-side parameter model / conservative early context-saver recognizer / analysis propagation and verify changes on a freshly imported database, not only an already corrected sandbox. Legitimate f1-f13 float arguments stay in the compiler spec.

## v7 result: NtClose recovered, architecture-scoped extension implementation prepared (2026-10-17)
- User correction: Xenon language `PowerPC:BE:64:XENON-32addr` and its `.cspec`/`.pspec` are separate from stock PPC/A2ALT. A Xenon language modification **cannot** rewrite stock PPC programs. Do not imply otherwise.
- Separate necessary distinction: the specific function **addresses, parameter types and bytes** discovered in retail kernel 17559 are *firmware-specific* and must not be applied to other Xbox 360 binaries merely because they select Xenon.
- v7 success on post-v6 `FPR_SANDBOX`: removing just 13 FPR ghosts from `USER_DEFINED` `KeGetCurrentProcessType@80071a68` (preserved `byte` return and `r3:1`) let Parameter ID recover `FUN_8008bd90(void)`, then `NtClose(ulonglong param_1)` while preserving `undefined8` return and `r3:8` return/argument storage. `KeBugCheckEx@800716e8` and its 13 FPR ghosts **remain untouched**, demonstrating that a proper boundary can stop propagation.
- Total recovered signatures from v1-v7 = **13**: saver 80075a38, wrapper 800759f8, caller 800778a8, caller 80077b38, DPC 800755d0, spinlock 8007018c, APC 80078118, IRQL 80075504, object-close leaf 80089d40, helper 80089df0, process-type query 80071a68, process-type wrapper 8008bd90, NtClose 80089eb0. User's **production** database has not been updated by sandbox experiments.
- Added extension analyzer `XEXLoaderWV/src/main/java/xexloaderwv/Xenon17559FprBoundaryAnalyzer.java` on `testing`. It is opt-in one-shot, explicitly for Xenon language + validated retail 17559 PE hashes + checked native saver fingerprint and direct-call topology. It copies the **13 verified signatures and dependency-ordered Parameter ID** chain into the extension itself, preserving GP parameters, return types/storage, names, unrelated USER_DEFINED metadata, and f1-f13 legality. It uses an inner database transaction with rollback on guard/postcondition failure and logs exact outcomes. This is a targeted repair implemented inside the extension, **not yet a generalized architecture-level fix for all Xenon context savers**.
- Need **build and run verification on Ghidra**, which is unavailable in current container. Do not claim compile/installation/production success. Test analyzer on a disposable pre-v1 retail kernel copy, with one-shot execution after ordinary analysis. Compare its 13 signatures, zero phantom parameters and unrelated USER_DEFINED protection. If it passes, consider the production one-shot application with a backup. If it fails, repair the extension implementation first.
- Next general extension task: use the native context-saver recognition evidence to design a processor-wide but Xenon-scoped analysis rule, independent of fixed 17559 addresses, while maintaining legitimate float calls. Keep the tested firmware-specific boundary analyzer as a regression oracle and database cleanup option.

## Root-cause-only direction (user decision 2026-10-17)
- **No band-aids.** User rejected any firmware-specific signature correction analyzer as the extension fix. We must identify and correct the mechanism that causes false `f1..f13` parameter inference, not add post-analysis rewriting of the resulting signatures.
- Deleted `XEXLoaderWV/src/main/java/xexloaderwv/Xenon17559FprBoundaryAnalyzer.java` from `testing` (commit `169f3d0903a9cbb84192e0a8083e543e6ca3674d`). Do not resurrect/enable it or substitute an equivalent "repair analyzer" without a new explicit decision.
- Important exact source comparison: `XEXLoaderWV/data/languages/xenon_64_32.cspec` is byte-for-byte identical to upstream NSA Ghidra `Ghidra/Processors/PowerPC/data/languages/ppc_64_32.cspec` currently on upstream master. Therefore no accidental Xenon-only compiler-spec edit caused the phenomenon. It does **not** prove stock PPC ABI accurately models the retail 360 toolchain.
- Ghidra official compiler-spec documentation states that parameter recovery inverts the compiler's register parameter-allocation list using liveness. Because `f1-f13` are declared floating parameter resources and native saver's 33 FP instructions consume CPU FPR contents to write context memory, it is plausible that real CPU-state inputs are promoted as formal function arguments and propagated to callers. **Hypothesis**, not root proven yet.
- Xenon language is its own architecture variant: `.cspec`/`.pspec`/SLEIGH edits affect only programs using Xenon, not stock PowerPC. Preserve legitimate floating argument support. Address/firmware gates apply only to *metadata*, not a general ISA/ABI fix.
- Committed `ghidra_scripts/AuditXenonFprRootPcode_20261017_v1.java` at `f9f4a0e5110353abd65fbd6277755f6570effb4e`. It is read-only, requires verified source SHA, Xenon language and saver's native fingerprint, and dumps instruction-level p-code and call targets for saver/wrapper and 9 dependent functions. Report prefix `XenonFprRootPcode_20261017_v1_`. Run against existing post-v7 sandbox **or** source-matching production because no database mutations.
- Next: use raw p-code to verify whether native FPR saves are represented correctly as memory writes (SLEIGH question) and where bogus arguments first enter decompiler propagation (ABI/inference question). Only then implement a **root-level semantic or ABI fix**, preferably generalized beyond exact function addresses, validated on a fresh Xenon kernel analysis and legitimate FP call samples. Avoid refactoring signatures in existing database until root is correct.
- Retain previously experimentally confirmed 13 function signatures as regression expectations and potential production metadata only **after** the root change succeeds. The sandbox metadata scripts are not the accepted solution.

## v1 raw-p-code audit: root-level parameter-inference diagnosis (2026-10-18)
- User ran `AuditXenonFprRootPcode_20261017_v1.java` successfully in the post-v7 `FPR_SANDBOX`, source kernel and saver fingerprint verified. No database mutation.
- `0x80075a38` is a pure FPR/FPSCR context snapshot: `stfd f0,0x988(r3)`; `mffs f0`; `stfd f1..f31,0x990..0xa80(r3)`; `stfd f0,0x980(r3)`; `blr`. All `stfd` native instructions translate correctly to p-code `INT_ADD r3+offset; STORE(...,fN)`. This function has 35 native instructions, 33 FP instructions, no calls. It consumes the old FPR file + FPSCR values and writes the 32-register state into the pointed structure.
- The native p-code for `bl 0x80075a38` at `0x80075a08` is ordinary `CALL`, preceded by LR update; nothing faulty at call instruction-level semantics.
- The exact error mechanism is now narrowed to **Ghidra core decompiler's input-prototype recovery**, not misdecoded Xenon FPR instruction semantics: all 32 FPRs are live-in machine state, but `f1..f13` match the ABI register argument candidates while `f0,f14..f31` do not. It therefore produces exactly 13 spurious formal parameters despite a state-snapshot routine that formally takes only its GPR context pointer.
- Verified against current upstream Ghidra C++ source `Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc`: `ActionInputPrototype::apply(Funcdata&)` enumerates `Varnode::input`, uses `data.getFuncProto().possibleInputParam(vn->getAddr(),vn->getSize())`, registers those inputs, marks candidates active when they have descendants, calls `resolveModel` / `deriveInputMap`, then `updateInputTypes`. FPR live-in inputs with `STORE` descendants pass those checks.
- Verified upstream Ghidra C++ `fspec.cc`: `ParamListStandard::fillinMap(ParamActive*)` builds/splits parameter candidate trial groups, applies no-use and inactive-chain logic, then marks active candidates used. `xenon_64_32.cspec` is byte-for-byte identical to stock PPC `ppc_64_32.cspec` and legitimately declares `f1..f13` float arguments.
- **Critical distinction:** The raw p-code describes the CPU state **correctly**. Neither `stfd`, SLEIGH register definitions, nor the physical calling-convention ABI can simply be altered without misrepresenting machine semantics or breaking genuine float functions. Correcting this *cause* requires treating state-snapshot live-ins differently from C-style formal arguments during prototype recovery, based on additional semantics/evidence, or specifying a truly distinct low-level function ABI where appropriate. Ghidra's core `ActionInputPrototype` is outside the extension's ordinary `.cspec/.pspec/SLEIGH` machinery.
- **Do not add any post-hoc signature repair analyzers or change f1-f13 entries.** The user rejected band-aids. Deleted `Xenon17559FprBoundaryAnalyzer` stays deleted. No new architecture fix was made yet.
- Follow-up for root fix: construct a minimal generalizable recognition criterion for a full FPR bank snapshot (not dependent on kernel hash, exact addresses or names), implement at **parameter recovery** rather than correcting persisted signatures. Test it against (1) the saver and fresh call-chain analysis and (2) real native floating-point argument passing. If extension interfaces cannot express this behavior, scope a patch to Ghidra's native decompiler rather than faking p-code in the extension. Verify from a new import before claiming success. Run an unbiased test that a normal function passing a double in `f1` retains its argument.
- Note separately that audit lists `b` at `0x800701b4` and `0x80071aa0` as flows of call type due to flow override but p-code shows `BRANCH`, not native `CALL`. This is control-flow nuance and not the source of the 13 FPR phantom inputs.
