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
