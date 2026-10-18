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
- v2 chain test: **PARTIAL PASS** (5 functions corrected, next ANALYSIS caller unchanged; 289 pre-existing USER_DEFINED signatures preserved).\n- v3 read-only boundary audit: **NOT RUN** (script committed).
- Production mutation: **NONE** from these experiments.
- Extension rebuild: **NOT REQUIRED** for the present experiment.
