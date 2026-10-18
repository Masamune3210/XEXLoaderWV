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

## Next experiment (prepared; not yet run)
`ghidra_scripts/ProbeXenonFprParamIdChainSandbox_20261017_v2.java`:
- Requires a **fresh disposable pre-v1** `FPR_SANDBOX` program, not the production database and not a sandbox already mutated by v1.
- Re-checks native bytes and exact baseline signatures before any mutation.
- Discovers a reverse call-reference path from wrapper `0x800759f8` to `NtClose` `0x80089eb0`; prints actual function addresses/names along that path.
- Corrects *only* the context-saver formal boundary, then runs Parameter ID on wrapper and each successive ancestor, one function at a time.
- Prints pre/post signatures and phantom counts at each hop, full-program before/after census, and verifies that existing USER_DEFINED function signatures were not altered.
- Preserves USER_DEFINED ancestor signatures rather than forcing changes.
- If no call path is available, aborts without mutation.

## Decision after v2
- If phantoms disappear through the chain, design an architecture-generic recognizer for context-state saver routines and a narrowly scoped analysis repair sequence. Treat runtime register saves as legitimate.
- If propagation stalls at a specific ancestor, inspect its other calls, explicit signature source and dataflow rather than changing Xenon's global ABI.
- Keep production signatures, unresolved parameter/storage types, and protected USER_DEFINED metadata unchanged until targeted sandbox validation supports a production-safe update.

## Verification
- v1 disposable-sandbox test: **PASS**, including scoped Parameter ID.
- v2 chain test: **NOT RUN** (await Ghidra output).
- Production mutation: **NONE** from these experiments.
- Extension rebuild: **NOT REQUIRED** for the present experiment.
