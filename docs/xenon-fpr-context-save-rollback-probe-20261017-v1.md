# Temporary Xenon context-saver ABI-prototype experiment (2026-10-17)

This work is intentionally **pre-build**: no Xenon SLEIGH, compiler specification, XEX importer, or installed Ghidra extension has been modified.

## Evidence

The 2026-10-17 live report `XenonFprContextAudit_1584235300417178772.tsv` contains 4,422 non-thunk native functions. The single 32-FPR saver `0x80075A38` appears upstream of 2,376/2,377 functions with 13 undefined FPR inputs. Most of those functions contain no native floating-point operations. The apparent outlier `0x801351B0` tail-branches via a likely thunk `0x800F7000` to `0x800EEEE0`, which the live graph already marks as reachable. The v2 census omitted thunks; v3 handles them as graph connectors and prints a targeted explanation.

At `0x80075A38`, original native instruction bytes (35 PowerPC instructions; SHA-256 `99af6e7e062400eeb32f418cec412f74e4d9acb28e3b1e5afc1e2de10ccd0f1b`) unconditionally store FPR0..FPR31 into the context record. Its saved Ghidra prototype shows 13 implicit undefined8 machine-state FPR inputs and one real `int` input with storage `r3:4`. The direct wrapper at `0x800759F8` has no native FP instructions yet its decompiled call passes all 13 FPR values onward. This is evidence of inferred register-state liveness crossing a call boundary, not a reason to alter the global floating-point calling convention.

## Disposable transaction probe

`ghidra_scripts/ProbeXenonFprSaveSignatureRollback_20261017_v1.java` checks the exact kernel SHA, Xenon language, native saver SHA, 13 FPR slot types/storage, and preserved 14th r3:4 parameter. It captures the Ghidra decompiled call text for the immediate wrapper, begins a Program transaction, enables custom argument storage on the saver, deletes *only* the f1..f13 formal parameters, and marks the temporary signature USER_DEFINED. It then decompiles the same wrapper with cache flushed, records the changed call text, and **rolls back** the transaction unconditionally. It finally rechecks that the original signature was restored. No archive bytes or native function bodies are touched.

This tests whether a corrected boundary prototype changes a direct caller's decompilation. It does **not** validate correct processor emulation or automatically remove propagated arguments from thousands of saved signatures. If the probe reports no change, do not assume the hypothesis is falsified: the wrapper's persisted parameter signature or decompiler cache may mask the effect. If it reports a change, that is evidence for a controlled follow-up in a disposable database with selective ParamID and signature reanalysis. It is not permission to bulk reset user-defined function contracts.

## Further work

63 affected saved signatures are `USER_DEFINED`; their existing storage cannot be assumed to repair automatically. If the rollback probe demonstrates an immediate effect, the next experimental step is to preserve full previous signatures/storage, intervene in a separately backed-up kernel Program, and run scoped dependency reanalysis to measure propagation. Any automatic extension analyzer must recognize FP-context capture by instruction behavior rather than hardcoded firmware addresses, and must be disabled by default until verified on at least another firmware module.
