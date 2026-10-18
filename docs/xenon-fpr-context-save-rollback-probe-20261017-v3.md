# Xenon context-save FPR rollback experiment, v3 (2026-10-17)

## Live result and diagnosis

The user ran v2 in Ghidra 12.1.3 on the 17559 kernel. It confirmed `0x80075A38` is a native function, had its exact fingerprint, and was already `customStorage=true` with 14 formal parameters: thirteen DEFAULT `undefined8` inputs in f1:8 through f13:8 and one DEFAULT `int` in r3:4. Return was `undefined` with `<UNASSIGNED>` storage. The wrapper `0x800759F8` also held the same 14-parameter custom-storage signature. Baseline decompilation visibly passed all 14 parameters into `FUN_80075a38`.

The v2 experiment then threw:

```text
Temporary probe altered real argument or return; rollback
```

This originated in a compound guard at line 155, **not** in the Ghidra decompiler. The experimental edits had been made and the enclosing `finally` rolled back its Program transaction. The guard compared the **entire `paramMeta` string** of the original `param_14` against the sole surviving parameter. Ghidra can rename default arguments upon removing earlier arguments (e.g. `param_14` becoming `param_1`). A name change by itself is not evidence that the actual `int` r3:4 carrier was damaged. The output cannot establish whether the name, return storage or actual datatype changed, because v2 did not print temporary metadata before its refusal.

## v3 refinement

`ghidra_scripts/ProbeXenonFprSaveSignatureRollback_20261017_v3.java` is the versioned successor and the only current script for this experiment. It retains the SHA/language, native-byte and parameter-storage guards and the unconditional rollback transaction.

- Its **real-argument invariant is independent of default parameter spelling**: it checks the original r3:4 carrier, datatype, and auto-parameter status rather than comparing `param_14` to the sole remaining `param_1`.
- It prints `TEMPORARY_REAL_ARG`, `REAL_ARG_BEFORE`, `TEMPORARY_RETURN` and separate `TEMP_VALIDATION` booleans *before* deciding whether to decompile.
- If storage, type, argument count or return is altered, it stops the experiment and rolls back as before, with concrete evidence of the mismatch. If only the default name is renumbered, the experiment proceeds.
- It catches experiment failures so it can verify rollback afterward rather than terminating immediately at the temporary guard. Failed/partial decompilations report inconclusive, not success.
- It rechecks complete original parameter metadata, signature and return storage after rollback. It changes no firmware bytes, datatype declarations, or unrelated function metadata.

## Next action

Run v3 in the existing retail kernel Ghidra database, without rebuilding the extension. We need `TEMP_VALIDATION`, `WRAPPER_CALL_AFTER`, `DIFFERENT_CALL_TEXT`, and `ROLLBACK_VERIFIED` to decide whether implicit FPR machine-state inputs truly propagate from the context saver into its wrapper.

Even if successful, this proves only the immediate call-boundary effect. The archived/native callgraph showed 2,376 of 2,377 all-FPR-signature functions reachable from this context-saver, but does **not** prove that a single analyzer change automatically repairs already stored signatures throughout the corpus. A disposable-program ParamID experiment is needed before we implement a globally enabled rule.
