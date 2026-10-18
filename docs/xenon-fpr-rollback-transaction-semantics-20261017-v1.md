# Ghidra FPR save prototype experiment: nested transaction semantics and recovery (2026-10-17)

## Reported v3 result

The user ran `ProbeXenonFprSaveSignatureRollback_20261017_v3.java` against original retail 17559 `xboxkrnl.exe`. The native saver at `0x80075A38` has 14 parameters (f1..f13 as `undefined8`, and `int` in `r3:4`), custom storage true, signatureSource ANALYSIS, return `undefined`/<UNASSIGNED>. Its wrapper `0x800759F8` likewise has 14 parameters.

Temporary saver modification:
```text
undefined __stdcall FUN_80075a38(int param_1)
```
was verified to preserve the physical `r3:4` carrier and return metadata. Re-decompiling the wrapper changed the apparent call from 14 parameters to only `FUN_80075a38(param_14)`. This is direct causal evidence that the 13 bogus arguments in the wrapper *call expression* originate in the saver's prototype.

## Why `WARNING_ROLLBACK_METADATA_MISMATCH` printed

Ghidra's `GhidraScript.executeNormal()` calls `start()` on entry and `end(true)` in a `finally` on exit. `FlatProgramAPI.start()` begins a Program transaction, making the v3 probe's explicit `startTransaction()` a **nested transaction**. `DomainObjectDBTransaction.endEntry(..., false)` marks the combined transaction ABORTED, but while the *outer script transaction is still active* the `getStatus()` is `NOT_DONE_BUT_ABORTED`. Actual DB rollback occurs only when the final outer transaction ends. `DomainObjectTransactionManager.endTransaction` then executes `dbh.endTransaction(..., false)`, invalidates caches and restores state.

The v3 script checked rollback **inside `run()`**, before the outer transaction ended. It therefore still saw the temporarily changed 1-argument signature and warned falsely. **The output cannot establish that rollback failed.** Because the script finished normally and the inner transaction requested rollback, standard Ghidra code strongly predicts the DB was restored *after the script finished*. A subsequent new script invocation is required to verify it.

## Read-only post-script verification

`ghidra_scripts/VerifyXenonFprSaverPostRollback_20261017_v1.java` is a new independent read-only verification script, executed **after** v3 has returned to the Ghidra interface. It checks retail kernel identity, the current saved saver and wrapper signatures, every original FPR/r3 carrier, return, signatureSource and custom storage. If all match the original log, it prints `ROLLBACK_COMPLETE`. If the 1-parameter temporary prototype persisted, it prints `ROLLBACK_INCOMPLETE`. The script makes no changes and needs no extension rebuild.

Do NOT apply a guessed restoration or use Undo until this verification establishes the current state. `Undo` could revert unrelated recent user work.

## Next processor-extension engineering

The temporary context-saver signature change affected its wrapper call expression immediately, without any SLEIGH or compiler-spec rebuild. This establishes a prototype-analysis/call-boundary issue, **not** that removing 13 FPR regs from `xenon_64_32.cspec` is safe. Accurate automatic handling will require recognizing native CPU-register-state saving, selecting a safe prototype model, and ensuring a fix to the root can propagate through existing archived USER_DEFINED signatures. Experimental metadata writes should be confined to disposable programs; use separate-script verification for Ghidra transaction rollbacks.
