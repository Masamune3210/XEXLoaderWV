# Native Xenon context-saver / ParamID cascade: clone-only test (2026-10-17)

## Verified from user's Ghidra runs

- `ProbeXenonFprSaveSignatureRollback_20261017_v3.java` showed that changing the saved context-saver prototype from 14 parameters to the single existing `int` in `r3:4` caused the immediate wrapper at `0x800759F8` to call the saver with **one** parameter instead of 14, preserving existing return type and storage.
- `VerifyXenonFprSaverPostRollback_20261017_v1.java` subsequently printed **`ROLLBACK_COMPLETE`**: the production kernel returned to its original 14-parameter `ANALYSIS` signature, custom FPR storage, r3:4 carrier and unknown return. No recovery or restoration is needed.
- Ghidra's `GhidraScript.executeNormal` creates an *outer* transaction; the rollback probe's nested `endTransaction(false)` was not finalized until after its `run()` returned. The old warning inside `run()` was premature.

## ParamID root-cause source examination

Ghidra's `DecompilerFunctionAnalyzer` runs at `AnalysisPriority.DATA_TYPE_PROPOGATION.after().after()`, uses `DecompilerParameterIdCmd` and is disabled by default for large non-PE inputs. `DecompilerParameterIdCmd` constructs an `AcyclicCallGraphBuilder`, resets eligible `ANALYSIS` signature sources to `DEFAULT`, decompiles functions bottom-up in the dependency graph, and commits inferred parameters as `ANALYSIS`. It does **not** clear `USER_DEFINED` signatures. This explains the call-graph cascade from the FPR save function and why merely changing the source of existing `ANALYSIS` signatures cannot automatically repair 63 already-affected `USER_DEFINED` declarations.

Native verification from the supplied 2026-10-15 archive: across **4,404** archived function ASM bodies, only `0x80075A38` stores at least 14 distinct floating-point registers through one base register (r3). It saves **32** FPRs (f0..f31), mostly in contiguous 8-byte slots, and transfers FPSCR using `mffs f0`. This is a strong behavior-based machine-state capture fingerprint. It does not prove all possible firmware variants have the same layout, nor that all register capture code uses this instruction pattern. No other native function in that archive meets the count threshold.

The exact Ghidra 12.1.3 source implementation may vary from upstream master viewed for code guidance. Actual prior script behavior on the installed user's 12.1.3 is separately verified.

## Next decisive experiment: disposable program ONLY

1. **In the Ghidra project browser, duplicate the kernel Program** rather than modifying the real `/System Firmware/xboxkrnl.exe`. Name the copied Project file so it contains `FPR_SANDBOX` (e.g. `xboxkrnl_FPR_SANDBOX`). Open this copied Program. Its executable SHA remains the same.
2. Execute `ghidra_scripts/ProbeXenonFprParamIdSandbox_20261017_v1.java` on the copy. It refuses to run if the currently opened Project file name lacks `FPR_SANDBOX`, if the executable SHA/language/native fingerprint differs, or if saved source metadata does not match the verified baseline.
3. The script **deliberately modifies the disposable copy**, first forcing the saver to retain only its already-established r3:4 argument, then executing Ghidra's actual `DecompilerParameterIdCmd` **only for wrapper entry `0x800759F8`**. Its dependency graph is bounded by the one-entry AddressSet, so it does not reanalyze unrelated kernel functions. It compares the wrapper's FPR formal count and printed call expression before/after.
4. Preserve the console output, then discard the sandbox copy. Do not transfer these provisional metadata changes to the production kernel.

**Interpretation:** `WRAPPER_PHANTOM_FPR_REMOVED_BY_SCOPED_PARAMID` proves the saved ANALYSIS contract can recover from the corrected root in a controlled live Ghidra pass. If it retains all 13 FPR slots, examine ParamID's actual output and original source rather than forcing a global spec change.

## Extension design after validation

The eventual fix should be generic to the Xenon language, scan for context-save behavior rather than firmware-specific function addresses or names, and run after function discovery but before ParamID's data-type propagation. The rule must not remove FPR registers from the normal ABI, alter source instructions, or overwrite user-defined function contracts. A freshly imported program and a disposable existing Program should both be checked before enabling it automatically across the firmware corpus.

Keep this experiment separate from the other confirmed Ghidra limitation: correctly linked kernel import function names do not by themselves import complete external prototypes into XAM.
