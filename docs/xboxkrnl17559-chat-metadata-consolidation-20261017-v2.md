# Consolidated retail 17559 kernel metadata, 2026-10-17 v2

## Purpose

A single directly runnable, repeat-safe Ghidra Java script verifies and applies **the concrete kernel metadata discussed in the XAM-readiness/CR0/FPR conversation**. It is intentionally narrower than re-running every historical kernel research script or rewriting all kernel/XAM externals.

Script: \`ghidra_scripts/ApplyXboxKrnl17559ChatMetadata_20261017_v2.java\` (open retail \`xboxkrnl.exe\`, PowerPC:BE:64:XENON-32addr, executable SHA-256 \`e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8\`).

### Metadata application inventory

1. Verify the 5 known CR0 \`rlwinm.\` and immediately following branch words, and confirm each has 32-bit zero-comparison p-code semantics. Preserve the 4 existing \`XenonCR0SF0_20261017\` categorized NOTE bookmarks or add any that are missing. The mathematical witnesses are not asserted to be reachable runtime inputs; no machine instruction changes.
2. Verify the exact 116-byte native hash \`aa65bd4ee6b78e0ce6ccdad8e8dd90235f998103e9189d07166f5ac7f6827381\`. Ensure the existing \`MiMakePhysicalProtectionMask\` identity at \`0x80080CB0\` and its \`uint protectionFlags\`, \`uint * outPhysicalMask\` parameter names. **Preserve the unknown \`undefined8\` return, parameters and storage.**
3. Independently verify the 35 native instruction bytes of the context saver \`0x80075A38\`, SHA-256 \`99af6e7e062400eeb32f418cec412f74e4d9acb28e3b1e5afc1e2de10ccd0f1b\`. If still generically named, assign the generalized function name \`SaveFloatingPointRegisterState\` without changing any of the current 14 parameters. Create datatype dependency first:

\`\`\`text
Structure: XenonFloatingPointSaveAreaView
Size: 0x108
Category: /Xbox360/Xenon
0x00 uint64_t fpscrRaw
0x08 uint64_t[32] fprBits
\`\`\`

The corresponding location is **at runtime \`r3 + 0x980\`**, not an absolute kernel memory address. The native \`stfd\` stores \`f0\` at context+0x988, \`f1\` at +0x990, through \`f31\` at +0xA80. \`mffs\` stores the FPSCR encoding at +0x980 after that. No address-range data redeclaration is appropriate. The structure's physical carrier is a 64-bit unsigned integer; Ghidra uses \`ulonglong\` for this equivalent native 8-byte representation. The script adds repeatable comments to the saver and its exact-byte-verified wrapper at \`0x800759F8\`, respecting all existing comments.
4. Verify the 5 original-byte SHA-qualified XAM-directed *void return* candidates, already proposed in \`RefineXboxKrnlXamBoundaryReturns_20261017_v1.java\`: \`KeEnterCriticalRegion\`, \`KeLeaveCriticalRegion\`, \`ObDereferenceObject\`, \`KfLowerIrql\`, and \`KeReleaseSpinLockFromRaisedIrql\`. Apply only when the current signature is still auto-inferred, lacks custom parameter storage, has the exact param count and has an undefined return. Already-correct \`void\` signatures are left alone. If custom storage or a user-defined signature is present, **WITHHOLD**, not silently adjust parameters/returns, because those declarations may already carry unresolved register storage.
5. Audit that the 15 preexisting named/saved Ghidra function contracts reported by the successful CR0 script still have the same entrypoint, return display name, parameter count and signature source. Never regenerate these from guesses. \`PRESERVED_DIFFERENT\` requires review, not automatic repair.

## Deliberately excluded from automatic application

- **No deletion of f1–f13 formal parameters from \`0x80075A38\` or any of the 2,377 affected functions.** The experiment proved that an altered saver prototype changes the wrapper's displayed call, but the root ABI fix has not been validated across the corpus. The separate post-script audit reported \`ROLLBACK_COMPLETE\`, confirming the original 14-parameter saver signature was restored and retained.
- No global compiler-spec edit that removes legitimate floating-point argument resources.
- No mass overwrite of already \`USER_DEFINED\` signatures, no creation of unnamed kernel function \`KiApcNormalRoutineNop\`, and no guessed XAM external prototypes. The extension's linked-import signature analyzer is a separate concern.
- No automatic promotion of additional kernel names from call-path speculation. Preserved call graph names are audited by their existing Ghidra metadata, not recreated from archive heuristics.

## Runtime behavior

Run in **the current kernel**, not XAM. Set \`APPLY=false\` for audit-only. Each change is guarded by exact 17559 executable SHA-256; function names are changed only if still \`FUN_<address>\`; existing data is not overwritten. Missing or changed evidence prints \`WITHHELD_*\`. Successful reruns should print \`ALREADY_*\` and \`applied=0\`. If a previously proven item is unexpectedly \`WITHHELD\`, investigate rather than weakening guards.

The script was prepared from actual prior runtime logs, saved scripts, and native ASM; it has **not** been executed in the user's live Ghidra 12.1.3 installation. Its modifications, unlike the rollback-only experiment, are intended to persist after the script completes. Use a Ghidra Program backup/checkpoint before the first application.

## v2 compilation correction

The v1 consolidation script did not compile in Ghidra at line 280 because the FPR-saver loop declared `for(int i=0;int<13 && intact;i++)`. v2 corrects the condition to `i<13` and updates the Java class name to match the new filename. No metadata decisions, native fingerprint guards, signature edits, datatype definitions, or bookmark logic were changed. The broken v1 script is removed from the active `ghidra_scripts` directory to avoid accidental reuse. Actual compilation/execution in Ghidra 12.1.3 still needs user verification.
