# XAM 17559 kernel dependency readiness, contract results (2026-10-17 v2)

## Inputs
- Ghidra read-only output `Xam17559KernelContractAudit_15819523401038207526.tsv`, 443 rows, 13 columns.
- Source `xam.xex`, SHA-256 `78b3dbd8ae866f4258f5444205486ea9f8451afaa30f469c875dcf345f828467`; retail `xboxkrnl.exe`, SHA-256 `e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8`.
- Native source: 2026-10-15 complete workspace, extracted per-function ASM/C. The saved October 17 kernel Program is more recent; every proposed write is gated by whole-function original-byte SHA and current Ghidra structure.
- XAM's link to `/System Firmware/xboxkrnl.exe` is valid. Import names being correct **does not** imply imported prototypes have been propagated.

## Actual counts (audit report, not estimated)
| Classification | Functions | Branch references |
|---|---:|---:|
| OPAQUE_TYPES | 375 | 4,791 |
| TYPED_USER_DEFINED | 36 | 2,127 |
| TYPED_NON_USER_DEFINED | 23 | 1,960 |
| REVIEW_ZERO_PARAMETER_SIGNATURE | 8 | 8 |
| KERNEL_ENTRY_UNRESOLVED | 1 | 1 |
| **Total** | **443** | **8,887** |

- XAM's external function prototype is `undefined Name()` for **437/443** imports. Six CRT formatting declarations are already typed on both sides: `_snprintf`, `sprintf`, `_swprintf`, `_vsnprintf`, `vsprintf`, `_vswprintf`.
- **242/443** kernel contracts carry at least 13 `undefined8` parameters, frequently preserved FPR registers `f1–f13`; these affect **2,479** branch references and are not evidence of 13 real semantic arguments. Never strip or reassign them blindly or bulk-copy these incomplete signatures into XAM.
- **281** kernel return types are `undefined*`. Void-return contracts require native verification before change.
- `KiApcNormalRoutineNop` is the single unresolved kernel function name, referenced once. Do not invent an entrypoint.
- Eight 0-parameter signatures deserve review, most audio getter routines. A zero-argument function can legitimately return a value; these are not proven errors.
- Five named imports have no direct `bl`/`b` calls in the exported cross-reference set; address-taking uses may still matter.

## First verified XAM-directed kernel return repairs
The original native entry/body behavior supports the following **return type only** corrections. The old `undefined` return is not evidence that callers consume a meaningful result. All existing parameter storage and types are retained.

```text
0x800718E0
void KeEnterCriticalRegion(void)

0x800718F8
void KeLeaveCriticalRegion(void)

0x8008B928
void ObDereferenceObject(longlong param_1)

0x800750F4
void KfLowerIrql(undefined8 previousIrql)

0x8007020C
void KeReleaseSpinLockFromRaisedIrql(uint * spinLock)
```

- `KeEnterCriticalRegion`: five instructions, increments kernel-thread APC disable depth negatively; native SHA `b804cbd2243abdb5c607944ce5de1595e6b9267943aef85e67b893460a439e39`; 460 XAM branch references.
- `KeLeaveCriticalRegion`: updates depth; tail-branches to a separately analyzed side-effect-only dispatch helper when pending work exists; SHA `b87c0e3f2713fc1a71ec6c77394d08a42d8a807cdbc996f53fc5e30645a1afae`; 496 XAM branch references.
- `ObDereferenceObject`: decrements object reference count and conditionally invokes deletion callbacks; SHA `31379f86f1061492a6be17a9bca7b70f3093e47a5b02bc012dfad87c253a8e34`; 126 branch references.
- `KfLowerIrql`: updates low-byte CPU IRQL and tail-dispatches pending levels when required; SHA `c1c3c1223ae0cdf60695c9999e6e12877f48b20dba543bc9ee702b6641214a25`; 116 references.
- `KeReleaseSpinLockFromRaisedIrql`: sync + clears lock word, no result computation; SHA `8528b6bfa38c3cc6a7c4320b6291ef768e36ec4d8757de3f4a858dfcb79f03e5`; 112 references.
- Together **1,310** XAM branch references, **not** 1,327. These are counts of xrefs, not distinct runtime calls.

Script `ghidra_scripts/RefineXboxKrnlXamBoundaryReturns_20261017_v1.java` checks SHA, function entry/name, all four-byte instruction units, parameter count, current undefined return, and absence of custom storage. It applies only `void` return changes, and skips mismatches or already-correct functions. Run it against **kernel**, not XAM. No current Program write has been executed in the assistant environment. Source APIs are checked, full Ghidra runtime execution is outstanding.

## What still blocks good XAM decompilation
1. The majority of XAM **external Function** declarations are still `undefined Name()` even if kernel types are established. Merely linking external programs does not automatically clone those types.
2. High-impact incomplete kernel contracts include `NtClose` (201 calls and 13 opaque FPR slots), `ExGetXConfigSetting` (157, many unresolved slots), `KeGetCurrentProcessType` (149, 13 slots), `KeWaitForSingleObject` (83, 14 opaque slots), and `NtOpenFile` / `NtCreateFile` / `NtReadFile` / `NtWriteFile`. These need signature/storage refinement based on real kernel AND XAM call sites, not guessed prototypes.
3. The eight zero-argument functions and one missing function should not delay the higher-use work.

## Next steps
- Run the exact-guard kernel void-return refinements, report their results.
- Build a conservative XAM external-signature propagation pass, restricted to native-verified, known ABI contracts; preserve unresolved registers, datatypes, pointer carrier widths, and independently defined XAM prototypes. Do not bulk-copy incomplete kernel function signatures.
- Then recheck the top unresolved XAM callers and refine the kernel functions they actually depend on.
- Once critical and widely used import contracts are actionable within XAM, start internal XAM service/initialization analysis.

## Decision
**Continue kernel work, but only on XAM's dependency set.** The name-linking phase is sufficient; reliable cross-program contracts are not yet sufficient.