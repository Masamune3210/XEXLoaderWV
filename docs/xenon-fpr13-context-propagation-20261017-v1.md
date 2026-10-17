# Xenon FPR13 phantom-argument investigation (2026-10-17)

## Question
Why does an otherwise integer-only retail 17559 kernel function such as `NtClose` have 13 leading `undefined8` parameters in FPR `f1`–`f13`? Is this a faulty XEX loader, wrong Xenon SLEIGH, wrong compiler spec, or Ghidra analysis?

## Evidence
Analyzed the already supplied `xboxkrnl-decompilation-20261015-continued.zip`, specifically its `full-export-final/asm/*.asm` and `full-export-final/c/*.c` files. This is an **archived October 15 export**, not a new execution of Ghidra on the current October 17 database. The XAM import contract report is `Xam17559KernelContractAudit_15819523401038207526.tsv`.

The 4,404 exported ASM functions yield the following complete contingency table. An edge exists only for a direct native `bl` or unconditional `b` to an exported function entrypoint; this may miss indirect calls and addresses without exports:

| Callgraph group | 13 leading undefined8 FPR slots | Other |
|---|---:|---:|
| Can reach native context-saver `0x80075A38` | 2,351 | 228 |
| No recorded path to saver | 6 | 1,819 |

Of the **2,357** signatures containing all 13 FPR slots, **2,338** functions have no native floating-point instructions in their bodies. The XAM link/contract audit includes **242** such heavily exposed signatures across **2,479** XAM branch references.

At `0x80075A38` (`FUN_80075a38` in archived analysis), the native code uses `stfd f0` through `stfd f31` to capture the floating-point machine context into a pointer supplied in `r3`. There are 35 native instructions. Ghidra treats `f1` through `f13` as formal `undefined8` inputs and the remaining machine-state registers `f14`–`f31` as free incoming registers. Whole-instruction-byte SHA256: `99af6e7e062400eeb32f418cec412f74e4d9acb28e3b1e5afc1e2de10ccd0f1b`.

The source's immediate wrapper `0x800759F8` calls the saver; the exported kernel scheduler path is:

```text
0x80089EB0 NtClose
  -> 0x8007018C KfReleaseSpinLock
  -> 0x80075504 KiDispatchPendingInterruptLevelsObserved
  -> 0x800755D0 KiDispatchDpcsAndPendingThreadObserved
  -> 0x80077B38 FUN_80077b38
  -> 0x800778A8 FUN_800778a8
  -> 0x800759F8 FUN_800759f8
  -> 0x80075A38 FUN_80075a38 [native FPR register-state saver]
```

`KeGetCurrentProcessType 0x80071A68` also has all 13 FPR parameters despite its 15-instruction body doing **no FP operations**. Its error branch tail-calls `KeBugCheckEx`, another route into the same call graph. The 6 signatures outside the archive graph have incomplete/unexported downstream targets; do not claim they are independent root defects.

## Diagnosis

**Ghidra decompiler ABI-parameter inference spreading implicit machine-state reads through its call graph.** The stock PowerPC 64/32 compiler spec and Xenon `xenon_64_32.cspec` both list `f1`–`f13` as floating-point argument resources. This is appropriate for genuine FP arguments. The context-saver routine deliberately consumes every FP register without receiving ordinary FP arguments. Ghidra promotes `f1`–`f13` into formal arguments because they are liveness inputs eligible under the prototype model; this contaminates higher-level callers. No evidence here demonstrates a Xenon instruction-decoding or XEX import-decoding defect.

**Do not globally remove `f1`–`f13` from `xenon_64_32.cspec`.** That would break legitimate floating-point ABI calls. **Do not bulk delete the existing 13-slot parameters**: they were intentionally preserved in historical partial signatures, many marked USER_DEFINED, and the live saved Program must remain intact until a narrowly controlled validation succeeds.

Ghidra compiler specification documentation explains that parameter recovery uses separate FP resources and may fill gaps in their allocation ordering: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/main/doc/cspec.xml

## Pre-build diagnostic committed

`ghidra_scripts/AuditXenonFprContextPropagation_20261017_v1.java` is READ ONLY and does not require rebuilding XEXLoaderWV. It scans the currently opened Xenon Program for functions storing 28 or more unique FPRs, constructs a cross-function direct call graph from Ghidra references, counts `f1`–`f13` undefined parameters versus native FP operations, prints a 2x2 contamination matrix, and writes a TSV to Downloads. It uses no firmware-specific function names for recognition; one example path at `NtClose` prints only if present in the current Program.

## Next experiment, not yet performed

Use a separately backed-up/disposable **kernel Program** to test fixing only the native FPR saver and immediate wrappers' ABI prototypes, ensuring CPU-register accesses are still represented within their bodies. Determine whether this breaks backward propagation when regenerated signatures are inferred. Explicitly established signatures and their unresolved parameters must not be rewritten in the user's live database during exploratory testing. Only after actual Ghidra reanalysis confirms a safe model should we implement a general extension analyzer to recognize genuine processor-state capture routines ahead of ParamID analysis. Re-run on at least one additional firmware module before enabling such an analyzer globally.

**Build decision:** Do not build/install a new extension revision solely to change Xenon FPR register assignment. This is first an analysis-modeling issue, not evidence that the Xenon ABI is incorrectly specified.
