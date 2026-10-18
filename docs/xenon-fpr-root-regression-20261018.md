# Xenon FPR input-prototype regression (2026-10-18)

## Why
The retail 17559 native state saver at `0x80075a38` has correct `stfd`/FPSCR p-code, but the decompiler misclassifies the live-in machine state in ABI-eligible `f1..f13` as formal arguments. The old error then propagates into callers. The user explicitly ruled out post-analysis signature repair, firmware-address special cases, removing valid floating ABI registers, and falsifying instruction p-code.

This fixture makes **both positive and negative requirements** reproducible outside the kernel, so a Ghidra core inference fix can be tested with a fresh database:

| ELF symbol | Expected formal argument behavior |
| --- | --- |
| `xenon_save_fpr_bank` | One context pointer in `r3`, **no FPR formal arguments**, despite reading/storing `f0..f31` |
| `xenon_save_fpr_wrapper` | One context pointer in `r3`, **no propagated FPR formal arguments** |
| `xenon_add_f64` | **Two real double parameters** in `f1` and `f2`; double return in `f1` |
| `xenon_call_add_f64` | Real `f1`/`f2` ABI inputs must not disappear; returned `f1` is valid |

The `save_fpr_bank` instructions intentionally duplicate the exact observed 35-instruction context saver, including the initial `stfd f0`, `mffs f0`, all other `stfd` instructions, and `blr`. The two wrappers are ordinary PowerPC64 calls.

## Build

Requires LLVM clang with the PowerPC64 assembler backend and LLD:

```powershell
clang -target powerpc64-unknown-linux-gnu -c tools/regression/xenon_fpr_inference_v2.s -o xenon_fpr_inference_v2.o
ld.lld -m elf64ppc --no-dynamic-linker -e xenon_save_fpr_bank -Ttext=0x100000 -o xenon_fpr_inference_v2.elf xenon_fpr_inference_v2.o
```

The 2026-10-18 local build succeeded using clang and LLD. The generated sample has PPC64 big-endian ELF executable type, entry at `0x100000`, four exported `FUNC` symbols, and direct call relocations resolved at link time. It is self-contained and does not execute on the user's Windows host.

## Ghidra test

1. Import the fixture ELF as `PowerPC:BE:64:XENON-32addr` / applicable Xenon compiler specification. Use a **fresh** test program and run normal analysis.
2. Record function signatures and decompiled calls for all four symbols. Do **not** edit parameter types, pin signatures, or run cleanup scripts.
3. Before a core change, record the actual inferred signatures. Confirm whether the minimal fixture reproduces the same context-saver/forwarding error as the firmware, and the actual floating-point function keeps `f1` and `f2`.
4. Apply only a true parameter-recovery model change, not a post-analysis metadata mutator. Rebuild and rerun analysis in a second **fresh** program. Both save functions must exclude FPR formals, while both floating-point functions must keep their real FPR arguments.

**No verified source-level correction is yet implemented.** The result of this fixture is needed to avoid relying on a heuristic that only accidentally fixes the retail kernel while breaking actual float arguments.

## Technical path
Ghidra's `Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc`, `ActionInputPrototype::apply()` registers live-in `Varnode::input` values whose addresses are accepted by `possibleInputParam`. The stock `ppc_64_32.cspec` (identical to current Xenon cspec) accepts `f1..f13` as floating-point inputs. The full-register snapshot is not a standard C-ABI argument list; raw hardware state and formal parameters must be distinguished.

A generic decompiler change must be proven against both sides of the fixture and additional unrelated binaries; a custom calling-convention model for machine-state helpers is also worth evaluating if the core model cannot make this distinction without unsafe assumptions. Do not introduce a generic "all STORE-only register inputs are not arguments" rule: real floating-point parameters can be immediately stored to memory too.
