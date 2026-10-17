# Xenon processor CR0 word-mode correction, 2026-10-17

## Branch and scope

Target: `Masamune3210/XEXLoaderWV` branch `testing`. The CR0 defect is in the **generated SLEIGH processor semantics**, not `xenon_64.pspec` (which controls context/settings). `XEXLoaderWV/build.gradle` generates `xenon_ppc_common.sinc` from Ghidra's stock `ppc_common.sinc`; the generated file is not tracked. This change patches only that Xenon-local generated copy using an exact upstream-text guard.

## Correction

In `macro cr0flags(result )`, create a full-width local `crFullResult`, take its low four bytes as `crResult32:4`, and use that word for the signed LT/GT/EQ tests. Preserve `xer_so`, the full-width GPR destinations, the source processor, and explicit-width comparisons such as `cmpdi`.

The preexisting `addic.` / `subic.` constructor-level `cr0flags(D:4)` fix remains intact, although the corrected common macro now handles implicit CR0 word comparison uniformly. The update is intentionally **fixed SF=0**, not a claim to dynamically switch on MSR[SF].

## Evidence and verification

Provenance: `Masamune3210/360decompwork/private_cr0/compiled-tested-cr0-32bit.patch` and `private_cr0/test-summary.json`. The privately compiled original-byte test established a baseline with 16 differences among 8,192 cases; the patched language passed all 8,192. Each variant also passed 84 instruction/CR0 tests and 256 decoder controls. The offline native census identified five wrapping `rlwinm.`/branch sites, with four additional model-level witnesses still awaiting native execution. These are NOT five independently verified runtime failures.

`verifyXenonSleigh` now depends on `testXenonCr0Mode`, which checks the *generated* macro and the model witness invariants. The existing compilation task compiles the actual SLEIGH before packaging. A local Ghidra SLEIGH compiler was not available in this assistant environment; do not interpret static/test-source validation as a new compiled build result. No installed processor or saved Ghidra project was changed.

## Next

On a Ghidra 12.1.3/JDK21 host, run `gradle buildExtension` on `testing`, inspect the new generated SLEIGH and compilation/test logs, and install/reopen/reanalyze in a separately backed-up database when ready. A changed SLEIGH model will not retroactively fix a previously analyzed Ghidra database merely by committing this source.
