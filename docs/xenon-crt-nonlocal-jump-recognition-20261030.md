# Reusable Xenon CRT nonlocal-jump recognition (2026-10-30)

## Why this exists

The Xenon CRT `setjmp` / `longjmp` family has been independently rediscovered multiple times while reversing different Xbox 360 binaries. In two verified cases, the same `longjmp` context-restoration semantics were present in XAM (`0x819611D0`, callback wrapper `0x8193EFF0`) and the original 1888 Blades dashboard (`0x92452420`, callback wrapper `0x9242D500`). The dashboard's apparent "Bad Instruction" at `0x9242D534` arose when Ghidra followed an ordinary call into `00 00 00 00` alignment padding instead of recognizing that the callee transfers control to an earlier saved continuation.

Reimplementing an address-locked Ghidra script for every new XEX is unnecessary and error-prone. The extension should identify the **semantic opcode pattern once** and apply reusable metadata to future XEXs.

## Implementation on `testing`

- `XEXLoaderWV/src/main/java/xexloaderwv/XenonNonlocalJumpPatterns.java`: Ghidra-independent, machine-word matcher. Verifies the full f14–f31 and r13–r31 saved-register restoration, consistent buffer base register, SP/CR/LR restoration, transfer through saved LR, the `returnValue==0 ? 1 : returnValue` rule, and the alternate call/unwind branch. Allows compiler variation in byte position of the restore sequence, buffer base register and relative call displacement. No binary version/address table.
- `XEXLoaderWV/src/main/java/xexloaderwv/XenonCrtNonlocalJumpAnalyzer.java`: normal enabled, one-shot-capable FUNCTION analyzer for Xenon/A2ALT XEX programs. After function discovery, matches longjmp functions by **bytes rather than names**; names recognized functions `longjmp` where not user-renamed; sets **No Return**; only refines a void return or simple parameter metadata when safe and never invents jump-buffer structures. A second pass identifies optional callback wrappers only when the terminal direct branch really targets a verified longjmp, a callback is called through `jumpBuffer+0x140`, `r4=1` is supplied, and the next DWORD is zero padding. Annotates these wrappers, sets **No Return**, retains user names.
- `XEXLoaderWV/tools/TestXenonNonlocalJumpPatterns_20261030_v1.java`: dependency-free JDK synthetic fixture reproducing the 1888 restore sequence and wrapper, probes alternative offsets and registers, and checks near misses (missing zero-to-one rule, missing FPR/GPR/SP restoration, missing unwind branch, nonterminal call, missing callback).
- Original targeted 1888 script `ghidra_scripts/RefineXenonLongjmp1888_20261030_v1.java` remains available as a byte-exact emergency annotation, but new imports should not require it.

### Conservative boundary

**Automatic `setjmp` renaming remains pending**: a verified corresponding **save-side** binary sequence has not yet been supplied. The new analyzer does not guess at generic context savers or use names/address proximity as proof. This is intentionally a reusable `longjmp` and wrapper recognition fix first. It will not change a function to `setjmp` without evidence.

No executable image bytes, linked import references, datatype declarations or user-refined parameter/storage signatures are rewritten. If the full pattern is missing or any mandatory byte is unreadable, no metadata is applied. Existing user-defined names are preserved.

## Verification status and expected runtime

- Instruction formulas were cross-checked against the user's displayed 1888 dashboard PowerPC words: f14, f31, r13, r31, saved SP, CR/LR loads and move to the return register match the complete encoding.
- Source committed to `testing`. **The full Ghidra extension compile and live analyzer execution are pending**, as is compilation of the standalone Java regression fixture. This is not yet a user-verified fix.
- After rebuilding, use `Analyze > One Shot > Xenon CRT nonlocal jumps` on the existing 1888 dashboard. The result should include `longjmpRecognized>=1`, `noReturnMarked>=1` if it wasn't already marked, and `callbackWrappers>=1` if the wrapper function is fully discovered and its direct call has a valid Ghidra flow reference.
- Confirm `0x92452420` and `0x9242D500` now have **No Return** and no executable bytes changed. Analyze/reanalyze `0x9242D500` if Ghidra retains a stale Bad Instruction bookmark at `0x9242D534`.
- On an XAM with the earlier verified implementation, repeat and confirm that it is matched only when the whole byte pattern is present. No address mapping is used.

## Next technical step

The correct setjmp saver pattern, including register storage offsets and whether there are multiple variants, needs native disassembly verification. Add that to `XenonNonlocalJumpPatterns` and tests before enabling automatic setjmp function identification. Do not regenerate per-firmware scripts or weaken the matcher to "calls RtlUnwind" alone.
