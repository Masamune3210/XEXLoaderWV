# XEX import thunk relocation token typing (2026-10-24)

Branch: `note-working/xex-import-thunk-token-data-20261024` (based on `testing`).

## Reason
The current XEX loader already identifies the 16-byte native import stubs and creates Ghidra external thunk relationships, but leaves their first eight bytes undefined. The pattern `0100OOOO 0200OOOO 7D6903A6 4E800420` is **two linker/loader relocation token words** followed by actual PPC `mtctr r11; bctr`, not four instructions. Ghidra currently displays the token words as `??` and may try disassembling the metadata as PowerPC code. Example: `xboxkrnl.exe::XAudioGetDuckerHoldTime` at `0x81A73D14`, ordinal `0x0357`.

## Existing decisions
- Preserve the source XEX and imported Program bytes; do not force fake executable `lis/ori` relocation stubs by default.
- Preserve the native thunk function **at the original 16-byte entrypoint**, its external function relationship, the existing imported slot labels/references, and `.pdata` protections. Never move the thunk to `+8` because calls target the original entrypoint, which the runtime linker patches.
- Explicit, disabled-by-default experimental veneer option remains separate.
- Type relocation metadata so ordinary code discovery will not invent instructions over it; only the trailing two words are real instructions in the unpatched image.

## Current state
- Located root implementation `XEXLoaderWV/src/main/java/xexloaderwv/XEXHeader.java::ProcessImportLibraries` and `IsCanonicalImportThunk` on `testing`; canonical check already verifies both tokens match the ordinal and the exact PPC tail.
- The previously used `fix/import-thunk-modeling-20261009` branch is not currently present remotely; `testing` contains the established import-linking implementation and `docs/import-thunk-modeling-20261009.md` handoff.
- Changes and verification to be recorded below on implementation. No prior data declarations, signatures or existing Ghidra database mutations assumed.

## Next
Implement loader-side typed tokens and safe tail disassembly without destroying thunk linkage, check source/build constraints, then user-test by newly importing a canonical XEX. Existing Ghidra Programs will not retroactively acquire new annotations without a migration script or reimport.

## Changes implemented (2026-10-24)
- **Loader commit `c9622f7c`** modifies `XEXHeader.java::ProcessImportLibraries` on this branch. The recognized canonical import thunk remains a native `FunctionManager.createThunkFunction` at its ORIGINAL `0x10`-byte entrypoint, with its original external target and import-slot references intact. Once the thunk is created, and only with default veneers-disabled behavior, it defines an `/XEX/ImportThunkRelocationTokens8` structure over the first eight original bytes: `+0x00 uint32 upperAddressToken`, `+0x04 uint32 lowerAddressToken`. The type is shared across canonical thunks, preserves byte values (`0100OOOO`, `0200OOOO`), and prevents disassembly over relocations. It then disassembles **only** the original actual PPC tail at `+8` (`mtctr r11; bctr`), with code-analysis scheduling disabled, and adds a plate comment explaining runtime linker patching. It does not rewrite source XEX or mapped Program bytes. If a raw thunk is not canonical, current conservative unsupported handling remains.
- The deliberately opt-in **experimental** analysis-veneer mode still creates its fake `lis/ori` words for users who explicitly enable it; the default is metadata typing with original bytes.
- **Existing Ghidra databases do not re-execute import logic merely because the extension was rebuilt**. A guarded in-place repair script was also committed to **`Masamune3210/360decompwork`**, path `ghidra_scripts/TypeExistingXexImportThunkTokens_20261024_v1.java`, commit `ac2ac2f8`. It scans preexisting external native thunk functions and applies the same structure only to exact byte-verified canonical descriptors when token bytes are currently undefined. It preserves function entrypoints and linkage, does not clear conflicting existing defined code/data, and decodes the real PPC tail. It emits counts and address samples.
- Source-level validation: checked canonical-thunk guard, creation order (native thunk before typed data), no default mapped byte rewrite, data type size, instruction tail `+8`, external link use, and optional-veneer separation. All eight focused checks passed. This is **not** a Ghidra runtime test or successful Gradle compile.

## Remaining verification
1. **Run Gradle extension build** for this branch in the user's configured Ghidra environment (Ghidra build environment not present here). Fix any API compile issues rather than assuming build passes.
2. On a **freshly imported** XEX containing the known `XAudioGetDuckerHoldTime` ordinal `0x0357` at `0x81A73D14`, confirm the original entry is a genuine external thunk and the first 8 bytes show `ImportThunkRelocationTokens8` as **data** (not instructions or `??`). Verify `0x81A73D1C` and `0x81A73D20` disassemble as `mtctr r11; bctr` and all 16 bytes remain untouched.
3. Alternatively, run the committed **existing database repair script** against the current Ghidra program, avoiding reimport. Check it preserves caller xrefs and the thunk function signature and that the analyzer doesn't redisassemble relocation tokens. If prior analysis already defined code/data over tokens, the script purposely skips that case and prints a conflict count; evaluate before modifying those definitions.
4. Probe an XEX with noncanonical import records to confirm conservative non-code fallback; no generic data/token guessing beyond the verified 16-byte import descriptor format.

## Scope boundaries
- This branch does not alter Ghidra's Xenon SLEIGH instruction decoding or the kernel PE disassembler: the issue is XEX import-loader metadata representation.
- No other emulator/XEX functionality or `testing` branch commits were changed.
