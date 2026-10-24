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
