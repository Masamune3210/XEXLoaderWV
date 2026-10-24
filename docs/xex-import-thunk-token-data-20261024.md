# XEX import thunk metadata handling (2026-10-24)

Branch: note-working/xex-import-thunk-token-data-20261024; based on testing.
Source: XEXLoaderWV/src/main/java/xexloaderwv/XEXHeader.java.
Example: xboxkrnl.exe::XAudioGetDuckerHoldTime at 0x81A73D14, ordinal 0x0357.

## Verified layout

XEX native import thunk, total 16 bytes:
- +0x00: 0100OOOO, loader upper-address relocation token (NOT PPC)
- +0x04: 0200OOOO, loader lower-address relocation token (NOT PPC)
- +0x08: 7D6903A6, executable PPC mtctr r11
- +0x0C: 4E800420, executable PPC bctr

OOOO is the import ordinal. The runtime linker replaces the two tokens with code loading the resolved target address into r11. Guest callers branch to the ORIGINAL start, not +8. Existing import handling already creates genuine native Ghidra thunk functions linked to the external export, with correct original entrypoints and import slots. Preserve those relationships and original bytes.

## Critical prior regression (do not repeat)

Prior work in docs/import-thunk-modeling-20261009.md tested declaring the two token words as DWord DATA at the same address as a Ghidra native thunk function. This produced 339 live Bad Instruction bookmarks, including 310 conflicting-data errors in 17559 XAM. Ghidra attempts disassembly at thunk function entrypoints/branch targets even if the entrypoint has been typed as data. Consequently, creating an 8-byte structure on the thunk entrypoint is NOT an acceptable fix. Earlier use of fake lis/ori mapped-memory veneers may mislead decompilation, so that mode remains experimental and disabled by default.

## Current source change

- Experimental commit c9622f7c briefly reintroduced the known-bad typed-data strategy. It was superseded by corrective commit 02657422 before user testing. Current branch does NOT define data over the token words.
- The loader retains canonical 16-byte pattern verification and the Ghidra external thunk function at the unchanged original address.
- With analysis veneers disabled (default), it adds a plate comment and EOL comments describing both relocation tokens as NON-executable metadata. It then disassembles ONLY the actual +8/+12 PPC tail, with further code analysis disabled. The first eight bytes remain untouched and undefined to avoid the prior typed-data conflict.
- The explicitly enabled experimental veneer mode is unchanged. It modifies only mapped Ghidra analysis memory, never the original XEX file.
- No data types, Ghidra function signatures, caller references, or external thunk links are changed.

## Existing Program support

The already loaded Program will not rerun the changed loader. Masamune3210/360decompwork now has ghidra_scripts/AnnotateExistingXexImportThunks_20261024_v2.java (commit 6fd883f1) to annotate byte-exact canonical linked thunks without reimporting, preserving all bytes and function links and skipping existing data/code conflicts. The unsafe earlier TypeExistingXexImportThunkTokens_20261024_v1.java was removed (commit d003c982).

## Verification and remaining limitation

Source-level invariants checked: unchanged canonical guard, external thunk entrypoint, original bytes, no data created at token bytes, comments, tail-only disassembly, separate experimental mode. NO live Ghidra extension build or test was possible in the current environment.

IMPORTANT: these annotations do NOT prevent other Ghidra automatic analyzers from attempting disassembly at thunk entrypoints. Thus they are a safe representation improvement, not a confirmed solution to recurrent Bad Instruction bookmarks. Genuine suppression with raw-byte fidelity and native thunk links requires further import-aware analyzer/disassembler handling and runtime verification, not the previously failed typed-data method.

Next verification: build against Ghidra 12.1.3, fresh-import an XEX containing 0x81A73D14, confirm byte-exact 01000357 02000357 7D6903A6 4E800420, original external thunk and import caller xrefs, first two words non-code/undefined with explanatory comments, and PPC mtctr/bctr decoded at +8/+12. Re-run auto-analysis and inspect LIVE bookmark counts. The retrofit script can be tested on the existing saved XAM Program without reimport. Do not claim suppression unless shown by runtime.

Unrelated Xenia wait analysis and Xenon ISA numerical testing are out of scope.
