# XEX import-thunk modeling (2026-10-09)

## Why this branch exists

XEXLoaderWV processed imports after .pdata-driven disassembly, created labels rather than genuine external thunks, and patched a detached PE byte buffer after memory mapping. For Xbox 360 17559 $flash_xam.xex, Ghidra recorded 443 Bad Instruction bookmarks on import tokens. A targeted repair linked all 443 to xboxkrnl.exe and removed those 443 stale bookmarks. Future imports should not require that repair.

## Changes

- Process import records after mapping sections but before .pdata function discovery.
- Validate type-0 slot/type-1 thunk records, ordinal matches, and mapped address ranges.
- Add external-library symbols/references and genuine Ghidra external thunk functions for recognized native stub layouts.
- Preserve mapped executable bytes; define import-token words as data to block incorrect PPC disassembly.
- Retain unknown data-only imports without guessing signatures, and report unrecognized thunk layouts.

## Status and next steps

Changes are committed to this branch. Build and fresh import in Ghidra 12.1.3 are NOT YET VERIFIED. The existing manually repaired XAM database is untouched.

Build against Ghidra 12.1.3, import the original $flash_xam.xex (SHA256 78b3dbd8ae866f4258f5444205486ea9f8451afaa30f469c875dcf345f828467) into a disposable test program, and confirm 443 real xboxkrnl.exe thunk links and 20 unpaired reference slots before analysis. Check that token words are data, original bytes are intact, and no import-token Bad Instruction bookmarks appear across two analysis passes. Verify a second XEX with a different import layout before merging. A mismatch may require changing the function-entry/data strategy; do not conceal errors with synthetic PPC instructions.

Not in scope: VMX128/Xenon language decoding, compiler-helper ABI fixes, and .pdata packed function-length modeling.