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

## Fresh-import regression (2026-10-09)

User imported the original 17559 XAM as a second program using this branch's loader and completed auto-analysis. The GZF was inspected offline; original image SHA256 was known from the working file. The current implementation **does not pass the no-recurring-import-errors test**. The GZF contains diagnostic records at 389 of 443 canonical thunk entries: 368 have a parseable "Failed to disassemble ... due to conflicting data" message, 31 have a constructor-failure message (some overlap); five additional malformed/truncated copies are ignored when counting unique addresses. Only 54 thunk entries have no such embedded record. There are 165 non-import constructor-error addresses, versus 335 in the prior analysed archive. The previous import produced constructor errors at all 443 thunk entries, so the change transforms a large part of the error class instead of eliminating it.

Cause to investigate: the branch simultaneously creates a function at a native import-token entry point and declares the same bytes as DWord data. Ghidra auto-analysis tries to disassemble at function entries/branch destinations and records a conflicting-data error. The disassembler expects actual instructions at function entries; declared data alone does not stop it from trying. Earlier branch success claims were premature.

Do **not** fix this by globally disabling "Mark Bad Disassembly", deleting bookmarks after analysis, or patching the original executable bytes. Consider an import-aware disassembly strategy or a clearly documented image-only patch with separately preserved native bytes if acceptable. Before deciding, use a read-only Ghidra audit to verify that all 443 thunk links and both token data declarations survive analysis; embedded GZF diagnostic records may be historical, not live bookmarks. No loader correction or new user-database mutation has been made based solely on this GZF.

Status: implementation present, regression test FAILED, keep branch unmerged.

## Follow-up implementation: mapped-memory runtime relocation veneers

The live read-only audit of the first fresh import confirmed that **all 443 genuine xboxkrnl.exe thunk links were correct**, all 443 original stubs were byte-exact, and both four-byte import tokens were defined as data. However, **339 live Bad Instruction bookmarks remained**: 310 conflicting-data and 29 invalid-instruction errors. The prior GZF-based diagnostic inventory included stale embedded records, so use live bookmarks for regression counts.

Xenia's runtime loader documents that real consoles replace both token words with PowerPC code loading the resolved target address into r11, followed by the native mtctr/bctr pair. Since the external address isn't known at import time, a new configurable loader option (default ON) now writes an **analysis-only unresolved relocation veneer** into the *Ghidra mapped memory*: `3D600000 616B0000 7D6903A6 4E800420` (lis r11,0; ori r11,r11,0; mtctr r11; bctr). Ghidra's native thunk relationship supplies the real external identity. This IS a byte change in the Ghidra database; it does **not** modify the original XEX on disk or the loader's `peImage`. The two original token words are retained in a plate comment at each function entry, and can be recovered from the original file. Disable the loader option to preserve raw imported bytes, at the cost of native-token disassembly errors.

Token words are no longer declared as data when the veneer option is ON, eliminating the known code/data conflict at function entries. The option is applied only to validated canonical 16-byte native import stubs. The prior failures for non-import Xenon instructions are explicitly out of scope.

**Verification status:** this second implementation is committed, but no local Ghidra 12.1.3 extension build, fresh import or repeated auto-analysis has been completed. The previous regression remains reproducible on the earlier first-version build and must not be described as solved until the second build passes.

### Verification

Build/reinstall this branch, import `$flash_xam.xex` under a new test program name, complete auto-analysis twice, and run `AuditXamLoadercheckThunksV2.java` from the Ghidra Script Manager. Expect 443 linked thunks, 443 relocation veneers, no defined data on first two words, and zero live Bad Instruction bookmarks at token +0/+4. Inspect the original-token plate comments and confirm the source XEX SHA256 has not changed. Then test a different XEX with imports. If the veneer body or external linkage is lost, do not merge.