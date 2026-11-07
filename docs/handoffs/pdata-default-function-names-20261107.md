# Preserve Ghidra default names for .pdata-created functions

Branch: `fix/pdata-default-function-names-20261107`; branched from `testing` after user confirmation that RVA-indexed kernel PE import works.

## Cause
Two loader code paths manufacture `Function_%08X` labels with `SourceType.ANALYSIS`, even though the only evidence is a .pdata address:
- `XEXHeader.ProcessPData`: calls `SymbolUtilities.createPreferredLabelOrFunctionSymbol(..., "Function_" + address, SourceType.ANALYSIS)` before creating the function.
- `XboxKernelMemoryPeLoader.importPData`: creates the function and then calls `function.setName("Function_%08X", SourceType.ANALYSIS)`.

These explicit names are not Ghidra defaults and are not automatically overridden by name-aware tooling expecting `FUN_...`. The user observed the issue in the 6717 kernel: `0x8006F910` and `0x800EA960` persisted as `Function_...` even after Function ID recognized their library functions.

## Decision
.pdata establishes **addresses**, not names. Let Ghidra create its own `FUN_...` default names and preserve existing user/import/export function names; do not synthesize `Function_` labels. Only the two offending production code paths need functional changes.

## Existing databases
A separate narrowly gated Ghidra script can revert *only* legacy `Function_XXXXXXXX` names when the suffix exactly matches their entrypoint and the source is ANALYSIS, using `Function.setName(null, SourceType.DEFAULT)`. Do not modify user symbols, renamed symbols, valid exports/imports, prototypes or function bodies. A review-only mode should be default.

## Verification
Not yet implemented/tested at branch creation. Update after commits. No changes to `testing` until user approval.
