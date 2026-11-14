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

## Implemented

- `XEXLoaderWV/src/main/java/xexloaderwv/XEXHeader.java`, commit `f831ea82`: remove analysis-source `Function_` label creation before `.pdata` `EnsureFunction`. Addresses remain processed; Ghidra supplies default function names automatically.
- `XEXLoaderWV/src/main/java/xexloaderwv/XboxKernelMemoryPeLoader.java`, commit `3dcbbd42`: remove `Function_` post-creation renaming in the reconstructed kernel PE loader, leaving true default function names.
- `XEXLoaderWV/ghidra_scripts/RestoreDefaultPDataFunctionNames.java`, commit `1050f8ce`: optional **preview-only by default** migration for existing Ghidra programs. Set `APPLY_CHANGES = true` in the script to apply after reviewing candidates. It requires an exact `Function_[8 hex]` entrypoint match, ANALYSIS source, and non-thunk function; then `function.setName(null, SourceType.DEFAULT)`. Ghidra's native default naming supplies `FUN_...`; it does not create a synthetic `FUN_` symbol. User-defined, imported and unrelated names are preserved.
- `XEXLoaderWV/src/test/java/xexloaderwv/PDataDefaultFunctionNamesTest.java`, commit `71a3cd8c`: dependency-free source contract guard for both `.pdata` paths and safety-critical repair-script defaults.

## Verification

- **10/10 targeted source assertions passed**, reading the committed repository content with the GitHub connector: both loaders still create functions, neither assigns `Function_` names, neither prelabels/renames them from `.pdata`, and the migration is gated to preview-only + ANALYSIS source + true Ghidra default reset.
- Independently checked upstream Ghidra's `FunctionDBTest.java`, which exercises `function.setName(null, SourceType.DEFAULT)`.
- Java source-contract regression test and complete Ghidra extension build **not executed** in this environment; Ghidra UI behavior on user database not yet reverified.
- Affected legacy symbols in the user's 6717 kernel example include `0x8006F910 Function_8006F910` and `0x800EA960 Function_800EA960`, both already recognized by Function ID but not renamed.
- Only this repair branch was modified; `testing` remains untouched.

## Next step

Build/import the modified extension and inspect newly imported or reanalyzed `.pdata` functions. They should retain the genuine `FUN_...` default until a meaningful name is identified. For old databases, run `RestoreDefaultPDataFunctionNames.java` first in preview mode; explicitly enable apply only after reviewing candidates, then rerun the Function ID Analyzer if desired. Promote to `testing` after user verification.

## Promotion to testing (2026-11-13)

- Integrated into `testing` through PR #1, merge commit `9d2491733c32a8b4dfe620b3bfb1fadb624ca314`, preserving the feature branch commits.
- The related `fix/kernel-memory-pe-rva-loader-20261107` branch was already an ancestor of `testing` (zero commits ahead); its loader behavior is retained.
- Ghidra 12.2 CI for the merged `.pdata` changes: https://github.com/Masamune3210/XEXLoaderWV/actions/runs/43546326371. Check the run conclusion before claiming a pass.
- Functional behavior remains to be verified on a fresh `.pdata` import; the optional migration script is preview-only by default and should not be applied without reviewing names.
