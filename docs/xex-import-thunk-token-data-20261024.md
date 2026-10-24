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

## Current design: persistent Xenon disassembly exclusion

**The annotation-only change was inadequate**, as confirmed by the user's live screenshot at 0x81A72334: an existing linked native thunk retains `??` bytes and Ghidra creates a Bad Instruction bookmark when its analyzers run again. Prior attempts to declare those bytes as data at a function entry yielded 310 conflicting-data bookmarks; a zero-address fake executable veneer is not faithful to the prelink XEX.

The new implementation addresses this at **Ghidra's Disassembler entrypoint**, not by commenting, hiding bookmarks, replacing bytes, or relabeling false code:

- Added `XEXLoaderWV/src/main/java/xexloaderwv/XenonImportAwareDisassembler.java`; registered `customDisassemblerClass=xexloaderwv.XenonImportAwareDisassembler` in `XEXLoaderWV/data/languages/xenon_64.pspec` (commits `9ec2e9bd`, `408eb05a`).
- `ProcessImportLibraries` now records successfully linked canonical stub entrypoint addresses in persistent Program options `XEX Import Thunks / Pre-link Relocation Token Entrypoints`. This is stored **in the Ghidra database** and survives reopening and rerunning analysis (commit `ee4aefdc`).
- Each freshly instantiated Xenon disassembler rereads that option, validates **all original 16 bytes** per entry (`0100OOOO 0200OOOO 7D6903A6 4E800420`, matching ordinal), and protects **only +0..+7**. If the bytes were genuinely patched into executable instructions, the exclusion no longer applies.
- Both the scalar and AddressSet disassemble entrypoints remove verified tokens from their disassembly **seed addresses**. They also subtract all token ranges from the allowed **follow-flow address set** before delegating to Ghidra's generic Disassembler. This matters because normal analyzers may independently enqueue incoming `bl` targets despite existing thunk labels or comments. The excluded range aborts flow before instruction decoding; the real +8/+12 PPC instructions remain eligible.
- There is no global disabling of bad-instruction reporting and no special treatment of non-import addresses; without the XEX Program option the custom disassembler simply delegates to Ghidra's original implementation. The external thunk function stays at the actual original call target.
- The loader continues to annotate relocation tokens and decode the actual PPC tail only, preserving original file and Program bytes and the existing native external link (the source code corrected the known-bad typed data experiment in commit `02657422`). Explicit experimental fake-veneer mode remains disabled by default.

**Existing Ghidra Program:** new script `Masamune3210/360decompwork/ghidra_scripts/ProtectExistingXexImportThunks_20261024_v3.java` (latest script preflight commit `4531cf66`) recognizes byte-exact already-linked native thunks, appends comments if missing, decodes only the actual tail, and persists the same Program option. It does not reimport, patch bytes, clear earlier bad bookmarks, or alter function definitions. The older annotation-only v2 and unsafe token-as-data v1 scripts were removed from the script repository; use v3 only. **Install the new Xenon language/extension and reopen the Ghidra Program before rerunning analyzers**, otherwise the property exists but the default disassembler still runs.

## Source/API investigation

Verified against the Ghidra source implementation and public API:
- `Disassembler.getDisassembler(...)` loads the `customDisassemblerClass` processor property from the language and constructs the matching subclass with a supported constructor. The subclass provides **all three reflection constructor forms** and overrides the two four-argument `disassemble` entrypoints.
- The base `Disassembler` checks `restrictedAddressSet` before parsing instruction prototypes during follow-flow, and its AddressSet overload dispatches each selected start through the scalar overload. Excluding both seeds and flow destinations is therefore required.
- `AddressSet.delete(AddressSetView)` removes exactly the verified token ranges; `Program.getOptions(...).getString/setString` persists markers per Program, not per analysis run.
- Separately marking token blocks non-executable would not solve this reliably: Ghidra's generic disassembler can still produce a **different memory restriction error bookmark** when an analyzer seeds the non-executable address. We did **not** choose that approach.

## Verification state and risks

Source hooks, address classification and Ghidra API contracts have been inspected; **extension build and repeated live Ghidra auto-analysis are not yet verified**. This is the first fix in this branch that actually intercepts future disassembly attempts; the screenshot predates this interception. User's chosen language must be `PowerPC:BE:64:XENON-32addr`: the processor-specific hook does **not** affect stock `A2ALT` fallback; the v3 script prints whether the active language advertises the custom class.

Required validation:
1. Build/reinstall the updated XEXLoaderWV extension, restart Ghidra and open the existing XEX database (no new import required). Run `ProtectExistingXexImportThunks_20261024_v3.java`; confirm **guarded token ranges > 0** and `Import-aware Xenon disassembler ACTIVE: true`.
2. In Listing, inspect `0x81A72334` and `0x81A73D14` if present. First eight bytes should remain byte-exact and undefined with annotations; the native external thunk and call references must remain. Only `mtctr r11; bctr` at +8/+12 should decode.
3. Clear **only existing** import-token Bad Instruction bookmarks to distinguish historical diagnostics from new runs, rerun Auto Analyze **twice**, then verify **zero new token parse/conflicting-data error bookmarks**. Keep normal Bad Instruction reporting enabled to catch other legitimate faults.
4. Check a non-import code path and original kernel PE program still disassemble normally, and that native thunk relationships remain intact. Test imported XEX with a different ordinal layout.

If any build/API/runtime issue arises, fix on this topic branch. Do not merge or claim this requirement is proven until the rerun confirms it. Keep `testing` branch free of speculative source commits. 
