# Xbox 360 kernel 17559: first real-function atomic/decompilation findings

## Inputs and scope

- Ghidra `PowerPC:BE:64:XENON-32addr`, `xboxkrnl.exe(9).gzf`, retail kernel 17559.
- User successfully decompiled 16/16 targeted real functions with `DecompileXboxKrnl17559RealFunctions.java`. Three functions retained 8 `CALLOTHER` operations in decompiler high p-code: `ExAllocatePoolTypeWithTag` (1), `ExFreePool` (1), `RtlEnterCriticalSection` (6).
- User supplied disassembly of all three functions. This investigation does **not** reopen the previously completed 3,414/3,414 Xenon numerical audit or require another synthetic test series.

## Explained CALLOTHER sites

Ghidra 12.1.3 inherited `ppc_instructions.sinc` uses `storeWordConditionalIndexed(...)` in `stwcx.`, and `sync(tmp)` in `sync`. Both are explicitly declared p-code user operations in `ppc_common.sinc`. The observed counts match precisely:

| Function | lwarx reservation load | stwcx. opaque conditional store | sync opaque barrier |
| --- | --- | --- | --- |
| `ExAllocatePoolTypeWithTag` @ `0x800644e8` | `0x80064574` | `0x8006457C` | none |
| `ExFreePool` @ `0x80064768` | `0x800647BC` | `0x800647C4` | none |
| `RtlEnterCriticalSection` @ `0x80088FA0` | `0x80088FBC`, `0x80089020`, `0x80089050` | `0x80088FC4`, `0x80089028`, `0x80089060` | `0x80088FD0`, `0x80089034`, `0x80089070` |

Thus **5 conditional-store userops and 3 barrier userops**, corresponding to exactly 8 actual flagged operations. A high-p-code count can depend on optimization, so the individual op mapping is independently grounded in machine instructions and SLEIGH source, not a printed per-op list from the decompiler report.

## Concrete inherited language defect, fixed on branch

The stock legacy `lwarx D,RA_OR_ZERO,B` constructor (`OP=31, XOP_1_10=20, BIT_0=0`) has the PowerPC reservation writes **commented out**. It is more specific than the inherited PPC ISA `lwarx TH,RA_OR_ZERO,B,BIT_0` constructor, which explicitly sets `RESERVE=1`, `RESERVE_LENGTH=4`, and `RESERVE_ADDRESS=ea`. These real atomic loops all use `BIT_0=0`. A `stwcx.` implementation that checks `RESERVE` cannot be modeled coherently when the preceding load-reserve omits that bookkeeping.

`XEXLoaderWV/build.gradle` now generates an isolated `xenon_ppc_instructions.sinc` from the installed Ghidra 12.1.3 `ppc_instructions.sinc`, and reactivates **only** those three established assignments in the legacy `lwarx` constructor. It verifies exact original constructor and read semantics, fails closed on Ghidra source drift, wires the copy through `xenon_ppc_common.sinc`, and never modifies stock Ghidra files or other processor variants. The existing `prepareXenonCommon` dependency automatically regenerates it on extension builds. A source-level regression was added to the existing `test_xenon_isa_coverage_v1.py`.

**Status:** code changed but new generated `.sla` has not yet been compiled or tested in the user's Ghidra runtime. Crucially, this change does **not** resolve `storeWordConditionalIndexed` or `sync` userops. Conditional stores must not be misrepresented as unconditional writes; barriers must not silently disappear.

## Directly applicable, evidence-grounded Ghidra metadata

The following declarations are **partial** on purpose: preserve the observed existing Ghidra parameter widths and unresolved return types. Names only are refined based on the machine instructions; do not replace existing code with speculative C pointer widths.

```text
0x800644E8
ulonglong __stdcall ExAllocatePoolTypeWithTag(undefined8 allocationSize, undefined4 allocationTag, undefined8 poolSelection)

0x80064768
undefined __stdcall ExFreePool(undefined8 poolAddress)

0x80088FA0
undefined __stdcall RtlEnterCriticalSection(undefined8 criticalSectionAddress)
```

- `ExAllocatePoolTypeWithTag`: `r3` controls allocator size classes and is passed as size into `0x80081250`; `r4` is stored with the allocation as its four-byte tag at `0x800645B8` / `0x8006472C`; `r5` selects allocator pool 1 or 2, with 0 defaulting through `KeGetCurrentProcessType`. Its original `ulonglong` return remains untouched.
- `ExFreePool`: `r3` is copied into `r28` at `0x80064774`, used as the pool address, so the pre-existing no-parameter signature is incomplete. The return type remains `undefined` rather than guessed.
- `RtlEnterCriticalSection`: `r3` is a pointer-like address to a critical section object, used at offsets 0x01, 0x10, 0x14, 0x18. Its existing unknown return type and 8-byte parameter width are preserved.

Partial observed record, useful for future type recovery but **not** an asserted complete Xbox CRT structure:

```text
Structure: XboxCriticalSectionObserved
Size: 0x1C (minimum observed span; not proven allocation size)

0x00 undefined1 unknown00
0x01 byte spinOrModeByte
0x02 undefined1[14] unknown02
0x10 int lockCount
0x14 int recursionCount
0x18 uint ownerThreadValue
```

`lockCount` is atomically incremented and compared against `-1`, `recursionCount` is set to 1 and incremented on re-entry, and `ownerThreadValue` is compared to a word loaded from `0x100(r13)` and assigned on acquisition. The exact identity representation, bitfields, remaining storage, and pointer width are not established; retain unknown bytes and do not automatically retype `param_1` until ABI storage is verified.

## Next real-decomp investigation

- Once the Xenon language is rebuilt/reloaded, examine these *same real functions*, not the numerical fixture, to determine whether fixing reservation tracking improves conditional-store control flow.
- Separately decide how to represent hardware contention in `stwcx.`: replacing its CALLOTHER with an unconditional store would give incorrect critical-section decompilation. `sync` is a real barrier, not an arithmetic implementation gap. Both remain intentionally unresolved here.
- Check whether the branch at `0x80088FF8` to `FUN_800890AC` crosses a genuine function boundary or reflects an erroneous auto-created entrypoint. The user's disassembly shows a local conditional path to that label, but there is not enough evidence to merge function extents safely yet.

## Verification

- Real kernel decompiler: **16/16** functions completed; three functions showed 1/1/6 CALLOTHER sites, as supplied by user.
- Reservation source patch: added, **not yet compiled/rerun in Ghidra**.
- Original 3,414 numerical regression cases: previously confirmed passing; **not rerun** and not expanded.

## Build regression after lwarx source copy (2026-10-10)

- User ran `gradle buildExtension` from inner `XEXLoaderWV`. `generateXenonIsaFixture` succeeded (86 families, 344 words); `verifyXenonSleigh` failed while preprocessing generated `xenon_ppc_instructions.sinc` at stock line 2245 because its relative `@include "lmwInstructions.sinc"` no longer pointed into Ghidra's PowerPC source folder.
- Ghidra 12.1.3's stock `ppc_instructions.sinc` has **five** relative helpers: `lmwInstructions.sinc`, `lswInstructions.sinc`, `mulhwInstructions.sinc`, `stmwInstructions.sinc`, and `stswiInstructions.sinc`. All five exist in the installed stock language directory and none has nested includes. This is an include-location regression of the copied file, not a failed ISA numerical fixture or invalid `lwarx` semantics.
- Updated `prepareXenonCommon` to rewrite those five includes to `$(PowerPC)/data/languages/<helper>` in the generated Xenon-only copy. Each name must occur exactly once and its installed stock file must exist; fail closed otherwise. The existing `-dPowerPC` compiler option resolves the prefix. No stock files are modified.
- Added a source-level test for all five include rewrites and brought the pre-existing embedded collision tests' expected generator inputs/outputs and instruction include into sync with the `lwarx` change.
- **Status:** source changes committed; the corrected build and SLEIGH compile have **not yet been run in the user's installation**. The next action is to pull and rerun `gradle buildExtension`, then recheck the same three real kernel functions under the rebuilt Xenon language. Do not repeat the completed 3,414-case numerical p-code audit merely to establish that include relocation compiles.

## SLEIGH -n/-u/-t diagnostic classification (2026-10-10)

- User ran `gradle diagnoseXenonSleigh`: 86 NOP constructors, 4 redundant zero extensions, 9 unused temporary writes, 4 unreferenced operand tables. These are diagnostics from the **Ghidra 12.1.3 inherited language sources**, not new VMX128-family decode failures.
- The 86 NOP entries are accounted for: 31 `LDMR` no-action alternatives in `lmwInstructions.sinc`; 31 `STMR` alternatives in `stmwInstructions.sinc`; 23 formatting/selection operand subtables in `xenon_ppc_common.sinc`; and the outer `vaddubm` AltiVec constructor, whose two subtable constructors implement byte additions.
- Redundant zero extensions are inherited from the stock PPC ISA (`mcrxrx`) and `FPRC.sinc`. One unused temporary in copied PPC ISA is `tmpcr` in `setb` and does not feed the `D` calculation. The four unused tables have no known consequence for Xenon decoding. Do not remove declarations merely to quiet these messages.
- **Real inherited bug:** all 8 `stswiInstructions.sinc` warnings correspond to `sa:1 = BH;` followed by `storeRegisterPartial(..., sa)`. In 12.1.3 stock `ppc_common.sinc`, this macro ignores `sa` entirely and always writes a four-byte word, corrupting 1-3 trailing destination bytes for partial-string stores.
- **Variant-only fix committed:** `prepareXenonCommon` now checks and substitutes the exact stock macro. Xenon `storeRegisterPartial` extracts bytes 3, 2, and 1 from the low 32-bit GPR in big-endian order, writing only the 1-3 bytes selected by `sa`, incrementing `ea` appropriately. `@ifdef BIT_64` continues to use only the low 32 bits of a 64-bit register. Installed Ghidra files remain unmodified. A source regression and static byte-order probes were added.
- **Verification pending:** need user `git pull`, then `gradle buildExtension` (mandatory real SLEIGH compile) and, optionally, `gradle diagnoseXenonSleigh` to see whether the eight `stswi` warnings disappear. Compiling does not establish numerical runtime correctness: use a targeted emulator/p-code test of `stswi` 1/2/3-byte remainder cases before declaring its semantics validated. The original 3,414 Xenon fixture results remain complete and need not be rerun. Return to the real kernel `lwarx`/`stwcx.` decompilation afterward.

## STSWI diagnostic rerun and numerical audit script (2026-10-10)

- User reran `gradle diagnoseXenonSleigh` after the Xenon-local `storeRegisterPartial` fix. **All eight** `stswiInstructions.sinc` unused-temporary warnings disappeared: total unused-temporary warnings dropped **9 -> 1**. The remaining one is inherited `xenon_ppc_isa.sinc:2575` (`setb` dead `tmpcr` computation). The NOP count remains **86**, redundant zero extensions **4**, and unreferenced tables **4**, all previously classified. SLEIGH preprocessing/compilation progressed through these diagnostics; the pasted excerpt does not itself include Gradle's final SUCCESS line.
- Confirmed Ghidra's documented SLEIGH truncation syntax: `word(3)` drops three **least-significant bytes** from a 32-bit varnode, so `word(3)`, `word(2)`, `word(1)` assigned to one-byte stores select the first, second, third big-endian byte, respectively. This is not the bit-range syntax `word[3,1]`.
- Added read-only `ghidra_scripts/AuditXenonStswiPartialStoresV1.java` for the user's already-loaded 17559 Xenon Program. Uses a fresh `EmulatorHelper` per case; writes synthetic STSWI instructions and sentinel destination bytes **only in emulator state**, never to Program memory. Source registers `r3..r10`; destination base `r20` deliberately does not alias a source. Checks full 48-byte buffers to detect trailing-byte clobber. Covers NB = 1..11, 31, 0 (architectural count 32), including all partial tails and whole-word boundaries.
- **Next:** run the focused audit script on the Xenon-language kernel Program (after installing/activating the rebuilt extension). Compilation and absence of warnings do not prove memory-side semantics. When the script passes, resume the three real kernel `lwarx`/`stwcx.` critical-section/allocator functions; do not repeat the 3,414-case completed numerical fixture.
