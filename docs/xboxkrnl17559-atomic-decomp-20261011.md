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

## STSWI numerical verification complete; proceed to real atomics (2026-10-10)

- User ran `AuditXenonStswiPartialStoresV1.java` inside the Xenon-language kernel Program. **All 13/13 numerical emulator cases passed** for NB=1..11,31,0 (architectural count 32). Each checked actual stored bytes and that the remainder of the 48-byte destination buffer remained unchanged. Audit reported **source Program unchanged**. **The corrected Xenon-only `storeRegisterPartial` semantics are now verified for all tested byte counts** and the STSWI warning regression is closed.
- Inspected installed-version Ghidra 12.1.3 source: `stwcx.` remains `if (RESERVE == 0) goto inst_next; *[ram]:4 EA = storeWordConditionalIndexed(S,RA_OR_ZERO,B); cr0flags(0)`. `sync` remains `sync(tmp)`. The existing `stwcx.` implementation does not encode a reservation-address or length check, does not clearly model reservation consumption on the failure path, and cannot express contention-dependent success via its opaque userop. `cr0flags(0)` forces EQ=1 on the guarded path regardless of actual hardware outcome. **Do not replace the opaque conditional store with a guaranteed store or simply erase barriers.**
- Cross-checked Xenia's `ppc_emit_memory.cc`: lwarx establishes a reserved value; stwcx uses atomic compare-exchange in its implementation and explicitly maps operation result to CR0.EQ, LT=GT=0, while retaining the appropriate SO bit. Xenia assumes global locking or uses atomic compare-exchange for competing writes; its implementation is useful evidence, **not proof that unconditional success matches Xenon hardware**.
- Added read-only, targeted `ghidra_scripts/AuditXboxKrnl17559AtomicPcodeV1.java`. It reads the **real Program's decoded p-code** at the five established lwarx/stwcx pairs and three `sync` sites, reports the `RESERVE`/`RESERVE_LENGTH`/`RESERVE_ADDRESS` outputs per lwarx, opaque userops, and function ownership across branch `0x80088FF8 -> 0x800890AC`. It does not mutate the database. **Runtime test pending** for that script; no changes to `stwcx.` p-code yet pending real-site evidence. No need to repeat the completed 3,414 numerical fixture or STSWI 13-case test.
- Next: run focused audit, inspect the resulting actual reservation p-code and CR0/store control flow, then decide on precise, conservative SLEIGH corrections for `stwcx.` preserving contention uncertainty and barrier semantics. Function-boundary fixes require demonstrated incorrect Ghidra ownership.

## Real 17559 atomic p-code audit result and conservative stwcx. model (2026-10-10)

- User uploaded complete `AuditXboxKrnl17559AtomicPcodeV1.java` output (244 log lines). **All five** real `lwarx` instructions wrote `RESERVE=1`, `RESERVE_LENGTH=4`, and `RESERVE_ADDRESS=EA`. Thus the earlier Xenon-only reservation fix is **runtime verified in the actual kernel** at `80064574`, `800647bc`, `80088fbc`, `80089020`, `80089050`. This supersedes earlier "pending" notes. No numerical fixture rerun is necessary.
- Each corresponding `stwcx.` site (`8006457c`, `800647c4`, `80088fc4`, `80089028`, `80089060`) emits exactly one `storeWordConditionalIndexed` CALLOTHER followed by an unconditional p-code STORE on the guarded path, then `cr0flags(0)`. RESERVE=0 branches straight to next instruction, leaving stale CR0. On the guarded path CR0.EQ is unconditionally set to 1 even though hardware can reject a reservation; this is **incorrect** and affects loop interpretation.
- Three real `sync 0x1` sites (`80088fd0`, `80089034`, `80089070`) still emit opaque `sync` CALLOTHERs and must remain intact until barrier semantics are modeled.
- Ghidra's conditional branch at `80088ff8` is confirmed as `bne 800890ac` with an actual flow edge into a separately defined entrypoint `FUN_800890ac`, while its source belongs to `RtlEnterCriticalSection @ 80088fa0`. **Do not merge or delete** that function merely on this evidence; no validated .pdata interval or incoming-XREF survey has yet been returned.
- Implemented a narrow, fail-closed replacement of the stock **`stwcx.` only** in `prepareXenonCommon`'s generated `xenon_ppc_instructions.sinc` (not Ghidra stock). Exact Ghidra 12.1.3 constructor text, including tabs, matched once. Replaced the unconditional STORE with an atomic `xenonAtomicStoreWordConditional` CALLOTHER returning a one-byte success indicator. The userop must perform the atomic memory commit as a single opaque side effect and return success/failure; no concrete CAS/contended behavior was invented. If RESERVE=0, success stays 0. After either outcome, RESERVE and RESERVE_LENGTH clear, and CR0.LT/GT are 0, CR0.EQ reflects success, CR0.SO copies XER.SO. Other `stdcx.` and `sync` constructors are unchanged.
- Added a source-level regression to `test_xenon_isa_coverage_v1.py` and a unique read-only `ghidra_scripts/AuditXboxKrnl17559AtomicPcodeV2.java`. V2 checks the five real lwarx and stwcx p-code shapes and prints the original function's comment/body extent, the `FUN_800890ac` ownership and references, plus a small instruction neighborhood. It does not modify Ghidra Program memory or functions.
- **Verification:** real V1 result PASSED for lwarx and exposed all five defective stwcx sites. Replacement source is committed but its **SLEIGH compile and runtime V2 tests remain pending**. When installed extension is rebuilt/reloaded, run V2. Atomic userop remains intentionally opaque and not executable as a native CAS in the generic Ghidra emulator; do not report full hardware emulation. Based on V2's .pdata/XREF evidence, determine whether the separate entry at `800890ac` should be merged or preserved. Do not repeat completed 3,414-case Xenon numerical suite or 13-case STSWI suite.

## V2 runtime verification and correct .pdata boundary; stdcx. follow-up (2026-10-10)

- User ran `AuditXboxKrnl17559AtomicPcodeV2.java` against installed Xenon-language kernel. **All 5/5 real lwarx and 5/5 updated stwcx. sites PASSED**: old userop=0, native STORE=0, new opaque `xenonAtomicStoreWordConditional`=1 (one-byte success output), both reservation fields cleared, and eight CR0 p-code writes per store conditional. All three `sync` userops remain present. This verifies compiled p-code structure on real firmware; **not** actual hardware contention or execution of the opaque userop.
- Crucial correction to earlier *suspected split*: branch `0x80088FF8: bne 0x800890AC` targets a **legitimate independent .pdata function** with verified unwind span `[0x800890AC,0x800890F8)`, separate prologue at `800890ac` (saves r31/LR/r30, allocates stack at `800890b8`), and one incoming `CONDITIONAL_JUMP` from the outer `RtlEnterCriticalSection` function. `RtlEnterCriticalSection` has body `[80088fa0,800890ab]`, 268 bytes. Helper `FUN_800890ac` has reachable body `[800890ac,800890f7]`, 76 bytes. **Do NOT merge/reassign 800890ac into RtlEnterCriticalSection or change the verified .pdata spans.** The branch likely transfers into a dedicated cold/slow-path helper but its precise purpose is not yet proven; preserve unresolved name/signature.
- Additional inherited ISA defect independently confirmed from exact installed Ghidra 12.1.3 source: `stdcx.` (XOP=214) has the same guarded opaque store + native unconditional 8-byte STORE, stale-CR0 failure path, and forced success on the taken path as `stwcx.`. Extended the Xenon-only exact-match generator with `xenonAtomicStoreDoubleWordConditional`, a one-byte success result, reservation consumption and result-based CR0.LT/GT/EQ/SO. Kept atomic memory side effect inside one opaque userop and kept original Ghidra sources untouched. Added separate static test. **New `stdcx.` correction not yet SLEIGH-compiled or p-code verified on real instructions; the user must rebuild.** No unsupported claim about actual hardware contention or CAS execution.
- Added read-only `ghidra_scripts/AuditXboxKrnl17559CriticalSectionHelperV1.java`. It prints target helper's metadata, instructions and decompiled output, branch caller neighborhood and incoming references, without changing Ghidra data. Use results to determine an evidence-based helper name/signature, if possible; do not guess one in advance.
- Next: `git pull`, `gradle buildExtension`, activate rebuilt language; run focused helper audit. An `stdcx.` 8-byte p-code audit can be added once a real target or deliberately scoped synthetic instance is identified, without repeating the completed 3,414 numerical fixture or 13-case STSWI tests.

## Consolidated branch audit and regression hardening (2026-10-11)

### Completed and verified externally
- Real kernel `AuditXboxKrnl17559AtomicPcodeV2` output: all **5/5** existing `lwarx` reservation writes and **5/5** patched `stwcx.` p-code shapes PASS; all three `sync` opaque barriers remain. This is p-code structural verification on the real 17559 kernel, **not** a runtime simulation of memory contention.
- Synthetic `stswi` numerical execution: **13/13** pass with sentinel byte preservation. The original Xenon numerical suite **3,414/3,414** passed previously and is not being rerun merely to repair tests.
- `FUN_800890ac` has its own verified `.pdata` span `[800890ac,800890f8)`, distinct function prologue, and one incoming conditional branch from `RtlEnterCriticalSection` at `80088ff8`. Retain two functions and separate unwind metadata; do **not** merge. Exact helper purpose, parameter types and return remain unresolved.

### Reproducibility defects fixed during complete source review
- Found that `XEXLoaderWV/tools/test_xenon_isa_coverage_v1.py` references `ghidra_scripts/AuditXenonNumericalPcode.java` in many tests, but an earlier cleanup deleted that source. Restored **only that unified stable script** from the last pre-deletion blob (`2f647d002839`), without resurrecting six superseded audit files.
- The test suite's `glob("AuditXenon*.java")` accidentally rejected the newer focused STSWI diagnostic. Narrowed it to `AuditXenonNumericalPcode*.java`, so it checks uniqueness of the numerical entry point rather than forbidding unrelated, scoped audits.
- Restored historical numerical script also had a machine-specific hardcoded `C:/Users/Johnny/...` manifest path, incompatible with the user's current `G:` checkout and fresh clones. It now locates `xenon_isa_fixture_v1.tsv` beside `currentProgram.getExecutablePath()`, with optional `XENON_ISA_FIXTURE_TSV` override. Matching test expectations updated.
- Added Gradle `testXenonIsaCoverage` Exec task and made it a dependency of `verifyXenonSleigh`, itself mandatory for `build`, `buildExtension`, `assemble`. A standard extension build now regenerates the fixture, runs the full offline Python regression suite (including dependency checks), and compiles SLEIGH before packaging. Tests intentionally always run instead of being skipped by cached timestamps.
- Performed **22/22 passing structural source guards** comparing exact stock Ghidra 12.1.3 constructor/macro bytes and unique matches, generated atomic result+no native-STORE invariants, inherited include tree, corrected byte stores, fixture portability and test-task wiring. Confirmed upstream `ppc_common`, `ppc_instructions`, and `ppc_isa` are the only stock files with relative include dependencies in the examined closure; all expected paths are handled.

### Verification boundaries / remaining engineering
- **Not performed in this execution environment**: run Python unittest suite or installed-Ghidra 12.1.3 `SleighCompile`, since the working repository and Ghidra installation are not accessible here. Never claim 22/22 static checks equals a compiled build or 3,414 new tests.
- `stdcx.` doubleword store-conditional was corrected in the Xenon-only generator by exact-match source and static tests, but there is no user-supplied compiled p-code or runtime numeric result for this **new** patch. Its atomic commit is an intentionally opaque userop, with contention and memory effects not emulated by generic Ghidra. `sync` is likewise deliberately opaque.
- No evidence-based rename or complete signature for `FUN_800890ac`; do not invent or merge metadata merely to make decompilation look cleaner. The existing read-only helper audit is available if separately desired, but no more one-by-one manual audit requests are needed for this source sweep.
- Next practical integration check is a **single** standard `gradle buildExtension` on an installed Ghidra 12.1.3 checkout, which now runs the offline tests + actual SLEIGH compile in one command. Capture failures only if any; otherwise this branch is structurally ready for integration review. Do not restart previous validated numerical audits.

## Ghidra script compilation failure fixed (2026-10-11)

- User's installed Ghidra 12.1.3 Java script compilation reported one **fatal** checked-exception diagnostic: `ghidra_scripts/AuditXboxKrnl17559CriticalSectionHelperV1.java:39`, `monitor.checkCancelled()` inside `private void dumpFunction(Function fn)` without declaring `CancelledException`. The helper now imports `ghidra.util.exception.CancelledException` and declares `throws CancelledException`; caller `run()` already declares `throws Exception`.
- A separate series of **nonfatal** `[removal]` warnings came from Ghidra's deprecated `EmulatorHelper` and `DefaultEmulator` in the stable unified numerical and 13-case STSWI scripts. Both now apply narrow class-level `@SuppressWarnings("removal")` to preserve their proven emulator-private numerical behavior without swallowing other compiler diagnostics. **No change to instruction semantics or test oracles**.
- Checked all five current `ghidra_scripts/*.java` for filename/public-class matching and the relevant `monitor.checkCancelled` method contexts; only the helper's `dumpFunction` required a checked-exception declaration. Added an offline Python source regression requiring the helper exception contract, matching Java entrypoint names, and targeted removal suppression; `buildExtension` already gates on this Python suite.
- **Verification:** the code changes and source audit were completed through the connected GitHub repository. The user's local Ghidra Java compiler is unavailable here, so actual recompilation of these revised scripts is **pending**. These warnings are not a reason to rewrite deprecated emulator APIs wholesale or repeat already-passing 3,414-case numerical and 13-case STSWI experiments.
