# X360 XEX Loader for Ghidra by Warranty Voider

This is a Ghidra loader extension for Xbox 360 XEX files.

## SaveEditors Fork Updates

This fork carries maintained fixes and publishes ready-to-install release zips.

- SaveEditors fork release: `13.0.0` (`Bug fixes`)
- Fixed PDB enum imports so enums use their actual underlying storage size instead of always importing as 8-byte enums.
- Fixed PDB root stream page counting so PDBs with sub-page root directories parse correctly.
- Fixed CodeView `LF_ARRAY` imports so byte lengths are converted into the correct element counts.
- Fixed `.pdata` handling so imported entries become real Ghidra functions instead of label-only symbols.
- Release zips for the fork are published on the [Releases](https://github.com/SaveEditors/XEXLoaderWV/releases) page.
- The upstream patch was submitted as [zeroKilo/XEXLoaderWV#33](https://github.com/zeroKilo/XEXLoaderWV/pull/33).

## Features

- Supports PDB/XDB files.
  - In the loader import page, click Advanced.
  - Tick `Load PDB File` and `Use experimental PDB loader`, then untick `Process .pdata`.
  - Select `MSDIA` parser.
- Supports XEXP delta patches.

Requires the minimum Java version required by your Ghidra install.

[![Alt text](https://img.youtube.com/vi/coGz0f7hHTM/0.jpg)](https://www.youtube.com/watch?v=coGz0f7hHTM)

<!-- this video is outdated -->
<!-- [![Alt text](https://img.youtube.com/vi/dBoofGgraKM/0.jpg)](https://www.youtube.com/watch?v=dBoofGgraKM) -->

## Build

This extension is built using the Gradle support files that ship with Ghidra. The required Java and Gradle versions come from:

```text
<GHIDRA_INSTALL_DIR>\Ghidra\application.properties
```

Do not edit those values in Ghidra just to build this project. Instead, use a JDK and Gradle version that satisfy your installed Ghidra release.

For Ghidra `12.0.4`, the current minimums are:

```text
application.java.min=21
application.gradle.min=8.5
```

This fork was validated against Ghidra `12.0.4`, JDK `21`, and Gradle `9.3.1`.

Example:

```powershell
$env:GHIDRA_INSTALL_DIR='A:\Tools\ghidra_12.0.4_PUBLIC'
$env:JAVA_HOME='A:\Tools\jdk-21'
gradle buildExtension
```

If you are building from Eclipse or another IDE, make sure it uses a compatible JDK and Gradle version for the Ghidra version you are targeting.


### Current Xenon branch verification (Ghidra 12.1.3)

The experimental `PowerPC:BE:64:XENON-32addr` language and the
`fix/import-thunk-modeling-20261009` branch are validated against
**Ghidra 12.1.3**; the generic loader build history above refers to the
older 12.0.4 environment.

A single `gradle buildExtension` now regenerates the Xenon ISA fixture,
runs `tools/test_xenon_isa_coverage_v1.py`, compiles the real SLEIGH
language, and only then packages the extension. Build failures in either
the Python suite or SLEIGH are fatal. The unified numerical Ghidra script
is `ghidra_scripts/AuditXenonNumericalPcode.java`. It locates its TSV
beside the imported fixture binary, with an optional
`XENON_ISA_FIXTURE_TSV` environment override, not a user-specific path.

Previously observed results: 86/86 family decoding expectations,
3,414/3,414 Xenon numerical p-code cases, 13/13 emulator-private STSWI
byte-store cases, and 5/5 `lwarx` plus 5/5 `stwcx.` real-kernel p-code
checks. The latter verify p-code *structure*, **not** executable hardware
contention behavior. The `stdcx.` doubleword atomic refinement is
source-checked but has not been compiled or runtime-verified in the
user's Ghidra installation. Both atomic-store commits and `sync`
barriers remain intentionally opaque user operations.

The retail 17559 `.pdata` span `0x800890AC..0x800890F8`
(end exclusive) belongs to a separate, genuine helper,
`FUN_800890ac`, reached by a branch from
`RtlEnterCriticalSection`. Do not merge those functions.
For detailed verification state and deliberately unresolved signatures,
see `docs/xboxkrnl17559-atomic-decomp-20261011.md` and
`docs/import-thunk-modeling-20261009.md`.

The older kernel import and decoder sections below are **chronological
investigation notes**, not current test instructions. Several one-off Java
audit scripts cited there were retired; only scripts actually present
under `ghidra_scripts/` should be run. This preserves historical results
without presenting deleted filenames as supported entrypoints.


### Xenon legacy `tlbiel RB,L` page-size decoding (October 2026)

The original HV17559 instruction at raw `0x3B4` is `7C201A24`.
PowerPC Book III v2.02 decodes this as **`tlbiel r3,1`**:
`RB=r3` and a **one-bit immediate `L=1`** selecting large-page
local TLB invalidation. The existing Xenon Ghidra language incorrectly
used newer POWER ISA 3.0 forms, showing `tlbiel r3,r1,0,0,0`
and supplying `r1` as a false processor-ID operand.

The `prepareXenonIsa` generator now removes exactly three newer
`tlbiel` constructors from the Xenon-only copy and generates the
explicit `L=1` constructor. The `prepareXenonCommon` generator
retains the original `L=0` form but supplies a constant `0` to
the existing `TLBInvalidateEntryLocal` userop; the `L=1` constructor
supplies a constant `1`. The TLB invalidation itself remains an
opaque user operation, **not an implementation of guest MMU effects**.
Stock Ghidra files and other PPC language variants are untouched.

`testXenonLegacyTlbiel` now runs during
`gradle buildExtension`, verifying the original `0x7C201A24`
bit fields, both constructor forms and removal of the ISA 3.0
collision. A separate **read-only** Ghidra runtime audit lives at
`360decompwork/ghidra_scripts/VerifyXenon17559TlbielLegacy_20261022_v1.java`.
It checks the actually loaded installed language's decoded instruction
and p-code and writes the result under the user's redirected Downloads/2.

**Verification:** source rewriting was cross-checked against archived
Ghidra 12.1.3 native SLEIGH sources, and the original instruction bits
against PowerPC 2.02 Book III, p. 54. Integrated Gradle compilation
and Ghidra runtime validation for this new `tlbiel` change remain
**pending**. The previously verified `hrfid` return-flow correction
is separate and retained.

### Xenon HV17559 `hrfid` return-flow correction (October 2026)

The retail 17559 HV contains a native `hrfid` at raw offset `0x994`.
The previously installed Xenon language represented this as an opaque
`CALLOTHER` with an incorrect `FALL_THROUGH` flow type. Its hardware
return target is HSRR0 (SPR 314, existing 64-bit `spr13a`), not `0x998`.
The code at `0x998` remains independently reached by the native branch
`0xC30: 4BFFFD68` and must not be deleted.

On `testing`, `prepareXenonIsa` now generates the narrowly changed constructor
`{ hrfidOp(); return[spr13a]; }`, preserving the opaque HSRR1/MSR effects.
It checks the *exact original constructor* in Ghidra's stock ISA and fails
closed if that source has changed. The extra
`tools/test_xenon_hrfid_flow_v1.py` regression is a required dependency
of `verifyXenonSleigh`, which runs on `gradle buildExtension`.

**Verification:** A task-private SLEIGH compile and actual p-code test of
both versions passed using the original HV instruction bytes
`4C000224 802D002C`. The private baseline was identical to the previously
installed language, and all installed extension file hashes were preserved
by the test. The integrated Gradle rebuild and database reload have **not**
yet been verified. This corrects **control flow only**, not full HSRR1/MSR
hardware modeling, CR0 semantics, or the native C++ decompiler.

Build and install the updated extension using the existing Ghidra 12.1.3
workflow. Preserve/export the current HV Ghidra program before switching
processor files; existing analyzed Ghidra programs do not necessarily
recalculate stored references and function boundaries automatically.
After restarting Ghidra with the rebuilt language, the read-only
`360decompwork/ghidra_scripts/VerifyXenonHrfid17559InstalledFlow_20261022_v1.java`
audits actual `0x994` p-code, the preserved branch into `0x998`, and
current function ownership. It writes under
`G:\\Users\\Johnny\\Downloads\\2` and **does not modify the program**.
Do not clear/reimport the existing hypervisor program merely to fix a
fallthrough edge.

## Xbox 360 retail 17559 kernel memory-image PE import

**IMPORTANT: The raw 17559 kernel split from the firmware is an already-mapped
memory image, not a normal file-layout PE.** Its embedded COFF section headers
retain file offsets that differ from where the firmware image actually stores
the section bytes. For example, `.text` content is at physical `0x21000`,
but `PointerToRawData` says `0x1C400`. Importing this exact original image
through Ghidra's ordinary PE loader produces **incorrect code bytes at nearly
all function addresses**, no matter how carefully functions are annotated.

The extension now offers two safe workflows:

1. **Original, unchanged verified kernel:** import `xboxkrnl.exe` and select
   **Xbox 360 Kernel 17559 Memory Image PE** in the import dialog. This
   SHA-256-gated `PeLoader` subclass reads section bytes from their in-memory
   virtual offsets and delegates standard PE metadata handling to Ghidra.
   This path never modifies the source firmware-derived image.
2. **Standard Ghidra PE loader:** normalize only the five section
   `PointerToRawData` fields with
   `tools/NormalizeRetailKernel17559MemoryPeV1.py`, then import the
   normalized copy as an ordinary PE. Keep the original kernel unchanged.

Both paths retain image base `0x80040000` and language
`PowerPC:BE:64:A2ALT-32addr`. The destination Ghidra Program should
be named `xboxkrnl.exe` for automatic XAM library linkage.

| File / import route | Expected executable SHA-256 |
| --- | --- |
| Original through **Xbox 360 Kernel 17559 Memory Image PE** | `e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8` |
| Normalized copy through **Portable Executable (PE)** | `1c6113602af25b0762fb10dfb0d7ad5c7fef1c7268826982188979b9bb2e4d85` |

`Xbox360RetailKernelPdataAnalyzer` only runs for one of these **correct
loader/file pairs**, never when the original memory-layout image is imported
with the standard FILE-layout PE loader.

The analyzer validates all 3,188 big-endian `.pdata` records (including
encoded unwind lengths), the 931-slot export directory, and all affected PE
memory blocks before creating any labels or functions. It uses bounded PPC
disassembly, seeds known function entries, constructs reachable-code bodies,
and preserves verified unwind extents in repeatable comments. It also
labels the 921 populated kernel exports via the shared `ImportRenamer`
ordinal mapping, preserving aliases.

**Validation sequence (Ghidra 12.1.3):**

1. Rebuild/install the extension and fully restart Ghidra.
2. Delete or set aside any prior kernel Program imported from the original
   memory image through the wrong PE loader. Its disassembly cannot be
   repaired by simply changing function boundaries.
3. Fresh import using **one** of the two correct loader/file pairs above.
   Enable `Xbox 360 Retail Kernel 17559 Pdata` at Auto Analyze.
4. Confirm the actual bytes at `0x80061010` are `7D 88 02 A6`
   (`mflr r12`), and `0x80089EB0` (`NtClose`) has the verified
   prologue. The earlier broken import presented zeros at `0x80061010`.
5. After Auto Analyze completes, compare the function/export counts with
   the independently recorded `.pdata` results in the branch handoff.
   The original `AuditXboxKrnl17559FlowBodiesV2.java` was retired.

The late Ghidra flow-repair errors and 700+ function removals seen in the
previous tests occurred against **incorrectly mapped instructions**.
Their persistence on a correctly mapped kernel is **not yet tested**.
The new memory-layout PE importer has been source-checked against Ghidra
12.1.3 APIs, but has not been compiled or executed in the user's installation.


### Retail kernel ordinal 126

The post-analysis V2 audit on the correctly mapped 17559 kernel demonstrated
all 3188 `.pdata` functions intact and 885/886 executable exports at function
entries. The sole remaining outlier was `KeLeaveUserMode`, ordinal 126,
`0x80073690`, a genuine code export without a `.pdata` unwind record.
The analyzer now conservatively seeds this single verified privileged-mode
routine, deriving its body only from reachable instructions within
`0x80073690..0x80073733`, rather than guessing a C signature or applying
new heuristics to all other no-`.pdata` exports.

This targeted addition is not yet runtime-tested. Existing correct-import
kernel databases otherwise pass the V2 boundary checks and can already
be used for XAM import/linkage investigation.


### Kernel decoder limitations and preserved error bookmarks

The latest verified 17559 kernel Ghidra archive passes the read-only
`.pdata`/export V2 audit (**3188/3188 functions; 886/886 code exports**) but
still stores **17 Bad Instruction bookmarks**: 16 actual Xenon vector
instructions absent from the stock PowerPC SLEIGH language (10 `lvx128`,
four `lvlx`, one `lvrx`, one `vupkd3d128`), plus a fall-through-into-padding
bookmark after the `KeBugCheckEx` call in `KeLeaveUserMode`. Function-boundary
success does not imply all instructions or their p-code are recovered.

The retired `AnnotateXboxKrnl17559MissingVectorInstructionsV1.java`
previously attached SHA- and opcode-verified EOL comments identifying those
16 decoded mnemonics in existing Programs. **It deliberately leaves all error bookmarks,
instruction bytes and function definitions alone**, and cannot substitute for
a Xenon VMX128-compatible language module. Check that `KeBugCheckEx` is marked
No Return and that its call at `0x80073730` terminates control flow before
removing the one obsolete padding bookmark. Do not clear legitimate
unsupported-instruction bookmarks to manufacture a clean audit.


### Existing kernel bookmark correction

The analyzer now automatically models the verified `KeLeaveUserMode` fatal
branch as a nonreturning call to `KeBugCheckEx`, validates its exact bytes,
and removes **only** the matching stale padding error bookmark. To apply
that same correction **without reimporting** an existing database, the
historical `RepairXboxKrnl17559ErrorBookmarksV2.java` was used; it is now
retired. Do not assume that source is included in this checkout or remove
bookmarks without rechecking the expected bytes.

The remaining 16 opcode bookmarks reflect missing stock PowerPC language
constructors; fixing those requires a compatible SLEIGH processor language,
not manipulating the PE loader or concealing errors. The current working
language and successful .pdata state remain unchanged.


### Experimental Xenon PowerPC language (VMX128 groundwork)

The default Ghidra `PowerPC:BE:64:A2ALT-32addr` cannot decode several actual
Xbox 360 vector instructions. The extension now contains an **experimental
separate language**, `PowerPC:BE:64:XENON-32addr`, compiled from
`data/languages/xenon_64_be.slaspec` and `xenon_vector_v1.sinc`.
The compiler's `-dPowerPC` option imports the installed Ghidra 12.1.3
stock processor sources. **Do not overwrite Ghidra's stock PowerPC .sla or
switch the language of an existing verified kernel Program to test it.**

The initial Xenon variant adds 128 independently addressable vector registers
and instruction constructors for `lvx128`, `lvlx`, `lvrx`, and
`vupkd3d128`. The indexed loads include vector p-code; D3D unpack uses an
explicit **opaque userop** because its per-format numeric behavior is not
yet modeled. This is a decoder prototype, **not complete Xenon compatibility**.

The verified 17559 kernel contains **422 32-bit words** matching those four
patterns in executable `.text` (269 `lvx128`, 127 `lvlx`, 15 `lvrx`,
11 `vupkd3d128`); all 16 current vector-error bookmarks are included.

**Safe validation workflow:** build the extension with Ghidra 12.1.3,
then preserve your existing `A2ALT` kernel database. On a **separate**
fresh import using the specialized kernel memory-PE loader, select the
experimental `XENON-32addr` language choice explicitly; the original
`A2ALT-32addr` language remains the preferred default. After auto-analysis
the historical 16/16 bookmark-address decode result can be compared with
the completed Xenon ISA fixture and actual kernel audits. Do not delete existing bookmarks merely
because a Ghidra language is now available. Compare the new Program's
function and export coverage with the proven kernel database.

For independent opcode-pattern validation on the verified source image, run
`python tools/validate_xenon_sleigh_patterns_v1.py xboxkrnl.exe`.

**Historical status:** this described the initial language prototype.
The later compiled Xenon language and runtime audits are summarized in the
current verification section above.


### Xenon kernel decoder follow-up: second VMX128 tranche

The real 17559 Xenon-language `xboxkrnl.exe(6).gzf` imported with
`PowerPC:BE:64:XENON-32addr`, eliminating all 16 prior bad-instruction
bookmarks, but exposed 13 *new* instruction errors in six other families:
`vpermwi128` (3), `vmulfp128` (3), `vmsum4fp128` (2),
`vrlimi128` (3), `stvx128` (1), and `vor128` (1).

Additional constructors for these are now included in
`data/languages/xenon_vector_v1.sinc`. The vector store and OR have
concrete p-code; floating-point/permute/rotate operations currently
preserve source/destination dependencies with **opaque userops** rather
than incorrect fabricated numerical semantics. Run `gradle buildExtension`
to compile/check the updated SLEIGH before installing.

The retired `RepairAuditXboxKrnl17559XenonVmxV2.java` historically checked
29 original and newly uncovered error sites and selectively cleared only
bookmarks whose exact instructions were verified to decode. The pure byte-level
`tools/validate_xenon_sleigh_patterns_v2.py` provides an independent
raw-encoding check against the two supported SHA-256-verified kernel images.

**Historical status:** subsequent 29/29 decoder verification completed.
Do not infer numerical p-code correctness from the absence of bookmarks;
refer to the separate numerical audit counts above.


### Xenon VMX128 word merges (kernel `xboxkrnl.exe(8).gzf`)

After the second-stage 29/29 opcode audit passed, the Xenon-language
17559 archive revealed only two new bad-instruction bookmarks:
`0x800BD280` and `0x800BD35C`, both `vmrglw128`. The same
function region also contains `vmrghw128` instructions. Both merge
families are now defined in `data/languages/xenon_vector_v1.sinc`
with concrete 128-bit four-word interleave p-code, accounting for
eight exact matches (four per instruction family) in verified kernel
`.text`.

The retired `RepairAuditXboxKrnl17559XenonVmxV3.java` checked 37
confirmed opcode sites. It is not an available runnable script on this
branch; the raw byte-pattern validator remains available.
`tools/validate_xenon_sleigh_patterns_v3.py` independently checks
the exact opcode words against the verified 17559 image.

**Historical implementation status:** this predates the later 86-family
fixture and 3,414-case numerical audit. The remaining opaque operations
and verification boundaries are described in the current section above.


### Classic Xenon LVSL masks

The Xenon-only generated classic `lvsl` constructor now produces the 16
big-endian mask bytes `(EA & 15) + [0..15]`. Its RA=0 operand supplies zero;
RB=0 still reads physical r0. The previous inherited stock constructor called
an unimplemented userop and incorrectly read r0 for RA=0. Stock PowerPC language
files, existing userop indices, LVSR and VMX128 constructors are preserved.

After `gradle buildExtension` and installing the rebuilt extension, run
`TestXenonLvslMasks.java <output-directory>` from `ghidra_scripts` on a Xenon
Program. It exercises 2,048 numerical cases with an independent byte-array
oracle, all alignments, randomized full64 GPR carriers, overlapping operands,
and unchanged LVSR/VMX128 controls. On the supplied DASH Program it also checks
its stored opcode at92866aac, giving 2,049 checks. Fixtures are rolled back.
The old model failed1,281 checks and passed768 controls; the corrected model
passes all2,049. This corrects the instruction semantics; it does not resolve
the separate Ghidra unique-varnode-hash failure in DASH function92866540.
