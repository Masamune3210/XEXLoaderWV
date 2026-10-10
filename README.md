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
5. After Auto Analyze completes, run the read-only
   `ghidra_scripts/AuditXboxKrnl17559FlowBodiesV2.java` and compare
   its surviving entry and export counts to the previous broken-byte run.

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

`ghidra_scripts/AnnotateXboxKrnl17559MissingVectorInstructionsV1.java`
can attach SHA- and opcode-verified EOL comments identifying the 16 decoded
mnemonics in an existing Program. **It deliberately leaves all error bookmarks,
instruction bytes and function definitions alone**, and cannot substitute for
a Xenon VMX128-compatible language module. Check that `KeBugCheckEx` is marked
No Return and that its call at `0x80073730` terminates control flow before
removing the one obsolete padding bookmark. Do not clear legitimate
unsupported-instruction bookmarks to manufacture a clean audit.


### Existing kernel bookmark correction

The analyzer now automatically models the verified `KeLeaveUserMode` fatal
branch as a nonreturning call to `KeBugCheckEx`, validates its exact bytes,
and removes **only** the matching stale padding error bookmark. To apply
that same correction **without reimporting** an existing database, run
`ghidra_scripts/RepairXboxKrnl17559ErrorBookmarksV2.java` in Ghidra.
This script also comments the 16 Xenon instructions with independently
verified mnemonics, but does **not** purport to decode them.

The remaining 16 opcode bookmarks reflect missing stock PowerPC language
constructors; fixing those requires a compatible SLEIGH processor language,
not manipulating the PE loader or concealing errors. The current working
language and successful .pdata state remain unchanged.
