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


## Xbox 360 retail 17559 kernel PE analysis

This extension includes `Xbox360RetailKernelPdataAnalyzer`, an **early Ghidra analyzer**
for the verified Microsoft retail 17559 `xboxkrnl.exe`. The normal **PE loader**
still imports this file; the analyzer is independently discovered by Ghidra,
and runs at `FORMAT_ANALYSIS + 1` before generic function discovery.

- Requires `PowerPC:BE:64:A2ALT-32addr`, PE image base `0x80040000` and the
  *exact verified retail* executable SHA-256
  `e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8`.
  Other builds are intentionally untouched.
- Validates the 3,188 non-overlapping big-endian `.pdata` records and the
  931-slot little-endian PE export directory before modifying the Program.
- Seeds bounded disassembly and explicit function bodies for established
  `.pdata` ranges. Uses the existing `ImportRenamer` ordinal-name mapping
  for all 921 populated exports, including 17 code aliases.
- Marks the 317 code exports not covered by `.pdata` as external entrypoints
  without guessing their function lengths. Names non-executable data exports,
  but does not turn them into functions.
- Does not change any imported bytes, function signatures, or datatypes.

**For a clean test**, build/install this extension, restart Ghidra, then
import `xboxkrnl.exe` as a regular PE and enable the
`Xbox 360 Retail Kernel 17559 Pdata` analyzer in the initial Auto Analyze
dialog. Confirm the Auto Analysis log's function counts, and inspect the
exported functions before importing XAM through the XEX loader.

The earlier standalone export/.pdata scripts are for diagnostic purposes; do
not run them on this clean-import test. The kernel analyzer has not yet been
compiled or end-to-end tested with Ghidra 12.1.3.


### Early kernel disassembly behavior

The FORMAT-stage kernel pass can encounter valid .pdata entries before Ghidra
has established instructions for them. The analyzer now reserves the exact
verified function body even if its entry point is still undefined, so later
generic function discovery cannot absorb that range. If the entry is already
defined as data, it remains untouched and is reported as an explicit conflict.
The analyzer separately reports pending instructions, true function creation
failures, and pre-existing export entrypoints. A successful metadata boundary
pass is not proof that every instruction has been decoded; check the normal
auto-analysis results before declaring full coverage.
