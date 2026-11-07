# Reconstructed Xbox 360 kernel PE import (2026-11-07)

Branch: `fix/kernel-memory-pe-rva-loader-20261107`, based on `testing`. No modifications to `testing` yet.

## Why
Retail CF/CG kernel updates reconstruct an RVA-indexed in-memory PE image, but its embedded PE section headers preserve disk-format `PointerToRawData` values. Ghidra's ordinary PE loader maps from those raw offsets instead of `VirtualAddress`. This leads to bogus PowerPC code and disassembly-flow errors when Ghidra analyzes an otherwise SHA-1-verified kernel.

Evidence from supplied genuine 6717 `xboxkrnl(3).exe`: PE base `0x80040000`, image/file size `0x130000`; executable `.text` section RVA `0x20C00`, raw pointer `0x14200` (difference `0xCA00`). At `0x80119C00` Ghidra sees `48 00 1F F1`, a bogus branch to `0x8011BBF0`, because it uses file offset `0xCD200`. The correct byte at RVA `0xD9C00` is `80 00 00 00` (non-code). At true `.text` RVA `0x20C00` the bytes start `38 00 00 0D 44 00 00 02 4E 80 00 20`, valid PPC, whereas the bytes at raw pointer `0x14200` are zeros.

## Plan
- Implement a **narrow detector** in the user's `XEXLoaderWV` extension recognizing *only* RVA-indexed Xbox 360 kernel PE images, not normal MZ files, XEX2, or conventional on-disk PE files.
- Provide a dedicated Ghidra loader mapping PE section data from file offset **VirtualAddress**, with original image base, permissions, kernel export ordinals and optional .pdata symbols. Favor the detected loader in the import dialog.
- Add dependency-free synthetic fixture regression tests for both memory-image detection and rejecting conventional PE.
- Verify build/test where possible; do not rewrite reconstructed kernel files or alter Ghidra projects invisibly.

## Implementation

- `XEXLoaderWV/src/main/java/xexloaderwv/XboxKernelMemoryPe.java`: dependency-free detector and PE header/section parser. Recognizes Xbox 360 PPC PE32 at 0x80040000 only if the file is an exact SizeOfImage-sized in-memory image, executable section RVA differs from stale raw pointer, and actual RVA bytes look more like PPC code than stale raw-pointer bytes. Does not claim conventional on-disk PE images.
- `XEXLoaderWV/src/main/java/xexloaderwv/XboxKernelMemoryPeLoader.java`: new dedicated auto-discovered Ghidra loader; preferred over generic PE importer on positive detection. Imports section data at **file offset = VirtualAddress**, keeps PE headers intact, maps section permissions and actual image length, exposes ordinal exports using the same `ImportRenamer.Rename("xboxkrnl", ordinal)` names XAM uses, creates .pdata functions, establishes entrypoint. Requires no modification to firmware files or Xenia.
- `XEXLoaderWV/src/test/java/xexloaderwv/XboxKernelMemoryPeTest.java`: dependency-free Java 21 synthetic regression for 6717-like RVA/raw mismatch, negative ordinary disk PE, kernel base/machine checks and malformed header bounds. The generated test image is synthetic; no proprietary binaries are committed.

Commits: `5299a3f0` detection helper, `26013b6e` importer, `c7202a97` Java compatibility and export-bounds fix, `91b5fe63` tests, `0e379509` exports named for the fork's ordinal renamer, `2454a762` preserve unsigned 32-bit .pdata addresses.

## Verification

- Inspected user's uploaded reconstructed 6717 kernel `xboxkrnl(3).exe`: original file size = PE SizeOfImage = **0x130000**; imageBase **0x80040000**; .text RVA **0x20C00**, raw pointer **0x14200**, virtual size **0xBAE00**. Detector's chosen eight-instruction PPC sample scores **7 at RVA and 0 at raw offset**, satisfying its strong positive signature.
- The false Ghidra instruction at VA **0x80119C00** corresponds to file offset **0xCD200** when using the stale raw pointer, where the source image contains **0x48001FF1** (branch to **0x8011BBF0**). The correct RVA-backed file offset **0xD9C00** contains **0x80000000**, not that branch. This explains the repeated nonexistent-memory branch errors.
- The new loader must be used when importing the file. **Re-running analysis in an existing GZF imported under the wrong PE layout cannot reconstruct its memory blocks; reimporting is required.**
- **Ghidra build and Java regression tests not yet executed**; no Ghidra installation is available in this execution environment. Real GUI import and native import-library linking still require verification on user's Ghidra installation. The isolated detector logic was checked against the actual 6717 binary with a Python equivalent.
- The branch is based on `testing`; `testing` remains untouched. No proprietary kernel binaries or user GZF data are committed.

## Next step
Build/install extension on user's machine. Import `xboxkrnl.exe` from 6717, selecting **Xbox 360 Reconstructed Kernel (RVA Memory Image)** if it is not automatically preferred. Confirm .text begins at VA 0x80060C00 with bytes `38 00 00 0D 44 00 00 02 4E 80 00 20`; confirm no false branch at VA 0x80119C00; run auto-analysis, verify kernel export ordinals and XAM import linking. Then test other reconstructed kernel versions. Merge to `testing` only after verification.
