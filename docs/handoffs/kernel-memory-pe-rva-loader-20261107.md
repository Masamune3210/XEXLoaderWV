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

## Verification
Initial state: not implemented. Update after code/test.
