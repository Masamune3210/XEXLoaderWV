# Early retail XEX PE section bounds (testing)

## Reason for change
Retail *Kameo: Elements of Power* (Xbox 360 launch title) decompresses to a
`0xBF0000`-byte XEX image. Its embedded PE metadata reports
`SizeOfImage=0xC8DC00`. The last section, `.reloc`, begins at RVA
`0xBA0200` and declares `VirtualSize=0x675C0`, extending to `0xC077C0`.
The prior importer rejected the executable because it required that the
entire declared PE section fit within the decompressed XEX image.

Analysis of retail kernel 1888 (recorded in
`Masamune3210/360decompwork/reports/1888-xex-loader-kameo-image-layout-20261105.md`)
established that the observed XEX mapping and decompression paths use XEX
security metadata / compressed-image descriptors, not embedded PE
`VirtualSize` as the source of decoded image size.

## Implemented
- `src/main/java/xexloaderwv/XexPeSectionExtent.java` determines the
  **backed** bytes of a PE section from its RVA, declared virtual length,
  and decoded XEX image length.
- `XEXHeader.ProcessPEImage` imports only backed bytes; it does **not**
  zero-pad a PE section's virtual tail or reinterpret decoded image bytes
  using `PointerToRawData`.
- Partially backed sections produce a loader warning and retain the
  original PE `VirtualSize` in their Ghidra memory-block description.
- Section starts outside the decoded image and negative sizes/RVAs remain
  import failures. No broad relaxation of XEX integrity checks was made.
- Unchanged: LZX SHA-1 authentication, decompression, import processing,
  `.pdata` extraction, export processing, entrypoint registration.

## Kameo regression
`0xBF0000 - 0xBA0200 = 0x4FE00` bytes are backed.
The remaining `0x675C0 - 0x4FE00 = 0x177C0` bytes are only declared in the
PE's section virtual extent and are not imported.

## Verification
- Standalone JDK 21 compile: **PASS** (only the new dependency-free
  helper and test harness).
- `src/test/java/xexloaderwv/XexPeSectionExtentTest.java`: **12 checks PASS**
  for Kameo, normal/exact-end sections, overflow-resistant arithmetic,
  and invalid section bounds.
- Full Ghidra extension compile/package: **NOT RUN** (no matching Ghidra
  SDK installed in the validation environment).
- Actual Kameo import inside Ghidra: **PENDING**.

## Next expected step
Build the `testing` extension with the user's installed Ghidra, import the
retail Kameo `default.xex`, and verify `.reloc` maps only
`0x82BA0200..0x82BEFFFF` while the importer logs the virtual tail
warning. Check that the rest of the game's sections and function discovery
remain intact. This fix does not address separate Xenia runtime behavior.
