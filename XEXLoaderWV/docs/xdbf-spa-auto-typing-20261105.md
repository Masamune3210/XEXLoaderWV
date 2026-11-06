# Automatic XDBF / SPA typing in XEXLoaderWV

## Purpose
During a normal XEX import, recognize embedded title SPA databases from
XEX optional-header `RESOURCE_INFO` (`0x000002FF`) and apply meaningful
Ghidra types automatically. An SPA is an XDBF container used for title
achievement, string and image metadata that XAM can use when creating
per-profile GPD files.

Sources: https://free60.org/System-Software/Formats/XDBF/
and https://free60.org/System-Software/Formats/SPA/

## Implementation on `testing`
- `src/main/java/xexloaderwv/XexXdbfResource.java`:
  dependency-free parser for BE XDBF, version `0x00010000`, validating
  declared XEX resource bounds, capacity-sized entry/free tables, and
  every active record's data-relative offset and length. Keeps
  `highestReferencedPayloadEnd` separate from declared resource length.
- `src/main/java/xexloaderwv/XexXdbfGhidra.java`:
  maps missing *initialized* bytes between already-mapped PE sections
  only from the decoded XEX image, without overlaps, then registers
  three reusable datatypes in `/Xbox360/XDBF`:
  - `XdbfHeader` (`0x18`): ASCII magic plus five BE dwords;
  - `XdbfEntry` (`0x12`): BE namespace ushort, ID uint64,
    payload-relative offset uint32 and payload length uint32;
  - `XdbfFreeSpaceEntry` (`0x08`): two BE uint32 fields.
- Automatically applies `XdbfHeader` at the resource start and
  `XdbfEntry[entryTableCapacity]` and
  `XdbfFreeSpaceEntry[freeSpaceTableCapacity]` at their exact offsets.
  The **capacity** counts determine the two table extents, rather than
  the **active** record counts.
- Labels the payload start and individual active namespace/ID records
  without replacing existing user-defined data or disassembly. Record
  body bytes and trailing zero padding are **not** cast into one giant
  array, so later format-specific SPA/PNG/string analysis remains possible.
- Hook: `XEXHeader.ProcessPEImage`, after normal PE block mapping and
  before import and `.pdata` processing.
- `src/test/java/xexloaderwv/XexXdbfResourceTest.java`: synthetic
  regression fixture exercises resource addressing, capacities, active
  entry IDs, offsets, malformed extent rejection and padded tails.

## Kameo evidence and corrections
Title ID `4D5307D2` raw XEX descriptor:
```
Resource start:      0x82B90000
Descriptor length:   0x0005C1BA
Descriptor end:      0x82BEC1B9 (inclusive)
Decoded image end:   0x82BEFFFF (inclusive)
User-observed final achievement icon: 0x82BE8FB9
```
These represent **different boundaries**. In particular, an icon ending
at `0x82BE8FB9` does not mean the database's last record or descriptor
ends at the same address, and neither descriptor length nor final
nonzero byte implies the last live payload. The user reports zero padding
from after the last icon to the end of the decoded image. Only the
validated active XDBF entries establish the referenced payload spans.
No old inference that the final nonzero byte equals the database's
logical end should be retained.

## Verification
- Source and hook reviewed on branch `testing`.
- Standalone Java parser and test compiled with OpenJDK 21 and **15 checks PASS**.
  Local source bytes were checked against the exact GitHub blob SHA for
  each file (`e0c4deb039847289151d094dc890b72d981d1306` and
  `741082bf3be4b7d49da73da066c732448bd43a0e`).
- Full extension compile/package **not run**: no matching Ghidra installation
  available in the validation container.
- Actual retail Kameo import in Ghidra **pending**.

## Next expected step
Compile/pack the extension in the user's Ghidra installation, re-import
Kameo, and verify header / entry arrays / free-table arrays exist under
`/Xbox360/XDBF` and the missing resource gap blocks are initialized.
Confirm individual record labels are placed at the payload-relative
addresses and that the padding after the final referenced record is
still available for manual analysis.

## 2026-11-05 follow-up: run on already imported XEX programs

User noticed XDBF typing was initially hardwired only into
`XEXHeader.ProcessPEImage` on fresh import. A separate **default-enabled,
one-shot Ghidra analyzer** now handles existing imported programs too:

- `XexXdbfAnalyzer.java` appears as
  **Analysis > One Shot > XEX: Type XDBF / SPA databases**.
- Restricts itself to programs imported with
  `XEX Loader by Warranty Voider` using big-endian PowerPC.
- Scans initialized mapped sections for a valid XDBF header, including
  signatures crossing scan-window boundaries. Reuses the existing
  `/Xbox360/XDBF` datatypes rather than introducing duplicates.
- If the original XEX still exists at the imported program's executable
  path, decodes it using existing loader key choices, verifies the image
  base and **every byte of the already mapped XDBF resource spans**,
  then restores only missing resource-gap bytes and performs the full
  array/record typing. A same-title but different-build source is rejected
  if its mapped resource bytes do not match.
  Never overwrites previously mapped PE bytes.
- If the source file cannot be recovered, applies header and capacity-sized
  table arrays **only where their entire ranges are already mapped and
  readable**. An unmapped table is explicitly reported rather than
  silently fabricated or partially typed.
- Existing equivalent XDBF datatypes are accepted idempotently; existing
  conflicting Ghidra user data/code remains untouched. Unreferenced
  payload bytes and final padding are not typed.
- Preexisting imports may have partially unmapped XDBF resource data,
  so recovery of complete arrays requires the original XEX to remain
  available. Re-running analysis does not require re-importing the program.

Verification status:
- Existing dependency-free Java parser fixture: **15/15 checks PASS**.
- New Ghidra analyzer code reviewed against existing analyzer conventions.
- **Full Ghidra compile and manual One Shot invocation not verified yet**
  in the tool environment; validate with the user's installed SDK.

Next: rebuild/install extension, open the **existing** Kameo program, and
invoke the One Shot analyzer. Check the analysis log for resource-gap
mapping, and verify the typed header and capacity-sized arrays. If Ghidra
reports a Java compilation error or import failure, capture the exact
error and correct the analyzer without changing existing manual analysis.

## 2026-11-05 correction: Kameo existing import left most SPA bytes untyped

User supplied a 52,024-line Ghidra listing from the existing Kameo
program (`Pasted text(20261106-031030).txt`). This confirms the analyzer
recognized the header but applied **only** `XdbfHeader` and
`XdbfEntry[44]`; no payload records or complete free-space array were
defined.

**Verified layout from Ghidra listing and XDBF header:**
```
Title XDBF resource       0x82B90000..0x82BEC1B9 (length 0x5C1BA)
Header                    0x82B90000..0x82B90017 (24 bytes)
Entry table               0x82B90018..0x82B9032F (44 x 0x12)
Free-space table          0x82B90330..0x82B903E7 (23 x 0x08)
Payload relative base     0x82B903E8

Existing PE blocks:
.idata                    0x82B90000..0x82B903C5
.XBLD                     0x82BA0000..0x82BA00CF
.reloc                    0x82BA0200..0x82BEFFFF

Unmapped resource gaps:
                          0x82B903C6..0x82B9FFFF (0xFC3A)
                          0x82BA00D0..0x82BA01FF (0x130)
Total missing bytes:      0xFD6A (17.2% of declared resource)
Already mapped:           0x4C450 (82.8% of declared resource)
```

**Root causes identified:**
1. `typeMappedLayout` never iterated entry descriptors, so it did
   **not** type even the 82.8% of resource bytes already mapped.
2. It required the *entire* free-space table to be mapped to type any
   of it. The first **18 of 23** free-space entries are actually fully
   present within the original `.idata` block.
3. The source-XEX fallback could not fill the remaining gaps when
   `Program.getExecutablePath()` did not resolve to a usable matching
   original file, and previously gave insufficient actionable diagnostics.

**Fix now on testing:**
- Both importer and existing-program analyzer type nonempty active
  record payload spans as actual `byte[]` arrays, split per mapped
  memory block and preserving any existing user definitions.
- Mapped-only analyzer walks each of 44 entries to find the payload
  addresses (relative to `0x82B903E8`), label records, annotate
  namespace/ID/length and type available initialized data.
- Partial free-space table fallback types each fully available entry,
  with the missing remainder left untouched until source recovery.
- A new **Original XEX file (optional)** Ghidra analyzer option accepts
  an explicit source file path when the existing program's saved
  executable path is absent/stale. Source-backed recovery first
  verifies the image base and all already mapped XDBF resource bytes.
- No blind mapping, no modifying original PE bytes, and no guessing
  the last meaningful record from padding.

**Validation:** Layout math independently checked against the
52,024-line listing and previous Kameo descriptor. Previous 15/15
pure-Java parser checks still stand. New Ghidra-dependent analyzer
edits need a real extension build and One Shot execution to verify.

**How to retry:** Build/install the new `testing` extension, open the
existing Kameo program, configure the analyzer's optional source XEX
path under Analysis Options when needed, and run
`Analysis > One Shot > XEX: Type XDBF / SPA databases`. Compare
the log's `sourceRecovered` and typed payload totals. Missing
`0xFD6A` bytes cannot be reconstructed from the original Ghidra
memory blocks alone; supply the original XEX to recover them.
