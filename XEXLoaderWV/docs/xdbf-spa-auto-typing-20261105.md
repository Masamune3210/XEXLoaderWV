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
  base and the already mapped XDBF header bytes, then restores only
  missing resource-gap bytes and performs the full array/record typing.
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
