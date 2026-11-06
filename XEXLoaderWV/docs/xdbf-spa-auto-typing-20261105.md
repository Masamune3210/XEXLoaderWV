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
- Synthetic Java regression test **added**; runtime execution still pending.
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
