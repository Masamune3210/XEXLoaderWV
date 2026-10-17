# Xbox 360 retail 17559: October 17 post-CR0 checkpoint, v12

## Inputs and custody

- Input: `xboxkrnl.exe(20261017-144550).gzf`, SHA-256 `340397b2800446ab6a72aa8030bebbde4fa7e0d27946f80f31d1e600b96285cb`.
- It is a Ghidra serialized archive with a ZIP local-entry/DEFLATE payload, **not** the uncompressed retail executable.
- Extracted internal Ghidra database: 46,579,712 bytes (2,843 x 0x4000 blocks), SHA-256 `377ba93aa0224fb6be9ad2d9a1dec24bc5ca6b15e2cd5d6e2ce1aedc4300a43a`.
- 2026-10-14 comparison database: 42,532,864 bytes (2,596 blocks). No native-byte equivalence claimed solely from these storage metrics.
- Local ASCII string inventory identified retained preexisting labels and newly retained Codex symbol names. Strings are **not authoritative names, addresses, or function signatures** without Ghidra DB inspection.

## Primary discovery: protection-mask helper

Source: `AleBello7276/xkrnl-decomp`, debug 17489 `src/mmx_d/mmsup.c`, routine `MiMakePhysicalProtectionMask`.
Retail native source: user's 2026-10-15 `xboxkrnl-decompilation-20261015-continued.zip`, `full-export-final/asm/80080cb0.asm`.

The native PPC function occupies `0x80080CB0..0x80080D20` inclusive, 29 consecutive instructions = 0x74 bytes.
SHA-256 of concatenated original instruction bytes: `aa65bd4ee6b78e0ce6ccdad8e8dd90235f998103e9189d07166f5ac7f6827381`.

It masks/validates protection flag combinations, derives an output physical mask, writes a uint32 through the second argument, and returns success/failure through r3. Original archived Ghidra prototype:

```
undefined8 FUN_80080cb0(uint param_1, uint * param_2)
```

Safely supported partial metadata (after exact native SHA-256 match against the *live* database):

```
Address: 0x80080CB0
undefined8 MiMakePhysicalProtectionMask(uint protectionFlags, uint * outPhysicalMask)
```

The imported 17489 source returns `int`, but this does **not** justify changing the preserved 17559 `undefined8` or physical return storage, especially given the project's full-GPR-carrier discipline. The script only renames `FUN_80080cb0` and the two generic input names, conditional on an exact 116-byte body match, an existing entry function, two existing four-byte input slots, and a pointer type for the second input. Other names, customized signatures, bodies and datatypes remain intact.

## Xenon CR0 site witnesses

Archived exact PPC words and following branch bytes:

| Site | `rlwinm.` word | following branch word | Witness input low word | Confidence |
|---|---|---|---|---|
| `0x80080CB4` | `556B05E9` | `4182000C` | `0x200` | earlier private original-byte regression |
| `0x80083AF0` | `556B0499` | `4182006C` | `0x4000` | mathematical model only |
| `0x800925E4` | `556B075F` | `41820010` | `0x8` | mathematical model only |
| `0x800A81E8` | `556B0733` | `4082003C` | `0x10` | mathematical model only |
| `0x8010BF8C` | `554A0203` | `41820018` | `0x1000000` | mathematical model only |

The four newly identified sites have evidence-backed code bookmarks generated only after checking their exact native instructions and following branch. The script evaluates P-code zero-comparison widths for each site, reporting `LOW32_COMPARISONS`, `FULL64_COMPARISONS`, or `INCONCLUSIVE`. This is session-time evidence about loaded SLEIGH. The `.gzf` alone cannot attest to the installed language version. **A record branch with a mathematical witness does not mean the runtime ever supplies that input.**

## Artifact

Committed to `Masamune3210/XEXLoaderWV` branch `testing` as `ghidra_scripts/AuditXboxKrnl17559PostCR0Checkpoint_20261017_v2.java`. This v2 is a repository relocation of the previously provided v1 script; the metadata application and byte guards are unchanged. The file's Java public class was updated to match its versioned filename. The script has not been executed against the live Ghidra project.


`AuditXboxKrnl17559PostCR0Checkpoint_20261017_v2.java`

- Run in the live 17559 kernel program after creating a backup.
- By default, applies only the native-SHA-qualified helper rename/generic parameter names and four repeat-safe, categorized Note bookmarks. Set `APPLY_VERIFIED_METADATA=false` for read-only auditing.
- Retains all function bodies, original instruction bytes, signatures and storage/return types, datatypes, and all existing comments/bookmarks.
- Prints `CR0_SITE`, `CR0_SUMMARY`, `PROTECTION_IDENTITY_VERIFIED`, `APPLIED_FUNCTION_NAME`, `PRESERVED_FUNCTION`, and final summary.
- Not executed against a live Ghidra installation in the assistant environment. Java API declarations checked against upstream Ghidra. Native evidence was extracted from original archive exports.

## Important existing state

This checkpoint visibly retains `MiGetPteAddress`, `MiGetMappedPteAddress`, `MiReadPhysicalMappingTable`, `EmaExecuteSingle`, and large amounts of new saved symbol/parameter work, including `BnDivide128By64Observed`, `BnAddModularVectorObserved`, `RtlpFormatBinary64FixedObserved`, and new syscall-selector names. These are already in the saved archive, not changes to reapply.

The SLEIGH source fix was pushed to `Masamune3210/XEXLoaderWV` branch `testing` in `de1feb73c32a20d21fb05b454010a8115562a739`. No assertion is made that this GZF was produced with that build; verify the loaded P-code first. The private fixed-SF0 correction passed 8192 original-helper cases; its scope does not prove dynamic MSR[SF] mode transitions.

## Next decision after live output

If sites show `FULL64_COMPARISONS`, fix/rebuild or load the corrected Xenon language before trusting affected control-flow/decompilation decisions. If they show `LOW32_COMPARISONS`, inspect the observed `0x80080B78`/`0x80080CB0` decompiled C under the new language and decide whether more parameter or result changes are justified. Do not replay old completed annotation scripts or clear existing function/storage information.