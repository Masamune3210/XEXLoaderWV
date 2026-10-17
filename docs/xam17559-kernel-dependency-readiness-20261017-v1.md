# XAM retail 17559 kernel-import contract readiness audit (2026-10-17)

## Source checkpoint

The user imported XAM SHA-256 `78b3dbd8ae866f4258f5444205486ea9f8451afaa30f469c875dcf345f828467` under Xenon Ghidra 12.1.3. Their Program Information shows 17,764 functions, 1,035,626 instructions, and 43 defined datatypes. The XAM external program link already resolves `xboxkrnl.exe` to `/System Firmware/xboxkrnl.exe`. The current kernel executable SHA-256 is `e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8`.

## Parsed user XAM cross-reference export

The 10,123-row Ghidra export identifies **443 named imported kernel functions**, with **438** having branch/call references in the export. There are **8,887 direct branch/call entries** targeting named kernel imports, across roughly 3,390 unique XAM caller labels (including callers with global references). Additional references to imported globals exist; those must be treated as data, not functions. The usage rank is frozen from this supplied export, not a live count. Imported thunk locations come from the export and are not kernel function entrypoint addresses.

Dominant imports are RtlLeaveCriticalSection (1296 branch refs/1144 distinct caller labels), RtlEnterCriticalSection (1240/1113), KeLeaveCriticalRegion (496/432), KeEnterCriticalRegion (460/411), _snprintf (334/210), RtlInitAnsiString (204/168), NtClose (201/173), RtlInitializeCriticalSection (167/136), ExGetXConfigSetting (157/98), KeGetCurrentProcessType (149/129). Counts reflect cross-reference rows, not independent runtime calls.

Five imports have no `bl`/`b` rows; IoInvalidDeviceRequest is among these but has address-taking references, so **absence of call rows must not be interpreted as unused**. Distinct XAM function labels are not guaranteed to equal distinct real function bodies.

## Script

`ghidra_scripts/AuditXam17559LinkedKernelContracts_20261017_v1.java` is **read-only**. Open XAM and run it. It opens the previously linked kernel project file read-only, checks both executable SHA-256 values and processor language, resolves imported kernel function names against native entries, and reports each imported external signature alongside the corresponding kernel signature. Prefer a confirmed exact linked address; otherwise require one unique exact kernel function name. Report ambiguous/missing/conflicting mappings without guesses.

The 443-row usage-ranked evidence is mirrored under `tools/data/xam17559-kernel-import-usage-20261017-v1.tsv`, and embedded in the script to avoid external file-path dependencies. It prints the top 45 imports and saves a complete TSV in Downloads. The contract buckets distinguish opaque types, zero-argument declarations worth reviewing, and typed contracts by signature source. **A USER_DEFINED signature is not automatically correct**, a 0-parameter signature can be legitimate, and the comparator does not assert physical ABI equivalence or modify either project database.

## Next step

Run the script in XAM, review `BUCKET_COUNTS` and the TSV, then target high-use weak kernel contracts first, refining verified signatures in the kernel before propagating known types into XAM. Work on XAM internals only after its actual dependency blockers are understood. No database edits, type invention, or bulk function renames are performed by this audit script. Compile/API verification against stubs is not real Ghidra runtime execution.
