# Linked XEX import signature propagation (2026-10-17)

## Why this belongs in the extension

Ghidra supports linking an imported library to another project Program but **does not automatically copy the provider's function prototypes** into its consumer's external Function records. The XAM 17559 contract audit observed 437/443 external functions still at `undefined Name()` even though the retail kernel is correctly linked. The XEX loader accurately creates imported function/thunk records, but currently cannot enrich their signatures after the user links a provider Program. This is a general Ghidra limitation, not evidence of corrupt XEX thunk decoding or a firmware-specific fault.

`XexLinkedImportSignatureAnalyzer` adds reusable cross-Program propagation to XEXLoaderWV. It is enabled for XEX Program analysis. It opens each *actually linked* dependency read-only, requires matching Language/CompilerSpec/pointer size, identifies functions by linked address or a unique exact name, and applies only complete `USER_DEFINED` signatures to previously empty, unedited external declarations. It avoids ABI coercion, source type invention, external symbol renames, kernel signature modifications, and any use of ordinal lists tied to 17559.

To prevent moving Ghidra's spurious opaque FPR slots into XAM, functions with any undefined parameter or return are not copied. Source custom storage is also skipped. Composite, enum and typedef dependencies are accepted only when already present as equivalent types in the importing Program; the analyzer never auto-installs conflicting layouts.

## Limitations

- The Xenon compiler spec `xenon_64_32.cspec` was verified byte-for-byte identical to stock Ghidra `ppc_64_32.cspec` (aside from files themselves being copied). The 13 FPR slots are not yet proven to be an extension-specific compiler-spec defect. Preserve unresolved f1–f13 storage.
- The analyzer may only see a dependency if the linked library path exists **before the analysis pass**. If links were established after XAM was imported, run the named analyzer again as a One Shot analysis pass. It is not a live listener for link changes.
- The strict default policy deliberately leaves ambiguous, partially typed and unverified kernel declarations unchanged. The original XAM report predicts **up to 36** USER_DEFINED fully typed imports, but existing complex datatype dependencies and other guards may reduce actual changes. It must not be advertised as repairing all 437 empty externals.
- No Ghidra runtime validation or Gradle SLEIGH compilation was performed in the assistant environment. Rebuilding the extension and testing the analyzer in an XAM backup is required before relying on the change in the entire firmware corpus.
- A user-defined signature is not automatically proved semantically correct. It is only the highest available trust level recorded in the provider project; the extension must never infer missing argument registers.

## Validation criteria

On an already linked test XAM Program, run the analyzer as a One Shot pass. Confirm that the report counts are nonzero only for unique, genuinely typed providers; external import names, ordinal links, 16-byte native thunks, and non-XEX Ghidra Programs remain unchanged. Verify that a second run applies zero signatures; custom or partially defined external signatures remain untouched. Check decompilation of RtlEnterCriticalSection and RtlLeaveCriticalSection calls before and after in a database backup.

After this is confirmed, further kernel work should target heavily used incomplete contracts, not patch individual XAM call sites.
