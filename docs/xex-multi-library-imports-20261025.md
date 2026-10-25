# Nonzero XEX import-library indices

DASH17559 supplies native token pairs such as `0101000f 0201000f 7d6903a6 4e800420`. The second byte selects the import library; it is not reserved zero. The old loader and import-aware disassembler recognized only index0. In the supplied analyzed DASH, 284 index1 kernel import thunks were unlinked and outside the guard registry, and most existing invalid-opcode errors occurred at those relocation tokens.

`XEXHeader.IsCanonicalImportThunk` and `XenonImportAwareDisassembler.isCanonicalTokenPair` now accept matching library bytes while retaining exact type, ordinal and real PPC-tail validation. Mismatched libraries/ordinals and modified tails remain rejected. No native bytes, SLEIGH semantics, processor specifications or language IDs change. The disassembler still requires an explicit per-Program registry; arbitrary unregistered invalid instructions retain normal diagnostics.

The regression executes the actual installed production predicates over all256 library-byte values, three boundary ordinals and five valid/invalid fixtures, plus the real loader/external manager/disassembler in a private Program-memory fixture. Test-only Unsafe allocation bypasses XEXHeader's decrypting constructor; the methods under test are not replaced. All private writes are rolled back. The original JAR failed for nonzero libraries and created only one of the two real fixture thunks; the rebuilt JAR passes7691 checks and creates/protects both. Original/red/green Program snapshots are identical.

Run the full extension build with the supported Ghidra/JDK/Gradle environment. Then install its JAR/ZIP and run the headless regression against an existing Xenon Program:

```sh
analyzeHeadless /tmp regression -import /path/to/program.gzf -readOnly -noanalysis \
  -scriptPath /path/to/XEXLoaderWV/ghidra_scripts \
  -postScript TestXexNonzeroLibraryTokens.java /tmp/multilib-result
```

Require `XEX MULTI-LIBRARY TOKEN REGRESSION: 7691 PASS` and no script errors; Ghidra exit0 alone does not prove success. The updated `ProtectExistingXexImportThunks_20261025_v4.java` also recognizes matching nonzero library bytes when registering already-linked native thunks. It does not reconstruct links missing from an older analyzed Program: those require byte/IAT-witnessed recovery with exact preservation gates, as supplied separately with the DASH checkpoint.
