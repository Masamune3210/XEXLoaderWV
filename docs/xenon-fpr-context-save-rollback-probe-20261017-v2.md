# Xenon FP context-saver rollback-only probe, v2 (2026-10-17)

## Reason for revision

Live Ghidra ran v1 but stopped before its native-byte fingerprint validation:

\`\`\`text
REFUSE: expected 14-parameter native saver and its native wrapper.
\`\`\`

That message collapsed five unrelated preconditions into one: missing saver, missing wrapper, saver thunk, wrapper thunk, archived parameter count, and a ban on custom argument storage. The refusal **does not** establish which was false. The archived context-saver declaration is not authoritative for the current saved Program. No changes were attempted.

## What v2 does

- Prints saver and wrapper function metadata before testing any prototype assumptions. Prints the source, storage, name, type, and auto-parameter status of **each** saver argument.
- Independently validates the same retail 17559 kernel SHA-256, Xenon language and exact 0x8c-byte native saver fingerprint.
- Allows already enabled custom storage: this can be legitimate in a saved analysis. It does not erase/reallocate existing custom storage preemptively.
- Still requires exactly the expected 13 unresolved f1..f13 machine-state arguments and the original r3:4 context argument, plus the exact function-body native fingerprint. If any differs, prints a specific refusal and performs **no** edit.
- If all match, decompiles the saved wrapper, enters an explicit Ghidra transaction, removes only the thirteen FPR formals, decompiles the wrapper again with cache flush, and **always rolls back** in a finally block.
- Verifies complete original signatures, parameter metadata and return storage after rollback. A verification mismatch is reported rather than falsely asserting restoration.

No data types, signatures, function names, bytes, SLEIGH sources or links are intended to persist. The script's native ABI/transaction result still needs actual Ghidra execution.

## Next

Run \`ghidra_scripts/ProbeXenonFprSaveSignatureRollback_20261017_v2.java\` with the current retail kernel open. Supply its console output, especially \`SAVER_METADATA\`, each \`SAVER_PARAMETER\`, \`REFUSE\` if any, \`WRAPPER_CALL_BEFORE\`, \`WRAPPER_CALL_AFTER\`, and \`ROLLBACK_VERIFIED\`. Do not change or delete unresolved FPR slots in the production database based only on this test. There is still no justification for removing all floating-point argument registers from the Xenon compiler specification.