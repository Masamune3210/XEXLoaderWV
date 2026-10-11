// Retired unsafe helper: the original V1 replaced unresolved allocator arguments.
//@category Xbox360
//
// Do not use V1 for metadata application. Its parameter replacement was not
// justified by evidence from the Xbox kernel. The revised V2 only annotates
// verified shared-register helper entrypoints and preserves ALL prototypes.
// This stub deliberately performs NO modifications.

import ghidra.app.script.GhidraScript;

public class ApplyXboxKrnl17559SharedRegisterHelpersV1 extends GhidraScript {
    @Override
    public void run() throws Exception {
        printerr("ApplyXboxKrnl17559SharedRegisterHelpersV1 is retired: " +
            "its inferred parameter removal was unsafe. " +
            "Use ApplyXboxKrnl17559SharedRegisterHelpersV2.java instead. " +
            "No changes were made to the Program.");
    }
}
