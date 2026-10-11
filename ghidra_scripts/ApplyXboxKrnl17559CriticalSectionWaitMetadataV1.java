// Apply established Xbox 360 kernel 17559 critical-section helper metadata.
//@category Xbox360
//
// Evidence: separate .pdata [0x800890AC,0x800890F8); conditional
// non-link branch 0x80088FF8 -> 0x800890AC; wait on the supplied
// critical-section object, then set owner and recursion fields.
//
// Changes ONLY the helper's descriptive name, already-known parameter
// names, and an appended repeatable comment. It preserves function
// bounds, body bytes, register storage, datatypes, return types, and
// caller's conditional jump. No forced pointer-width changes.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;

public class ApplyXboxKrnl17559CriticalSectionWaitMetadataV1
        extends GhidraScript {

    private static final long ENTRY_PARENT = 0x80088FA0L;
    private static final long ENTRY_WAIT = 0x800890ACL;
    private static final String WAIT_NAME = "RtlpWaitForCriticalSection";
    private static final String PARAM_NAME = "criticalSectionAddress";

    private void require(boolean good, String what) {
        if (!good) {
            throw new IllegalStateException(what);
        }
    }

    private Instruction verified(long address, String text) {
        Instruction inst = currentProgram.getListing()
            .getInstructionAt(toAddr(address));
        require(inst != null && text.equals(inst.toString()),
            "Unexpected instruction at " + toAddr(address) +
            " (expected " + text + ", got " +
            (inst == null ? "<undefined>" : inst.toString()) + ")");
        return inst;
    }

    private void verifyInput() {
        require("PowerPC:BE:64:XENON-32addr".equals(
            currentProgram.getLanguageID().toString()),
            "This metadata applies only to the verified Xenon kernel");

        Function parent = currentProgram.getFunctionManager()
            .getFunctionAt(toAddr(ENTRY_PARENT));
        Function helper = currentProgram.getFunctionManager()
            .getFunctionAt(toAddr(ENTRY_WAIT));
        require(parent != null && helper != null,
            "The two independently verified .pdata function entries are missing");
        require("RtlEnterCriticalSection".equals(parent.getName()),
            "Unexpected parent function; do not rename a different function");
        require(("FUN_800890ac".equals(helper.getName()) ||
            WAIT_NAME.equals(helper.getName())),
            "Wait helper already has a different name; preserve manual metadata");
        require(parent.getBody().getMinAddress().equals(toAddr(0x80088FA0L)) &&
            parent.getBody().getMaxAddress().equals(toAddr(0x800890ABL)),
            "Parent function bounds differ from verified .pdata analysis");
        require(helper.getBody().getMinAddress().equals(toAddr(ENTRY_WAIT)) &&
            helper.getBody().getMaxAddress().equals(toAddr(0x800890F7L)),
            "Wait helper bounds differ from verified .pdata analysis");

        String note = helper.getRepeatableComment();
        require(note != null &&
            note.contains("0x800890AC-0x800890F8"),
            "Missing original verified .pdata annotation; do not modify extents");

        verified(0x80088FF8L, "bne 0x800890ac");
        verified(0x800890D0L, "bl 0x80073120");
        verified(0x800890D4L, "lwz r4,0x100(r13)");
        verified(0x800890DCL, "stw r4,0x18(r30)");
        verified(0x800890E0L, "stw r8,0x14(r30)");
        verified(0x800890F4L, "blr");

        ReferenceIterator refs = currentProgram.getReferenceManager()
            .getReferencesTo(toAddr(ENTRY_WAIT));
        int count = 0;
        while (refs.hasNext()) {
            Reference ref = refs.next();
            require(ref.getFromAddress().equals(toAddr(0x80088FF8L)) &&
                ref.getReferenceType().isJump(),
                "Unexpected incoming reference; preserve existing symbols");
            ++count;
        }
        require(count == 1, "Expected one conditional branch into the helper");

        require(parent.getParameterCount() >= 1 &&
                helper.getParameterCount() >= 1,
            "Unresolved parameter storage; refusing to invent parameters");
        for (Function fn : new Function[] { parent, helper }) {
            Parameter p = fn.getParameter(0);
            require(p != null &&
                ("param_1".equals(p.getName()) ||
                 PARAM_NAME.equals(p.getName())),
                "Preserving an existing nondefault parameter name on " +
                fn.getName());
        }
    }

    private void nameParameter(Function function) throws Exception {
        Parameter p = function.getParameter(0);
        if (!PARAM_NAME.equals(p.getName())) {
            p.setName(PARAM_NAME, SourceType.USER_DEFINED);
        }
        println("  " + function.getEntryPoint() +
            " param[0] now " + p.getName() +
            ", datatype preserved: " + p.getDataType().getName());
    }

    @Override
    public void run() throws Exception {
        verifyInput();
        Function parent = currentProgram.getFunctionManager()
            .getFunctionAt(toAddr(ENTRY_PARENT));
        Function helper = currentProgram.getFunctionManager()
            .getFunctionAt(toAddr(ENTRY_WAIT));

        // RtlpWaitForCriticalSection is a descriptive, inferred name,
        // not a symbol recovered from Xbox kernel debugging information.
        if (!WAIT_NAME.equals(helper.getName())) {
            helper.setName(WAIT_NAME, SourceType.USER_DEFINED);
        }
        nameParameter(parent);
        nameParameter(helper);

        String line = "Inferred RtlEnterCriticalSection contended-acquisition " +
            "helper: reached by non-link bne from 0x80088FF8; " +
            "KeWaitForSingleObject(object=r3, reason=8, mode=0, " +
            "alertable=0, timeout=0); then write current thread value " +
            "[r13+0x100] to criticalSection+0x18 and recursionCount=1 " +
            "to +0x14; restores caller LR and returns. " +
            "RtlpWaitForCriticalSection is descriptive, not a recovered symbol.";
        String existing = helper.getRepeatableComment();
        if (!existing.contains(line)) {
            helper.setRepeatableComment(existing + "\n" + line);
        }
        println("Applied conservative critical-section metadata.");
        println("  " + helper.getEntryPoint() + " -> " + helper.getName());
        println("  Return types, parameter storage and 2 .pdata bounds preserved.");
        println("  No code bytes or instruction references changed.");
    }
}
