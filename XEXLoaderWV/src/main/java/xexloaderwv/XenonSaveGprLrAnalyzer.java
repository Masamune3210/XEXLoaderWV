package xexloaderwv;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

/**
 * Models the compiler's out-of-line PowerPC GPR/LR save prologue.
 *
 * A call to one of these helpers is not an ordinary C ABI function call:
 * r3-r10 are untouched, so treating r3 as a return value corrupts dataflow.
 * Only exact, full instruction sequences are eligible; no address or symbol
 * names are assumed. The call-fixup p-code is defined in Xenon's .cspec.
 */
public final class XenonSaveGprLrAnalyzer extends AbstractAnalyzer {
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final String FIXUP_PREFIX = "XenonSaveGprLr";
    private static final int BLR = 0x4E800020;
    private static final int SAVE_R12 = 0xF981FFF8;

    public XenonSaveGprLrAnalyzer() {
        super("Xenon GPR/LR Save Helpers",
            "Identify compiler-generated GPR/LR save routines and use " +
            "call-fixups so the decompiler retains live input registers.",
            AnalyzerType.FUNCTION_ANALYZER);
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis(true);
        setPriority(AnalysisPriority.FUNCTION_ANALYSIS);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return LANGUAGE.equals(program.getLanguageID().getIdAsString());
    }

    /**
     * A standard helper stores rFIRST..r31 into negative offsets from r1,
     * followed by std r12,-8(r1); blr. Offset is always
     * 8 * (register - 31) - 0x10, independently of the entry address.
     *
     * The retail HV 17559 provides all 18 overlapping entries (r14-r31)
     * at raw offsets 0xA7D0..0xA814. Those offsets are evidence only; this
     * matcher applies to equivalent code anywhere in any Xenon program.
     */
    private static int detectFirstSavedRegister(Program program, Function fn) {
        if (fn.isExternal() || fn.isThunk()) {
            return -1;
        }
        Address entry = fn.getEntryPoint();
        Memory memory = program.getMemory();
        for (int first = 14; first <= 31; ++first) {
            try {
                int cursor = 0;
                boolean matches = true;
                for (int reg = first; reg <= 31; ++reg) {
                    int disp = 8 * (reg - 31) - 0x10;
                    int expected = 0xF8000000 | (reg << 21) | (1 << 16) |
                                   (disp & 0xFFFC);
                    if (memory.getInt(entry.add(cursor)) != expected) {
                        matches = false;
                        break;
                    }
                    cursor += 4;
                }
                if (matches &&
                    memory.getInt(entry.add(cursor)) == SAVE_R12 &&
                    memory.getInt(entry.add(cursor + 4)) == BLR) {
                    // Only use a recognized instruction stream, not bytes
                    // coincidentally embedded in data or another function.
                    Address end = entry.add(cursor + 4);
                    if (program.getListing().getInstructionAt(entry) != null &&
                        program.getListing().getInstructionAt(end) != null &&
                        fn.getBody().contains(end)) {
                        return first;
                    }
                }
            } catch (Exception invalidMemoryOrAddress) {
                // A truncated function cannot match a complete helper.
            }
        }
        return -1;
    }

    @Override
    public boolean added(Program program, AddressSetView set,
                         TaskMonitor monitor, MessageLog log) {
        int applied = 0;
        FunctionIterator functions = program.getFunctionManager().getFunctions(set, true);
        while (functions.hasNext()) {
            if (monitor.isCancelled()) {
                return false;
            }
            Function function = functions.next();
            int first = detectFirstSavedRegister(program, function);
            if (first < 0) {
                continue;
            }
            String requestedFixup = FIXUP_PREFIX + first;
            String existing = function.getCallFixup();
            if (requestedFixup.equals(existing)) {
                continue;
            }
            // Never overwrite a manually installed or independently supplied
            // call-fixup. Only auto-annotate an unclaimed helper.
            if (existing != null && !existing.isEmpty()) {
                continue;
            }
            if (program.getCompilerSpec().getPcodeInjectLibrary().getPayload(
                    InjectPayload.CALLFIXUP_TYPE, requestedFixup) == null) {
                log.appendMsg("Xenon GPR/LR Save Helpers",
                    "Missing compiler-spec fixup " + requestedFixup);
                return false;
            }
            function.setCallFixup(requestedFixup);
            applied++;
        }
        if (applied > 0) {
            log.appendMsg("Xenon GPR/LR Save Helpers",
                "Applied " + applied + " verified GPR/LR save call-fixups.");
        }
        return true;
    }
}
