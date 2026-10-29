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
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;
import java.util.HashSet;
import java.util.Set;

/**
 * Recognize out-of-line Xenon GPR/LR save helpers and attach call-fixups.
 *
 * These helpers have overlapping entry points: a save-r22 function can enter
 * halfway through the save-r14 sequence, and its last instructions can be
 * owned by another Ghidra function. Recognize the bytes IN MEMORY rather
 * than demanding that every instruction belong to the function body.
 *
 * The injected P-code is in xenon_64_32.cspec. It leaves r3 (and all other
 * unsaved registers) untouched, unlike an ordinary ABI function call.
 */
public final class XenonSaveGprLrAnalyzer extends AbstractAnalyzer {
    private static final String LANGUAGE = "PowerPC:BE:64:XENON-32addr";
    private static final String FIXUP_PREFIX = "XenonSaveGprLr";
    private static final int BLR = 0x4E800020;
    private static final int SAVE_R12 = 0xF981FFF8;

    public XenonSaveGprLrAnalyzer() {
        super("Xenon GPR/LR Save Helpers",
            "Identify compiler-generated GPR/LR save entry points, including " +
            "entry points within overlapping helper bodies, and attach " +
            "register-preserving call-fixups.",
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
     * The compiler emits std rFIRST,-offset(r1) ... std r31,-16(r1),
     * std r12,-8(r1), blr. Verify the ENTIRE suffix from a candidate entry.
     * Do not require the suffix to be in the same Ghidra function body.
     *
     * Retail HV 17559 contains the r14-r31 entries at raw offsets
     * 0xA7D0..0xA814. Addresses are not used to recognize other images.
     */
    private static int detectFirstSavedRegister(Program program, Address entry) {
        if (entry == null || !entry.isMemoryAddress() ||
            program.getListing().getInstructionAt(entry) == null) {
            return -1;
        }
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
                    memory.getInt(entry.add(cursor + 4)) == BLR &&
                    program.getListing().getInstructionAt(
                        entry.add(cursor + 4)) != null) {
                    return first;
                }
            } catch (Exception unreadable) {
                // Candidate does not have a complete executable suffix.
            }
        }
        return -1;
    }

    private static final class Counts {
        int recognized;
        int applied;
        int alreadyApplied;
        int conflicts;
        int missingFunctions;
    }

    private static void attach(Program program, Address entry,
                               Set<Address> visited, Counts counts,
                               MessageLog log) {
        if (entry == null || !visited.add(entry)) {
            return;
        }
        int first = detectFirstSavedRegister(program, entry);
        if (first < 0) {
            return;
        }
        counts.recognized++;
        Function function = program.getFunctionManager().getFunctionAt(entry);
        if (function == null) {
            counts.missingFunctions++;
            log.appendMsg("Xenon GPR/LR Save Helpers",
                "Verified entry at " + entry + " is not a Ghidra " +
                "function entry; cannot attach a function call-fixup.");
            return;
        }
        String fixup = FIXUP_PREFIX + first;
        String existing = function.getCallFixup();
        if (fixup.equals(existing)) {
            counts.alreadyApplied++;
            return;
        }
        if (existing != null && !existing.isEmpty()) {
            counts.conflicts++;
            log.appendMsg("Xenon GPR/LR Save Helpers",
                "Preserving existing call-fixup " + existing +
                " at " + entry);
            return;
        }
        if (program.getCompilerSpec().getPcodeInjectLibrary().getPayload(
                InjectPayload.CALLFIXUP_TYPE, fixup) == null) {
            counts.conflicts++;
            log.appendMsg("Xenon GPR/LR Save Helpers",
                "Missing compiler-spec fixup " + fixup +
                " for " + entry);
            return;
        }
        try {
            function.setCallFixup(fixup);
            counts.applied++;
            log.appendMsg("Xenon GPR/LR Save Helpers",
                "Installed " + fixup + " at " + entry);
        } catch (Exception failure) {
            counts.conflicts++;
            log.appendMsg("Xenon GPR/LR Save Helpers",
                "Failed to attach " + fixup + " at " + entry +
                ": " + failure.getMessage());
        }
    }

    @Override
    public boolean added(Program program, AddressSetView set,
                         TaskMonitor monitor, MessageLog log) {
        Set<Address> visited = new HashSet<>();
        Counts counts = new Counts();

        // 1. Existing function entries, whether or not all their instructions
        //    are claimed by their Ghidra function bodies.
        FunctionIterator functions =
            program.getFunctionManager().getFunctions(set, true);
        while (functions.hasNext()) {
            if (monitor.isCancelled()) return false;
            Function function = functions.next();
            if (!function.isExternal()) {
                attach(program, function.getEntryPoint(), visited, counts, log);
            }
        }

        // 2. Direct call targets within the analyzed range. This also finds
        //    entries when analysis is rerun on callers, or when an entry lies
        //    in the middle of a shared helper's larger function body.
        InstructionIterator instructions =
            program.getListing().getInstructions(set, true);
        while (instructions.hasNext()) {
            if (monitor.isCancelled()) return false;
            Instruction instruction = instructions.next();
            if (!instruction.getFlowType().isCall()) {
                continue;
            }
            for (Address target : instruction.getFlows()) {
                attach(program, target, visited, counts, log);
            }
        }

        log.appendMsg("Xenon GPR/LR Save Helpers",
            "Recognized " + counts.recognized + " helper entries; applied " +
            counts.applied + ", previously applied " + counts.alreadyApplied +
            ", no function entry " + counts.missingFunctions +
            ", conflicts " + counts.conflicts + ".");
        return true;
    }
}
