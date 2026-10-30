package xexloaderwv;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recognize Xenon CRT longjmp and a directly terminating callback wrapper.
 *
 * The pattern implementation has no firmware addresses, and requires a full
 * saved-context restore plus the alternate RtlUnwind call sequence. An
 * ordinary context loader is not enough. Avoids inventing jmp_buf structures
 * and does not classify setjmp without a separately established save pattern.
 *
 * No executable bytes or external import symbols are modified.
 */
public final class XenonCrtNonlocalJumpAnalyzer extends AbstractAnalyzer {
    private static final String XEX_FORMAT = "XEX Loader by Warranty Voider";

    private static final class Counts {
        int recognized;
        int renamed;
        int alreadyNamed;
        int noReturnMarked;
        int wrappers;
        int wrappersNamed;
        int wrapperNoReturnMarked;
        int conflictingNames;
        int failed;
    }

    public XenonCrtNonlocalJumpAnalyzer() {
        super("Xenon CRT nonlocal jumps",
            "Recognize verified PowerPC CRT longjmp restorers and terminating " +
            "callback wrappers by instructions across XEX firmware families; " +
            "mark No Return without inventing unverified context layouts.",
            AnalyzerType.FUNCTION_ANALYZER);
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis(true);
        setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
    }

    @Override
    public boolean canAnalyze(Program program) {
        if (program == null || !XEX_FORMAT.equals(program.getExecutableFormat()))
            return false;
        String id = program.getLanguageID().getIdAsString();
        return "PowerPC:BE:64:XENON-32addr".equals(id) ||
            "PowerPC:BE:64:A2ALT-32addr".equals(id);
    }

    private static XenonNonlocalJumpPatterns.Words words(
            Memory memory, Address entry) {
        return offset -> memory.getInt(entry.add(offset));
    }

    private static boolean recognizedLongjmp(Program program, Function f) {
        if (f == null || f.isExternal()) return false;
        return XenonNonlocalJumpPatterns.isLongjmp(
            words(program.getMemory(), f.getEntryPoint()));
    }

    private static void refineLongjmp(Program program, Function function,
            Counts counts, MessageLog log) {
        counts.recognized++;
        int transaction = program.startTransaction(
            "Recognize Xenon CRT longjmp " + function.getEntryPoint());
        boolean commit = false;
        try {
            String name = function.getName();
            if ("longjmp".equals(name)) {
                counts.alreadyNamed++;
            } else if (function.getSymbol().getSource() == SourceType.USER_DEFINED) {
                counts.conflictingNames++;
                log.appendMsg("Xenon CRT nonlocal jumps",
                    "Preserving user function name " + name + " at " +
                    function.getEntryPoint() + " (longjmp pattern verified)");
            } else {
                try {
                    function.setName("longjmp", SourceType.ANALYSIS);
                    counts.renamed++;
                } catch (Exception collision) {
                    counts.conflictingNames++;
                    log.appendMsg("Xenon CRT nonlocal jumps",
                        "Could not rename verified longjmp at " +
                        function.getEntryPoint() + ": " + collision.getMessage());
                }
            }
            if (!function.hasNoReturn()) {
                function.setNoReturn(true);
                counts.noReturnMarked++;
            }

            // Keep the current jump-buffer datatype, parameter storage and
            // existing manually edited signature. Return is never delivered
            // to the immediate caller: control resumes at saved LR instead.
            if (function.getSignatureSource() != SourceType.USER_DEFINED &&
                    !function.hasCustomVariableStorage()) {
                if (function.getReturnType().getName().startsWith("undefined")) {
                    function.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);
                }
                if (function.getParameterCount() == 2) {
                    Parameter buffer = function.getParameter(0);
                    Parameter value = function.getParameter(1);
                    if (buffer.getName() != null &&
                            buffer.getName().startsWith("param_")) {
                        buffer.setName("jumpBuffer", SourceType.ANALYSIS);
                    }
                    // r4 is examined as a signed 32-bit value. Do not
                    // arbitrarily shrink wider or custom-storage parameters.
                    if (value.getDataType().getName().startsWith("undefined") &&
                            value.getDataType().getLength() == 4) {
                        value.setDataType(IntegerDataType.dataType, SourceType.ANALYSIS);
                    }
                    if (value.getName() != null &&
                            value.getName().startsWith("param_")) {
                        value.setName("returnValue", SourceType.ANALYSIS);
                    }
                }
            }
            if (function.getComment() == null || function.getComment().isBlank()) {
                function.setComment(
                    "Verified Xenon CRT longjmp: converts requested value 0 to 1, " +
                    "restores f14-f31/r13-r31 and saved SP/CR/LR, and resumes " +
                    "at the saved continuation. Alternate path invokes " +
                    "RtlUnwind. Does not return to its direct caller.");
            }
            commit = true;
        } catch (Exception failure) {
            counts.failed++;
            log.appendMsg("Xenon CRT nonlocal jumps",
                "Could not update " + function.getEntryPoint() + ": " +
                failure.getMessage());
        } finally {
            program.endTransaction(transaction, commit);
        }
    }

    private static void refineWrapper(Program program, Function function,
            Counts counts, MessageLog log) {
        counts.wrappers++;
        int transaction = program.startTransaction(
            "Recognize Xenon CRT longjmp wrapper " + function.getEntryPoint());
        boolean commit = false;
        try {
            if (!function.hasNoReturn()) {
                function.setNoReturn(true);
                counts.wrapperNoReturnMarked++;
            }
            // A wrapper is identified only with a verified indirect callback
            // from jumpBuffer+0x140 followed by longjmp(buffer, 1).
            if (!"LongjmpAfterOptionalCallback".equals(function.getName()) &&
                    function.getSymbol().getSource() != SourceType.USER_DEFINED) {
                try {
                    function.setName("LongjmpAfterOptionalCallback",
                        SourceType.ANALYSIS);
                    counts.wrappersNamed++;
                } catch (Exception collision) {
                    counts.conflictingNames++;
                    log.appendMsg("Xenon CRT nonlocal jumps",
                        "Could not rename callback wrapper at " +
                        function.getEntryPoint() + ": " + collision.getMessage());
                }
            }
            if (function.getComment() == null || function.getComment().isBlank()) {
                function.setComment(
                    "Invokes optional callback from jumpBuffer+0x140, then " +
                    "longjmp(jumpBuffer, 1). The call is terminal; following " +
                    "zero-filled bytes are non-executable padding.");
            }
            commit = true;
        } catch (Exception failure) {
            counts.failed++;
            log.appendMsg("Xenon CRT nonlocal jumps",
                "Could not update wrapper " + function.getEntryPoint() +
                ": " + failure.getMessage());
        } finally {
            program.endTransaction(transaction, commit);
        }
    }

    private static boolean terminatesInCallbackLongjmp(Program program,
            Function function, Map<Address, Boolean> matchedLongjmps) {
        if (function == null || function.isExternal()) return false;
        // Ghidra function bodies can be noncontiguous. A terminal direct call
        // must be the last defined instruction in the function's body, not
        // merely the last instruction on one control-flow path.
        InstructionIterator instructions = program.getListing()
            .getInstructions(function.getBody(), true);
        Instruction last = null;
        while (instructions.hasNext()) {
            last = instructions.next();
        }
        if (last == null || !last.getFlowType().isCall() ||
                last.getLength() != 4 || last.getFlows().length != 1)
            return false;
        Address target = last.getFlows()[0];
        if (target == null || !target.isMemoryAddress()) return false;
        Boolean recognized = matchedLongjmps.get(target);
        if (recognized == null) {
            Function callee = program.getFunctionManager().getFunctionAt(target);
            recognized = recognizedLongjmp(program, callee);
            matchedLongjmps.put(target, recognized);
        }
        if (!recognized) return false;
        long displacement = last.getAddress().subtract(function.getEntryPoint());
        if (displacement < 0 || displacement > 0x400) return false;
        return XenonNonlocalJumpPatterns.isCallbackWrapper(
            words(program.getMemory(), function.getEntryPoint()), (int) displacement);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        if (!canAnalyze(program)) return true;

        Counts counts = new Counts();
        Map<Address, Boolean> matchedLongjmps = new HashMap<>();

        // Pass A: identify longjmp callees first, independent of names. This
        // will be rerun as a One Shot analyzer on existing imported XEXs.
        FunctionIterator functions = program.getFunctionManager()
            .getFunctions(set, true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();
            if (function.isExternal()) continue;
            boolean matched = recognizedLongjmp(program, function);
            matchedLongjmps.put(function.getEntryPoint(), matched);
            if (matched) {
                refineLongjmp(program, function, counts, log);
            }
        }

        // Pass B: now recognize the callback wrapper by its *verified*
        // terminal callee and the independent callback/zero-padding pattern.
        functions = program.getFunctionManager().getFunctions(set, true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();
            if (terminatesInCallbackLongjmp(program, function, matchedLongjmps)) {
                refineWrapper(program, function, counts, log);
            }
        }

        log.appendMsg("Xenon CRT nonlocal jumps",
            "longjmpRecognized=" + counts.recognized +
            " renamed=" + counts.renamed +
            " alreadyNamed=" + counts.alreadyNamed +
            " noReturnMarked=" + counts.noReturnMarked +
            " callbackWrappers=" + counts.wrappers +
            " wrapperNamesApplied=" + counts.wrappersNamed +
            " wrapperNoReturnMarked=" + counts.wrapperNoReturnMarked +
            " preservedOrConflictingNames=" + counts.conflictingNames +
            " failed=" + counts.failed +
            " (instruction-validated; native bytes unchanged)");
        return true;
    }
}
