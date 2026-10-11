// Read-only investigation of the separate .pdata function at 800890AC.
//@category Xbox360
// Preserve confirmed .pdata function boundaries. Print only metadata,
// real instructions, selected references and two decompilation excerpts.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;

public class AuditXboxKrnl17559CriticalSectionHelperV1 extends GhidraScript {
    private void dumpFunction(Function fn) throws CancelledException {
        if (fn == null) {
            println("Missing function");
            return;
        }
        println("Function: " + fn.getName() + " entry=" +
            fn.getEntryPoint() + " body=" + fn.getBody().getMinAddress() +
            ".." + fn.getBody().getMaxAddress() +
            " span=" + fn.getBody().getNumAddresses() +
            " return=" + fn.getReturnType().getDisplayName());
        println("  calling convention=" + fn.getCallingConventionName() +
            " signature=" + fn.getSignature());
        for (Parameter p : fn.getParameters()) {
            println("  param " + p.getOrdinal() + ": " +
                p.getName() + " " + p.getDataType().getDisplayName() +
                " storage=" + p.getVariableStorage());
        }
        InstructionIterator it =
            currentProgram.getListing().getInstructions(fn.getBody(), true);
        int count = 0;
        while (it.hasNext() && count < 72) {
            monitor.checkCancelled();
            Instruction inst = it.next();
            println("  " + inst.getAddress() + " " + inst);
            for (Address to : inst.getFlows()) {
                if (inst.getFlowType().isCall()) {
                    Function callee = currentProgram.getFunctionManager()
                        .getFunctionAt(to);
                    println("      calls " + to + " " +
                        (callee == null ? "<unknown>" : callee.getName()));
                } else if (!fn.getBody().contains(to)) {
                    Function next = currentProgram.getFunctionManager()
                        .getFunctionAt(to);
                    println("      exits to " + to + " " +
                        (next == null ? "<other code>" : next.getName()));
                }
            }
            ++count;
        }
        println("  instructions dumped=" + count +
            (it.hasNext() ? " (truncated)" : ""));
    }

    private void dumpDecomp(DecompInterface ifc, Function fn)
            throws Exception {
        if (fn == null) return;
        DecompileResults results = ifc.decompileFunction(fn, 40, monitor);
        println("Decompiled " + fn.getEntryPoint() + " success=" +
            results.decompileCompleted());
        if (!results.decompileCompleted() ||
                results.getDecompiledFunction() == null) {
            println("  error=" + results.getErrorMessage());
            return;
        }
        String c = results.getDecompiledFunction().getC();
        int length = Math.min(9000, c.length());
        println(c.substring(0, length));
        if (length != c.length()) println("  ... decompilation truncated");
    }

    private void dumpIncoming(Address target) {
        println("Incoming references to " + target + ":");
        ReferenceIterator refs =
            currentProgram.getReferenceManager().getReferencesTo(target);
        int count = 0;
        while (refs.hasNext() && count < 30) {
            Reference ref = refs.next();
            Function owner = currentProgram.getFunctionManager()
                .getFunctionContaining(ref.getFromAddress());
            println("  " + ref.getFromAddress() + " " +
                ref.getReferenceType() + " owner=" +
                (owner == null ? "<none>" : owner.getName()));
            ++count;
        }
    }

    @Override
    public void run() throws Exception {
        if (!"PowerPC:BE:64:XENON-32addr".equals(
                currentProgram.getLanguageID().toString())) {
            throw new IllegalStateException("Requires Xenon language");
        }
        Address main = toAddr(0x80088FA0L);
        Address slow = toAddr(0x800890ACL);
        Function a = currentProgram.getFunctionManager().getFunctionAt(main);
        Function b = currentProgram.getFunctionManager().getFunctionAt(slow);
        if (a == null || b == null) {
            throw new IllegalStateException(
                "Expected separate .pdata functions are absent");
        }
        println("CRITICAL SECTION: DISTINCT VERIFIED .pdata FUNCTIONS");
        println("No function merges, splits, labels, or data edits.");
        dumpIncoming(slow);
        dumpFunction(b);
        println("Caller branch neighborhood:");
        for (long p = 0x80088FE0L; p <= 0x80089008L; p += 4) {
            Instruction i =
                currentProgram.getListing().getInstructionAt(toAddr(p));
            if (i != null) println("  " + i.getAddress() + " " + i);
        }
        DecompInterface ifc = new DecompInterface();
        try {
            ifc.toggleCCode(true);
            if (!ifc.openProgram(currentProgram)) {
                println("Decompiler initialization failed");
                return;
            }
            dumpDecomp(ifc, b);
            dumpDecomp(ifc, a);
        }
        finally {
            ifc.dispose();
        }
        println("Audit complete: Program unchanged.");
    }
}
