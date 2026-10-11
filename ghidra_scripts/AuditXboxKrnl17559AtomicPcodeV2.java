// Follow-up to V1: check Xenon atomic p-code + critical-section ownership.
//@category Xbox360
// Read only. Inspects existing instruction p-code, metadata, and references.
// Does not modify code bytes, functions, analysis settings, or comments.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class AuditXboxKrnl17559AtomicPcodeV2 extends GhidraScript {
    private static final long[][] PAIRS = {
        {0x80064574L, 0x8006457CL},
        {0x800647BCL, 0x800647C4L},
        {0x80088FBCL, 0x80088FC4L},
        {0x80089020L, 0x80089028L},
        {0x80089050L, 0x80089060L}
    };
    private static final long[] BARRIERS = {
        0x80088FD0L, 0x80089034L, 0x80089070L
    };

    private Instruction requireInstruction(long offset, String name) {
        Address a = toAddr(offset);
        Instruction i = currentProgram.getListing().getInstructionAt(a);
        if (i == null || !name.equals(i.getMnemonicString())) {
            throw new IllegalStateException(
                "Expected " + name + " at " + a + "; got " +
                (i == null ? "<undefined>" : i.getMnemonicString()));
        }
        return i;
    }

    private String outputRegister(PcodeOp op) {
        Varnode v = op.getOutput();
        if (v == null) return "";
        Register r = currentProgram.getLanguage().getRegister(
            v.getAddress(), v.getSize());
        return r == null ? "" : r.getName();
    }

    private String userOpName(PcodeOp op) {
        if (op.getOpcode() != PcodeOp.CALLOTHER ||
                op.getNumInputs() < 1 || op.getInput(0) == null ||
                !op.getInput(0).isConstant()) return "";
        String s = currentProgram.getLanguage().getUserDefinedOpName(
            (int) op.getInput(0).getOffset());
        return s == null ? "<unknown-userop>" : s;
    }

    private boolean isConstantCopy(PcodeOp op, String register, long value) {
        return PcodeOp.COPY == op.getOpcode() &&
            register.equals(outputRegister(op)) &&
            op.getNumInputs() == 1 && op.getInput(0).isConstant() &&
            op.getInput(0).getOffset() == value;
    }

    private boolean auditReserve(Instruction i) {
        boolean flag = false, len = false, address = false;
        for (PcodeOp op : i.getPcode()) {
            flag |= isConstantCopy(op, "RESERVE", 1);
            len |= isConstantCopy(op, "RESERVE_LENGTH", 4);
            address |= "RESERVE_ADDRESS".equals(outputRegister(op));
        }
        boolean pass = flag && len && address;
        println("  " + i.getAddress() + " lwarx reservation writes: " +
            "RESERVE=" + flag + " LENGTH=4=" + len +
            " ADDRESS=" + address + " => " + (pass ? "PASS" : "FAIL"));
        return pass;
    }

    private boolean auditStore(Instruction i) {
        int nativeStores = 0, oldOps = 0, atomicOps = 0, cr0Writes = 0;
        boolean clearFlag = false, clearLength = false, atomicBoolean = false;
        for (PcodeOp op : i.getPcode()) {
            String name = userOpName(op);
            if (op.getOpcode() == PcodeOp.STORE) ++nativeStores;
            if ("storeWordConditionalIndexed".equals(name)) ++oldOps;
            if ("xenonAtomicStoreWordConditional".equals(name)) {
                ++atomicOps;
                atomicBoolean = op.getOutput() != null &&
                    op.getOutput().getSize() == 1;
            }
            if ("cr0".equals(outputRegister(op))) ++cr0Writes;
            clearFlag |= isConstantCopy(op, "RESERVE", 0);
            clearLength |= isConstantCopy(op, "RESERVE_LENGTH", 0);
        }
        boolean pass = nativeStores == 0 && oldOps == 0 &&
            atomicOps == 1 && atomicBoolean && clearFlag &&
            clearLength && cr0Writes >= 4;
        println("  " + i.getAddress() + " stwcx.: " +
            "legacy-userop=" + oldOps + " native-STORE=" + nativeStores +
            " atomic-userop=" + atomicOps +
            " success-output-1-byte=" + atomicBoolean +
            " clears-reservation=" + clearFlag +
            " clears-length=" + clearLength +
            " cr0-writes=" + cr0Writes +
            " => " + (pass ? "PASS" : "NOT YET VERIFIED"));
        if (!pass) {
            for (PcodeOp op : i.getPcode()) {
                String name = userOpName(op);
                String out = outputRegister(op);
                if (op.getOpcode() == PcodeOp.STORE ||
                        !name.isEmpty() || "cr0".equals(out) ||
                        out.startsWith("RESERVE")) {
                    println("    " + op +
                        (name.isEmpty() ? "" : " [userop=" + name + "]") +
                        (out.isEmpty() ? "" : " [out=" + out + "]"));
                }
            }
        }
        return pass;
    }

    private void showFunction(Function f, String which) {
        if (f == null) {
            println("  " + which + ": <no function>");
            return;
        }
        println("  " + which + ": " + f.getName() +
            " entry=" + f.getEntryPoint() +
            " body-min=" + f.getBody().getMinAddress() +
            " body-max=" + f.getBody().getMaxAddress() +
            " body-bytes=" + f.getBody().getNumAddresses() +
            " symbol-source=" + f.getSymbol().getSource());
        String note = f.getRepeatableComment();
        if (note != null && !note.isEmpty()) {
            println("    repeatable metadata: " +
                note.substring(0, Math.min(700, note.length()))
                    .replace('\n', ' '));
        }
    }

    private void auditFunctionBoundary() throws Exception {
        Address source = toAddr(0x80088FF8L);
        Address target = toAddr(0x800890ACL);
        Instruction branch =
            currentProgram.getListing().getInstructionAt(source);
        Function owner = currentProgram.getFunctionManager()
            .getFunctionContaining(source);
        Function dst = currentProgram.getFunctionManager()
            .getFunctionContaining(target);
        println("Critical-section boundary investigation:");
        println("  branch at " + source + ": " +
            (branch == null ? "<undefined>" : branch.toString()));
        if (branch != null) {
            for (Address flow : branch.getFlows()) {
                println("    flow -> " + flow);
            }
        }
        showFunction(owner, "source owner");
        showFunction(dst, "target owner");
        Function entry =
            currentProgram.getFunctionManager().getFunctionAt(target);
        println("  independent entry at target=" + (entry != null));
        println("  target inside source body=" +
            (owner != null && owner.getBody().contains(target)));
        println("  target incoming references:");
        ReferenceIterator refs = currentProgram.getReferenceManager()
            .getReferencesTo(target);
        int count = 0;
        while (refs.hasNext() && count < 80) {
            Reference ref = refs.next();
            Function from = currentProgram.getFunctionManager()
                .getFunctionContaining(ref.getFromAddress());
            println("    from=" + ref.getFromAddress() +
                " type=" + ref.getReferenceType() +
                " owner=" + (from == null ? "<none>" : from.getName()));
            ++count;
        }
        println("  incoming displayed=" + count +
            (refs.hasNext() ? " (truncated)" : ""));
        println("  target neighborhood:");
        for (long p = 0x80089094L; p <= 0x800890D0L; p += 4) {
            monitor.checkCancelled();
            Instruction i = currentProgram.getListing().getInstructionAt(toAddr(p));
            if (i != null) println("    " + i.getAddress() + " " + i);
        }
    }

    @Override
    public void run() throws Exception {
        String id = currentProgram.getLanguageID().toString();
        if (!"PowerPC:BE:64:XENON-32addr".equals(id)) {
            throw new IllegalStateException("Expected Xenon language: " + id);
        }
        println("XBOXKRNL 17559 ATOMIC PCODE V2 (READ ONLY)");
        int goodReserve = 0, goodStore = 0;
        for (long[] pair : PAIRS) {
            monitor.checkCancelled();
            if (auditReserve(requireInstruction(pair[0], "lwarx")))
                ++goodReserve;
            if (auditStore(requireInstruction(pair[1], "stwcx.")))
                ++goodStore;
        }
        println("  lwarx " + goodReserve + "/5; updated stwcx. " +
            goodStore + "/5");
        for (long p : BARRIERS) {
            Instruction i = requireInstruction(p, "sync");
            for (PcodeOp op : i.getPcode()) {
                String name = userOpName(op);
                if (!name.isEmpty()) println(
                    "  " + i.getAddress() + " sync userop=" + name);
            }
        }
        auditFunctionBoundary();
        println("Audit complete; Program unchanged.");
    }
}
