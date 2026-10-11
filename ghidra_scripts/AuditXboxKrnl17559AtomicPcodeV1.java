// Read-only, real-instruction Xenon 17559 atomic p-code audit.
//@category Xbox360
//
// Checks the five verified lwarx/stwcx. pairs and three sync barriers.
// Reads the Program's *actual* instruction p-code, not fixture-generated
// source. No disassembly, reanalysis, comments, or memory edits.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class AuditXboxKrnl17559AtomicPcodeV1 extends GhidraScript {
    private static final long[][] PAIRS = {
        {0x80064574L, 0x8006457CL},
        {0x800647BCL, 0x800647C4L},
        {0x80088FBCL, 0x80088FC4L},
        {0x80089020L, 0x80089028L},
        {0x80089050L, 0x80089060L},
    };
    private static final long[] BARRIERS = {
        0x80088FD0L, 0x80089034L, 0x80089070L,
    };

    private String outputRegister(PcodeOp op) {
        Varnode out = op.getOutput();
        if (out == null) {
            return "";
        }
        Register r = currentProgram.getLanguage().getRegister(
            out.getAddress(), out.getSize());
        return r == null ? "" : r.getName();
    }

    private String userOp(PcodeOp op) {
        if (op.getOpcode() != PcodeOp.CALLOTHER || op.getNumInputs() < 1) {
            return "";
        }
        Varnode index = op.getInput(0);
        return (index == null || !index.isConstant()) ? "<dynamic>" :
            currentProgram.getLanguage().getUserDefinedOpName(
                (int) index.getOffset());
    }

    private Instruction checkedInstruction(long offset, String mnemonic) {
        Address address = toAddr(offset);
        Instruction instruction =
            currentProgram.getListing().getInstructionAt(address);
        if (instruction == null ||
                !mnemonic.equals(instruction.getMnemonicString())) {
            throw new IllegalStateException(
                "Expected " + mnemonic + " at " + address + ", found " +
                (instruction == null ? "<undefined>" :
                    instruction.getMnemonicString()));
        }
        return instruction;
    }

    private boolean examine(long offset, String mnemonic,
            boolean verbose) throws Exception {
        Instruction instruction = checkedInstruction(offset, mnemonic);
        Function enclosing =
            currentProgram.getFunctionManager().getFunctionContaining(
                instruction.getAddress());
        PcodeOp[] ops = instruction.getPcode();
        boolean reserve = false, length = false, address = false;
        int store = 0, others = 0;
        println("  " + instruction.getAddress() + " " +
            instruction.toString() + "  function=" +
            (enclosing == null ? "<none>" : enclosing.getName()));
        for (PcodeOp op : ops) {
            String out = outputRegister(op);
            if ("RESERVE".equals(out)) reserve = true;
            if ("RESERVE_LENGTH".equals(out)) length = true;
            if ("RESERVE_ADDRESS".equals(out)) address = true;
            if (op.getOpcode() == PcodeOp.STORE) ++store;
            String userop = userOp(op);
            if (op.getOpcode() == PcodeOp.CALLOTHER) ++others;
            if (verbose || !userop.isEmpty() || out.startsWith("RESERVE")) {
                println("    " + op + (out.isEmpty() ? "" : " [out=" + out +
                    "]") + (userop.isEmpty() ? "" : " [userop=" + userop + "]"));
            }
        }
        if ("lwarx".equals(mnemonic)) {
            boolean ok = reserve && length && address;
            println("    lwarx reservation outputs: RESERVE=" + reserve +
                ", LENGTH=" + length + ", ADDRESS=" + address +
                " -> " + (ok ? "PASS" : "FAIL"));
            return ok;
        }
        println("    pcode ops=" + ops.length +
            ", STORE=" + store + ", CALLOTHER=" + others);
        return true;
    }

    private void examineCriticalSectionBranch() {
        // An earlier decompilation showed a local branch from
        // RtlEnterCriticalSection to a separately named FUN_800890AC.
        // Inspect actual ownership/flow rather than merging functions
        // based on the address adjacency or misleading symbol names.
        Address from = toAddr(0x80088FF8L);
        Address target = toAddr(0x800890ACL);
        Instruction branch = currentProgram.getListing().getInstructionAt(from);
        Function sourceFunction =
            currentProgram.getFunctionManager().getFunctionContaining(from);
        Function targetFunction =
            currentProgram.getFunctionManager().getFunctionContaining(target);
        Function directTarget =
            currentProgram.getFunctionManager().getFunctionAt(target);
        println("Potential RtlEnterCriticalSection function split:");
        println("  branch=" + (branch == null ? "<undefined>" :
            branch.toString()) + " @ " + from);
        if (branch != null) {
            for (Address flow : branch.getFlows()) {
                println("  actual flow target=" + flow);
            }
        }
        println("  source owner=" + (sourceFunction == null ? "<none>" :
            sourceFunction.getName() + " @ " +
            sourceFunction.getEntryPoint()));
        println("  800890AC owner=" +
            (targetFunction == null ? "<none>" :
                targetFunction.getName() + " @ " +
                targetFunction.getEntryPoint()));
        println("  function starts at 800890AC=" +
            (directTarget == null ? "<no>" : directTarget.getName()));
        println("  same function=" + (sourceFunction != null &&
            sourceFunction.equals(targetFunction)));
    }

    @Override
    public void run() throws Exception {
        String language = currentProgram.getLanguageID().toString();
        if (!"PowerPC:BE:64:XENON-32addr".equals(language)) {
            throw new IllegalStateException(
                "Requires Xenon 32-bit-address language; got " + language);
        }
        println("XBOXKRNL 17559 REAL ATOMIC PCODE AUDIT");
        println("Read only; kernel Program unchanged.");
        int good = 0;
        for (long[] pair : PAIRS) {
            monitor.checkCancelled();
            println("Pair:");
            if (examine(pair[0], "lwarx", true)) ++good;
            examine(pair[1], "stwcx.", true);
        }
        println("Barriers:");
        for (long location : BARRIERS) {
            monitor.checkCancelled();
            examine(location, "sync", false);
        }
        examineCriticalSectionBranch();
        println("RESERVATION PCODE " + good + "/" + PAIRS.length +
            " real lwarx instructions wrote all 3 reservation registers.");
        if (good != PAIRS.length) {
            println("FAIL: reservation update absent from at least one site.");
        } else {
            println("PASS: installed Xenon ISA emits corrected lwarx writes.");
        }
        println("The presence of opaque stwcx./sync CALLOTHERs does not " +
            "establish their hardware behavior.");
    }
}
