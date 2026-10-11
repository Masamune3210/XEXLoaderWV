// Identify shared Xenon register-save/restore multi-entry routines and
// repair two allocator signatures polluted by automatically inferred FPR args.
//@category Xbox360
//
// Hardware image: retail xboxkrnl 17559 SHA256-gated. Each mutation has
// checked opcode, caller-flow and/or existing parameter metadata evidence.
// Only names, comments and two export prototypes change. Never clear code,
// remove a function, change its body, or override the proven .pdata spans.
//
// The routines legitimately contain multiple entrypoints. These are NOT
// "stray" function splits: bl __savegprlr_N and b __restgprlr_N select
// the first callee-saved register via a fall-through store/load sequence.

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

public class ApplyXboxKrnl17559SharedRegisterHelpersV1 extends GhidraScript {
    private static final String SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String ISA = "PowerPC:BE:64:XENON-32addr";

    private static final long SAVE_GPR = 0x8010CB90L;
    private static final long REST_GPR = 0x8010CBE0L;
    private static final long SAVE_FPR = 0x8010D240L;
    private static final long REST_FPR = 0x8010D28CL;

    // Export prototype correction is independently guarded and uses explicit
    // original GPR types/storage. Set false to only name verified thunks.
    private static final boolean APPLY_ALLOCATOR_PROTOTYPES = true;

    private void check(boolean valid, String reason) {
        if (!valid) throw new IllegalStateException(reason);
    }

    private Instruction at(long address) {
        Instruction i = currentProgram.getListing().getInstructionAt(toAddr(address));
        check(i != null, "Missing decoded instruction at " + toAddr(address));
        return i;
    }

    private boolean registerStoreOrLoad(long address, String mnemonic,
                                        String bank, int index) {
        Instruction i = currentProgram.getListing()
            .getInstructionAt(toAddr(address));
        if (i == null || !mnemonic.equals(i.getMnemonicString())) return false;
        Register reg = i.getRegister(0);
        if (reg == null) return false;
        String n = reg.getName().toLowerCase(java.util.Locale.ROOT);
        String expected = Integer.toString(index);
        if ("gpr".equals(bank)) return ("r" + expected).equals(n);
        return ("f" + expected).equals(n) || ("fr" + expected).equals(n);
    }

    private boolean completeFamily(long address, String mnemonic, String bank) {
        for (int reg = 14; reg <= 31; reg++) {
            if (!registerStoreOrLoad(address + 4L * (reg - 14),
                                     mnemonic, bank, reg)) {
                return false;
            }
        }
        return true;
    }

    private void requireFlow(long from, long to, boolean expectCall) {
        Instruction instruction = at(from);
        check(instruction.getFlowType().isCall() == expectCall,
            "Unexpected branch/link form at " + toAddr(from));
        for (Address destination : instruction.getFlows()) {
            if (destination.equals(toAddr(to))) return;
        }
        throw new IllegalStateException(
            "Wrong branch destination at " + toAddr(from) +
            "; expected " + toAddr(to));
    }

    private boolean hasUnwindAt(long entry, long end) {
        Function f = currentProgram.getFunctionManager().getFunctionAt(
            toAddr(entry));
        if (f == null) return false;
        String note = f.getRepeatableComment();
        if (note == null) return false;
        String marker = "0x" + Long.toHexString(entry).toUpperCase() +
                        "-0x" + Long.toHexString(end).toUpperCase();
        return note.toUpperCase().contains(marker.toUpperCase());
    }

    private int nameExistingEntries(long first, String prefix,
                                    String provenance) throws Exception {
        int n = 0;
        for (int reg = 14; reg <= 31; reg++) {
            monitor.checkCancelled();
            long addr = first + (reg - 14) * 4L;
            Function f = currentProgram.getFunctionManager()
                .getFunctionAt(toAddr(addr));
            if (f == null) continue; // Do NOT create or split a function.
            String desired = prefix + reg;
            String prior = f.getName();
            check(prior.startsWith("FUN_") || desired.equals(prior),
                "Preserving existing nondefault symbol " + prior +
                " at " + toAddr(addr));
            if (!desired.equals(prior))
                f.setName(desired, SourceType.USER_DEFINED);
            String old = f.getRepeatableComment();
            if (old == null) old = "";
            if (!old.contains(provenance)) {
                f.setRepeatableComment(
                    old.isEmpty() ? provenance : old + "\n" + provenance);
            }
            ++n;
            println("  " + toAddr(addr) + " -> " + desired);
        }
        return n;
    }

    private Function knownExport(long address, String expected) {
        Function f = currentProgram.getFunctionManager()
            .getFunctionAt(toAddr(address));
        check(f != null && expected.equals(f.getName()),
            "Expected export " + expected + " at " + toAddr(address));
        return f;
    }

    private boolean isAutoParameter(Parameter p) {
        return p.getName().startsWith("param_") &&
               p.getSource() != SourceType.USER_DEFINED;
    }

    private void repairAllocator(Function f) throws Exception {
        Parameter[] all = f.getParameters();
        if (all.length == 3 && "allocationSize".equals(all[0].getName())
                && "allocationTag".equals(all[1].getName())
                && "poolSelection".equals(all[2].getName())) {
            println("  ExAllocatePoolTypeWithTag prototype already refined");
            return;
        }
        check(all.length == 16,
            "Allocator prototype differs from observed 13 FPR + 3 GPR parameters");
        for (int k = 0; k < 13; k++) {
            check(isAutoParameter(all[k]) &&
                all[k].getVariableStorage().toString().startsWith("f"),
                "Refusing to discard nondefault or non-FPR allocator argument " + k);
        }
        for (int k = 13; k < 16; k++)
            check(isAutoParameter(all[k]),
                "Refusing to replace manually named allocator parameter " + k);

        String[] expected = {"r3", "r4", "r5"};
        for (int k = 0; k < 3; k++) {
            check(all[k + 13].getVariableStorage().toString()
                .startsWith(expected[k] + ":"),
                "Allocator GPR storage differs at " + k);
        }
        ParameterImpl[] params = new ParameterImpl[3];
        String[] names = {"allocationSize", "allocationTag", "poolSelection"};
        for (int k = 0; k < 3; k++) {
            DataType t = all[k + 13].getDataType();
            Register reg = currentProgram.getRegister(expected[k]);
            check(reg != null, "Missing register " + expected[k]);
            params[k] = new ParameterImpl(names[k], t, reg, currentProgram);
        }
        f.updateFunction(null, null, FunctionUpdateType.CUSTOM_STORAGE,
            false, SourceType.USER_DEFINED, (Variable[])params);
        println("  ExAllocatePoolTypeWithTag: 16 inferred args -> 3 verified GPR args");
    }

    private void repairFree(Function f) throws Exception {
        Parameter[] all = f.getParameters();
        if (all.length == 1 && "poolAddress".equals(all[0].getName())) {
            println("  ExFreePool prototype already refined");
            return;
        }
        check(all.length == 13,
            "Free-pool prototype differs from observed 13 spurious FPR arguments");
        for (Parameter p : all)
            check(isAutoParameter(p) &&
                p.getVariableStorage().toString().startsWith("f"),
                "Refusing to remove manually defined/non-FPR free-pool arguments");
        ParameterImpl input = new ParameterImpl("poolAddress",
            Undefined8DataType.dataType, currentProgram.getRegister("r3"),
            currentProgram);
        f.updateFunction(null, null, FunctionUpdateType.CUSTOM_STORAGE,
            false, SourceType.USER_DEFINED, input);
        println("  ExFreePool: 13 inferred FPR args -> 1 verified r3 argument");
    }

    @Override
    public void run() throws Exception {
        check(ISA.equals(currentProgram.getLanguageID().toString()),
              "Unexpected PowerPC language");
        check(SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()),
              "Unexpected kernel image SHA256");
        check("Xbox 360 Kernel 17559 Memory Image PE".equals(
              currentProgram.getExecutableFormat()), "Unexpected kernel loader");

        // Verify the independent unwinding entries before any rename.
        check(hasUnwindAt(SAVE_GPR, 0x8010CBE0L),
              "The recorded GPR save .pdata span differs");
        check(hasUnwindAt(SAVE_FPR, 0x8010D28CL) &&
              hasUnwindAt(REST_FPR, 0x8010D2D8L),
              "Recorded FPR .pdata spans differ");

        check(completeFamily(SAVE_GPR, "std", "gpr"),
              "Unexpected GPR save instruction/register sequence");
        check(completeFamily(REST_GPR, "ld", "gpr"),
              "Unexpected GPR restore instruction/register sequence");
        requireFlow(0x800644ECL, 0x8010CBB8L, true);
        requireFlow(0x8006476CL, 0x8010CBC4L, true);
        requireFlow(0x80064760L, 0x8010CC08L, false);
        requireFlow(0x80064964L, 0x8010CC14L, false);

        boolean fprSave = completeFamily(SAVE_FPR, "stfd", "fpr");
        boolean fprRestore = completeFamily(REST_FPR, "lfd", "fpr");

        println("17559 SHARED SAVE/RESTORE ROUTINE METADATA");
        println("Verified 18 GPR stores, 18 GPR loads, two paired");
        println("prologue calls and two matching epilogue branches.");
        String provenance =
            "Verified Xenon multiple-entry register helper. Each entry " +
            "continues through the remaining shared stores/loads. " +
            "Keep the individual entrypoint and original .pdata unwind span.";
        int save = nameExistingEntries(SAVE_GPR, "__savegprlr_", provenance);
        int restore = nameExistingEntries(REST_GPR, "__restgprlr_", provenance);

        int savedFpr = 0, restoredFpr = 0;
        if (fprSave)
            savedFpr = nameExistingEntries(SAVE_FPR, "__savefpr_", provenance);
        else println("FPR save opcode/register pattern did not match; skipped names");
        if (fprRestore)
            restoredFpr = nameExistingEntries(REST_FPR, "__restfpr_", provenance);
        else println("FPR restore opcode/register pattern did not match; skipped names");

        if (APPLY_ALLOCATOR_PROTOTYPES) {
            Function allocator = knownExport(0x800644E8L,
                "ExAllocatePoolTypeWithTag");
            Function free = knownExport(0x80064768L, "ExFreePool");
            // Existing conventions and return types are retained.
            repairAllocator(allocator);
            repairFree(free);
        }

        println("Functions named/verified: gpr save=" + save +
            ", gpr restore=" + restore + ", fpr save=" + savedFpr +
            ", fpr restore=" + restoredFpr);
        println("No functions created/deleted/repartitioned; preserved " +
            "existing .pdata, return types, calling conventions and bytes.");
        println("The two longer VMX helper regions remain deliberately unnamed.");
    }
}
