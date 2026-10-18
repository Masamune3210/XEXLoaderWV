package xexloaderwv;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * One-shot recovery of VERIFIED retail-17559 Xenon FPR parameter boundaries.
 *
 * This is an extension-side metadata/analysis repair, not a change to the
 * PowerPC calling convention. f1-f13 remain legal floating-point parameters.
 *
 * The address-specific signatures below were independently recovered in
 * disposable FPR_SANDBOX experiments v1-v7. This analyzer is intentionally
 * opt-in and SHA-scoped; its rules must not be extrapolated to other firmware
 * images merely because they use the same Xenon language.
 *
 * Run on an analyzed retail-17559 kernel database from Analyze -> One Shot
 * after function discovery / ordinary Parameter ID. It is repeat-safe for
 * signatures already in the verified post-v7 state. No function names,
 * structures, or valid unresolved return types are fabricated.
 */
public class Xenon17559FprBoundaryAnalyzer extends AbstractAnalyzer {
    private static final String XENON = "PowerPC:BE:64:XENON-32addr";
    private static final String ORIGINAL_SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String NORMALIZED_SHA =
        "1c6113602af25b0762fb10dfb0d7ad5c7fef1c7268826982188979b9bb2e4d85";
    private static final String SAVER_SHA =
        "99af6e7e062400eeb32f418cec412f74e4d9acb28e3b1e5afc1e2de10ccd0f1b";

    private static final long SAVER = 0x80075a38L;
    private static final long WRAPPER = 0x800759f8L;
    private static final long FIRST_CALLER = 0x800778a8L;
    private static final long SECOND_CALLER = 0x80077b38L;
    private static final long DPC = 0x800755d0L;
    private static final long RELEASE = 0x8007018cL;
    private static final long APC = 0x80078118L;
    private static final long IRQL = 0x80075504L;
    private static final long CLOSE_LEAF = 0x80089d40L;
    private static final long CLOSE_HELPER = 0x80089df0L;
    private static final long PROCESS_TYPE = 0x80071a68L;
    private static final long PROCESS_PROBE = 0x8008bd90L;
    private static final long NTCLOSE = 0x80089eb0L;

    public Xenon17559FprBoundaryAnalyzer() {
        super("Xenon 17559: Recover FPR signature boundaries",
            "Apply sandbox-verified Xenon context-saver and caller metadata without changing the ABI",
            AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
        setDefaultEnablement(false);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program p) {
        if (p == null || !XENON.equals(p.getLanguageID().getIdAsString()) ||
                p.getImageBase().getOffset() != 0x80040000L) return false;
        String sha = p.getExecutableSHA256();
        return sha != null &&
            (ORIGINAL_SHA.equalsIgnoreCase(sha) || NORMALIZED_SHA.equalsIgnoreCase(sha));
    }

    private static Address at(Program p, long offset) {
        return p.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static Function get(Program p, long offset) {
        return p.getFunctionManager().getFunctionAt(at(p, offset));
    }

    private static void ensure(boolean valid, String reason) {
        if (!valid) throw new IllegalStateException(reason);
    }

    private static String hash(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder out = new StringBuilder();
        for (byte b : digest) out.append(String.format("%02x", b & 255));
        return out.toString();
    }

    private static boolean isFprPhantom(Parameter p, int index) {
        return p != null && "undefined8".equals(p.getDataType().getName()) &&
            ("f" + index + ":8").equals(p.getVariableStorage().toString());
    }

    private static int phantomCount(Function f) {
        if (f == null) return -1;
        int found = 0;
        for (Parameter p : f.getParameters()) {
            for (int k = 1; k <= 13; k++) {
                if (isFprPhantom(p, k)) {
                    found++;
                    break;
                }
            }
        }
        return found;
    }

    private static void ensureFprPrefix(Function f) {
        ensure(f.getParameterCount() >= 13, "FPR baseline truncated: " + f.getEntryPoint());
        for (int i = 0; i < 13; i++)
            ensure(isFprPhantom(f.getParameter(i), i + 1),
                "Unexpected parameter in f1-f13 prefix: " + f.getEntryPoint());
    }

    private static void ensureParam(Parameter p, String type, String storage) {
        ensure(p != null && type.equals(p.getDataType().getName()) &&
            storage.equals(p.getVariableStorage().toString()),
            "Unexpected GP parameter type/storage: " + (p == null ? "MISSING" : p));
    }

    private static void ensureReturn(Function f, String type, String storage) {
        ensure(type.equals(f.getReturnType().getName()) &&
            storage.equals(f.getReturn().getVariableStorage().toString()),
            "Unexpected return type/storage: " + f.getEntryPoint());
    }

    private static int nativeFpCount(Program p, Function f, TaskMonitor monitor)
            throws CancelledException {
        int count = 0;
        InstructionIterator instructions = p.getListing().getInstructions(f.getBody(), true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            String mnemonic = instructions.next().getMnemonicString()
                .toLowerCase(Locale.ROOT);
            if (mnemonic.startsWith("f") || mnemonic.startsWith("lfd") ||
                mnemonic.startsWith("lfs") || mnemonic.startsWith("stfd") ||
                mnemonic.startsWith("stfs") || mnemonic.startsWith("ps_")) count++;
        }
        return count;
    }

    private static boolean calls(Program p, long from, long to, TaskMonitor monitor)
            throws CancelledException {
        Function f = get(p, from);
        if (f == null) return false;
        InstructionIterator instructions = p.getListing().getInstructions(f.getBody(), true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction insn = instructions.next();
            if (!insn.getFlowType().isCall()) continue;
            for (Address dest : insn.getFlows())
                if (dest.equals(at(p, to))) return true;
        }
        return false;
    }

    private static String snapshot(Function f) {
        StringBuilder s = new StringBuilder(f.getPrototypeString(true, true));
        s.append(" @").append(f.getSignatureSource());
        s.append(" custom=").append(f.hasCustomVariableStorage());
        s.append(" returnStorage=").append(f.getReturn().getVariableStorage());
        for (Parameter param : f.getParameters()) {
            s.append(" | ").append(param.getName()).append(':')
                .append(param.getDataType().getName()).append('@')
                .append(param.getVariableStorage());
        }
        return s.toString();
    }

    private static Map<Address, String> userDefinedSnapshot(Program p, TaskMonitor monitor)
            throws CancelledException {
        Map<Address, String> result = new HashMap<>();
        FunctionIterator iter = p.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            monitor.checkCancelled();
            Function f = iter.next();
            if (f.getSignatureSource() == SourceType.USER_DEFINED)
                result.put(f.getEntryPoint(), snapshot(f));
        }
        return result;
    }

    private static boolean allowedPinnedAddress(Program p, Address a) {
        return a.equals(at(p, SAVER)) || a.equals(at(p, RELEASE)) ||
            a.equals(at(p, PROCESS_TYPE));
    }

    private static void preflight(Program p, TaskMonitor monitor) throws Exception {
        byte[] bytes = new byte[0x8c];
        ensure(p.getMemory().getBytes(at(p, SAVER), bytes) == bytes.length &&
            SAVER_SHA.equals(hash(bytes)), "Unrecognized Xenon context-saver instructions");

        for (long address : new long[] {
            SAVER, WRAPPER, FIRST_CALLER, SECOND_CALLER, DPC, RELEASE, APC, IRQL,
            CLOSE_LEAF, CLOSE_HELPER, PROCESS_TYPE, PROCESS_PROBE, NTCLOSE
        }) {
            Function f = get(p, address);
            ensure(f != null && !f.isThunk(), "Missing/thunk function " +
                Long.toHexString(address));
            if (address != SAVER)
                ensure(nativeFpCount(p, f, monitor) == 0,
                    "Unexpected native FP instructions at " + f.getEntryPoint());
        }

        for (long[] pair : new long[][] {
            { WRAPPER, SAVER }, { FIRST_CALLER, WRAPPER },
            { SECOND_CALLER, FIRST_CALLER }, { DPC, SECOND_CALLER },
            { IRQL, DPC }, { IRQL, APC }, { APC, RELEASE }, { RELEASE, IRQL },
            { CLOSE_HELPER, CLOSE_LEAF }, { PROCESS_PROBE, PROCESS_TYPE },
            { NTCLOSE, PROCESS_PROBE }, { NTCLOSE, CLOSE_HELPER },
            { NTCLOSE, RELEASE }
        }) {
            ensure(calls(p, pair[0], pair[1], monitor),
                "Unexpected call topology " + Long.toHexString(pair[0]) +
                " -> " + Long.toHexString(pair[1]));
        }

        // Verify all pinned return types before touching database metadata.
        ensureReturn(get(p, SAVER), "undefined", "<UNASSIGNED>");
        ensureReturn(get(p, RELEASE), "undefined", "<UNASSIGNED>");
        ensureReturn(get(p, PROCESS_TYPE), "byte", "r3:1");
        ensureReturn(get(p, DPC), "uint", "r3:4");
        ensureReturn(get(p, NTCLOSE), "undefined8", "r3:8");
    }

    private static int pinKnownBoundary(Program p, long address, String returnType,
            String returnStorage, String[] gpTypes, String[] gpStorage,
            TaskMonitor monitor) throws Exception {
        Function f = get(p, address);
        ensureReturn(f, returnType, returnStorage);
        int remaining = phantomCount(f);
        if (remaining == 0) {
            ensure(f.getParameterCount() == gpTypes.length,
                "Clean signature has unexpected GP arguments: " + f.getEntryPoint());
            for (int k = 0; k < gpTypes.length; k++)
                ensureParam(f.getParameter(k), gpTypes[k], gpStorage[k]);
            return 0;
        }
        ensure(remaining == 13 && f.getParameterCount() == gpTypes.length + 13 &&
            (f.getSignatureSource() == SourceType.USER_DEFINED ||
             f.getSignatureSource() == SourceType.ANALYSIS),
            "Signature baseline differs at " + f.getEntryPoint());
        ensureFprPrefix(f);
        for (int k = 0; k < gpTypes.length; k++)
            ensureParam(f.getParameter(k + 13), gpTypes[k], gpStorage[k]);
        for (int i = 12; i >= 0; i--) {
            monitor.checkCancelled();
            f.removeParameter(i);
        }
        f.setSignatureSource(SourceType.USER_DEFINED);
        ensureReturn(f, returnType, returnStorage);
        ensure(phantomCount(f) == 0 &&
            f.getParameterCount() == gpTypes.length,
            "Pinned boundary did not retain GP arguments: " + f.getEntryPoint());
        for (int k = 0; k < gpTypes.length; k++)
            ensureParam(f.getParameter(k), gpTypes[k], gpStorage[k]);
        return 1;
    }

    private static void recover(Program p, long address, String returnType,
            String returnStorage, String[] gpTypes, String[] gpStorage,
            TaskMonitor monitor) throws Exception {
        Function f = get(p, address);
        ensure(f.getSignatureSource() == SourceType.ANALYSIS,
            "Refusing to overwrite USER_DEFINED signature " + f.getEntryPoint());
        ensureReturn(f, returnType, returnStorage);
        if (phantomCount(f) == 13) {
            ensureFprPrefix(f);
            DecompilerParameterIdCmd cmd = new DecompilerParameterIdCmd(
                "Xenon 17559 verified FPR repair at " + f.getEntryPoint(),
                new AddressSet(f.getEntryPoint(), f.getEntryPoint()),
                SourceType.ANALYSIS, true, false, 60);
            ensure(cmd.applyTo(p, monitor),
                "Parameter ID failed at " + f.getEntryPoint() + ": " +
                    cmd.getStatusMsg());
            f = get(p, address);
        }
        ensure(f.getSignatureSource() == SourceType.ANALYSIS &&
            phantomCount(f) == 0 && f.getParameterCount() == gpTypes.length,
            "Unexpected Parameter ID result at " + f.getEntryPoint());
        ensureReturn(f, returnType, returnStorage);
        for (int k = 0; k < gpTypes.length; k++)
            ensureParam(f.getParameter(k), gpTypes[k], gpStorage[k]);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        if (!canAnalyze(program)) return true;
        int tx = -1;
        boolean commit = false;
        try {
            preflight(program, monitor);
            Map<Address, String> before = userDefinedSnapshot(program, monitor);

            // Child transaction permits rollback if any later guard fails.
            tx = program.startTransaction("Xenon 17559 verified FPR metadata repair");

            int pinned = 0;
            pinned += pinKnownBoundary(program, SAVER, "undefined", "<UNASSIGNED>",
                new String[] {"int"}, new String[] {"r3:4"}, monitor);
            recover(program, WRAPPER, "undefined", "<UNASSIGNED>",
                new String[] {"int"}, new String[] {"r3:4"}, monitor);
            recover(program, FIRST_CALLER, "undefined", "<UNASSIGNED>",
                new String[] {"int"}, new String[] {"r3:4"}, monitor);
            recover(program, SECOND_CALLER, "undefined", "<UNASSIGNED>",
                new String[] {"int"}, new String[] {"r3:4"}, monitor);
            recover(program, DPC, "uint", "r3:4",
                new String[0], new String[0], monitor);

            pinned += pinKnownBoundary(program, RELEASE, "undefined", "<UNASSIGNED>",
                new String[] {"uint *32", "ulonglong"},
                new String[] {"r3:4", "r4:8"}, monitor);
            recover(program, APC, "undefined", "<UNASSIGNED>",
                new String[0], new String[0], monitor);
            recover(program, IRQL, "undefined", "<UNASSIGNED>",
                new String[] {"ulonglong", "ulonglong"},
                new String[] {"r3:8", "r4:8"}, monitor);

            recover(program, CLOSE_LEAF, "undefined", "<UNASSIGNED>",
                new String[] {"longlong", "ulonglong"},
                new String[] {"r3:8", "r4:8"}, monitor);
            recover(program, CLOSE_HELPER, "undefined", "<UNASSIGNED>",
                new String[] {"longlong", "ulonglong"},
                new String[] {"r3:8", "r4:8"}, monitor);

            pinned += pinKnownBoundary(program, PROCESS_TYPE, "byte", "r3:1",
                new String[0], new String[0], monitor);
            recover(program, PROCESS_PROBE, "undefined8", "r3:8",
                new String[0], new String[0], monitor);
            recover(program, NTCLOSE, "undefined8", "r3:8",
                new String[] {"ulonglong"}, new String[] {"r3:8"}, monitor);

            int checked = 0;
            for (Map.Entry<Address, String> ent : before.entrySet()) {
                monitor.checkCancelled();
                if (allowedPinnedAddress(program, ent.getKey())) continue;
                Function f = program.getFunctionManager().getFunctionAt(ent.getKey());
                ensure(f != null && ent.getValue().equals(snapshot(f)),
                    "Unexpected user-defined metadata change at " + ent.getKey());
                checked++;
            }
            commit = true;
            log.appendMsg("Xenon 17559 FPR repair PASS: 13 signatures verified; " +
                "pinned boundaries changed=" + pinned + ", unrelated USER_DEFINED " +
                "signatures preserved=" + checked +
                ". No ISA/cspec changes; KeBugCheckEx remains unmodified.");
            return true;
        }
        catch (CancelledException ex) { throw ex; }
        catch (Exception ex) {
            log.appendMsg("Xenon 17559 FPR repair ABORTED: " + ex.getMessage());
            return false;
        }
        finally {
            if (tx >= 0) program.endTransaction(tx, commit);
        }
    }
}
