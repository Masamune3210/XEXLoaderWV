// Read-only diagnostic of the first Xenon FPR Parameter ID propagation boundary.
// Run on the SAME disposable FPR_SANDBOX after the v2 chain probe, or on
// production if comparing baseline metadata. This script NEVER mutates either.
//@category Xbox360.Analysis
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;

public class AuditXenonFprBoundary_20261017_v3 extends GhidraScript {
    private static final String IMAGE_SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final long[] FOCUS = {
        0x80075a38L, // context saver
        0x800759f8L, // wrapper
        0x800755d0L, // last cleaned dispatcher
        0x80075504L, // first stubborn ANALYSIS signature
        0x8007018cL, // USER_DEFINED KfReleaseSpinLock
        0x80089eb0L  // NtClose
    };
    private final Map<Address,Integer> fpNativeCache = new HashMap<>();

    private Address at(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(offset);
    }
    private Function functionAt(long offset) {
        return currentProgram.getFunctionManager().getFunctionAt(at(offset));
    }
    private int phantomCount(Function f) {
        int n = 0;
        if (f == null) return 0;
        for (Parameter p : f.getParameters()) {
            if (!"undefined8".equals(p.getDataType().getName())) continue;
            for (int k = 1; k <= 13; k++) {
                if (p.getVariableStorage().toString().equals("f" + k + ":8")) {
                    n++;
                    break;
                }
            }
        }
        return n;
    }
    private boolean nativeFp(String mnemonic) {
        if (mnemonic == null) return false;
        String s = mnemonic.toLowerCase(Locale.ROOT);
        return s.startsWith("f") || s.startsWith("lfd")
            || s.startsWith("lfs") || s.startsWith("stfd")
            || s.startsWith("stfs") || s.startsWith("ps_");
    }
    private int countNativeFp(Function f) throws Exception {
        if (f == null || f.isExternal() || f.getBody().isEmpty()) return 0;
        Integer cached = fpNativeCache.get(f.getEntryPoint());
        if (cached != null) return cached;
        int n = 0;
        InstructionIterator it = currentProgram.getListing()
            .getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            if (nativeFp(it.next().getMnemonicString())) n++;
        }
        fpNativeCache.put(f.getEntryPoint(), n);
        return n;
    }
    private String summary(Function f) throws Exception {
        if (f == null) return "NOT_A_FUNCTION";
        return "entry=" + f.getEntryPoint()
            + " source=" + f.getSignatureSource()
            + " thunk=" + f.isThunk()
            + " custom=" + f.hasCustomVariableStorage()
            + " phantomFprs=" + phantomCount(f)
            + " nativeFpInstructions=" + countNativeFp(f)
            + " prototype=" + f.getPrototypeString(true, true);
    }
    private void line(PrintWriter report, String text) {
        println(text);
        report.println(text);
    }
    private void auditCalls(PrintWriter report, Function owner) throws Exception {
        if (owner == null || owner.isExternal()) return;
        Map<Address, List<String>> outgoing = new LinkedHashMap<>();
        List<String> unresolved = new ArrayList<>();
        int opCount = 0;
        InstructionIterator it = currentProgram.getListing()
            .getInstructions(owner.getBody(), true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Instruction inst = it.next();
            opCount++;
            if (!inst.getFlowType().isCall()) continue;
            Address[] flows = inst.getFlows();
            if (flows == null || flows.length == 0) {
                unresolved.add(inst.getAddress() + " " + inst.getMnemonicString()
                    + " (no resolved call flow; possibly indirect)");
                continue;
            }
            for (Address dest : flows)
                outgoing.computeIfAbsent(dest, k -> new ArrayList<>())
                    .add(inst.getAddress().toString());
        }
        line(report, "CALL_AUDIT owner=" + owner.getEntryPoint()
            + " instructions=" + opCount
            + " directDistinct=" + outgoing.size()
            + " unresolvedCallSites=" + unresolved.size());
        int fprTargets = 0;
        for (Map.Entry<Address, List<String>> entry : outgoing.entrySet()) {
            Function callee = currentProgram.getFunctionManager()
                .getFunctionAt(entry.getKey());
            if (callee == null) callee = currentProgram.getFunctionManager()
                .getFunctionContaining(entry.getKey());
            boolean suspect = callee != null && phantomCount(callee) != 0;
            if (suspect) fprTargets++;
            line(report, "CALL" + (suspect ? "_FPR_SUSPECT" : "")
                + " from=" + owner.getEntryPoint()
                + " sites=" + String.join(",", entry.getValue())
                + " target=" + entry.getKey()
                + " name=" + (callee == null ? "UNRESOLVED" : callee.getName())
                + " " + summary(callee));
        }
        for (String issue : unresolved)
            line(report, "CALL_UNRESOLVED from=" + owner.getEntryPoint() + " " + issue);
        line(report, "CALL_AUDIT_SUMMARY owner=" + owner.getEntryPoint()
            + " calleesWithPhantomFprs=" + fprTargets);
    }
    private void auditIncoming(PrintWriter report, Function target) throws Exception {
        if (target == null) return;
        Map<Address,Integer> callers = new TreeMap<>();
        ReferenceIterator it = currentProgram.getReferenceManager()
            .getReferencesTo(target.getEntryPoint());
        while (it.hasNext()) {
            monitor.checkCancelled();
            Reference r = it.next();
            if (!r.getReferenceType().isFlow()) continue;
            Function caller = currentProgram.getFunctionManager()
                .getFunctionContaining(r.getFromAddress());
            if (caller == null || caller.getEntryPoint().equals(target.getEntryPoint()))
                continue;
            Address entry = caller.getEntryPoint();
            callers.put(entry, callers.getOrDefault(entry, 0) + 1);
        }
        line(report, "INCOMING target=" + target.getEntryPoint()
            + " distinctCallers=" + callers.size());
        int emitted = 0;
        for (Map.Entry<Address,Integer> item : callers.entrySet()) {
            Function f = currentProgram.getFunctionManager().getFunctionAt(item.getKey());
            if (++emitted <= 80)
                line(report, "INCOMING_CALLER target=" + target.getEntryPoint()
                    + " refCount=" + item.getValue() + " " + summary(f));
        }
        if (callers.size() > 80)
            line(report, "INCOMING_TRUNCATED target=" + target.getEntryPoint()
                + " omitted=" + (callers.size() - 80));
    }
    private void auditNativeFp(PrintWriter report, Function owner) throws Exception {
        if (owner == null || owner.isExternal()) return;
        int found = 0;
        InstructionIterator it = currentProgram.getListing()
            .getInstructions(owner.getBody(), true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Instruction op = it.next();
            if (!nativeFp(op.getMnemonicString())) continue;
            found++;
            if (found <= 80)
                line(report, "NATIVE_FP owner=" + owner.getEntryPoint()
                    + " address=" + op.getAddress() + " " + op.toString());
        }
        line(report, "NATIVE_FP_SUMMARY owner=" + owner.getEntryPoint()
            + " instructions=" + found);
    }
    private void auditDecompile(PrintWriter report, DecompInterface decompiler,
                              Function f) throws Exception {
        if (f == null || f.isExternal()) return;
        decompiler.flushCache();
        DecompileResults result = decompiler.decompileFunction(f, 90, monitor);
        if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
            line(report, "DECOMP_FAILED " + f.getEntryPoint()
                + " " + result.getErrorMessage());
            return;
        }
        String c = result.getDecompiledFunction().getC();
        report.println("DECOMP_BEGIN " + f.getEntryPoint() + " " + f.getName());
        report.println(c);
        report.println("DECOMP_END " + f.getEntryPoint());
        String[] lines = c.split("\\R");
        int shown = 0;
        for (String s : lines) {
            String trimmed = s.trim();
            if (trimmed.contains("KiDispatch")
                || trimmed.contains("KfReleaseSpinLock")
                || trimmed.contains("FUN_80075")
                || trimmed.contains("FUN_80077")
                || trimmed.contains("f1")
                || trimmed.contains("param_1_00")) {
                if (shown++ < 24)
                    line(report, "DECOMP_RELEVANT " + f.getEntryPoint()
                        + " " + trimmed);
            }
        }
        line(report, "DECOMP_SUMMARY " + f.getEntryPoint()
            + " lines=" + lines.length
            + " relevantMatches=" + shown
            + " fullTextInReport=true");
    }
    @Override protected void run() throws Exception {
        if (!IMAGE_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())
            || !"PowerPC:BE:64:XENON-32addr".equals(
                currentProgram.getLanguageID().getIdAsString())) {
            println("REFUSE_IMAGE_OR_LANGUAGE: read-only audit expects kernel 17559.");
            return;
        }
        File downloads = new File(System.getProperty("user.home"), "Downloads");
        File destination = downloads.isDirectory()
            ? downloads : new File(System.getProperty("java.io.tmpdir"));
        File output = File.createTempFile(
            "XenonFprBoundaryAudit_20261017_v3_", ".txt", destination);
        try (PrintWriter report = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8))) {
            line(report, "XENON_FPR_BOUNDARY_AUDIT READ_ONLY program="
                + currentProgram.getName()
                + " domain=" + currentProgram.getDomainFile().getName()
                + " sha256=" + currentProgram.getExecutableSHA256());
            for (long offset : FOCUS) {
                monitor.checkCancelled();
                Function f = functionAt(offset);
                line(report, "FOCUS " + summary(f));
            }
            for (long offset : new long[] {0x80075504L, 0x8007018cL, 0x80089eb0L}) {
                Function f = functionAt(offset);
                auditNativeFp(report, f);
                auditCalls(report, f);
                auditIncoming(report, f);
            }
            DecompInterface decompiler = new DecompInterface();
            try {
                if (!decompiler.openProgram(currentProgram))
                    throw new IllegalStateException("Decompiler failed to open program");
                for (long offset : new long[] {
                    0x80075504L, 0x8007018cL, 0x80089eb0L
                }) auditDecompile(report, decompiler, functionAt(offset));
            } finally {
                decompiler.dispose();
            }
            line(report, "DONE READ_ONLY no Program modifications; report="
                + output.getAbsolutePath());
        }
        println("REPORT " + output.getAbsolutePath());
    }
}
