// Follow-up experiment: test whether fixing a verified Xenon context-saver
// boundary allows Parameter ID to recover a whole caller chain.
// MUTATES A DISPOSABLE FPR_SANDBOX COPY ONLY. NEVER USE ON PRODUCTION.
//@category Xbox360.Analysis
import java.security.MessageDigest;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class ProbeXenonFprParamIdChainSandbox_20261017_v2 extends GhidraScript {
    private static final long SAVER = 0x80075a38L;
    private static final long WRAPPER = 0x800759f8L;
    private static final long NTCLOSE = 0x80089eb0L;
    private static final String IMAGE_SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String SAVER_NATIVE_SHA =
        "99af6e7e062400eeb32f418cec412f74e4d9acb28e3b1e5afc1e2de10ccd0f1b";
    private static final int SAVER_NATIVE_LENGTH = 0x8c;
    private static final int MAX_GRAPH_DEPTH = 24;

    private Address at(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(offset);
    }

    private String sha256(byte[] bytes) throws Exception {
        StringBuilder s = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(bytes))
            s.append(String.format("%02x", b & 255));
        return s.toString();
    }

    private Function get(long entry) {
        return currentProgram.getFunctionManager().getFunctionAt(at(entry));
    }

    private int phantomCount(Function f) {
        int count = 0;
        for (Parameter p : f.getParameters()) {
            String storage = p.getVariableStorage().toString();
            if (!"undefined8".equals(p.getDataType().getName()))
                continue;
            for (int i = 1; i <= 13; i++)
                if (storage.equals("f" + i + ":8")) {
                    count++;
                    break;
                }
        }
        return count;
    }

    private String signatureRecord(Function f) {
        StringBuilder b = new StringBuilder();
        b.append(f.getPrototypeString(true, true))
            .append(" source=").append(f.getSignatureSource())
            .append(" custom=").append(f.hasCustomVariableStorage())
            .append(" returnStorage=")
            .append(f.getReturn().getVariableStorage());
        for (Parameter p : f.getParameters())
            b.append(" | ").append(p.getName()).append(":")
                .append(p.getDataType().getName()).append("@")
                .append(p.getVariableStorage());
        return b.toString();
    }

    private void report(String prefix, Function f) {
        println(prefix + " entry=" + f.getEntryPoint()
            + " name=" + f.getName()
            + " fprPhantoms=" + phantomCount(f)
            + " " + signatureRecord(f));
    }

    private Map<Address, String> protectedSignatures() throws Exception {
        Map<Address, String> protectedFns = new HashMap<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function f = it.next();
            if (f.getSignatureSource() == SourceType.USER_DEFINED)
                protectedFns.put(f.getEntryPoint(), signatureRecord(f));
        }
        return protectedFns;
    }

    private int[] census() throws Exception {
        int[] values = {0, 0, 0};
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function f = it.next();
            if (f.isExternal()) continue;
            int n = phantomCount(f);
            if (n > 0) values[0]++;
            if (n == 13) values[1]++;
            values[2] += n;
        }
        return values;
    }

    // Discover callers from actual flow references, without guessing the
    // intermediate function addresses or trusting their current names.
    // The known endpoints are guardrails, not a repair whitelist.
    private List<Address> pathFromWrapperToNtClose() throws Exception {
        Address start = at(WRAPPER);
        Address goal = at(NTCLOSE);
        ArrayDeque<Address> q = new ArrayDeque<>();
        Map<Address, Address> nextTowardWrapper = new HashMap<>();
        Map<Address, Integer> depths = new HashMap<>();
        q.add(start);
        depths.put(start, 0);
        while (!q.isEmpty()) {
            monitor.checkCancelled();
            Address callee = q.removeFirst();
            if (callee.equals(goal)) break;
            int depth = depths.get(callee);
            if (depth >= MAX_GRAPH_DEPTH) continue;
            ReferenceIterator it = currentProgram.getReferenceManager()
                .getReferencesTo(callee);
            while (it.hasNext()) {
                Reference r = it.next();
                if (!r.getReferenceType().isFlow()) continue;
                Function caller = currentProgram.getFunctionManager()
                    .getFunctionContaining(r.getFromAddress());
                if (caller == null || caller.isExternal()) continue;
                Address parent = caller.getEntryPoint();
                if (parent.equals(callee) || depths.containsKey(parent))
                    continue;
                depths.put(parent, depth + 1);
                nextTowardWrapper.put(parent, callee);
                q.addLast(parent);
            }
        }
        if (!depths.containsKey(goal)) return Collections.emptyList();
        List<Address> result = new ArrayList<>();
        Address cursor = goal;
        Set<Address> seen = new HashSet<>();
        while (!cursor.equals(start) && seen.add(cursor)) {
            result.add(cursor);
            cursor = nextTowardWrapper.get(cursor);
            if (cursor == null) return Collections.emptyList();
        }
        if (!cursor.equals(start)) return Collections.emptyList();
        Collections.reverse(result);
        return result;
    }

    private boolean validateOriginalRoot(Function root, Function wrapper) {
        if (root == null || wrapper == null || root.isThunk() || wrapper.isThunk()
            || root.getParameterCount() != 14
            || wrapper.getParameterCount() != 14
            || !root.hasCustomVariableStorage()
            || !wrapper.hasCustomVariableStorage()
            || root.getSignatureSource() != SourceType.ANALYSIS
            || wrapper.getSignatureSource() != SourceType.ANALYSIS
            || phantomCount(root) != 13 || phantomCount(wrapper) != 13)
            return false;
        for (int i = 0; i < 13; i++) {
            Parameter p = root.getParameter(i);
            if (!p.getVariableStorage().toString().equals("f" + (i + 1) + ":8")
                || !p.getDataType().getName().equals("undefined8"))
                return false;
        }
        Parameter carrier = root.getParameter(13);
        return carrier.getVariableStorage().toString().equals("r3:4")
            && carrier.getDataType().getName().equals("int");
    }

    private void runParamId(Function f, int index) throws Exception {
        report("HOP_BEFORE_" + index, f);
        if (f.getSignatureSource() != SourceType.ANALYSIS) {
            println("HOP_SKIP_" + index + " source="
                + f.getSignatureSource() + " (preserved)");
            return;
        }
        DecompilerParameterIdCmd cmd = new DecompilerParameterIdCmd(
            "Sandbox: Xenon FPR context caller hop " + index,
            new AddressSet(f.getEntryPoint(), f.getEntryPoint()),
            SourceType.ANALYSIS, true, false, 60);
        boolean ok = cmd.applyTo(currentProgram, monitor);
        println("HOP_PARAMID_" + index + " ok=" + ok
            + " detail=" + cmd.getStatusMsg());
        Function revised = currentProgram.getFunctionManager()
            .getFunctionAt(f.getEntryPoint());
        if (revised == null) throw new IllegalStateException(
            "Parameter ID unexpectedly removed function at " + f.getEntryPoint());
        report("HOP_AFTER_" + index, revised);
        if (!ok) throw new IllegalStateException(
            "Scoped Parameter ID failed at " + f.getEntryPoint());
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram.getDomainFile() == null
            || !currentProgram.getDomainFile().getName()
                .toUpperCase(Locale.ROOT).contains("FPR_SANDBOX")) {
            println("REFUSE_PRODUCTION: program name must contain FPR_SANDBOX.");
            return;
        }
        if (!IMAGE_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())
            || !currentProgram.getLanguageID().getIdAsString()
                .equals("PowerPC:BE:64:XENON-32addr")) {
            println("REFUSE_IMAGE_OR_LANGUAGE: not the verified retail 17559 kernel.");
            return;
        }
        Function root = get(SAVER);
        Function wrapper = get(WRAPPER);
        if (!validateOriginalRoot(root, wrapper)) {
            println("REFUSE_SIGNATURE_BASELINE: use a fresh pre-probe sandbox copy.");
            if (root != null) report("ROOT_CURRENT", root);
            if (wrapper != null) report("WRAPPER_CURRENT", wrapper);
            return;
        }
        byte[] nativeBytes = new byte[SAVER_NATIVE_LENGTH];
        if (currentProgram.getMemory().getBytes(at(SAVER), nativeBytes)
                != SAVER_NATIVE_LENGTH
            || !SAVER_NATIVE_SHA.equals(sha256(nativeBytes))) {
            println("REFUSE_SAVER_FINGERPRINT: native instructions differ.");
            return;
        }

        List<Address> callerPath = pathFromWrapperToNtClose();
        if (callerPath.isEmpty() || !get(NTCLOSE).getEntryPoint()
                .equals(callerPath.get(callerPath.size() - 1))) {
            println("REFUSE_CALL_PATH: cannot establish wrapper -> NtClose chain.");
            return;
        }
        println("PATH_CALLERS_FROM_WRAPPER_TO_NTCLOSE hops=" + callerPath.size());
        println("PATH_START " + at(SAVER) + " -> " + at(WRAPPER));
        for (Address address : callerPath) {
            Function f = currentProgram.getFunctionManager().getFunctionAt(address);
            println("PATH_CALLER " + address + " " + f.getName()
                + " source=" + f.getSignatureSource()
                + " phantomFprs=" + phantomCount(f));
        }
        Map<Address, String> userDefinedBefore = protectedSignatures();
        int[] before = census();
        String originalReturnType = root.getReturnType().getName();
        String originalReturnStorage =
            root.getReturn().getVariableStorage().toString();
        report("SAVER_BEFORE", root);
        report("WRAPPER_BEFORE", wrapper);

        // As established by v1: only repair the context-saver formal boundary.
        // Do not change native instructions, register uses, or any caller by hand.
        for (int i = 12; i >= 0; i--) root.removeParameter(i);
        root.setSignatureSource(SourceType.USER_DEFINED);
        if (root.getParameterCount() != 1
            || !root.getParameter(0).getVariableStorage().toString().equals("r3:4")
            || !root.getParameter(0).getDataType().getName().equals("int")
            || !root.getReturnType().getName().equals(originalReturnType)
            || !root.getReturn().getVariableStorage().toString()
                .equals(originalReturnStorage))
            throw new IllegalStateException("Context-saver carrier or return changed");
        report("SAVER_CORRECTED", root);

        // Process callers from the saver outward, observing each hop.
        runParamId(wrapper, 0);
        for (int i = 0; i < callerPath.size(); i++) {
            Function f = currentProgram.getFunctionManager()
                .getFunctionAt(callerPath.get(i));
            if (f == null) throw new IllegalStateException(
                "Path function disappeared: " + callerPath.get(i));
            runParamId(f, i + 1);
        }

        int[] after = census();
        println("CENSUS_BEFORE functionsWithPhantomFprs=" + before[0]
            + " withAll13=" + before[1] + " totalPhantomSlots=" + before[2]);
        println("CENSUS_AFTER functionsWithPhantomFprs=" + after[0]
            + " withAll13=" + after[1] + " totalPhantomSlots=" + after[2]);

        int changedProtected = 0;
        for (Map.Entry<Address, String> item : userDefinedBefore.entrySet()) {
            Function f = currentProgram.getFunctionManager()
                .getFunctionAt(item.getKey());
            if (f == null || !item.getValue().equals(signatureRecord(f))) {
                changedProtected++;
                println("PROTECTED_SIGNATURE_CHANGED " + item.getKey());
            }
        }
        println("USER_DEFINED_SIGNATURES checked=" + userDefinedBefore.size()
            + " changed=" + changedProtected);
        if (changedProtected != 0)
            throw new IllegalStateException("Existing USER_DEFINED signature changed");
        println("SANDBOX_ONLY: discard this project copy; do not merge it to production.");
    }
}
