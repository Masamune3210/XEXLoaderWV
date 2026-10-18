// Experimental, MUTATES ONLY AN EXPLICITLY NAMED DISPOSABLE KERNEL COPY.
// No processor extension rebuild. Never run on the production kernel.
//@category Xbox360.Analysis
import java.security.MessageDigest;
import java.util.Locale;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

public class ProbeXenonFprParamIdSandbox_20261017_v1 extends GhidraScript {
    private static final long SAVER=0x80075a38L;
    private static final long WRAPPER=0x800759f8L;
    private static final String SHA=
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String NATIVE_SHA=
        "99af6e7e062400eeb32f418cec412f74e4d9acb28e3b1e5afc1e2de10ccd0f1b";
    private static final int NATIVE_LENGTH=0x8c;
    private Address at(long x) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x);
    }
    private String sha256(byte[] bytes) throws Exception {
        StringBuilder out=new StringBuilder();
        for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))
            out.append(String.format("%02x", b & 255));
        return out.toString();
    }
    private int fprCount(Function f) {
        int n=0;
        for(Parameter p:f.getParameters()) {
            String storage=p.getVariableStorage().toString();
            String type=p.getDataType().getName();
            for(int i=1;i<=13;i++) {
                if(storage.equals("f"+i+":8") && type.startsWith("undefined")) {
                    n++;
                    break;
                }
            }
        }
        return n;
    }
    private void status(String label,Function f) {
        println(label+" at="+f.getEntryPoint()+
            " signature="+f.getPrototypeString(true,true)+
            " source="+f.getSignatureSource()+
            " params="+f.getParameterCount()+
            " FPR_UNDEFINED="+fprCount(f)+
            " customStorage="+f.hasCustomVariableStorage()+
            " return="+f.getReturnType().getName());
    }
    private String decompileCall(DecompInterface decompiler,Function wrapper) {
        decompiler.flushCache();
        DecompileResults r=decompiler.decompileFunction(wrapper,60,monitor);
        if(!r.decompileCompleted()||r.getDecompiledFunction()==null)
            return "DECOMPILATION_FAILED "+r.getErrorMessage();
        String c=r.getDecompiledFunction().getC();
        int pos=c.indexOf("FUN_80075a38(");
        if(pos<0) return "NO_NAMED_SAVER_CALL "+
            c.substring(0,Math.min(c.length(),280)).replace('\n',' ');
        return c.substring(pos,Math.min(c.length(),pos+280))
            .replace('\n',' ').replaceAll("\\s+"," ").trim();
    }

    @Override protected void run() throws Exception {
        if(currentProgram.getDomainFile()==null ||
            !currentProgram.getDomainFile().getName()
                .toUpperCase(Locale.ROOT).contains("FPR_SANDBOX")) {
            println("REFUSE_PRODUCTION_DATABASE: create/open a distinct project "+
                "copy with FPR_SANDBOX in its file name; no changes performed.");
            return;
        }
        if(!SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()) ||
            !"PowerPC:BE:64:XENON-32addr".equals(
                currentProgram.getLanguageID().getIdAsString())) {
            println("REFUSE: unexpected executable SHA or language");
            return;
        }
        Function root=currentProgram.getFunctionManager().getFunctionAt(at(SAVER));
        Function wrapper=currentProgram.getFunctionManager().getFunctionAt(at(WRAPPER));
        if(root==null||wrapper==null||root.isThunk()||wrapper.isThunk() ||
            root.getParameterCount()!=14||wrapper.getParameterCount()!=14 ||
            !root.hasCustomVariableStorage()||!wrapper.hasCustomVariableStorage()||
            root.getSignatureSource()!=SourceType.ANALYSIS ||
            wrapper.getSignatureSource()!=SourceType.ANALYSIS ||
            fprCount(root)!=13||fprCount(wrapper)!=13) {
            println("REFUSE: source signatures not identical to the verified "+
                "baseline; do not mutate the test copy");
            if(root!=null)status("ROOT_CURRENT",root);
            if(wrapper!=null)status("WRAPPER_CURRENT",wrapper);
            return;
        }
        Parameter originalCarrier=root.getParameter(13);
        if(!originalCarrier.getVariableStorage().toString().equals("r3:4") ||
            !originalCarrier.getDataType().getName().equals("int")) {
            println("REFUSE: saved context-pointer carrier differs");
            return;
        }
        for(int i=0;i<13;i++) {
            Parameter p=root.getParameter(i);
            if(!p.getVariableStorage().toString().equals("f"+(i+1)+":8") ||
                !p.getDataType().getName().equals("undefined8")) {
                println("REFUSE: unexpected root FPR index="+i);
                return;
            }
        }
        byte[] bytes=new byte[NATIVE_LENGTH];
        if(currentProgram.getMemory().getBytes(at(SAVER),bytes)!=NATIVE_LENGTH ||
            !NATIVE_SHA.equals(sha256(bytes))) {
            println("REFUSE: context-saver native fingerprint differs");
            return;
        }
        String retType=root.getReturnType().getName();
        String retStorage=root.getReturn().getVariableStorage().toString();
        status("BEFORE_SAVER",root);
        status("BEFORE_WRAPPER",wrapper);
        DecompInterface decompiler=new DecompInterface();
        try {
            if(!decompiler.openProgram(currentProgram))
                throw new IllegalStateException("Unable to open decompiler");
            println("CALL_BEFORE "+decompileCall(decompiler,wrapper));
            // This script intentionally commits to the DISPOSABLE database.
            // The outer GhidraScript transaction is allowed to complete normally.
            for(int i=12;i>=0;i--) root.removeParameter(i);
            root.setSignatureSource(SourceType.USER_DEFINED);
            if(root.getParameterCount()!=1 ||
                !"r3:4".equals(root.getParameter(0).getVariableStorage().toString()) ||
                !"int".equals(root.getParameter(0).getDataType().getName()) ||
                !retType.equals(root.getReturnType().getName()) ||
                !retStorage.equals(root.getReturn().getVariableStorage().toString()))
                throw new IllegalStateException(
                    "SANDBOX: intervention changed retained argument or return");
            status("CORRECTED_SAVER",root);
            println("CALL_WITH_ROOT_CORRECTED "+decompileCall(decompiler,wrapper));
            // Ghidra's DecompilerParameterIdCmd resets ANALYSIS signatures,
            // protects USER_DEFINED root, and scopes its graph to this
            // one wrapper function; it is not a global kernel reanalysis.
            DecompilerParameterIdCmd paramId=new DecompilerParameterIdCmd(
                "Sandbox: re-infer only Xenon FPR save wrapper",
                new AddressSet(at(WRAPPER),at(WRAPPER)),
                SourceType.ANALYSIS,true,false,60);
            boolean result=paramId.applyTo(currentProgram,monitor);
            println("PARAMID_COMMAND_RESULT="+result+
                " detail="+paramId.getStatusMsg());
            Function revised=currentProgram.getFunctionManager().getFunctionAt(at(WRAPPER));
            status("AFTER_WRAPPER",revised);
            println("CALL_AFTER_PARAMID "+decompileCall(decompiler,revised));
            int remaining=fprCount(revised);
            if(!result) println("RESULT PARAMID_FAILED review reported status");
            else if(remaining==0) println(
                "RESULT WRAPPER_PHANTOM_FPR_REMOVED_BY_SCOPED_PARAMID");
            else println("RESULT WRAPPER_STILL_HAS_"+remaining+
                "_OPAQUE_FPR_ARGUMENTS investigate remaining inferences");
        }
        finally {
            decompiler.dispose();
        }
        println("SANDBOX_ONLY: discard the test project when finished; "+
            "production database was never opened for mutation.");
    }
}
