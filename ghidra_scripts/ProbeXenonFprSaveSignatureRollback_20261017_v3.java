// Temporary FPR context-saver prototype experiment.
// A Ghidra transaction is ALWAYS rolled back. No extension build required.
// Test changes only the analyzer's stored signature in memory, not instructions.
//@category Xbox360.Analysis
import java.security.MessageDigest;
import java.util.Arrays;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

public class ProbeXenonFprSaveSignatureRollback_20261017_v3 extends GhidraScript {
    private static final long SAVER=0x80075a38L, WRAPPER=0x800759f8L;
    private static final String EXECUTABLE_SHA=
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String SAVER_SHA=
        "99af6e7e062400eeb32f418cec412f74e4d9acb28e3b1e5afc1e2de10ccd0f1b";
    private static final int SAVER_BYTES=0x8c;

    private Address a(long value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }
    private String sha(byte[] b) throws Exception {
        StringBuilder out=new StringBuilder();
        for(byte x:MessageDigest.getInstance("SHA-256").digest(b))
            out.append(String.format("%02x",x & 255));
        return out.toString();
    }
    private String code(DecompInterface decoder,Function f,String phase) {
        decoder.flushCache();
        DecompileResults result=decoder.decompileFunction(f,60,monitor);
        if(!result.decompileCompleted() || result.getDecompiledFunction()==null) {
            println("DECOMPILE_"+phase+"_FAIL "+result.getErrorMessage());
            return null;
        }
        return result.getDecompiledFunction().getC();
    }
    private String callContext(String c,String targetName) {
        if(c==null)return "UNAVAILABLE";
        int i=c.indexOf(targetName+"(");
        if(i<0)return "CALL_NOT_FOUND; C-prefix="+
            c.substring(0,Math.min(250,c.length())).replace('\n',' ');
        return c.substring(Math.max(0,i-80),Math.min(c.length(),i+700))
            .replace('\n',' ').replaceAll("\\s+"," ").trim();
    }

    private String metadata(Function function) {
        if(function==null)return "MISSING_FUNCTION";
        return "entry="+function.getEntryPoint()+" name="+function.getName()+
            " isThunk="+function.isThunk()+" parameters="+function.getParameterCount()+
            " autoParameters="+function.getAutoParameterCount()+
            " customStorage="+function.hasCustomVariableStorage()+
            " signatureSource="+function.getSignatureSource()+
            " return="+function.getReturnType().getName()+
            " returnStorage="+function.getReturn().getVariableStorage()+
            " convention="+function.getCallingConventionName()+
            " prototype="+function.getPrototypeString(true,true);
    }
    private String paramMeta(Parameter p) {
        return "name="+p.getName()+" datatype="+p.getDataType().getName()+
            " storage="+p.getVariableStorage()+" source="+p.getSource()+
            " auto="+p.isAutoParameter();
    }
    private String[] paramSnapshot(Function f) {
        Parameter[] p=f.getParameters();
        String[] answer=new String[p.length];
        for(int i=0;i<p.length;i++)answer[i]=paramMeta(p[i]);
        return answer;
    }
    // Removal of default-named parameters may renumber param_14 to param_1.
    // Parameter *names* are not storage invariants: require the exact original
    // datatype and r3:4 register carrier instead.
    private boolean preservedCarrier(Parameter p, String storage, String type, boolean wasAuto) {
        return p != null && storage.equals(p.getVariableStorage().toString()) &&
            type.equals(p.getDataType().getName()) &&
            p.isAutoParameter() == wasAuto;
    }
    @Override protected void run() throws Exception {
        if(!"xboxkrnl.exe".equalsIgnoreCase(currentProgram.getName()) ||
            !EXECUTABLE_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()) ||
            !"PowerPC:BE:64:XENON-32addr".equals(
                currentProgram.getLanguageID().getIdAsString())) {
            println("REFUSE: not the expected retail 17559 Xenon kernel.");
            return;
        }
        Function saver=currentProgram.getFunctionManager().getFunctionAt(a(SAVER));
        Function wrapper=currentProgram.getFunctionManager().getFunctionAt(a(WRAPPER));
        println("SAVER_METADATA "+metadata(saver));
        println("WRAPPER_METADATA "+metadata(wrapper));
        if(saver!=null) {
            Parameter[] params=saver.getParameters();
            for(int i=0;i<params.length;i++)
                println("SAVER_PARAMETER index="+i+" "+paramMeta(params[i]));
        }
        if(saver==null || wrapper==null || saver.isThunk() || wrapper.isThunk()) {
            println("REFUSE: saver/wrapper entry missing or is a thunk. No changes.");
            return;
        }
        byte[] nativeBytes=new byte[SAVER_BYTES];
        if(currentProgram.getMemory().getBytes(a(SAVER),nativeBytes)!=SAVER_BYTES ||
            !SAVER_SHA.equals(sha(nativeBytes))) {
            println("REFUSE: saver native SHA mismatch");
            return;
        }
        if(saver.getParameterCount()!=14) {
            println("REFUSE: saver currently has "+saver.getParameterCount()+
                " parameters, not the 14 in the archived export. No prototype edits.");
            return;
        }
        for(int i=0;i<13;i++) {
            Parameter p=saver.getParameter(i);
            String expected="f"+(i+1)+":8";
            if(!expected.equals(p.getVariableStorage().toString()) ||
                !p.getDataType().getName().startsWith("undefined") ||
                p.isAutoParameter()) {
                println("REFUSE: FPR param mismatch index="+i+" expectedStorage="+
                    expected+" actual="+paramMeta(p));
                return;
            }
        }
        Parameter ptr=saver.getParameter(13);
        if(!"r3:4".equals(ptr.getVariableStorage().toString())) {
            println("REFUSE: preserved context-pointer r3:4 has drifted: "+
                paramMeta(ptr));
            return;
        }
        String beforeSignature=saver.getPrototypeString(true,true);
        boolean beforeCustom=saver.hasCustomVariableStorage();
        String beforeReturn=saver.getReturnType().getName();
        String beforeReturnStorage=saver.getReturn().getVariableStorage().toString();
        String[] beforeParams=paramSnapshot(saver);
        String expectedPtr=paramMeta(ptr);
        String expectedPtrStorage=ptr.getVariableStorage().toString();
        String expectedPtrType=ptr.getDataType().getName();
        boolean expectedPtrAuto=ptr.isAutoParameter();
        DecompInterface decoder=new DecompInterface();
        try {
            if(!decoder.openProgram(currentProgram))
                throw new IllegalStateException("Unable to start decompiler");
            String baseline=code(decoder,wrapper,"BASELINE");
            println("SAVER_ORIGINAL "+beforeSignature);
            println("WRAPPER_CALL_BEFORE "+callContext(baseline,saver.getName()));
            int transaction=currentProgram.startTransaction(
                "ROLLBACK ONLY: Xenon context saver prototype probe");
            String duringSignature="";
            String changedCall="";
            boolean tested=false;
            String experimentFailure=null;
            try {
                if(!saver.hasCustomVariableStorage())
                    saver.setCustomVariableStorage(true);
                if(saver.getParameterCount()!=14 ||
                    !preservedCarrier(saver.getParameter(13), expectedPtrStorage,
                        expectedPtrType, expectedPtrAuto)) {
                    throw new IllegalStateException(
                        "Storage-mode conversion changed the real r3 argument");
                }
                // Custom storage preserves the true r3 carrier. These
                // machine-state FPRs are removed only in this transaction.
                for(int i=12;i>=0;i--) saver.removeParameter(i);
                saver.setSignatureSource(SourceType.USER_DEFINED);
                Parameter remaining=saver.getParameterCount()==1?
                    saver.getParameter(0):null;
                boolean argumentOkay=preservedCarrier(remaining,
                    expectedPtrStorage, expectedPtrType, expectedPtrAuto);
                boolean returnTypeOkay=beforeReturn.equals(
                    saver.getReturnType().getName());
                boolean returnStorageOkay=beforeReturnStorage.equals(
                    saver.getReturn().getVariableStorage().toString());
                println("TEMPORARY_SIGNATURE "+saver.getPrototypeString(true,true));
                println("TEMPORARY_REAL_ARG "+(remaining==null?"MISSING":paramMeta(remaining)));
                println("REAL_ARG_BEFORE "+expectedPtr);
                println("TEMPORARY_RETURN type="+saver.getReturnType().getName()+
                    " storage="+saver.getReturn().getVariableStorage());
                println("TEMP_VALIDATION paramCount="+saver.getParameterCount()+
                    " realArgPreserved="+argumentOkay+
                    " realArgNameChanged="+
                    (remaining!=null && !ptr.getName().equals(remaining.getName()))+
                    " returnTypePreserved="+returnTypeOkay+
                    " returnStoragePreserved="+returnStorageOkay);
                if(saver.getParameterCount()!=1 || !argumentOkay ||
                    !returnTypeOkay || !returnStorageOkay) {
                    println("PROBE_WITHHELD temporary signature invariants violated");
                }
                else {
                    duringSignature=saver.getPrototypeString(true,true);
                    String modified=code(decoder,wrapper,"PROBE");
                    changedCall=callContext(modified,saver.getName());
                    println("SAVER_TEMPORARY "+duringSignature);
                    println("WRAPPER_CALL_AFTER "+changedCall);
                    if(baseline==null || modified==null) {
                        println("DIFFERENT_CALL_TEXT=INCONCLUSIVE_DECOMPILATION_FAILURE");
                    }
                    else {
                        tested=true;
                        println("DIFFERENT_CALL_TEXT="+
                            !callContext(baseline,saver.getName()).equals(changedCall));
                    }
                }
            }
            catch(Exception ex) {
                experimentFailure=ex.getClass().getSimpleName()+": "+ex.getMessage();
                println("PROBE_EXCEPTION_BEFORE_ROLLBACK "+experimentFailure);
            }
            finally {
                // False discards EVERY tentative database change, even if
                // Ghidra's prototype editor throws midway through removal.
                currentProgram.endTransaction(transaction,false);
                decoder.flushCache();
            }
            Function restored=currentProgram.getFunctionManager().getFunctionAt(a(SAVER));
            if(restored==null || restored.getParameterCount()!=14 ||
                restored.hasCustomVariableStorage()!=beforeCustom ||
                !beforeSignature.equals(restored.getPrototypeString(true,true)) ||
                !beforeReturn.equals(restored.getReturnType().getName()) ||
                !beforeReturnStorage.equals(
                    restored.getReturn().getVariableStorage().toString()) ||
                !Arrays.equals(beforeParams,paramSnapshot(restored))) {
                println("WARNING_ROLLBACK_METADATA_MISMATCH "+
                    "Compare program state or restore a backup before analysis");
                println("RESTORED_METADATA "+metadata(restored));
            }
            else println("ROLLBACK_VERIFIED full original prototype, "+
                "return and parameter storage restored");
            println("PROBE_EXECUTED="+tested+" experimentError="+experimentFailure);
            println("DONE no extension build; no intended persistent database changes");
        }
        finally {decoder.dispose();}
    }
}
