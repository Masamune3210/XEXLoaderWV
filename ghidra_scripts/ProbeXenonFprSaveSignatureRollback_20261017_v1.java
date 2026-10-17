// Temporary FPR context-saver prototype experiment.
// A Ghidra transaction is ALWAYS rolled back. No extension build required.
// Test changes only the analyzer's stored signature in memory, not instructions.
//@category Xbox360.Analysis
import java.security.MessageDigest;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

public class ProbeXenonFprSaveSignatureRollback_20261017_v1 extends GhidraScript {
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
        if(saver==null || wrapper==null || saver.isThunk() || wrapper.isThunk() ||
            saver.getParameterCount()!=14 || saver.hasCustomVariableStorage()) {
            println("REFUSE: expected 14-parameter native saver and its native wrapper.");
            return;
        }
        byte[] nativeBytes=new byte[SAVER_BYTES];
        if(currentProgram.getMemory().getBytes(a(SAVER),nativeBytes)!=SAVER_BYTES ||
            !SAVER_SHA.equals(sha(nativeBytes))) {
            println("REFUSE: saver native SHA mismatch");
            return;
        }
        for(int i=0;i<13;i++){
            Parameter p=saver.getParameter(i);
            if(!("f"+(i+1)+":8").equals(p.getVariableStorage().toString()) ||
                !p.getDataType().getName().startsWith("undefined")){
                println("REFUSE: FP param storage/type drift index="+i);
                return;
            }
        }
        Parameter ptr=saver.getParameter(13);
        if(!"r3:4".equals(ptr.getVariableStorage().toString())) {
            println("REFUSE: original r3:4 context-pointer carrier changed.");
            return;
        }
        String beforeSignature=saver.getPrototypeString(true,true);
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
            try {
                saver.setCustomVariableStorage(true);
                // Remove *only* the machine-state f1..f13 formals, from
                // highest index downwards. Preserve original r3:4 parameter,
                // its datatype, source name, and the unknown return.
                for(int i=12;i>=0;i--) saver.removeParameter(i);
                saver.setSignatureSource(SourceType.USER_DEFINED);
                if(saver.getParameterCount()!=1 ||
                    !"r3:4".equals(
                        saver.getParameter(0).getVariableStorage().toString()))
                    throw new IllegalStateException("Temporary r3 storage changed");
                duringSignature=saver.getPrototypeString(true,true);
                String modified=code(decoder,wrapper,"PROBE");
                changedCall=callContext(modified,saver.getName());
                println("SAVER_TEMPORARY "+duringSignature);
                println("WRAPPER_CALL_AFTER "+changedCall);
                println("DIFFERENT_CALL_TEXT="+
                    !callContext(baseline,saver.getName()).equals(changedCall));
            }
            finally {
                // False means discard every database change in this script.
                currentProgram.endTransaction(transaction,false);
                decoder.flushCache();
            }
            Function restored=currentProgram.getFunctionManager().getFunctionAt(a(SAVER));
            if(restored==null || restored.getParameterCount()!=14 ||
                restored.hasCustomVariableStorage() ||
                !beforeSignature.equals(restored.getPrototypeString(true,true))) {
                println("WARNING: Check the Ghidra Undo/transaction state; "+
                    "original prototype could not be independently verified");
            }
            else println("ROLLBACK_VERIFIED original 14-parameter signature restored");
            println("DONE no extension build; no intended persistent database changes");
        }
        finally {decoder.dispose();}
    }
}
