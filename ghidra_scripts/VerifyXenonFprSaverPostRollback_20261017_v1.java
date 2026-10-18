// READ-ONLY: verify the Ghidra transaction rollback has fully completed
// AFTER the previous script has returned to the CodeBrowser.
//@category Xbox360.Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;

public class VerifyXenonFprSaverPostRollback_20261017_v1 extends GhidraScript {
    private static final String EXECUTABLE_SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private Address at(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }
    @Override protected void run() throws Exception {
        if(!"xboxkrnl.exe".equalsIgnoreCase(currentProgram.getName()) ||
            !EXECUTABLE_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()) ||
            !"PowerPC:BE:64:XENON-32addr".equals(
                currentProgram.getLanguageID().getIdAsString())) {
            println("REFUSE WRONG_KERNEL");
            return;
        }
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(0x80075a38L));
        Function w=currentProgram.getFunctionManager().getFunctionAt(at(0x800759f8L));
        if (f==null) {
            println("ROLLBACK_UNKNOWN SAVER_MISSING");
            return;
        }
        println("SAVER_CURRENT signature="+f.getPrototypeString(true,true)+
            " source="+f.getSignatureSource()+
            " customStorage="+f.hasCustomVariableStorage()+
            " parameterCount="+f.getParameterCount()+
            " return="+f.getReturnType().getName()+
            " returnStorage="+f.getReturn().getVariableStorage());
        if(w!=null)
            println("WRAPPER_CURRENT signature="+w.getPrototypeString(true,true)+
                " source="+w.getSignatureSource()+
                " customStorage="+w.hasCustomVariableStorage()+
                " parameterCount="+w.getParameterCount());
        else println("WRAPPER_MISSING");
        int n=f.getParameterCount();
        boolean original=n==14 && f.hasCustomVariableStorage() &&
            f.getSignatureSource()==SourceType.ANALYSIS &&
            "undefined".equals(f.getReturnType().getName()) &&
            "<UNASSIGNED>".equals(f.getReturn().getVariableStorage().toString());
        for(int i=0;i<n;i++) {
            Parameter p=f.getParameter(i);
            String storage=p.getVariableStorage().toString();
            println("SAVER_PARAM "+i+" name="+p.getName()+
                " type="+p.getDataType().getName()+" storage="+storage+
                " source="+p.getSource());
            if(i<13)
                original &= ("f"+(i+1)+":8").equals(storage) &&
                    "undefined8".equals(p.getDataType().getName());
            else if(i==13)
                original &= "r3:4".equals(storage) &&
                    "int".equals(p.getDataType().getName());
        }
        if(original) {
            println("ROLLBACK_COMPLETE original 14-parameter FPR/r3 ABI metadata is present");
        }
        else if(n==1 &&
            "r3:4".equals(f.getParameter(0).getVariableStorage().toString())) {
            println("ROLLBACK_INCOMPLETE one-parameter experimental signature persists. "+
                "Do not run further modifying probes; recover the known original signature.");
        }
        else {
            println("ROLLBACK_DIVERGENT saved state differs from both the original "+
                "14-parameter declaration and the 1-parameter experiment.");
        }
        println("READ_ONLY_VERIFICATION_COMPLETE no Program edits performed");
    }
}
