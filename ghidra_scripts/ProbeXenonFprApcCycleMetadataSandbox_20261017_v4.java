// Sandbox-only experiment: apply verified FPR metadata and probe the APC/IRQL
// recursive call cycle. No global ABI rewrite. NEVER run against production.
//@category Xbox360.Analysis
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class ProbeXenonFprApcCycleMetadataSandbox_20261017_v4 extends GhidraScript {
    private static final String EXE_SHA =
        "e1d1c87dbcbec01c71c5400cc129a462fa46738d267e29151a91c5354bdf6cb8";
    private static final String SAVER_SHA =
        "99af6e7e062400eeb32f418cec412f74e4d9acb28e3b1e5afc1e2de10ccd0f1b";
    private static final long SAVER=0x80075a38L;
    private static final long WRAPPER=0x800759f8L;
    private static final long FIRST_CALLER=0x800778a8L;
    private static final long SECOND_CALLER=0x80077b38L;
    private static final long DPC=0x800755d0L;
    private static final long IRQL=0x80075504L;
    private static final long APC=0x80078118L;
    private static final long RELEASE=0x8007018cL;
    private static final long NTCLOSE=0x80089eb0L;
    private PrintWriter output;

    private Address at(long v) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
    }
    private Function f(long v) {
        return currentProgram.getFunctionManager().getFunctionAt(at(v));
    }
    private void log(String msg) {
        println(msg);
        if (output != null) output.println(msg);
    }
    private int fpr(Function fun) {
        if (fun == null) return -1;
        int count=0;
        for(Parameter p: fun.getParameters())
            if ("undefined8".equals(p.getDataType().getName()))
                for(int j=1;j<=13;j++)
                    if (p.getVariableStorage().toString().equals("f"+j+":8")) {
                        count++;
                        break;
                    }
        return count;
    }
    private boolean fprPrefix(Function fun, int slots) {
        if(fun==null || fun.getParameterCount()<slots) return false;
        for(int i=0;i<slots;i++) {
            Parameter p=fun.getParameter(i);
            if(!"undefined8".equals(p.getDataType().getName())
                || !("f"+(i+1)+":8").equals(p.getVariableStorage().toString()))
                return false;
        }
        return true;
    }
    private boolean param(Parameter p, String name, String type, String storage) {
        return p!=null && p.getName().equals(name) &&
            p.getDataType().getName().equals(type) &&
            p.getVariableStorage().toString().equals(storage);
    }
    private int nativeFp(Function fun) throws Exception {
        int n=0;
        InstructionIterator it=currentProgram.getListing().getInstructions(fun.getBody(),true);
        while(it.hasNext()) {
            monitor.checkCancelled();
            String x=it.next().getMnemonicString().toLowerCase(Locale.ROOT);
            if (x.startsWith("f") || x.startsWith("lfd") || x.startsWith("lfs") ||
                x.startsWith("stfd") || x.startsWith("stfs") || x.startsWith("ps_"))
                n++;
        }
        return n;
    }
    private String describe(Function fun) {
        if(fun==null) return "MISSING";
        StringBuilder s=new StringBuilder(fun.getPrototypeString(true,true));
        s.append(" source=").append(fun.getSignatureSource())
            .append(" custom=").append(fun.hasCustomVariableStorage())
            .append(" phantomFprs=").append(fpr(fun))
            .append(" returnStorage=").append(fun.getReturn().getVariableStorage());
        for(Parameter p:fun.getParameters())
            s.append(" | ").append(p.getName()).append(":")
                .append(p.getDataType().getName()).append("@")
                .append(p.getVariableStorage());
        return s.toString();
    }
    private String fingerprint(byte[] bytes) throws Exception {
        StringBuilder s=new StringBuilder();
        for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))
            s.append(String.format("%02x",b&255));
        return s.toString();
    }
    private void require(boolean ok, String why) {
        if(!ok) throw new IllegalStateException("ABORT_UNEXPECTED_METADATA "+why);
    }
    private boolean calls(Function caller, long dest) throws Exception {
        InstructionIterator it=currentProgram.getListing().getInstructions(caller.getBody(),true);
        while(it.hasNext()) {
            monitor.checkCancelled();
            Instruction op=it.next();
            if(!op.getFlowType().isCall()) continue;
            for(Address a:op.getFlows())
                if(a.equals(at(dest))) return true;
        }
        return false;
    }
    private void signature(long address, String tag) {
        log(tag+" "+Long.toHexString(address)+" "+describe(f(address)));
    }
    private boolean applyParamId(long address) throws Exception {
        Function fun=f(address);
        require(fun!=null && !fun.isThunk(), "missing function "+Long.toHexString(address));
        if(fun.getSignatureSource()!=SourceType.ANALYSIS) {
            log("PARAMID_SKIPPED_USER_DEFINED "+fun.getEntryPoint());
            return false;
        }
        int before=fpr(fun);
        DecompilerParameterIdCmd cmd=new DecompilerParameterIdCmd(
            "Sandbox Xenon FPR caller recovery "+fun.getEntryPoint(),
            new AddressSet(fun.getEntryPoint(),fun.getEntryPoint()),
            SourceType.ANALYSIS,true,false,60);
        boolean success=cmd.applyTo(currentProgram,monitor);
        log("PARAMID "+Long.toHexString(address)+" success="+success+
            " status="+cmd.getStatusMsg()+" fprBefore="+before+
            " fprAfter="+fpr(f(address)));
        require(success, "Parameter ID failed at "+fun.getEntryPoint());
        return fpr(f(address))!=before;
    }
    private void applyVerifiedMetadata() throws Exception {
        Function root=f(SAVER);
        require(root!=null && !root.isThunk(),"saver missing");
        byte[] bytes=new byte[0x8c];
        require(currentProgram.getMemory().getBytes(at(SAVER),bytes)==bytes.length
            && SAVER_SHA.equals(fingerprint(bytes)),"saver native bytes differ");
        signature(SAVER,"VERIFIED_METADATA_BEFORE");
        if(fpr(root)==13) {
            require(root.getParameterCount()==14 && fprPrefix(root,13)
                && "int".equals(root.getParameter(13).getDataType().getName())
                && "r3:4".equals(root.getParameter(13).getVariableStorage().toString())
                && root.getSignatureSource()==SourceType.ANALYSIS,
                "unexpected saver baseline");
            String returnType=root.getReturnType().getName();
            String returnStorage=root.getReturn().getVariableStorage().toString();
            for(int i=12;i>=0;i--)root.removeParameter(i);
            root.setSignatureSource(SourceType.USER_DEFINED);
            require(root.getReturnType().getName().equals(returnType)
                && root.getReturn().getVariableStorage().toString().equals(returnStorage),
                "saver return changed");
            log("VERIFIED_METADATA_APPLIED saver removed 13 phantom FPR arguments");
        } else {
            require(fpr(root)==0 && root.getParameterCount()==1
                && "int".equals(root.getParameter(0).getDataType().getName())
                && "r3:4".equals(root.getParameter(0).getVariableStorage().toString())
                && root.getSignatureSource()==SourceType.USER_DEFINED,
                "unexpected cleaned saver");
            log("VERIFIED_METADATA_ALREADY_PRESENT saver");
        }
        signature(SAVER,"VERIFIED_METADATA_AFTER");

        long[] chain={WRAPPER,FIRST_CALLER,SECOND_CALLER,DPC};
        String[] expectedReturns={"undefined","undefined","undefined","uint"};
        int[] expectedParams={1,1,1,0};
        for(int i=0;i<chain.length;i++) {
            Function fun=f(chain[i]);
            require(fun!=null && !fun.isThunk(), "missing verified function");
            signature(chain[i],"VERIFIED_METADATA_BEFORE");
            if(fpr(fun)==13) {
                require(fun.getSignatureSource()==SourceType.ANALYSIS
                    && fprPrefix(fun,13),
                    "unexpected signature source for verified caller "+fun.getEntryPoint());
                applyParamId(chain[i]);
            }
            fun=f(chain[i]);
            require(fpr(fun)==0 && fun.getParameterCount()==expectedParams[i]
                && expectedReturns[i].equals(fun.getReturnType().getName()),
                "verified function disagrees with sandbox recovery at "+fun.getEntryPoint());
            if(expectedParams[i]==1)
                require("int".equals(fun.getParameter(0).getDataType().getName())
                    && "r3:4".equals(fun.getParameter(0).getVariableStorage().toString()),
                    "retained argument differs at "+fun.getEntryPoint());
            log("VERIFIED_METADATA_APPLIED_OR_CONFIRMED "+fun.getEntryPoint());
            signature(chain[i],"VERIFIED_METADATA_AFTER");
        }

        Function irql=f(IRQL);
        require(irql!=null && irql.getParameterCount()==15
            && fprPrefix(irql,13)
            && param(irql.getParameter(13),"requestedIrql","ulonglong","r3:8")
            && param(irql.getParameter(14),"pendingLevelsWord","ulonglong","r4:8"),
            "protected IRQL two GP parameters differ");
        log("VERIFIED_METADATA_PRESERVED irql requestedIrql@r3:8 and pendingLevelsWord@r4:8");
    }
    private Map<Address,String> protectedSignatures() throws Exception {
        Map<Address,String> s=new HashMap<>();
        FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);
        while(it.hasNext()) {
            monitor.checkCancelled();
            Function fun=it.next();
            if(fun.getSignatureSource()==SourceType.USER_DEFINED)
                s.put(fun.getEntryPoint(),describe(fun));
        }
        return s;
    }
    private void printCallees(long address) throws Exception {
        Function fun=f(address);
        if(fun==null)return;
        log("CALLEES_BEGIN "+fun.getName()+"@"+fun.getEntryPoint()+
            " nativeFp="+nativeFp(fun));
        InstructionIterator it=currentProgram.getListing().getInstructions(fun.getBody(),true);
        while(it.hasNext()) {
            monitor.checkCancelled();
            Instruction op=it.next();
            if(!op.getFlowType().isCall())continue;
            Address[] targets=op.getFlows();
            if(targets.length==0) log("INDIRECT_CALL "+op.getAddress()+" "+op);
            for(Address target:targets) {
                Function dest=currentProgram.getFunctionManager().getFunctionAt(target);
                log("CALLEE callSite="+op.getAddress()+" dest="+target+
                    " name="+(dest==null?"UNRESOLVED":dest.getName())+
                    " phantomFprs="+fpr(dest));
            }
        }
    }
    private void decompile(PrintWriter p,DecompInterface di,long address) throws Exception {
        Function fun=f(address);
        if(fun==null)return;
        di.flushCache();
        DecompileResults results=di.decompileFunction(fun,90,monitor);
        p.println("DECOMP_BEGIN "+fun.getEntryPoint()+" "+fun.getName());
        if(results.decompileCompleted() && results.getDecompiledFunction()!=null)
            p.println(results.getDecompiledFunction().getC());
        else p.println("DECOMP_FAILED "+results.getErrorMessage());
        p.println("DECOMP_END "+fun.getEntryPoint());
    }
    private void applyCycleProbe() throws Exception {
        Function release=f(RELEASE);
        require(release!=null && release.getSignatureSource()==SourceType.USER_DEFINED
            && !release.isThunk() && release.getParameterCount()==15
            && fprPrefix(release,13),"KfReleaseSpinLock baseline differs");
        require(param(release.getParameter(13),"spinLock","uint *32","r3:4")
            && param(release.getParameter(14),"previousIrql","ulonglong","r4:8"),
            "KfReleaseSpinLock proven GP parameter metadata differs");
        require(nativeFp(release)==0 && calls(release,IRQL),
            "KfReleaseSpinLock native calls/FP evidence differs");
        // Experimental only. The known spinlock signature is USER_DEFINED
        // but its first 13 parameters are precisely the stale f1..f13
        // Ghidra-Parameter-ID artifacts. Preserve all other metadata.
        String retType=release.getReturnType().getName();
        String retStorage=release.getReturn().getVariableStorage().toString();
        signature(RELEASE,"EXPERIMENT_BEFORE_SPINLOCK");
        for(int i=12;i>=0;i--)release.removeParameter(i);
        require(release.getParameterCount()==2 && fpr(release)==0
            && param(release.getParameter(0),"spinLock","uint *32","r3:4")
            && param(release.getParameter(1),"previousIrql","ulonglong","r4:8")
            && release.getReturnType().getName().equals(retType)
            && release.getReturn().getVariableStorage().toString().equals(retStorage),
            "spinlock probe did not retain known GP arguments and return");
        signature(RELEASE,"EXPERIMENT_AFTER_SPINLOCK");
        log("SANDBOX_HYPOTHESIS spinlock phantom FPRs removed; NOT production-safe yet");
        for(int pass=1;pass<=3;pass++) {
            log("CYCLE_PASS_START "+pass);
            for(long target:new long[]{APC,IRQL,NTCLOSE})
                applyParamId(target);
            for(long target:new long[]{APC,IRQL,NTCLOSE})
                signature(target,"CYCLE_PASS_AFTER_"+pass);
        }
    }
    @Override protected void run() throws Exception {
        if(currentProgram.getDomainFile()==null ||
            !currentProgram.getDomainFile().getName()
                .toUpperCase(Locale.ROOT).contains("FPR_SANDBOX")) {
            println("REFUSE_PRODUCTION: disposable FPR_SANDBOX copy only");
            return;
        }
        if(!EXE_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())
            || !"PowerPC:BE:64:XENON-32addr".equals(
                currentProgram.getLanguageID().getIdAsString())) {
            println("REFUSE_IMAGE: unexpected kernel executable/language");
            return;
        }
        File dl=new File(System.getProperty("user.home"),"Downloads");
        File dir=dl.isDirectory()?dl:new File(System.getProperty("java.io.tmpdir"));
        File report=File.createTempFile("XenonFprApcCycleMetadataSandbox_20261017_v4_",".txt",dir);
        try(PrintWriter writer=new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(report),StandardCharsets.UTF_8))) {
            output=writer;
            log("SANDBOX_METADATA_AND_APC_CYCLE program="+currentProgram.getName());
            Map<Address,String> protectedBefore=protectedSignatures();
            applyVerifiedMetadata();
            for(long target:new long[]{IRQL,APC,RELEASE,NTCLOSE})
                signature(target,"SCC_BEFORE");
            for(long target:new long[]{IRQL,APC,RELEASE,NTCLOSE})
                printCallees(target);
            // First confirm that the APC/IRQL/spinlock structure is real.
            require(f(APC)!=null && calls(f(IRQL),APC)
                && calls(f(APC),RELEASE) && calls(f(RELEASE),IRQL),
                "expected IRQL -> APC -> spinlock -> IRQL cycle missing");
            applyCycleProbe();
            for(long target:new long[]{IRQL,APC,RELEASE,NTCLOSE})
                printCallees(target);
            DecompInterface di=new DecompInterface();
            try{
                require(di.openProgram(currentProgram),"decompiler open failed");
                for(long target:new long[]{IRQL,APC,RELEASE,NTCLOSE})
                    decompile(writer,di,target);
            } finally { di.dispose(); }
            int protectedChanged=0;
            for(Map.Entry<Address,String> entry:protectedBefore.entrySet()) {
                Address address=entry.getKey();
                if(address.equals(at(RELEASE))) continue; // explicit sandbox probe
                Function fun=currentProgram.getFunctionManager().getFunctionAt(address);
                if(fun==null || !entry.getValue().equals(describe(fun))) {
                    // SAVER is only USER_DEFINED before the probe if v2 was run.
                    protectedChanged++;
                    log("PROTECTED_SIGNATURE_CHANGED "+address);
                }
            }
            log("PROTECTED_SIGNATURES_UNCHANGED otherThanTest="+
                (protectedBefore.size()-(protectedBefore.containsKey(at(RELEASE))?1:0))+
                " unexpectedChanges="+protectedChanged);
            require(protectedChanged==0,"unrelated pre-existing USER_DEFINED signature changed");
            log("DONE SANDBOX_ONLY metadata recovered/probed; report="+report.getAbsolutePath());
        } finally { output=null; }
        println("REPORT "+report.getAbsolutePath());
    }
}
